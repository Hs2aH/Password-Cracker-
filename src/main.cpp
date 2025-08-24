#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <openssl/evp.h>

// ========================== Utility ==========================

static std::string trim(const std::string &s) {
    const char *ws = " \t\r\n";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

static bool starts_with(const std::string &s, const std::string &p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

static std::string to_hex(const unsigned char *bytes, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << (int)bytes[i];
    return oss.str();
}

static std::string lower_copy(std::string v) {
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c){ return std::tolower(c); });
    return v;
}

// ========================== EVP hashing ==========================

static std::string hash_evp(const std::string &input, const EVP_MD *algo) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_DigestInit_ex(ctx, algo, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(ctx);
    return to_hex(digest, digest_len);
}

static const EVP_MD* algo_from_name(const std::string &name) {
    std::string n = lower_copy(name);
    if (n == "md5")    return EVP_md5();
    if (n == "sha1")   return EVP_sha1();
    if (n == "sha256") return EVP_sha256();
    return nullptr;
}

// ========================== Charset builder ==========================

static std::string build_charset(const std::string &spec) {
    std::unordered_set<char> set;
    auto add = [&](const std::string &s){ for (char c : s) set.insert(c); };

    std::stringstream ss(spec);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        tok = trim(tok);
        if (tok.empty()) continue;
        if (tok == "lower") add("abcdefghijklmnopqrstuvwxyz");
        else if (tok == "upper") add("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        else if (tok == "digits") add("0123456789");
        else if (tok == "symbols") add("!@#$%^&*()-_=+[]{};:'\"\\|,<.>/?`~");
        else if (starts_with(tok, "lit:")) add(tok.substr(4));
        else add(tok); // treat as literal characters
    }
    std::string out(set.begin(), set.end());
    std::sort(out.begin(), out.end());
    if (out.empty()) throw std::runtime_error("Empty charset after parsing spec");
    return out;
}

// ========================== Brute-force state ==========================

struct BFState {
    int len = 0;                     // current length
    unsigned long long counter = 0;  // index within current length
};

// Very small JSON I/O (len & counter only)
static void save_state(const std::string &path, const BFState &s) {
    if (path.empty()) return;
    std::ofstream f(path);
    if (!f) return;
    f << "{\n";
    f << "  \"len\": " << s.len << ",\n";
    f << "  \"counter\": " << s.counter << "\n";
    f << "}\n";
}

static void load_state(const std::string &path, BFState &s) {
    if (path.empty()) return;
    std::ifstream f(path);
    if (!f) return;
    std::string json((std::istreambuf_iterator<char>(f)), {});
    auto find_num = [&](const std::string &key)->std::optional<unsigned long long>{
        auto p = json.find("\"" + key + "\"");
        if (p == std::string::npos) return std::nullopt;
        p = json.find(':', p);
        if (p == std::string::npos) return std::nullopt;
        ++p;
        while (p < json.size() && std::isspace((unsigned char)json[p])) ++p;
        unsigned long long v = 0;
        size_t consumed = 0;
        try {
            v = std::stoull(json.substr(p), &consumed, 10);
        } catch (...) { return std::nullopt; }
        return v;
    };
    if (auto v = find_num("len")) s.len = (int)*v;
    if (auto v = find_num("counter")) s.counter = *v;
}

// ========================== Brute-force core ==========================

// Convert a base-N "counter" to a string of fixed length using charset
static inline void counter_to_candidate(
    unsigned long long counter,
    int len,
    const std::string &charset,
    std::string &out
) {
    const size_t N = charset.size();
    out.assign(len, charset[0]); // fill with first char for leading positions
    for (int i = len - 1; i >= 0; --i) {
        out[i] = charset[counter % N];
        counter /= N;
    }
}

// Total combinations for given length
static inline unsigned long long combos_for_len(int len, size_t base) {
    // beware overflow for very large len; in practice keep len reasonable
    unsigned long long total = 1;
    for (int i = 0; i < len; ++i) {
        if (total > (std::numeric_limits<unsigned long long>::max() / base))
            return std::numeric_limits<unsigned long long>::max();
        total *= (unsigned long long)base;
    }
    return total;
}

// ========================== Cracking modes ==========================

struct Result {
    bool found = false;
    std::string password;
};

static Result wordlist_attack(
    const std::string &target_hash_hex,
    const EVP_MD *algo,
    const std::string &wordlist_path
) {
    Result r;
    std::ifstream in(wordlist_path);
    if (!in) throw std::runtime_error("Cannot open wordlist: " + wordlist_path);

    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty()) continue;
        const std::string h = hash_evp(line, algo);
        if (h == lower_copy(target_hash_hex)) {
            r.found = true;
            r.password = line;
            return r;
        }
    }
    return r;
}

static std::atomic<bool> g_stop(false);
static void handle_sigint(int){ g_stop.store(true); }

// Brute force single-thread worker
static void brute_worker(
    const std::string target_hash,
    const EVP_MD *algo,
    const std::string &charset,
    int len,
    unsigned long long start_idx,
    unsigned long long end_idx, // exclusive
    unsigned long long step,
    std::atomic<bool> &found_flag,
    std::string &found_value,
    std::mutex &found_mutex
) {
    std::string cand; cand.reserve(len);
    for (unsigned long long idx = start_idx; idx < end_idx && !found_flag.load() && !g_stop.load(); idx += step) {
        counter_to_candidate(idx, len, charset, cand);
        if (hash_evp(cand, algo) == target_hash) {
            std::lock_guard<std::mutex> lk(found_mutex);
            if (!found_flag.load()) {
                found_flag.store(true);
                found_value = cand;
            }
            return;
        }
    }
}

// Brute-force orchestrator (supports multithread; resume only in single-thread)
static Result brute_force_attack(
    const std::string &target_hash_hex,
    const EVP_MD *algo,
    const std::string &charset,
    int min_len,
    int max_len,
    int threads,
    const std::string &resume_file // empty means no resume
) {
    Result r;
    const std::string target_hash = lower_copy(target_hash_hex);
    threads = std::max(1, threads);

    // Resume only when threads == 1 (to keep state simple)
    BFState state;
    if (!resume_file.empty() && threads == 1) {
        load_state(resume_file, state);
    } else {
        state.len = std::max(min_len, 1);
        state.counter = 0ULL;
    }

    // If SIGINT, set flag so we can save state and exit gracefully
    std::signal(SIGINT, handle_sigint);

    for (int len = std::max(min_len, 1); len <= max_len && !g_stop.load(); ++len) {
        unsigned long long total = combos_for_len(len, charset.size());
        unsigned long long begin = 0ULL;

        if (threads == 1) {
            if (state.len > len) continue; // resume passed this length
            if (state.len == len) begin = state.counter;
            else begin = 0ULL;
        } else {
            begin = 0ULL; // in multithread we ignore resume
        }

        if (begin >= total) continue;

        if (threads == 1) {
            // Single-threaded scan with periodic resume
            const unsigned long long save_every = 200000ULL; // adjust as needed
            std::string cand; cand.reserve(len);

            for (unsigned long long idx = begin; idx < total && !g_stop.load(); ++idx) {
                counter_to_candidate(idx, len, charset, cand);
                if (hash_evp(cand, algo) == target_hash) {
                    r.found = true;
                    r.password = cand;
                    return r;
                }
                if (!resume_file.empty() && idx % save_every == 0) {
                    state.len = len;
                    state.counter = idx;
                    save_state(resume_file, state);
                }
            }
            // save end-of-length progress
            if (!resume_file.empty()) {
                state.len = len + 1;
                state.counter = 0;
                save_state(resume_file, state);
            }
        } else {
            // Multithreaded: split by striding
            std::atomic<bool> found(false);
            std::string found_value;
            std::mutex found_mutex;
            std::vector<std::thread> pool;
            pool.reserve(threads);

            for (int t = 0; t < threads; ++t) {
                unsigned long long start_idx = (unsigned long long)t;
                pool.emplace_back(brute_worker, target_hash, algo, charset, len,
                                  start_idx, total, (unsigned long long)threads,
                                  std::ref(found), std::ref(found_value), std::ref(found_mutex));
            }
            for (auto &th : pool) th.join();

            if (found.load()) {
                r.found = true;
                r.password = found_value;
                return r;
            }
            if (g_stop.load()) break;
        }
    }
    return r;
}

// ========================== CLI parsing ==========================

struct Args {
    std::string hash_hex;
    std::string algo_name; // md5 | sha1 | sha256
    std::string wordlist;
    bool use_bruteforce = false;
    std::string charset_spec = "lower,digits";
    int min_len = 1;
    int max_len = 6;
    int threads = 1;
    std::string resume_file; // for brute-force (single-thread)
};

static void print_usage(const char* prog) {
    std::cout <<
R"(Usage:
  )" << prog << R"( --hash <hex> --algo <md5|sha1|sha256> --wordlist <path>

  )" << prog << R"( --hash <hex> --algo <md5|sha1|sha256> --bruteforce [--charset <spec>] [--min <n>] [--max <n>] [--threads <n>] [--resume <file>]

Examples:
  # Wordlist
  )" << prog << R"( --hash 5d41402abc4b2a76b9719d911017c592 --algo md5 --wordlist rockyou.txt

  # Brute-force lower+digits, length 1..5, 4 threads
  )" << prog << R"( --hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 --algo sha256 --bruteforce --charset lower,digits --min 1 --max 5 --threads 4

Charset spec:
  Comma-separated tokens:
    lower, upper, digits, symbols, lit:<chars>
  e.g. --charset "lower,upper,digits,lit:_-"
Notes:
  * --resume works only with single-thread brute-force (--threads 1).
  * Press Ctrl+C to stop; progress is saved if --resume is used.)" << std::endl;
}

static Args parse_args(int argc, char* argv[]) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto need = [&](const char* name)->std::string{
            if (i + 1 >= argc) throw std::runtime_error(std::string("Missing value for ") + name);
            return std::string(argv[++i]);
        };
        if (k == "--hash") a.hash_hex = lower_copy(need("--hash"));
        else if (k == "--algo") a.algo_name = need("--algo");
        else if (k == "--wordlist") a.wordlist = need("--wordlist");
        else if (k == "--bruteforce") a.use_bruteforce = true;
        else if (k == "--charset") a.charset_spec = need("--charset");
        else if (k == "--min") a.min_len = std::stoi(need("--min"));
        else if (k == "--max") a.max_len = std::stoi(need("--max"));
        else if (k == "--threads") a.threads = std::max(1, std::stoi(need("--threads")));
        else if (k == "--resume") a.resume_file = need("--resume");
        else if (k == "-h" || k == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("Unknown option: " + k);
        }
    }
    if (a.hash_hex.empty() || a.algo_name.empty())
        throw std::runtime_error("Missing --hash or --algo. Use --help for usage.");
    if (!a.use_bruteforce && a.wordlist.empty())
        throw std::runtime_error("Provide --wordlist or use --bruteforce.");
    if (a.min_len < 1) a.min_len = 1;
    if (a.max_len < a.min_len) a.max_len = a.min_len;
    return a;
}

// ========================== main ==========================

int main(int argc, char* argv[]) {
    try {
        Args args = parse_args(argc, argv);
        const EVP_MD *algo = algo_from_name(args.algo_name);
        if (!algo) {
            std::cerr << "Unsupported algo: " << args.algo_name << " (use md5|sha1|sha256)\n";
            return 2;
        }

        auto t0 = std::chrono::steady_clock::now();

        Result res;
        if (!args.wordlist.empty() && !args.use_bruteforce) {
            std::cout << "[*] Mode: wordlist\n";
            res = wordlist_attack(args.hash_hex, algo, args.wordlist);
        } else {
            std::cout << "[*] Mode: brute-force\n";
            std::cout << "    charset: " << args.charset_spec << "\n";
            std::string charset = build_charset(args.charset_spec);
            res = brute_force_attack(args.hash_hex, algo, charset, args.min_len, args.max_len, args.threads, args.resume_file);
        }

        auto t1 = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(t1 - t0).count();

        if (res.found) {
            std::cout << "[+] Password found: " << res.password << "\n";
        } else {
            std::cout << "[-] Password not found.\n";
        }
        std::cout << "[*] Time: " << std::fixed << std::setprecision(2) << secs << "s\n";
        return res.found ? 0 : 1;
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        std::cerr << "Use --help for usage.\n";
        return 3;
    }
}
