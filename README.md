# Password Cracker 🔐

### Overview ✨
This is a multi-threaded C++ command-line tool designed to demonstrate and test password security by performing brute-force and wordlist attacks on cryptographic hashes. It utilizes the OpenSSL library for hashing functions (MD5, SHA1, SHA256) and supports resuming a brute-force attack from a previously saved state.

### Features ⚙️
- Two Cracking Modes:
  - Brute-Force: Tries every combination of characters within a specified length and character set. It can be run on multiple threads for faster cracking.
  - Wordlist: Attempts to crack the hash by comparing it against a list of passwords from a text file.

+ Multi-threading: The brute-force mode can leverage multiple CPU cores to significantly speed up the cracking process.

+ State Management: The brute-force attack can be paused and resumed. The tool saves its progress (current password length and counter) to a JSON file.

+ Customizable Character Set: You can define the characters to be used in a brute-force attack using a simple specification (e.g., lower,digits,lit:!@#).

+ Hash Algorithm Support: Supports MD5, SHA1, and SHA256 hash algorithms.

### Prerequisites 🛠️
+ A C++ compiler that supports C++17 or newer (e.g., GCC, Clang).

+ The OpenSSL development libraries.

+ On Ubuntu/Debian: sudo apt-get install libssl-dev

+ On Fedora/RHEL: sudo dnf install openssl-devel

+ On macOS (using Homebrew): brew install openssl

### Building the Tool 🏗️
To compile the source code, run the following command in your terminal. You may need to adjust the path to your OpenSSL libraries.

    g++ main.cpp -o password_cracker -lssl -lcrypto -std=c++17 -lpthread

### Usage 🏃‍♂
The tool's functionality is controlled through command-line arguments.

**Wordlist Attack 📚
**To perform a wordlist attack, you must specify the hash, the algorithm, and the path to your wordlist.

    ./password_cracker --hash <target_hash> --algo <md5|sha1|sha256> --wordlist <path_to_wordlist>

Example:

    ./password_cracker --hash a6b4a20b72c72b53448f21782245b0c7 --algo sha1 --wordlist my_common_passwords.txt

**Brute-Force Attack 💪
**To perform a brute-force attack, you need to specify the hash, the algorithm, the character set, and the password length range.

    ./password_cracker --hash <target_hash> --algo <md5|sha1|sha256> --brute-force --charset <charset_spec> --min-len <length> --max-len <length> [--threads <count>] [--resume <path_to_state_file>]

**Charset Specification:
**
1. lower: lowercase letters (a-z)

2. upper: uppercase letters (A-Z)

3. digits: numbers (0-9)

4. symbols: common symbols (!@#$%^&*()-_=+[]{};:'"\|,<.>/?~`)

5. lit:<characters>: literal characters (e.g., lit:abc123)

You can combine multiple specifications with commas, e.g., lower,digits.

Example:
To brute-force a 4-digit PIN:

    ./password_cracker --hash 827ccb0eea8a706c4c34a16891f84e7b --algo md5 --brute-force --charset digits --min-len 4 --max-len 4 --threads 4

To resume an attack, simply use the --resume flag with the path to the state file that was automatically created on a previous run. 
