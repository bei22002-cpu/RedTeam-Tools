"""
Cryptography Toolkit Module - Encryption/decryption, certificate generation,
key analysis, and cryptographic operations.
"""

import base64
import hashlib
import os

from modules.utils import (
    Colors,
    print_section,
    print_info,
    print_warning,
    print_error,
    print_status,
    run_command,
    check_tool,
    get_user_input,
    display_menu,
    confirm_action,
)


def crypto_toolkit_menu():
    """Cryptography toolkit menu."""
    options = [
        "Hash Generator (MD5/SHA/BLAKE2)",
        "File Hash Verifier",
        "Base64 Encode/Decode",
        "Hex Encode/Decode",
        "Generate Random Passwords/Keys",
        "RSA Key Pair Generator",
        "Self-Signed Certificate Generator",
        "Certificate Inspector",
        "Encrypt/Decrypt File (OpenSSL)",
        "SSH Key Generator & Analyzer",
    ]

    while True:
        choice = display_menu("CRYPTOGRAPHY TOOLKIT", options, Colors.MAGENTA)
        if choice == 0:
            break
        elif choice == 1:
            hash_generator()
        elif choice == 2:
            file_hash_verifier()
        elif choice == 3:
            base64_tool()
        elif choice == 4:
            hex_tool()
        elif choice == 5:
            random_generator()
        elif choice == 6:
            rsa_keygen()
        elif choice == 7:
            self_signed_cert()
        elif choice == 8:
            cert_inspector()
        elif choice == 9:
            file_encrypt_decrypt()
        elif choice == 10:
            ssh_key_tool()


def hash_generator():
    """Generate hashes for input text."""
    print_section("Hash Generator")

    text = get_user_input("Enter text to hash")
    if not text:
        print_error("No text provided.")
        return

    data = text.encode()

    algorithms = [
        ("MD5", hashlib.md5(data).hexdigest()),
        ("SHA-1", hashlib.sha1(data).hexdigest()),
        ("SHA-224", hashlib.sha224(data).hexdigest()),
        ("SHA-256", hashlib.sha256(data).hexdigest()),
        ("SHA-384", hashlib.sha384(data).hexdigest()),
        ("SHA-512", hashlib.sha512(data).hexdigest()),
        ("BLAKE2b", hashlib.blake2b(data).hexdigest()),
        ("BLAKE2s", hashlib.blake2s(data).hexdigest()),
    ]

    print_section("Hash Results")
    for name, digest in algorithms:
        print_info("  {:10s} {}".format(name, digest))

    # HMAC
    print_section("HMAC (with custom key)")
    key = get_user_input("Enter HMAC key (or press enter to skip)", "")
    if key:
        import hmac
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            h = hmac.new(key.encode(), data, algo).hexdigest()
            print_info("  HMAC-{}: {}".format(algo.upper(), h))


def file_hash_verifier():
    """Verify file integrity with hashes."""
    print_section("File Hash Verifier")

    filepath = get_user_input("Enter file path")
    if not filepath:
        print_error("No file provided.")
        return

    stdout, _, rc = run_command("test -f {} && echo exists".format(filepath))
    if "exists" not in stdout:
        print_error("File not found.")
        return

    print_status("Computing hashes...")

    algorithms = ["md5sum", "sha1sum", "sha256sum", "sha512sum"]
    for algo in algorithms:
        stdout, _, _ = run_command("{} {} 2>/dev/null".format(algo, filepath))
        if stdout:
            digest = stdout.split()[0]
            print_info("  {:12s} {}".format(algo.replace("sum", "").upper(), digest))

    # Verify against expected hash
    expected = get_user_input("Enter expected hash to verify (or press enter to skip)", "")
    if expected:
        expected = expected.strip().lower()
        # Check all computed hashes
        for algo in algorithms:
            stdout, _, _ = run_command("{} {} 2>/dev/null".format(algo, filepath))
            if stdout:
                digest = stdout.split()[0].lower()
                if digest == expected:
                    print_info("MATCH! Hash verified with {}".format(algo))
                    return
        print_error("NO MATCH - hash does not match any computed algorithm.")


def base64_tool():
    """Base64 encode/decode."""
    print_section("Base64 Encode/Decode")

    options = ["Encode text", "Decode text", "Encode file", "Decode file"]
    choice = display_menu("Base64 Operation", options, Colors.CYAN)

    if choice == 0:
        return
    elif choice == 1:
        text = get_user_input("Enter text to encode")
        if text:
            encoded = base64.b64encode(text.encode()).decode()
            print_info("Encoded: {}".format(encoded))
            print_info("Decode command: echo '{}' | base64 -d".format(encoded))

    elif choice == 2:
        text = get_user_input("Enter base64 to decode")
        if text:
            try:
                decoded = base64.b64decode(text).decode("utf-8", errors="replace")
                print_info("Decoded: {}".format(decoded))
            except Exception as e:
                print_error("Decode error: {}".format(e))

    elif choice == 3:
        filepath = get_user_input("Enter file path")
        output = get_user_input("Output file", filepath + ".b64")
        if filepath:
            stdout, _, rc = run_command("base64 {} > {} 2>/dev/null".format(filepath, output))
            if rc == 0:
                print_info("File encoded: {}".format(output))
            else:
                print_error("Failed to encode file.")

    elif choice == 4:
        filepath = get_user_input("Enter base64 file path")
        output = get_user_input("Output file", filepath + ".decoded")
        if filepath:
            stdout, _, rc = run_command("base64 -d {} > {} 2>/dev/null".format(filepath, output))
            if rc == 0:
                print_info("File decoded: {}".format(output))
            else:
                print_error("Failed to decode file.")


def hex_tool():
    """Hex encode/decode."""
    print_section("Hex Encode/Decode")

    options = ["Encode text to hex", "Decode hex to text", "Hex dump file"]
    choice = display_menu("Hex Operation", options, Colors.CYAN)

    if choice == 0:
        return
    elif choice == 1:
        text = get_user_input("Enter text")
        if text:
            hex_str = text.encode().hex()
            print_info("Hex: {}".format(hex_str))
            # Also show spaced version
            spaced = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            print_info("Spaced: {}".format(spaced))

    elif choice == 2:
        hex_str = get_user_input("Enter hex string")
        if hex_str:
            try:
                clean = hex_str.replace(" ", "").replace("0x", "").replace("\\x", "")
                decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
                print_info("Decoded: {}".format(decoded))
            except Exception as e:
                print_error("Decode error: {}".format(e))

    elif choice == 3:
        filepath = get_user_input("Enter file path")
        if filepath:
            if check_tool("xxd"):
                stdout, _, _ = run_command("xxd {} | head -40".format(filepath))
            else:
                stdout, _, _ = run_command("od -A x -t x1z -v {} | head -40".format(filepath))
            if stdout:
                print(stdout)


def random_generator():
    """Generate random passwords and cryptographic keys."""
    print_section("Random Password/Key Generator")

    options = [
        "Generate strong password",
        "Generate passphrase",
        "Generate random hex key",
        "Generate random base64 key",
        "Generate UUID",
    ]
    choice = display_menu("Generator", options, Colors.CYAN)

    if choice == 0:
        return
    elif choice == 1:
        length = get_user_input("Password length", "20")
        count = get_user_input("Number of passwords", "5")
        try:
            length = int(length)
            count = int(count)
        except ValueError:
            length, count = 20, 5

        import secrets
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:',.<>?"
        print_section("Generated Passwords")
        for i in range(count):
            pw = "".join(secrets.choice(chars) for _ in range(length))
            print_info("  {}".format(pw))

    elif choice == 2:
        words = get_user_input("Number of words", "5")
        count = get_user_input("Number of passphrases", "5")
        try:
            num_words = int(words)
            num_phrases = int(count)
        except ValueError:
            num_words, num_phrases = 5, 5

        # Try to use system wordlist
        stdout, _, _ = run_command(
            "shuf -n {} /usr/share/dict/words 2>/dev/null | tr '\\n' '-'".format(num_words * num_phrases)
        )
        if stdout:
            all_words = stdout.strip().rstrip("-").split("-")
            print_section("Generated Passphrases")
            for i in range(num_phrases):
                start = i * num_words
                phrase = "-".join(all_words[start:start + num_words])
                print_info("  {}".format(phrase))
        else:
            import secrets
            common = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
                       "golf", "hotel", "india", "juliet", "kilo", "lima",
                       "mike", "november", "oscar", "papa", "quebec", "romeo",
                       "sierra", "tango", "uniform", "victor", "whiskey",
                       "xray", "yankee", "zulu", "red", "blue", "green",
                       "cyber", "shield", "sword", "castle", "tower"]
            print_section("Generated Passphrases")
            for _ in range(num_phrases):
                phrase = "-".join(secrets.choice(common) for _ in range(num_words))
                print_info("  {}".format(phrase))

    elif choice == 3:
        length = get_user_input("Key length in bytes", "32")
        try:
            length = int(length)
        except ValueError:
            length = 32
        key = os.urandom(length).hex()
        print_info("Hex key ({} bytes): {}".format(length, key))

    elif choice == 4:
        length = get_user_input("Key length in bytes", "32")
        try:
            length = int(length)
        except ValueError:
            length = 32
        key = base64.b64encode(os.urandom(length)).decode()
        print_info("Base64 key ({} bytes): {}".format(length, key))

    elif choice == 5:
        import uuid
        print_section("Generated UUIDs")
        for _ in range(5):
            print_info("  {}".format(uuid.uuid4()))


def rsa_keygen():
    """Generate RSA key pairs."""
    print_section("RSA Key Pair Generator")

    if not check_tool("openssl"):
        print_error("openssl is required.")
        return

    bits = get_user_input("Key size (2048/4096)", "4096")
    output_dir = get_user_input("Output directory", "/tmp")
    name = get_user_input("Key name", "mykey")

    private_key = os.path.join(output_dir, "{}.pem".format(name))
    public_key = os.path.join(output_dir, "{}.pub.pem".format(name))

    print_status("Generating {}-bit RSA key pair...".format(bits))

    # Generate private key
    stdout, stderr, rc = run_command(
        "openssl genrsa -out {} {} 2>&1".format(private_key, bits)
    )
    if rc != 0:
        print_error("Failed to generate private key: {}".format(stderr))
        return

    # Extract public key
    stdout, stderr, rc = run_command(
        "openssl rsa -in {} -pubout -out {} 2>&1".format(private_key, public_key)
    )
    if rc != 0:
        print_error("Failed to extract public key: {}".format(stderr))
        return

    # Set permissions
    run_command("chmod 600 {}".format(private_key))
    run_command("chmod 644 {}".format(public_key))

    print_info("Private key: {}".format(private_key))
    print_info("Public key: {}".format(public_key))

    # Show key info
    stdout, _, _ = run_command("openssl rsa -in {} -text -noout 2>/dev/null | head -5".format(private_key))
    if stdout:
        print_info("Key info: {}".format(stdout))


def self_signed_cert():
    """Generate a self-signed SSL certificate."""
    print_section("Self-Signed Certificate Generator")

    if not check_tool("openssl"):
        print_error("openssl is required.")
        return

    cn = get_user_input("Common Name (domain)", "localhost")
    days = get_user_input("Validity (days)", "365")
    output_dir = get_user_input("Output directory", "/tmp")

    key_file = os.path.join(output_dir, "{}.key".format(cn))
    cert_file = os.path.join(output_dir, "{}.crt".format(cn))

    subject = "/C=US/ST=State/L=City/O=Organization/CN={}".format(cn)

    print_status("Generating self-signed certificate...")
    stdout, stderr, rc = run_command(
        "openssl req -x509 -newkey rsa:4096 -keyout {} -out {} "
        "-days {} -nodes -subj '{}' 2>&1".format(key_file, cert_file, days, subject)
    )

    if rc == 0:
        print_info("Key file: {}".format(key_file))
        print_info("Cert file: {}".format(cert_file))

        # Show cert info
        stdout, _, _ = run_command(
            "openssl x509 -in {} -noout -subject -issuer -dates 2>/dev/null".format(cert_file)
        )
        if stdout:
            print_section("Certificate Details")
            print(stdout)

        print_info("Use in nginx: ssl_certificate {}; ssl_certificate_key {};".format(cert_file, key_file))
    else:
        print_error("Failed to generate certificate: {}".format(stderr))


def cert_inspector():
    """Inspect SSL/TLS certificates."""
    print_section("Certificate Inspector")

    options = ["Inspect remote certificate", "Inspect local certificate file"]
    choice = display_menu("Certificate Source", options, Colors.CYAN)

    if choice == 0:
        return

    if not check_tool("openssl"):
        print_error("openssl is required.")
        return

    if choice == 1:
        host = get_user_input("Enter hostname")
        port = get_user_input("Port", "443")
        if not host:
            print_error("No hostname.")
            return

        print_status("Fetching certificate...")
        stdout, _, _ = run_command(
            "echo | openssl s_client -connect {}:{} -servername {} 2>/dev/null | "
            "openssl x509 -noout -text 2>/dev/null".format(host, port, host)
        )
        if stdout:
            print(stdout)
        else:
            print_error("Could not fetch certificate.")

    elif choice == 2:
        filepath = get_user_input("Certificate file path")
        if not filepath:
            print_error("No file.")
            return

        stdout, _, _ = run_command(
            "openssl x509 -in {} -noout -text 2>/dev/null".format(filepath)
        )
        if stdout:
            print(stdout)
        else:
            print_error("Could not read certificate.")


def file_encrypt_decrypt():
    """Encrypt or decrypt files using OpenSSL."""
    print_section("File Encryption/Decryption")

    if not check_tool("openssl"):
        print_error("openssl is required.")
        return

    options = [
        "Encrypt file (AES-256-CBC)",
        "Decrypt file (AES-256-CBC)",
        "Encrypt file (ChaCha20)",
        "Decrypt file (ChaCha20)",
    ]
    choice = display_menu("Operation", options, Colors.CYAN)

    if choice == 0:
        return

    if choice in (1, 2):
        cipher = "aes-256-cbc"
    else:
        cipher = "chacha20"

    if choice in (1, 3):
        # Encrypt
        infile = get_user_input("Input file")
        outfile = get_user_input("Output file", infile + ".enc" if infile else "")

        if not infile:
            print_error("No input file.")
            return

        print_status("Encrypting with {}...".format(cipher))
        stdout, stderr, rc = run_command(
            "openssl enc -{} -salt -pbkdf2 -in {} -out {} 2>&1".format(cipher, infile, outfile),
            timeout=30,
        )
        if rc == 0:
            print_info("Encrypted: {}".format(outfile))
        else:
            print_error("Encryption failed: {}".format(stderr))

    else:
        # Decrypt
        infile = get_user_input("Encrypted file")
        outfile = get_user_input("Output file", infile.replace(".enc", ".dec") if infile else "")

        if not infile:
            print_error("No input file.")
            return

        print_status("Decrypting with {}...".format(cipher))
        stdout, stderr, rc = run_command(
            "openssl enc -{} -d -salt -pbkdf2 -in {} -out {} 2>&1".format(cipher, infile, outfile),
            timeout=30,
        )
        if rc == 0:
            print_info("Decrypted: {}".format(outfile))
        else:
            print_error("Decryption failed: {}".format(stderr))


def ssh_key_tool():
    """Generate and analyze SSH keys."""
    print_section("SSH Key Generator & Analyzer")

    options = [
        "Generate ED25519 key pair (recommended)",
        "Generate RSA key pair",
        "Analyze existing SSH key",
        "Convert key format",
        "Show SSH fingerprint",
    ]
    choice = display_menu("SSH Key Operation", options, Colors.CYAN)

    if choice == 0:
        return

    if choice == 1:
        name = get_user_input("Key filename", "/tmp/id_ed25519_test")
        comment = get_user_input("Key comment/email", "user@host")
        stdout, stderr, rc = run_command(
            "ssh-keygen -t ed25519 -C '{}' -f {} -N '' 2>&1".format(comment, name)
        )
        if rc == 0:
            print_info("Private key: {}".format(name))
            print_info("Public key: {}.pub".format(name))
            stdout, _, _ = run_command("cat {}.pub".format(name))
            if stdout:
                print_info("Public key content:")
                print(stdout)
        else:
            print_error("Failed: {}".format(stderr))

    elif choice == 2:
        bits = get_user_input("Key size", "4096")
        name = get_user_input("Key filename", "/tmp/id_rsa_test")
        comment = get_user_input("Key comment/email", "user@host")
        stdout, stderr, rc = run_command(
            "ssh-keygen -t rsa -b {} -C '{}' -f {} -N '' 2>&1".format(bits, comment, name)
        )
        if rc == 0:
            print_info("Private key: {}".format(name))
            print_info("Public key: {}.pub".format(name))
        else:
            print_error("Failed: {}".format(stderr))

    elif choice == 3:
        keyfile = get_user_input("Key file path")
        if keyfile:
            stdout, _, _ = run_command("ssh-keygen -l -f {} 2>&1".format(keyfile))
            if stdout:
                print_info("Key info: {}".format(stdout))
            stdout, _, _ = run_command("ssh-keygen -e -f {} 2>/dev/null | head -5".format(keyfile))
            if stdout:
                print_info("Key header:")
                print(stdout)

    elif choice == 4:
        keyfile = get_user_input("Key file to convert")
        if keyfile:
            print_info("Converting to PEM format...")
            stdout, stderr, rc = run_command(
                "ssh-keygen -e -m PEM -f {} 2>&1".format(keyfile)
            )
            if stdout:
                print(stdout)
            else:
                print_error("Conversion failed: {}".format(stderr))

    elif choice == 5:
        keyfile = get_user_input("Key file path")
        if keyfile:
            for hash_algo in ["md5", "sha256"]:
                stdout, _, _ = run_command(
                    "ssh-keygen -l -E {} -f {} 2>&1".format(hash_algo, keyfile)
                )
                if stdout:
                    print_info("  {}: {}".format(hash_algo.upper(), stdout))
