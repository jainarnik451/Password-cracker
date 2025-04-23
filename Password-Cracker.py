import hashlib        # For hashing algorithms like MD5, SHA256, etc.
import bcrypt         # For bcrypt hashes
import passlib.hash   # For various hash types (from the passlib library)

def detect_hash_type(password_hash):
    """
    Detect which hash type the given password hash belongs to.
    """
    password_hash = password_hash.strip().lower()

    # Check if it's an MD5 hash
    if len(password_hash) == 32 and all(c in '0123456789abcdef' for c in password_hash):
        return "MD5"

    # Check if it's a SHA-1 hash
    elif len(password_hash) == 40 and all(c in '0123456789abcdef' for c in password_hash):
        return "SHA-1"

    # Check if it's a SHA-256 hash
    elif len(password_hash) == 64 and all(c in '0123456789abcdef' for c in password_hash):
        return "SHA-256"

    # Check if it's a bcrypt hash
    elif password_hash.startswith('$2a$') or password_hash.startswith('$2b$') or password_hash.startswith('$2y$'):
        return "bcrypt"

    # Check if it's PBKDF2 hash
    elif password_hash.startswith('$pbkdf2$'):
        return "PBKDF2"

    # Check if it's Argon2 hash
    elif password_hash.startswith('$argon2'):
        return "Argon2"

    return None

def crack_hash(password_hash, hash_type, dictionary_file='dictionary.txt'):
    """
    Crack the password hash using a dictionary attack.
    """
    try:
        with open(dictionary_file, 'r') as file:
            dictionary = file.readlines()
    except FileNotFoundError:
        print(f"Could not find {dictionary_file}. Please create it with one password per line.")
        return None

    if hash_type == "MD5":
        for password in dictionary:
            password = password.strip()
            if hashlib.md5(password.encode()).hexdigest() == password_hash:
                print(f"Password cracked: {password}")
                return password

    elif hash_type == "SHA-1":
        for password in dictionary:
            password = password.strip()
            if hashlib.sha1(password.encode()).hexdigest() == password_hash:
                print(f"Password cracked: {password}")
                return password

    elif hash_type == "SHA-256":
        for password in dictionary:
            password = password.strip()
            if hashlib.sha256(password.encode()).hexdigest() == password_hash:
                print(f"Password cracked: {password}")
                return password

    elif hash_type == "bcrypt":
        for password in dictionary:
            password = password.strip()
            if bcrypt.checkpw(password.encode(), password_hash.encode()):
                print(f"Password cracked: {password}")
                return password

    elif hash_type == "PBKDF2":
        # PBKDF2 cracking logic can be added here
        pass

    elif hash_type == "Argon2":
        # Argon2 cracking logic can be added here
        pass

    print("Failed to crack the password.")
    return None

def main():
    password_hash = input("Enter the password hash: ").strip()

    hash_type = detect_hash_type(password_hash)
    if hash_type:
        print(f"Detected hash type: {hash_type}")
        # Only call crack_hash, do not print again here
        crack_hash(password_hash, hash_type)
    else:
        print("Hash type could not be detected. Please check the hash format.")

if __name__ == "__main__":
    main()
