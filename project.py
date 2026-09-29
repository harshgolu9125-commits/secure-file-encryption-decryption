import os
import json
import time
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ==========================================
# SETTINGS
# ==========================================

BLUE = "\033[94m"
RESET = "\033[0m"

STATE_FILE = "file_state.json"
LOG_FILE = "activity_log.txt"

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

MAX_ATTEMPTS = 3
LOCK_TIME = 5

HEADER = b"SFE2"


# ==========================================
# FIXED PASSWORD
# ==========================================

MASTER_PASSWORD = "Harsh@123"


# ==========================================
# BLUE RESULT MESSAGE
# ==========================================

def result(message):
    print(BLUE + message + RESET)


# ==========================================
# SECURITY ACTIVITY LOG
# ==========================================

def log_activity(message):

    current_time = time.strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as file:
        file.write(
            f"{current_time} - {message}\n"
        )


# ==========================================
# RSA KEY GENERATION
# ==========================================

def generate_rsa_keys():

    if os.path.exists(PRIVATE_KEY_FILE) and \
       os.path.exists(PUBLIC_KEY_FILE):

        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Save private key
    with open(PRIVATE_KEY_FILE, "wb") as file:

        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with open(PUBLIC_KEY_FILE, "wb") as file:

        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    log_activity(
        "RSA key pair generated"
    )


# ==========================================
# LOAD RSA PUBLIC KEY
# ==========================================

def load_public_key():

    with open(PUBLIC_KEY_FILE, "rb") as file:

        return serialization.load_pem_public_key(
            file.read()
        )


# ==========================================
# LOAD RSA PRIVATE KEY
# ==========================================

def load_private_key():

    with open(PRIVATE_KEY_FILE, "rb") as file:

        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


# ==========================================
# CREATE AES KEY FROM PASSWORD
# ==========================================

def create_aes_key(password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )

    return kdf.derive(
        password.encode()
    )


# ==========================================
# ENCRYPT FILE USING AES + RSA
# ==========================================

def encrypt(filename):

    # Generate random salt
    salt = os.urandom(16)

    # Create password key using fixed password
    password_key = create_aes_key(
        MASTER_PASSWORD,
        salt
    )

    # Generate random AES-256 key
    aes_key = AESGCM.generate_key(
        bit_length=256
    )

    aes = AESGCM(aes_key)

    # Generate random AES nonce
    nonce = os.urandom(12)

    # Read original file
    with open(filename, "rb") as file:
        file_data = file.read()

    # AES-256-GCM encryption
    encrypted_data = aes.encrypt(
        nonce,
        file_data,
        None
    )

    # Load RSA public key
    public_key = load_public_key()

    # Encrypt AES key using RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Create password verification data
    password_check = AESGCM(
        password_key
    )

    password_nonce = os.urandom(12)

    password_verification = password_check.encrypt(
        password_nonce,
        b"PASSWORD_OK",
        None
    )

    # Write encrypted file
    with open(filename, "wb") as file:

        # Header
        file.write(HEADER)

        # Salt
        file.write(salt)

        # Password verification nonce
        file.write(password_nonce)

        # Password verification length
        file.write(
            len(password_verification).to_bytes(
                4,
                "big"
            )
        )

        # Password verification data
        file.write(
            password_verification
        )

        # Encrypted AES key length
        file.write(
            len(encrypted_aes_key).to_bytes(
                4,
                "big"
            )
        )

        # Encrypted AES key
        file.write(
            encrypted_aes_key
        )

        # AES nonce
        file.write(
            nonce
        )

        # Encrypted file data
        file.write(
            encrypted_data
        )


# ==========================================
# DECRYPT FILE USING AES + RSA
# ==========================================

def decrypt(filename, password):

    try:

        with open(filename, "rb") as file:
            file_data = file.read()

        position = 0

        # Check header
        if not file_data.startswith(HEADER):

            return False

        position += len(HEADER)

        # Get salt
        salt = file_data[
            position:position + 16
        ]

        position += 16

        # Get password verification nonce
        password_nonce = file_data[
            position:position + 12
        ]

        position += 12

        # Get verification length
        verification_length = int.from_bytes(
            file_data[
                position:position + 4
            ],
            "big"
        )

        position += 4

        # Get password verification data
        password_verification = file_data[
            position:
            position + verification_length
        ]

        position += verification_length

        # Create password key from entered password
        password_key = create_aes_key(
            password,
            salt
        )

        # Check password
        password_check = AESGCM(
            password_key
        )

        password_check.decrypt(
            password_nonce,
            password_verification,
            None
        )

        # Get encrypted AES key length
        key_length = int.from_bytes(
            file_data[
                position:position + 4
            ],
            "big"
        )

        position += 4

        # Get encrypted AES key
        encrypted_aes_key = file_data[
            position:
            position + key_length
        ]

        position += key_length

        # Get AES nonce
        nonce = file_data[
            position:
            position + 12
        ]

        position += 12

        # Remaining data = encrypted file
        encrypted_data = file_data[
            position:
        ]

        # Load RSA private key
        private_key = load_private_key()

        # Decrypt AES key using RSA private key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # AES decryption
        aes = AESGCM(
            aes_key
        )

        decrypted_data = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )

        # Write original file
        with open(filename, "wb") as file:
            file.write(
                decrypted_data
            )

        return True

    except Exception:

        return False


# ==========================================
# PASSWORD CHECK
# ==========================================

def password_check(filename):

    attempts = 0

    while attempts < MAX_ATTEMPTS:

        password = input(
            "Enter password: "
        )

        attempts += 1

        # Try decryption
        if decrypt(
            filename,
            password
        ):

            return True

        else:

            remaining = MAX_ATTEMPTS - attempts

            log_activity(
                f"Wrong password attempt "
                f"for {filename}"
            )

            result(
                f"Wrong password! "
                f"Attempts remaining: {remaining}"
            )


    # ======================================
    # SYSTEM LOCK
    # ======================================

    result(
        "Too many incorrect attempts!"
    )

    result(
        f"System locked for "
        f"{LOCK_TIME} seconds."
    )

    log_activity(
        f"System locked after 3 wrong attempts "
        f"for {filename}"
    )


    # ======================================
    # LOCK COUNTDOWN
    # ======================================

    for remaining_time in range(
        LOCK_TIME,
        0,
        -1
    ):

        print(
            BLUE
            + f"System locked. "
              f"Try again in "
              f"{remaining_time} seconds..."
            + RESET
        )

        time.sleep(1)


    result(
        "System unlocked."
    )

    log_activity(
        "System unlocked after lock period"
    )

    return False


# ==========================================
# LOAD FILE STATUS
# ==========================================

def load_states():

    if not os.path.exists(
        STATE_FILE
    ):

        return {}

    try:

        with open(
            STATE_FILE,
            "r"
        ) as file:

            return json.load(file)

    except:

        return {}


# ==========================================
# SAVE FILE STATUS
# ==========================================

def save_states(states):

    with open(
        STATE_FILE,
        "w"
    ) as file:

        json.dump(
            states,
            file,
            indent=4
        )


# ==========================================
# GET FILE SIZE
# ==========================================

def get_file_size(filename):

    file_size = os.path.getsize(
        filename
    )

    if file_size < 1024:

        return f"{file_size} Bytes"

    elif file_size < 1024 * 1024:

        return (
            f"{file_size / 1024:.2f} KB"
        )

    else:

        return (
            f"{file_size / (1024 * 1024):.2f} MB"
        )


# ==========================================
# START PROGRAM
# ==========================================

generate_rsa_keys()


# ==========================================
# MAIN PROGRAM
# ==========================================

while True:

    print(
        "\n===================================="
    )

    print(
        "     SECURE FILE ENCRYPTION SYSTEM"
    )

    print(
        "===================================="
    )

    print(
        "1. Encrypt File"
    )

    print(
        "2. Decrypt File"
    )

    print(
        "3. Check File Status"
    )

    print(
        "4. Exit"
    )

    print(
        "===================================="
    )


    choice = input(
        "Enter your choice: "
    )

    states = load_states()


    # ======================================
    # ENCRYPTION
    # ======================================

    if choice == "1":

        filename = input(
            "Enter file name: "
        )


        # Check file
        if not os.path.exists(
            filename
        ):

            result(
                "File not found!"
            )

            continue


        # Check status
        status = states.get(
            filename,
            "unknown"
        )


        if status == "encrypted":

            result(
                "File is already encrypted!"
            )

            continue


        # ==================================
        # AES + RSA ENCRYPTION
        # ==================================

        encrypt(
            filename
        )


        # Save status
        states[filename] = "encrypted"

        save_states(
            states
        )


        # Activity log
        log_activity(
            f"{filename} encrypted using "
            f"AES-256-GCM and RSA-2048"
        )


        result(
            "File Encrypted Successfully!"
        )


    # ======================================
    # DECRYPTION
    # ======================================

    elif choice == "2":

        filename = input(
            "Enter file name: "
        )


        # Check file
        if not os.path.exists(
            filename
        ):

            result(
                "File not found!"
            )

            continue


        # Check status
        status = states.get(
            filename,
            "unknown"
        )


        if status == "decrypted":

            result(
                "File is already decrypted!"
            )

            continue


        # Password authentication
        if password_check(
            filename
        ):

            states[filename] = "decrypted"

            save_states(
                states
            )


            log_activity(
                f"{filename} decrypted using "
                f"AES-256-GCM and RSA-2048"
            )


            result(
                "File Decrypted Successfully!"
            )

        else:

            result(
                "Decryption failed!"
            )


    # ======================================
    # FILE STATUS
    # ======================================

    elif choice == "3":

        filename = input(
            "Enter file name: "
        )


        if not os.path.exists(
            filename
        ):

            result(
                "File not found!"
            )

            continue


        status = states.get(
            filename,
            "unknown"
        )


        size_text = get_file_size(
            filename
        )


        print(
            BLUE
            + "------------------------------------"
            + RESET
        )


        print(
            BLUE
            + "File Name   : "
            + filename
            + RESET
        )


        print(
            BLUE
            + "File Status : "
            + status
            + RESET
        )


        print(
            BLUE
            + "File Size   : "
            + size_text
            + RESET
        )


        print(
            BLUE
            + "Encryption  : AES-256-GCM"
            + RESET
        )


        print(
            BLUE
            + "Key Security: RSA-2048"
            + RESET
        )


        print(
            BLUE
            + "------------------------------------"
            + RESET
        )


        # Activity log for file status
        log_activity(
            f"File status checked: {filename} - {status}"
        )


    # ======================================
    # EXIT
    # ======================================

    elif choice == "4":

        result(
            "Thank you for using "
            "Secure File Encryption System!"
        )

        break


    # ======================================
    # INVALID CHOICE
    # ======================================

    else:

        result(
            "Invalid choice! "
            "Please enter 1, 2, 3 or 4."
        )