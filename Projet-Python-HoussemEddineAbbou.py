import cowsay
import re
import stdiomask
import hashlib
import bcrypt
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


#---------------------------------------------------------------------------------#
#                                  1- Enregistrement                              # 
#---------------------------------------------------------------------------------#
def enterEmail():
    while True:
        email = input("Enter your email: ")

        emailPattern = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
        if re.fullmatch(emailPattern, email):
            return email
        cowsay.cow("Invalid email")


def enterPassword():
    while True:
        #password = getpass.getpass("Enter your password:")
        password = stdiomask.getpass("Enter your password:")

        passwordPattern = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!])(.{8,})$')
        if re.fullmatch(passwordPattern, password):
            return password
        cowsay.cow("Invalid password, please follow the password requirements:\n"
              "- At least one uppercase letter (A-Z)\n"
              "- At least one lowercase letter (a-z)\n"
              "- At least one digit (0-9)\n"
              "- At least one special character from [@#$%^&+=!]\n"
              "- Minimum length of 8 characters")
        

def saveCredentials(email, password):
    with open("Enregistrement.txt", "a") as file:
        file.write(f"{email}|{password}\n")

#---------------------------------------------------------------------------------#
#                                  2- Authentification                            # 
#---------------------------------------------------------------------------------#
def authenticateUser(email, password):
    try:
        with open("Enregistrement.txt", "r") as f:
            for line in f:
                emailFile, passwordFile = line.strip().split("|")
                if email == emailFile and password == passwordFile:
                    return True
    except FileNotFoundError:
        print("File not found")
    return False

#---------------------------------------------------------------------------------#
#                 Le menu, une fois authentifié,est comme suit                    # 
#---------------------------------------------------------------------------------#
def showMenuAuthenticated():
    while True:
        cowsay.cow("A- Give a word to hash (in invisible mode)\n"
                   "B- Encryption (RSA)\n"
                   "C- Certificate (RSA)\n"
                   "D- Quit")
        choice = input("Enter your choice: ")
        if choice == "A":
            invisibileMode()
        elif choice == "B":
            rsaEncryption()
        elif choice == "C":
            print("Your choice is C")
        elif choice == "D":
            cowsay.cow("THANK YOU FOR YOUR ATTENTION !")
            exit(0)
        else:
            cowsay.cow("Invalid choice")

#---------------------------------------------------------------------------------#
#                 A- Donnez un mot à haché (en mode invisible)                    # 
#---------------------------------------------------------------------------------#
def invisibileMode():
    while True:
        cowsay.cow("a- Hash the word with SHA-256\n"
                   "b- Hash the word by generating a salt (bcrypt)\n"
                   "c- Dictionary attack on the inserted word\n"
                   "d- Return to the main menu")

        choice = input("Enter your choice: ")

        if choice == "a":
            textSHA256 = input("Enter the text to hash using SHA-256: ")
            sha256Hash = hashlib.sha256(textSHA256.encode()).hexdigest()
            print("SHA-256 Hash:", sha256Hash)

        elif choice == "b":
            textBcrypt = input("Enter the text to hash using bcrypt with salt: ")
            salt = bcrypt.gensalt()
            bcryptHash = bcrypt.hashpw(textBcrypt.encode(), salt)
            print("Salted Hash (bcrypt):", bcryptHash)

        elif choice == "c":
            word = input("Type a word to perform a dictionary attack: ")
            
            with open('wordlist.txt', 'r') as file:
                list = [line.strip() for line in file]
            print("Performing dictionary attack...")

            for i in range(4):
                print("." * (i + 1), end='', flush=True) 
                time.sleep(1)
            
            print("\n")

            found = False
            for i in list:
                if word == i:
                    print("The word",word,"you entered has been attacked by the dictionary")
                    found = True
                    break

            if not found:
                print("The word",word,"you entered is a STRONG one GG")

        elif choice == "d":
            return
        else:
            print("Invalid choice")

#---------------------------------------------------------------------------------#
#                            B- Chiffrement (RSA)                                 # 
#---------------------------------------------------------------------------------#

def generateKeys():
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    privateKeyPem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    publicKeyPem = privateKey.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as privateKeyFile:
        privateKeyFile.write(privateKeyPem)
    with open("public_key.pem", "wb") as publicKeyFile:
        publicKeyFile.write(publicKeyPem)

    print("RSA key pair generated and saved to private_key.pem and public_key.pem")

def openPublicKey():
    try:
        with open("public_key.pem", "rb") as publicKeyFile:
            publicKey = serialization.load_pem_public_key(
                publicKeyFile.read(),
                backend=default_backend()
            )
        return publicKey
    except FileNotFoundError:
        print("File not found")

def openPrivateKey():
    try:
        with open("private_key.pem", "rb") as privateKeyFile:
            privateKey = serialization.load_pem_private_key(
                privateKeyFile.read(),
                password=None
            )
        return privateKey
    except FileNotFoundError:
        print("File not found")

def rsaEncryption():
    while True:
        cowsay.cow("a- Generate RSA key pairs and save them \n"
                   "b- Encrypt a message with RSA\n"
                   "c- Decrypt the encrypted message\n"
                   "d- Sign a message with RSA\n"
                   "e- Verify the message signature\n"
                   "f- Return to the main menu")

        choice = input("Enter your choice: ")

        if choice == "a":
            generateKeys()

        elif choice == "b":
            msg = input("Enter the message to encrypt: ")
            encryptedMsg = openPublicKey().encrypt(
                msg.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Encrypted message:",encryptedMsg.hex())

        elif choice == "c":
            encryptedMsg = input("Enter the encrypted message (in hexadecimal): ")
            msg = bytes.fromhex(encryptedMsg)
            decryptedMsg = openPrivateKey().decrypt(
                msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Decrypted message:", decryptedMsg.decode())

        elif choice == "d":
            message = input("Enter the message to sign: ")
            signature = openPrivateKey().sign(
                message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature:",signature.hex())
        elif choice == "e":
            message = input("Enter the message to verify: ")
            signature_hex = input("Enter the signature to verify (in hexadecimal): ")
            signature = bytes.fromhex(signature_hex)
            
            try:
                openPublicKey().verify(
                    signature,
                    message.encode("utf-8"),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Signature is valid")
            except InvalidSignature:
                print("Signature is invalid")

        elif choice == "f":
            return
        else:
            cowsay.cow("Invalid choice")

#---------------------------------------------------------------------------------#
#                                   MAIN                                          # 
#---------------------------------------------------------------------------------#
def main():
    print("Welcome to Houssem's project")
    while True:
        cowsay.cow("1. Register \n"
                   "2. Authenticate")

        choice = input("Choose option: ")
        if choice == "1":
            email = enterEmail()
            password = enterPassword()
            saveCredentials(email, password)
            cowsay.cow("Registration done")
        elif choice == "2":
            email = enterEmail()
            password = enterPassword()
            if authenticateUser(email, password):
                print("Authentication done")
                showMenuAuthenticated()
            else:
                cowsay.cow("Authentication failed")
        else:
            cowsay.cow("Invalid choice")

if __name__ == "__main__":
   main()