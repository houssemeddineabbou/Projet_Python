import cowsay
import re
import stdiomask
import hashlib
import bcrypt


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
            print("Your choice is B")
        elif choice == "C":
            print("Your choice is C")
        elif choice == "D":
            cowsay.cow("Merci pour votre attention moooo KEKW")
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
            print("Dictionary attack")
        elif choice == "d":
            return
        else:
            print("Invalid choice")

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