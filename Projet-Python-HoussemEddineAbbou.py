import cowsay
import re
import stdiomask


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
            print(email) 
            print(password)
        elif choice == "2":
            cowsay.cow("Option 2")
        else:
            cowsay.cow("Invalid choice")

if __name__ == "__main__":
    main()