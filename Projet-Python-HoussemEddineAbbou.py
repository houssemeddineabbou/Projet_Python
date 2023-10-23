import cowsay
import re

def enterEmail():
    while True:
        email = input("Enter your email: ")

        emailPattern = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
        if re.fullmatch(emailPattern, email):
            return email
        cowsay.cow("Invalid email")

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
            print(email) 
        elif choice == "2":
            cowsay.cow("Option 2")
        else:
            cowsay.cow("Invalid choice")

if __name__ == "__main__":
    main()