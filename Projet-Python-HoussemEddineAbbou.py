import cowsay

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
            cowsay.cow("Option 1")
        elif choice == "2":
            cowsay.cow("Option 2")
        else:
            cowsay.cow("Invalid choice")

if __name__ == "__main__":
    main()