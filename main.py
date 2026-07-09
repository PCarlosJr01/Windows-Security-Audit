from checks.firewall import run_firewall_audit


def main():
    print("=" * 50)
    print("Windows Security Audit Tool")
    print("=" * 50)
    print()
    print("Enter a valid number 1-10")
    print("=" * 50)
    print("1. Firewall Audit")
    print()

    choice = input("Enter your choice: ")
    if choice == "1":
        run_firewall_audit()
    else:
        print("Invalid choice. Please enter a number between 1 and 10.")


if __name__ == "__main__":
    main()