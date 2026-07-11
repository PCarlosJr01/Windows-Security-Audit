from checks.firewall import run_firewall_audit


def print_header():
    print("=" * 50)
    print("Windows Security Audit Tool")
    print("=" * 50)


def print_menu():
    print()
    print("Select an audit to run:")
    print("-" * 50)
    print("1. Firewall Audit")
    print("0. Exit")
    print()


def main():
    print_header()

    while True:
        print_menu()

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            print()
            run_firewall_audit()

        elif choice == "0":
            print()
            print("Exiting Windows Security Audit Tool.")
            break

        else:
            print()
            print("Invalid choice. Please enter one of the available options.")


if __name__ == "__main__":
    main()