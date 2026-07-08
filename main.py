from checks.firewall import run_firewall_audit


def main():
    print("=" * 50)
    print("Windows Security Audit Tool")
    print("=" * 50)
    print()

    run_firewall_audit()


if __name__ == "__main__":
    main()