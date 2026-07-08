from checks import check_firewall

def print_results(results):
    status = results["status"]
    name = results["name"]
    message = results["message"]

    print(f"[{status}] {name}")
    print(f"       {message}")
    print()

def main():
    print("=" * 50)
    print("Windows Security Audit Tool")
    print("=" * 50)
    print()

    results = check_firewall()

    print_results(results)

if __name__ == "__main__":
    main()