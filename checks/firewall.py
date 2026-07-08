import json

from checks.powershell import run_powershell


def get_firewall_profiles():
    command = """
    Get-NetFirewallProfile |
    Select-Object Name,
    @{Name='Enabled';Expression={$_.Enabled.ToString()}},
    @{Name='DefaultInboundAction';Expression={$_.DefaultInboundAction.ToString()}},
    @{Name='DefaultOutboundAction';Expression={$_.DefaultOutboundAction.ToString()}},
    @{Name='LogBlocked';Expression={$_.LogBlocked.ToString()}} |
    ConvertTo-Json
    """

    output = run_powershell(command)

    try:
        firewall_profiles = json.loads(output)
    except json.JSONDecodeError:
        return None

    if isinstance(firewall_profiles, dict):
        firewall_profiles = [firewall_profiles]

    return firewall_profiles


def analyze_firewall_profiles(firewall_profiles):
    failed_items = []
    warning_items = []

    for profile in firewall_profiles:
        name = profile.get("Name", "Unknown")
        enabled = profile.get("Enabled")
        inbound_action = profile.get("DefaultInboundAction")
        outbound_action = profile.get("DefaultOutboundAction")
        log_blocked = profile.get("LogBlocked")

        if enabled == "False":
            failed_items.append(f"{name} firewall profile is disabled")

        if inbound_action == "Allow":
            failed_items.append(f"{name} profile allows inbound connections by default")

        if inbound_action == "NotConfigured":
            warning_items.append(f"{name} profile inbound action is not explicitly configured")

        if outbound_action == "NotConfigured":
            warning_items.append(f"{name} profile outbound action is not explicitly configured")

        if log_blocked == "False":
            warning_items.append(f"{name} profile is not logging blocked traffic")

    if failed_items:
        return "FAIL", failed_items

    if warning_items:
        return "WARNING", warning_items

    return "PASS", ["Firewall profiles are enabled and inbound/outbound actions are explicitly configured."]


def print_firewall_report(firewall_profiles, status, findings):
    print("[Firewall Audit]")
    print("-" * 50)
    print(f"Overall Status: {status}")
    print()

    print("Profile Details:")

    for profile in firewall_profiles:
        name = profile.get("Name", "Unknown")
        enabled = profile.get("Enabled")
        inbound_action = profile.get("DefaultInboundAction")
        outbound_action = profile.get("DefaultOutboundAction")
        log_blocked = profile.get("LogBlocked")

        print(f"  {name} Profile")
        print(f"    Enabled: {enabled}")
        print(f"    Default Inbound Action: {inbound_action}")
        print(f"    Default Outbound Action: {outbound_action}")
        print(f"    Log Blocked Traffic: {log_blocked}")
        print()

    print("Findings:")

    for finding in findings:
        print(f"  - {finding}")

    print()


def run_firewall_audit():
    firewall_profiles = get_firewall_profiles()

    if firewall_profiles is None:
        print("[Firewall Audit]")
        print("-" * 50)
        print("Overall Status: WARNING")
        print()
        print("Could not read firewall profile settings.")
        print()
        return

    status, findings = analyze_firewall_profiles(firewall_profiles)

    print_firewall_report(firewall_profiles, status, findings)