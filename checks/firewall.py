from checks.powershell import run_powershell

def check_firewall():
    command = "Get-NetFirewallProfile | Select-Object -Property Name, Enabled"
    output = run_powershell(command)
    
    if "False" in output:
        return {
            "status": "FAIL",
            "name": "Windows Firewall",
            "message": "One or more firewall profiles are disabled."
        }

    return {
        "status": "PASS",
        "name": "Windows Firewall",
        "message": "All firewall profiles appear to be enabled."
    }