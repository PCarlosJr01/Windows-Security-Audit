import subprocess
import os   

def run_powershell(command):
    result = subprocess.run(
        ["powershell", "-Command", command],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()

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