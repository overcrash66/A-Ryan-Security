import subprocess
import logging
import os
def scan_directory(directory):
    try:
        # Use list format to avoid shell injection
        # Note: PowerShell command parsing implies we typically use -Command or passed args.
        # Safest is to pass the command as a script block or direct args if possible.
        # However, for Start-MpScan, it's a cmdlet.
        cmd = ["powershell", "-Command", f"Start-MpScan -ScanType CustomScan -ScanPath '{directory}'"]
        result = subprocess.run(cmd, capture_output=True, text=True) # shell=False is default
        logging.info(f'Antivirus scan: {result.stdout}')
        return result.stdout
    except Exception as e:
        logging.error(f'AV error: {e}')
        return str(e)

def extra_antivirus_layer():
    dirs = ['C:\\Windows\\Temp', f'C:\\Users\\{os.getlogin()}\\Downloads']
    results = {d: scan_directory(d) for d in dirs}
    return results
