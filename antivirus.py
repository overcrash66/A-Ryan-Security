import subprocess
import logging
import os
def scan_directory(directory):
    try:
        cmd = f'powershell Start-MpScan -ScanType CustomScan -ScanPath "{directory}"'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        logging.info(f'Antivirus scan: {result.stdout}')
        return result.stdout
    except Exception as e:
        logging.error(f'AV error: {e}')
        return str(e)

def extra_antivirus_layer():
    dirs = ['C:\\Windows\\Temp', f'C:\\Users\\{os.getlogin()}\\Downloads']
    results = {d: scan_directory(d) for d in dirs}
    return results
