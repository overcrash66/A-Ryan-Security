import subprocess
import logging

def check_firewall_status():
    try:
        cmd = 'netsh advfirewall show allprofiles'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        logging.info(f'Firewall status: {result.stdout}')
        return result.stdout
    except Exception as e:
        logging.error(f'Firewall error: {e}')
        return str(e)

def add_rule(name, dir, action, program=None):
    try:
        cmd = f'netsh advfirewall firewall add rule name="{name}" dir={dir} action={action}'
        if program:
            cmd += f' program="{program}"'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        logging.info(f'Added rule: {result.stdout}')
        return result.stdout
    except Exception as e:
        logging.error(f'Rule error: {e}')
        return str(e)

def list_rules():
    try:
        cmd = 'netsh advfirewall firewall show rule name=all'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return result.stdout
    except Exception as e:
        return str(e)