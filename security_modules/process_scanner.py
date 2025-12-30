import psutil
import logging
import os
import hashlib
from datetime import datetime
from pathlib import Path
import subprocess
import json
import winreg
import time

def scan_running_processes():
    """
    Scan running processes on Windows system for security analysis.
    Returns detailed information about processes, suspicious activities, and security recommendations.
    """
    logging.info("Starting Windows process security scan...")
    
    try:
        processes = []
        suspicious_processes = []
        high_resource_processes = []
        network_processes = []
        
        max_processes = 50  # Limit for performance/testing
        process_count = 0
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time', 'username']):
            if process_count >= max_processes:
                break
            process_count += 1
            try:
                proc_info = proc.info
                
                # Skip system processes that can't be accessed
                if not proc_info['exe']:
                    continue
                
                # Get additional process details
                process_details = {
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'exe_path': proc_info['exe'],
                    'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                    'cpu_percent': proc_info['cpu_percent'],
                    'memory_percent': proc_info['memory_percent'],
                    'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else None,
                    'username': proc_info['username'],
                    'status': proc.status(),
                    'num_threads': proc.num_threads(),
                }
                
                # Check for network connections
                try:
                    connections = proc.connections()
                    if connections:
                        process_details['network_connections'] = len(connections)
                        process_details['listening_ports'] = [conn.laddr.port for conn in connections if conn.status == 'LISTEN']
                        network_processes.append(process_details)
                    else:
                        process_details['network_connections'] = 0
                        process_details['listening_ports'] = []
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    process_details['network_connections'] = 0
                    process_details['listening_ports'] = []
                
                # Get file information if available
                if proc_info['exe']:
                    try:
                        file_info = get_file_security_info(proc_info['exe'])
                        process_details.update(file_info)
                    except Exception as e:
                        logging.debug(f"Could not get file info for {proc_info['exe']}: {e}")
                
                processes.append(process_details)
                
                # Identify suspicious processes
                if is_suspicious_process(process_details):
                    suspicious_processes.append(process_details)
                
                # Identify high resource usage processes
                if (proc_info['cpu_percent'] and proc_info['cpu_percent'] > 50) or \
                   (proc_info['memory_percent'] and proc_info['memory_percent'] > 20):
                    high_resource_processes.append(process_details)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logging.error(f"Error processing process {proc_info.get('pid', 'unknown')}: {e}")
                continue
        
        # Generate security analysis
        analysis = analyze_process_security(processes, suspicious_processes, high_resource_processes, network_processes)
        
        result = {
            'scan_time': datetime.now().isoformat(),
            'total_processes': len(processes),
            'suspicious_processes': len(suspicious_processes),
            'high_resource_processes': len(high_resource_processes),
            'network_processes': len(network_processes),
            'processes': processes[:20],  # Limit to first 20 for performance
            'suspicious_details': suspicious_processes,
            'high_resource_details': high_resource_processes[:10],
            'network_details': network_processes[:20],
            'security_analysis': analysis
        }
        
        logging.info(f"Process scan completed: {len(processes)} processes analyzed, {len(suspicious_processes)} suspicious")
        return result
        
    except Exception as e:
        logging.error(f"Error during process scan: {e}")
        return {
            'error': f"Process scan failed: {str(e)}",
            'scan_time': datetime.now().isoformat(),
            'total_processes': 0
        }

def get_file_security_info(file_path):
    """Get security-related information about a file."""
    try:
        file_info = {}
        path_obj = Path(file_path)
        
        if path_obj.exists():
            stat = path_obj.stat()
            file_info.update({
                'file_size': stat.st_size,
                'file_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'file_created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })
            
            # Get file hash for known malware detection
            try:
                with open(file_path, 'rb') as f:
                    # Read first 8KB for hash (performance optimization)
                    chunk = f.read(8192)
                    file_hash = hashlib.md5(chunk).hexdigest()
                    file_info['file_hash_partial'] = file_hash
            except Exception:
                pass
            
            # Check if file is signed (Windows specific)
            if os.name == 'nt':
                try:
                    # Escape single quotes for PowerShell
                    escaped_path = file_path.replace("'", "''")
                    result = subprocess.run([
                        'powershell', '-Command',
                        f"Get-AuthenticodeSignature -LiteralPath '{escaped_path}' | Select-Object Status"
                    ], capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0 and 'Valid' in result.stdout:
                        file_info['digitally_signed'] = True
                    else:
                        file_info['digitally_signed'] = False
                except Exception:
                    file_info['digitally_signed'] = 'unknown'
        
        return file_info
        
    except Exception as e:
        logging.debug(f"Error getting file info for {file_path}: {e}")
        return {}

def is_suspicious_process(process_details):
    """Identify potentially suspicious processes based on various indicators."""
    suspicious_indicators = []
    
    name = process_details.get('name', '').lower()
    exe_path = process_details.get('exe_path', '').lower()
    cmdline = process_details.get('cmdline', '').lower()
    
    # Check for suspicious names
    suspicious_names = [
        'svchost.exe', 'winlogon.exe', 'explorer.exe', 'lsass.exe', 'csrss.exe'
    ]
    
    # Check if system process is running from wrong location
    if name in suspicious_names:
        if 'system32' not in exe_path and 'syswow64' not in exe_path:
            suspicious_indicators.append(f"System process {name} running from unusual location: {exe_path}")
    
    # Check for processes with no digital signature
    if process_details.get('digitally_signed') == False:
        suspicious_indicators.append("Process executable is not digitally signed")
    
    # Check for high network activity
    if process_details.get('network_connections', 0) > 10:
        suspicious_indicators.append(f"High network activity: {process_details['network_connections']} connections")
    
    # Check for suspicious command line arguments
    suspicious_cmdline_patterns = [
        'powershell -enc', 'cmd /c echo', 'wscript', 'cscript',
        'regsvr32', 'rundll32', 'mshta', 'certutil -decode'
    ]
    
    for pattern in suspicious_cmdline_patterns:
        if pattern in cmdline:
            suspicious_indicators.append(f"Suspicious command line pattern: {pattern}")
    
    # Check for processes running from temp directories
    temp_locations = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\', '\\windows\\temp\\']
    for temp_loc in temp_locations:
        if temp_loc in exe_path:
            suspicious_indicators.append(f"Process running from temporary directory: {exe_path}")
    
    # Check for unusual file extensions
    if exe_path.endswith(('.scr', '.pif', '.bat', '.cmd', '.vbs', '.js')):
        suspicious_indicators.append(f"Unusual executable extension: {exe_path}")
    
    # Add suspicious indicators to process details
    if suspicious_indicators:
        process_details['suspicious_indicators'] = suspicious_indicators
        return True
    
    return False

def analyze_process_security(processes, suspicious_processes, high_resource_processes, network_processes):
    """Analyze process data and provide security recommendations."""
    
    analysis = {
        'risk_level': 'LOW',
        'findings': [],
        'recommendations': []
    }
    
    # Analyze suspicious processes
    if len(suspicious_processes) > 0:
        analysis['risk_level'] = 'HIGH' if len(suspicious_processes) > 5 else 'MEDIUM'
        analysis['findings'].append(f"Found {len(suspicious_processes)} potentially suspicious processes")
        
        for proc in suspicious_processes[:3]:  # Show top 3
            indicators = proc.get('suspicious_indicators', [])
            analysis['findings'].append(f"Suspicious: {proc['name']} (PID: {proc['pid']}) - {', '.join(indicators[:2])}")
    
    # Analyze high resource usage
    if len(high_resource_processes) > 10:
        analysis['findings'].append(f"High resource usage detected in {len(high_resource_processes)} processes")
        if analysis['risk_level'] == 'LOW':
            analysis['risk_level'] = 'MEDIUM'
    
    # Analyze network processes
    listening_ports = []
    for proc in network_processes:
        listening_ports.extend(proc.get('listening_ports', []))
    
    if len(set(listening_ports)) > 20:
        analysis['findings'].append(f"High number of listening ports detected: {len(set(listening_ports))}")
        if analysis['risk_level'] == 'LOW':
            analysis['risk_level'] = 'MEDIUM'
    
    # Generate recommendations
    if suspicious_processes:
        analysis['recommendations'].append("Investigate suspicious processes immediately")
        analysis['recommendations'].append("Run full antivirus scan on suspicious process locations")
        analysis['recommendations'].append("Consider isolating system if multiple suspicious processes detected")
    
    if high_resource_processes:
        analysis['recommendations'].append("Monitor high resource usage processes for performance impact")
        analysis['recommendations'].append("Investigate processes consuming excessive CPU/memory")
    
    if len(network_processes) > 20:
        analysis['recommendations'].append("Review network connections for unauthorized communication")
        analysis['recommendations'].append("Implement network monitoring for unusual traffic patterns")
    
    # General recommendations
    analysis['recommendations'].extend([
        "Regularly update all software and operating system",
        "Enable Windows Defender or install reputable antivirus software",
        "Use Windows Firewall or third-party firewall solution",
        "Implement process monitoring and alerting",
        "Regular security audits and process reviews"
    ])
    
    if not analysis['findings']:
        analysis['findings'].append("No immediate security concerns detected in running processes")
    
    return analysis

def get_system_services():
    """Get information about Windows services with timeout and limits."""
    logging.info("Starting system services scan...")
    try:
        services = []
        max_services = 100
        timeout = 30
        start_time = time.time()

        for service in psutil.win_service_iter():
            if time.time() - start_time > timeout:
                logging.warning("System services scan timed out")
                return {'error': 'Timed out after 30s', 'partial_services': services}
            try:
                service_info = service.as_dict()
                service_details = {
                    'name': service_info.get('name', 'Unknown'),
                    'display_name': service_info.get('display_name', 'Unknown'),
                    'status': service_info.get('status', 'Unknown'),
                    'start_type': service_info.get('start_type', 'Unknown'),
                    'pid': service_info.get('pid', None),
                    'binpath': service_info.get('binpath', 'Unknown'),
                    'username': service_info.get('username', 'Unknown'),
                    'description': service_info.get('description', '')[:200]
                }
                services.append(service_details)
                if len(services) >= max_services:
                    logging.info(f"Reached service limit ({max_services})")
                    break
            except Exception as e:
                logging.debug(f"Error getting service info: {e}")
                continue

        return {
            'total_services': len(services),
            'running_services': len([s for s in services if s['status'] == 'running']),
            'stopped_services': len([s for s in services if s['status'] == 'stopped']),
            'services': services
        }
    except Exception as e:
        logging.error(f"System services error: {e}")
        return {'error': f"Could not retrieve services: {str(e)}"}

def get_startup_programs():
    """Get startup programs with timeout and limits."""
    logging.info("Starting startup programs scan...")
    try:
        startup_programs = []
        max_programs = 20
        timeout = 15
        start_time = time.time()

        startup_locations = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        ]

        for location in startup_locations:
            if time.time() - start_time > timeout:
                logging.warning("Startup programs scan timed out")
                return {'error': 'Timed out after 15s', 'partial_programs': startup_programs}
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, location)
                i = 0
                while i < max_programs:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        startup_programs.append({
                            'name': name,
                            'command': value,
                            'location': f"HKLM\\{location}"
                        })
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
                if len(startup_programs) >= max_programs:
                    logging.info(f"Reached startup program limit ({max_programs})")
                    break
            except Exception:
                continue

        return {
            'total_startup_programs': len(startup_programs),
            'startup_programs': startup_programs
        }
    except Exception as e:
        logging.error(f"Startup programs error: {e}")
def safe_process_scan():
    """Safe process scan that doesn't require Flask context."""
    try:
        return scan_running_processes()
    except Exception as e:
        logging.error(f"Error in safe process scan: {e}")
        return {'error': str(e), 'total_processes': 0}
