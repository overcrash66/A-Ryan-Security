import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from datetime import datetime
from typing import Dict, List, Optional, Any
from cache import cache

from input_validation import InputValidator, validate_and_sanitize_scan_request
from error_handlers import safe_database_operation, safe_scan_operation, log_security_event, SecurityError

logger = logging.getLogger(__name__)

class SecurityService:
    """Service layer for security operations."""

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='security_scan')
        self._lock = threading.Lock()

    def __del__(self):
        """Cleanup executor on destruction."""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)

    @safe_scan_operation("antivirus_scan")
    def perform_antivirus_scan(self, scan_path: str) -> Dict[str, Any]:
        """Perform antivirus scan with proper validation."""
        try:
            # Validate input
            validated_path = InputValidator.validate_scan_path(scan_path)

            # Import here to avoid circular imports
            from antivirus import extra_antivirus_layer

            # Perform scan
            results = extra_antivirus_layer()

            # Log the operation
            log_security_event('antivirus_scan', f'Scan completed for {validated_path}')

            return {
                'status': 'success',
                'data': results,
                'scan_path': validated_path,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Antivirus scan failed: {str(e)}")
            raise SecurityError(f"Antivirus scan failed: {str(e)}")

    @safe_scan_operation("vulnerability_scan")
    def perform_vulnerability_scan(self, scan_path: str, save_history: bool = True) -> Dict[str, Any]:
        """Perform vulnerability scan with proper validation and error handling."""
        try:
            # Validate input
            validated_path = InputValidator.validate_scan_path(scan_path)

            # Import here to avoid circular imports
            from vuln_checker import scan_vulnerabilities

            # Perform scan
            vulns_data, osv_data = scan_vulnerabilities(scan_path=validated_path, save_history=save_history)

            # Log the operation
            log_security_event('vulnerability_scan', f'Scan completed for {validated_path}')

            return {
                'status': 'success',
                'data': {
                    'vulns': vulns_data,
                    'osv': osv_data
                },
                'scan_path': validated_path,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Vulnerability scan failed: {str(e)}")
            raise SecurityError(f"Vulnerability scan failed: {str(e)}")

    @safe_scan_operation("network_analysis")
    def perform_network_analysis(self, host: str = '127.0.0.1', count: int = 5) -> Dict[str, Any]:
        """Perform network analysis with proper validation."""
        try:
            # Validate input
            validated_host = InputValidator.validate_ip_address(host)

            # Import here to avoid circular imports
            from network_analyzer import scan_network, analyze_traffic

            # Perform network scan
            network_data = scan_network(host=validated_host)

            # Perform traffic analysis
            traffic_data = analyze_traffic(count=count)

            # Log the operation
            log_security_event('network_analysis', f'Analysis completed for {validated_host}')

            return {
                'status': 'success',
                'data': {
                    'network': network_data,
                    'traffic': traffic_data
                },
                'host': validated_host,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Network analysis failed: {str(e)}")
            raise SecurityError(f"Network analysis failed: {str(e)}")

    @safe_scan_operation("process_scan")
    def perform_process_scan(self) -> Dict[str, Any]:
        """Perform process scan with proper error handling."""
        try:
            # Import here to avoid circular imports
            from process_scanner import scan_running_processes, get_system_services, get_startup_programs

            # Perform process scan
            processes = scan_running_processes()

            # Get system services
            services = get_system_services()

            # Get startup programs
            startup = get_startup_programs()

            # Log the operation
            log_security_event('process_scan', 'Process scan completed')

            return {
                'status': 'success',
                'data': {
                    'processes': processes,
                    'services': services,
                    'startup': startup
                },
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Process scan failed: {str(e)}")
            raise SecurityError(f"Process scan failed: {str(e)}")

    def perform_comprehensive_scan(self, scan_path: str) -> Dict[str, Any]:
        """Perform comprehensive security scan with all components."""
        try:
            # Validate input
            validated_path = InputValidator.validate_scan_path(scan_path)

            # Submit all scan tasks
            futures = {
                'antivirus': self.executor.submit(self.perform_antivirus_scan, validated_path),
                'vulnerability': self.executor.submit(self.perform_vulnerability_scan, validated_path),
                'network': self.executor.submit(self.perform_network_analysis),
                'processes': self.executor.submit(self.perform_process_scan)
            }

            results = {}

            # Collect results as they complete
            for scan_type, future in futures.items():
                try:
                    result = future.result(timeout=300)  # 5 minute timeout
                    results[scan_type] = result
                except Exception as e:
                    logger.error(f"Scan {scan_type} failed: {str(e)}")
                    results[scan_type] = {
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    }

            # Log comprehensive scan completion
            log_security_event('comprehensive_scan', f'Comprehensive scan completed for {validated_path}')

            return {
                'status': 'success',
                'data': results,
                'scan_path': validated_path,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Comprehensive scan failed: {str(e)}")
            raise SecurityError(f"Comprehensive scan failed: {str(e)}")

    @safe_database_operation("get_scan_history")
    def get_scan_history(self, user_id: int, limit: int = 20) -> Dict[str, Any]:
        """Get scan history for a user."""
        try:
            from models import ScanHistory

            scans = ScanHistory.query.filter_by(user_id=user_id)\
                                    .order_by(ScanHistory.timestamp.desc())\
                                    .limit(limit)\
                                    .all()

            scan_history = [{
                'id': scan.id,
                'scan_path': scan.scan_path,
                'status': scan.status,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'scan_duration': scan.scan_duration,
                'osv_version': scan.osv_version,
                'timestamp': scan.timestamp.isoformat() if scan.timestamp else None
            } for scan in scans]

            return {
                'status': 'success',
                'data': scan_history,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get scan history: {str(e)}")
            raise SecurityError(f"Failed to get scan history: {str(e)}")

    @safe_database_operation("get_security_logs")
    def get_security_logs(self, limit: int = 50) -> Dict[str, Any]:
        """Get security logs."""
        try:
            from models import Log

            logs = Log.query.order_by(Log.timestamp.desc()).limit(limit).all()

            log_data = [{
                'id': log.id,
                'level': log.level,
                'message': log.message,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'user_id': log.user_id,
                'ip_address': log.ip_address,
                'event_type': log.event_type
            } for log in logs]

            return {
                'status': 'success',
                'data': log_data,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get security logs: {str(e)}")
            raise SecurityError(f"Failed to get security logs: {str(e)}")

    def get_cached_status_data(self) -> Dict[str, Any]:
        """Get cached status data for performance."""
        cache_keys = ['av_status', 'fw_status', 'net_status', 'traffic_status', 'process_status']

        cached_data = {}
        missing_keys = []

        # Check cache for existing data
        for key in cache_keys:
            data = cache.get(key)
            if data is not None:
                cached_data[key] = data
            else:
                missing_keys.append(key)

        return {
            'cached_data': cached_data,
            'missing_keys': missing_keys,
            'cache_timestamp': datetime.utcnow().isoformat()
        }

    def refresh_cached_data(self, data_keys: List[str]) -> Dict[str, Any]:
        """Refresh specific cached data."""
        refresh_functions = {
            'av_status': lambda: self.perform_antivirus_scan('.'),
            'net_status': lambda: self.perform_network_analysis(),
            'process_status': lambda: self.perform_process_scan()
        }

        refreshed_data = {}

        for key in data_keys:
            if key in refresh_functions:
                try:
                    result = refresh_functions[key]()
                    if result['status'] == 'success':
                        cache.set(key, result['data'], timeout=300)
                        refreshed_data[key] = result['data']
                    else:
                        refreshed_data[key] = {'error': 'Refresh failed'}
                except Exception as e:
                    logger.error(f"Failed to refresh {key}: {str(e)}")
                    refreshed_data[key] = {'error': str(e)}

        return {
            'status': 'success',
            'refreshed_data': refreshed_data,
            'timestamp': datetime.utcnow().isoformat()
        }

# Global service instance
def get_system_services():
    """Get system services information."""
    try:
        from process_scanner import get_system_services as _get_system_services
        return _get_system_services()
    except Exception as e:
        logger.error(f"Error getting system services: {e}")
        return {'error': str(e), 'total_services': 0}

def get_startup_programs():
    """Get startup programs information."""
    try:
        from process_scanner import get_startup_programs as _get_startup_programs
        return _get_startup_programs()
    except Exception as e:
        logger.error(f"Error getting startup programs: {e}")
        return {'error': str(e), 'total_startup_programs': 0}
security_service = SecurityService()