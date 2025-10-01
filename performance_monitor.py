from flask import g, request
import time
import logging
import psutil
import threading
from functools import wraps
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from cache import cache

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """Comprehensive performance monitoring for the security application."""

    def __init__(self):
        self.slow_requests = deque(maxlen=100)
        self.endpoint_stats = defaultdict(lambda: {
            'count': 0,
            'total_time': 0.0,
            'avg_time': 0.0,
            'min_time': float('inf'),
            'max_time': 0.0,
            'errors': 0
        })
        self.system_metrics = {}
        self._lock = threading.Lock()
        self._monitoring_active = True

        # Start background monitoring
        self._start_system_monitoring()

    def _start_system_monitoring(self):
        """Start background system monitoring thread."""
        def monitor_system():
            while self._monitoring_active:
                try:
                    self._collect_system_metrics()
                    time.sleep(30)  # Collect metrics every 30 seconds
                except Exception as e:
                    logger.error(f"System monitoring error: {e}")
                    time.sleep(60)  # Wait longer on error

        monitor_thread = threading.Thread(target=monitor_system, daemon=True, name='system_monitor')
        monitor_thread.start()

    def _collect_system_metrics(self):
        """Collect system performance metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()

            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used = memory.used / 1024 / 1024  # MB
            memory_total = memory.total / 1024 / 1024  # MB

            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_used = disk.used / 1024 / 1024 / 1024  # GB
            disk_total = disk.total / 1024 / 1024 / 1024  # GB

            # Network metrics
            network = psutil.net_io_counters()
            bytes_sent = network.bytes_sent / 1024 / 1024  # MB
            bytes_recv = network.bytes_recv / 1024 / 1024  # MB

            # Process count
            process_count = len(psutil.pids())

            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count
                },
                'memory': {
                    'percent': memory_percent,
                    'used_mb': memory_used,
                    'total_mb': memory_total
                },
                'disk': {
                    'percent': disk_percent,
                    'used_gb': disk_used,
                    'total_gb': disk_total
                },
                'network': {
                    'bytes_sent_mb': bytes_sent,
                    'bytes_recv_mb': bytes_recv
                },
                'processes': process_count
            }

            with self._lock:
                self.system_metrics = metrics

            # Cache metrics for 5 minutes
            cache.set('system_metrics', metrics, timeout=300)

        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")

    def start_request_timer(self):
        """Start timing a request."""
        g.request_start_time = time.time()

    def end_request_timer(self, response):
        """End timing a request and record metrics."""
        if not hasattr(g, 'request_start_time'):
            return

        request_time = time.time() - g.request_start_time
        endpoint = request.endpoint or 'unknown'

        with self._lock:
            stats = self.endpoint_stats[endpoint]
            stats['count'] += 1
            stats['total_time'] += request_time
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['min_time'] = min(stats['min_time'], request_time)
            stats['max_time'] = max(stats['max_time'], request_time)

            # Track slow requests (>5 seconds)
            if request_time > 5.0:
                self.slow_requests.append({
                    'endpoint': endpoint,
                    'time': request_time,
                    'timestamp': datetime.utcnow().isoformat(),
                    'method': request.method,
                    'url': request.url
                })

        # Log slow requests
        if request_time > 10.0:  # Very slow requests
            logger.warning(f"Slow request detected: {endpoint} took {request_time:.2f}s")

        return response

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        with self._lock:
            return {
                'endpoint_stats': dict(self.endpoint_stats),
                'slow_requests_count': len(self.slow_requests),
                'system_metrics': self.system_metrics,
                'timestamp': datetime.utcnow().isoformat()
            }

    def get_endpoint_stats(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific endpoint."""
        with self._lock:
            return self.endpoint_stats.get(endpoint, {})

    def get_slow_requests(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent slow requests."""
        with self._lock:
            return list(self.slow_requests)[-limit:]

    def clear_stats(self, endpoint: Optional[str] = None):
        """Clear performance statistics."""
        with self._lock:
            if endpoint:
                if endpoint in self.endpoint_stats:
                    del self.endpoint_stats[endpoint]
            else:
                self.endpoint_stats.clear()
                self.slow_requests.clear()

    def performance_logging(func):
        """Decorator to add performance logging to functions."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            func_name = f"{func.__module__}.{func.__name__}"

            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time

                # Log performance for functions taking longer than 1 second
                if execution_time > 1.0:
                    logger.info(f"Performance: {func_name} took {execution_time:.2f}s")

                return result

            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"Performance: {func_name} failed after {execution_time:.2f}s: {e}")
                raise

        return wrapper

    def memory_usage(func):
        """Decorator to monitor memory usage of functions."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            process = psutil.Process()
            memory_before = process.memory_info().rss / 1024 / 1024  # MB

            try:
                result = func(*args, **kwargs)
                memory_after = process.memory_info().rss / 1024 / 1024  # MB
                memory_delta = memory_after - memory_before

                # Log significant memory usage
                if memory_delta > 50:  # More than 50MB increase
                    logger.warning(f"Memory usage: {func.__name__} increased memory by {memory_delta:.1f}MB")

                return result

            except Exception as e:
                memory_after = process.memory_info().rss / 1024 / 1024  # MB
                memory_delta = memory_after - memory_before
                logger.error(f"Memory usage: {func.__name__} failed with {memory_delta:.1f}MB delta: {e}")
                raise

        return wrapper

    def stop_monitoring(self):
        """Stop all monitoring activities."""
        self._monitoring_active = False

# Global performance monitor instance
performance_monitor = PerformanceMonitor()

def setup_performance_middleware(app):
    """Set up performance monitoring middleware for Flask app."""
    @app.before_request
    def before_request():
        performance_monitor.start_request_timer()

    @app.after_request
    def after_request(response):
        return performance_monitor.end_request_timer(response)

    logger.info("Performance monitoring middleware configured")