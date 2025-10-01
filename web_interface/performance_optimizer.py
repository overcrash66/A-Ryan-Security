"""
Performance Optimization Module for A-Ryan Security Application
Handles asset optimization, caching, and performance monitoring
"""

import gzip
import json
import time
from functools import wraps
from flask import request, g, current_app
from datetime import datetime, timedelta
import logging

class PerformanceMonitor:
    """Monitor and log performance metrics"""
    
    def __init__(self):
        self.metrics = {}
        self.slow_requests = []
    
    def start_request_timer(self):
        """Start timing a request"""
        g.start_time = time.time()
        g.request_id = f"{int(time.time())}-{request.remote_addr}"
    
    def end_request_timer(self, response):
        """End timing and log performance metrics"""
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            
            # Log slow requests (>2 seconds)
            if duration > 2.0:
                slow_request = {
                    'url': request.url,
                    'method': request.method,
                    'duration': duration,
                    'timestamp': datetime.utcnow().isoformat(),
                    'user_agent': request.headers.get('User-Agent', ''),
                    'ip': request.remote_addr
                }
                self.slow_requests.append(slow_request)
                current_app.logger.warning(f"SLOW REQUEST: {request.url} took {duration:.2f}s")
            
            # Store metrics
            endpoint = request.endpoint or 'unknown'
            if endpoint not in self.metrics:
                self.metrics[endpoint] = []
            
            self.metrics[endpoint].append({
                'duration': duration,
                'timestamp': datetime.utcnow(),
                'status_code': response.status_code
            })
            
            # Keep only last 100 metrics per endpoint
            if len(self.metrics[endpoint]) > 100:
                self.metrics[endpoint] = self.metrics[endpoint][-100:]
        
        return response
    
    def get_performance_stats(self):
        """Get performance statistics"""
        stats = {}
        for endpoint, metrics in self.metrics.items():
            if metrics:
                durations = [m['duration'] for m in metrics]
                stats[endpoint] = {
                    'avg_duration': sum(durations) / len(durations),
                    'max_duration': max(durations),
                    'min_duration': min(durations),
                    'request_count': len(durations),
                    'slow_requests': len([d for d in durations if d > 2.0])
                }
        return stats

def performance_cache(timeout=300):
    """Decorator for caching expensive operations"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from cache import cache
            
            # Create cache key from function name and arguments
            cache_key = f"perf_{f.__name__}_{hash(str(args) + str(kwargs))}"
            
            # Try to get from cache first
            result = cache.get(cache_key)
            if result is not None:
                current_app.logger.debug(f"Cache HIT for {f.__name__}")
                return result
            
            # Execute function and cache result
            start_time = time.time()
            result = f(*args, **kwargs)
            duration = time.time() - start_time
            
            current_app.logger.debug(f"Cache MISS for {f.__name__} - took {duration:.2f}s")
            cache.set(cache_key, result, timeout=timeout)
            
            return result
        return decorated_function
    return decorator

def batch_api_calls(api_calls):
    """Batch multiple API calls for better performance"""
    import asyncio
    import aiohttp
    
    async def fetch_data(session, url, headers=None):
        try:
            async with session.get(url, headers=headers or {}) as response:
                return await response.json()
        except Exception as e:
            return {'error': str(e)}
    
    async def batch_fetch(calls):
        async with aiohttp.ClientSession() as session:
            tasks = [fetch_data(session, call['url'], call.get('headers')) for call in calls]
            return await asyncio.gather(*tasks)
    
    # Run batch requests
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(batch_fetch(api_calls))
        loop.close()
        return results
    except Exception as e:
        current_app.logger.error(f"Batch API call failed: {e}")
        return [{'error': str(e)} for _ in api_calls]

def compress_response(response):
    """Compress response data for faster transfer"""
    if (response.status_code < 200 or 
        response.status_code >= 300 or 
        'gzip' not in request.headers.get('Accept-Encoding', '')):
        return response
    
    response.data = gzip.compress(response.data)
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(response.data)
    
    return response

def optimize_database_queries():
    """Optimize common database queries"""
    from models import db, Log, Issue, ScanHistory
    from sqlalchemy import text
    
    # Add database indexes for common queries
    try:
        # Index for log queries (most common)
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp_desc 
            ON log (timestamp DESC)
        """))
        
        # Index for issue queries
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_issues_severity_desc 
            ON issue (severity DESC)
        """))
        
        # Index for scan history queries
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_user_timestamp 
            ON scan_history (user_id, timestamp DESC)
        """))
        
        db.session.commit()
        current_app.logger.info("Database indexes optimized")
        
    except Exception as e:
        current_app.logger.error(f"Error optimizing database: {e}")
        db.session.rollback()

# Global performance monitor instance
performance_monitor = PerformanceMonitor()