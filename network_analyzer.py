import nmap
from scapy.all import sniff, IP
import torch
import torch.nn as nn
import numpy as np
import logging
import time
from cache import cache
import threading
from contextlib import contextmanager

class Autoencoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(5, 3), nn.ReLU(), nn.Linear(3, 2))
        self.decoder = nn.Sequential(nn.Linear(2, 3), nn.ReLU(), nn.Linear(3, 5))

    def forward(self, x):
        return self.decoder(self.encoder(x))

model = Autoencoder()
optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
criterion = nn.MSELoss()

def train_model(data):
    for epoch in range(10):
        output = model(data)
        loss = criterion(output, data)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

@contextmanager
def safe_db_context():
    """Context manager for safe database operations."""
    try:
        from flask import has_app_context
        from models import db
        
        if has_app_context():
            yield db
        else:
            logging.warning("Database operation skipped: No Flask application context")
            yield None
    except Exception as e:
        logging.error(f"Database context error: {e}")
        yield None

def detect_anomaly(packet_data):
    """Detect network anomalies with safe database handling."""
    if not hasattr(model, 'trained'):
        train_model(packet_data)
        model.trained = True

    with torch.no_grad():
        recon = model(packet_data)
        anomalies = []
        issues_to_add = []
        
        for i in range(packet_data.size(0)):
            packet_loss = criterion(recon[i], packet_data[i])
            threshold = 0.5
            
            if packet_loss > threshold:
                error_value = packet_loss.item()
                
                if error_value > 2.0:
                    description = f'Suspicious network traffic detected (anomaly score: {error_value:.2f}). This may indicate unusual network behavior or potential security threats.'
                    severity = 'High'
                elif error_value > 1.0:
                    description = f'Unusual network pattern detected (anomaly score: {error_value:.2f}). Monitor for potential security issues.'
                    severity = 'Medium'
                else:
                    description = f'Minor network anomaly detected (anomaly score: {error_value:.2f}). This could be normal traffic variation.'
                    severity = 'Low'
                
                # Create issue object but only save if context is available
                try:
                    from models import Issue
                    issue = Issue(
                        category='Network Anomaly',
                        description=description,
                        severity=severity
                    )
                    issues_to_add.append(issue)
                except ImportError:
                    logging.warning("Issue model not available")
                
                anomalies.append(True)
            else:
                anomalies.append(False)
    
        # Only save to database if we have proper context
        if issues_to_add:
            try:
                with safe_db_context() as db:
                    if db is not None:
                        db.session.bulk_save_objects(issues_to_add)
                        db.session.commit()
                        logging.info(f"Saved {len(issues_to_add)} network anomalies to database")
                    else:
                        logging.warning(f"Could not save {len(issues_to_add)} network anomalies: No database context")
            except Exception as e:
                logging.error(f"Error saving anomalies to database: {e}")
                # Don't try to rollback if we don't have context
                try:
                    with safe_db_context() as db:
                        if db is not None:
                            db.session.rollback()
                except Exception:
                    pass
        
        return anomalies

def scan_network(host='127.0.0.1'):
    """Scan network with enhanced error handling."""
    try:
        nm = nmap.PortScanner()
        results = nm.scan(hosts=host, arguments='-sV')
        logging.info(f'Nmap scan completed for {host}')
        return results
    except Exception as e:
        logging.error(f"Error scanning network: {e}")
        return {'error': str(e), 'host': host}

def extract_packet_features(packet):
    """Extract packet features with robust error handling."""
    try:
        if hasattr(packet, 'haslayer') and callable(packet.haslayer):
            has_ip = packet.haslayer(IP)
        else:
            has_ip = IP in packet
            
        if not has_ip:
            return None
            
        if hasattr(packet, '__getitem__'):
            ip = packet[IP]
        else:
            ip = packet
            
        flags = int(ip.flags) if hasattr(ip, 'flags') and ip.flags else 0
        
        return {
            'length': len(packet),
            'src': ip.src,
            'dst': ip.dst,
            'proto': ip.proto,
            'ttl': ip.ttl,
            'flags': flags,
            'tos': ip.tos,
            'timestamp': time.time()
        }
    except Exception as e:
        logging.error(f"Error extracting packet features: {e}")
        return None

class TrafficAnalyzer:
    """Thread-safe traffic analyzer that doesn't require Flask context."""
    
    def __init__(self):
        self.packets = []
        self.features_batch = []
        self.lock = threading.Lock()
        
    def packet_callback(self, packet):
        """Callback for packet processing."""
        features = extract_packet_features(packet)
        if features:
            with self.lock:
                self.features_batch.append(features)
                self.packets.append(str(packet))
    
    def analyze_batch(self):
        """Analyze collected packet features."""
        if not self.features_batch:
            return []
            
        try:
            numeric_features = [
                [f['length'], f['proto'], f['ttl'], f['flags'], f['tos']] 
                for f in self.features_batch
            ]
            batch_features = torch.tensor(numeric_features, dtype=torch.float32)
            anomalies = detect_anomaly(batch_features)
            
            # Log anomalies and cache them
            anomaly_count = sum(anomalies)
            if anomaly_count > 0:
                logging.warning(f'Detected {anomaly_count} anomalous packets out of {len(anomalies)} analyzed')
                
                # Cache anomaly information without requiring Flask context
                for i, is_anomaly in enumerate(anomalies):
                    if is_anomaly and i < len(self.features_batch):
                        timestamp = self.features_batch[i].get('timestamp', time.time())
                        try:
                            cache.set(f'anomaly:{timestamp}', self.features_batch[i], timeout=3600)
                        except Exception as cache_error:
                            logging.error(f"Error caching anomaly: {cache_error}")
            
            return self.packets
            
        except Exception as e:
            logging.error(f"Error in batch analysis: {e}")
            return self.packets
#update this detect iface
#Ethernet
#Wifi
from scapy.all import *
current_interface = conf.iface
def analyze_traffic(iface=current_interface, count=10, batch_size=100):
    """Analyze traffic with thread-safe, context-independent processing."""
    analyzer = TrafficAnalyzer()
    total_captured = 0
    timeout_per_loop = 5
    max_loops = 6
    
    try:
        logging.info(f"Starting traffic analysis on interface {iface}")
        
        for loop_count in range(max_loops):
            try:
                remaining_count = count - total_captured
                if remaining_count <= 0:
                    break
                    
                captured = sniff(
                    iface=iface, 
                    prn=analyzer.packet_callback, 
                    count=min(remaining_count, batch_size),
                    store=False, 
                    timeout=timeout_per_loop
                )
                
                captured_count = len(captured) if hasattr(captured, '__len__') else 0
                total_captured += captured_count
                
                logging.info(f"Loop {loop_count + 1}: Captured {captured_count} packets (total: {total_captured})")
                
                if total_captured >= count:
                    break
                    
            except Exception as loop_error:
                logging.error(f"Error in traffic capture loop {loop_count + 1}: {loop_error}")
                continue
        
        # Analyze the collected packets
        result_packets = analyzer.analyze_batch()
        
        logging.info(f"Traffic analysis completed. Analyzed {len(analyzer.features_batch)} packets")
        
        return result_packets
    
    except Exception as e:
        logging.error(f"Traffic analysis error: {e}")
        return []

def get_network_interface_info():
    """Get available network interfaces safely."""
    try:
        import psutil
        interfaces = psutil.net_if_addrs()
        active_interfaces = []
        
        for interface_name, addresses in interfaces.items():
            for addr in addresses:
                if addr.family == 2:  # IPv4
                    active_interfaces.append({
                        'name': interface_name,
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                    break
        
        return active_interfaces
        
    except ImportError:
        logging.warning("psutil not available, using default interface")
        return [{'name': 'Ethernet', 'address': '127.0.0.1', 'netmask': '255.0.0.0'}]
    except Exception as e:
        logging.error(f"Error getting network interface info: {e}")
        return [{'name': 'Ethernet', 'address': '127.0.0.1', 'netmask': '255.0.0.0'}]

def get_network_statistics():
    """Get network statistics without requiring Flask context."""
    try:
        import psutil
        net_io = psutil.net_io_counters()
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errors_in': net_io.errin,
            'errors_out': net_io.errout,
            'drops_in': net_io.dropin,
            'drops_out': net_io.dropout
        }
    except ImportError:
        return {'error': 'psutil not available'}
    except Exception as e:
        logging.error(f"Error getting network statistics: {e}")
def safe_network_analysis(count=10):
    """Safe network analysis that doesn't require Flask context."""
    try:
        return analyze_traffic(count=count)
    except Exception as e:
        logging.error(f"Error in safe network analysis: {e}")
        return {'error': str(e), 'count': count}
        return {'error': str(e)}