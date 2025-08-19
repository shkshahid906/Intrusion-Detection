#!/usr/bin/env python3
"""
Network Packet Capture Engine for SecureWatch IDS
Live network analysis with Scapy integration
"""

import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import socket
import struct
import psutil
import re

try:
    from scapy.all import (
        sniff, get_if_list, get_if_addr, IP, TCP, UDP, ICMP, 
        Raw, Ether, ARP, DNS, HTTP, HTTPRequest, HTTPResponse
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

from app import db, NetworkEvent, SystemStats, broadcast_event, broadcast_stats
from config import Config
from threat_detection import analyze_advanced_threats
from alert_manager import get_alert_manager

logger = logging.getLogger(__name__)

class NetworkCapture:
    """Network packet capture and analysis engine"""
    
    def __init__(self):
        self.running = False
        self.capture_thread = None
        self.interface = Config.PACKET_CAPTURE_INTERFACE
        self.packet_count = 0
        self.start_time = None
        
        # Traffic analysis data
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.ip_connections = {}  # Track connections per IP
        self.port_activity = {}   # Track port usage
        self.suspicious_ips = set()
        self.blocked_ips = set()
        
        # Detection thresholds
        self.port_scan_threshold = Config.PORT_SCAN_THRESHOLD
        self.brute_force_threshold = Config.BRUTE_FORCE_THRESHOLD
        self.ddos_threshold = Config.DDOS_THRESHOLD
        
        # Connection tracking
        self.connection_tracker = {}
        self.failed_connections = {}
        
        logger.info("Network capture engine initialized")
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        if not SCAPY_AVAILABLE:
            return ['eth0', 'wlan0', 'lo']  # Default interfaces
        
        try:
            interfaces = get_if_list()
            return [iface for iface in interfaces if iface != 'lo']
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return ['eth0']
    
    def set_interface(self, interface: str):
        """Set the network interface for packet capture"""
        self.interface = interface
        logger.info(f"Network interface set to: {interface}")
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.running:
            logger.warning("Packet capture already running")
            return
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - starting simulation mode")
            self.start_simulation_mode()
            return
        
        self.running = True
        self.start_time = datetime.utcnow()
        self.packet_count = 0
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        
        # Start stats update thread
        stats_thread = threading.Thread(target=self._update_stats_loop, daemon=True)
        stats_thread.start()
        
        logger.info(f"Started packet capture on interface: {self.interface}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        logger.info("Packet capture stopped")
    
    def _capture_packets(self):
        """Main packet capture loop using Scapy"""
        try:
            # Start packet sniffing
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
                store=False,  # Don't store packets in memory
                timeout=1     # Check stop condition every second
            )
        except PermissionError:
            logger.error("Permission denied - run as root/administrator for packet capture")
            self.start_simulation_mode()
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.start_simulation_mode()
    
    def _process_packet(self, packet):
        """Process captured packet and extract information"""
        try:
            self.packet_count += 1
            
            # Extract basic packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Analyze packet for threats
            threat_analysis = self._analyze_packet_threat(packet, packet_info)
            
            # Create network event
            event = self._create_network_event(packet_info, threat_analysis)
            
            # Store in database and broadcast
            self._store_and_broadcast_event(event)
            
            # --- ALERT GENERATION INTEGRATION ---
            if threat_analysis['threat_level'] in ['HIGH', 'CRITICAL']:
                alert_mgr = get_alert_manager()
                if alert_mgr:
                    alert_mgr.generate_alert(packet_info, threat_analysis)
            
            # Update traffic statistics
            self._update_traffic_stats(packet_info)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract relevant information from packet"""
        try:
            info = {
                'timestamp': datetime.utcnow(),
                'packet_size': len(packet),
                'protocol': 'Unknown',
                'source_ip': None,
                'destination_ip': None,
                'source_port': None,
                'destination_port': None,
                'flags': '',
                'payload_info': ''
            }
            
            # Extract IP layer information
            if IP in packet:
                ip_layer = packet[IP]
                info['source_ip'] = ip_layer.src
                info['destination_ip'] = ip_layer.dst
                info['protocol'] = ip_layer.proto
                
                # Extract TCP information
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    info['protocol'] = 'TCP'
                    info['source_port'] = tcp_layer.sport
                    info['destination_port'] = tcp_layer.dport
                    info['flags'] = str(tcp_layer.flags)
                    
                    # Check for HTTP traffic
                    if tcp_layer.dport in [80, 8080] or tcp_layer.sport in [80, 8080]:
                        if Raw in packet:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            if 'HTTP' in payload:
                                info['protocol'] = 'HTTP'
                                info['payload_info'] = payload[:200]  # First 200 chars
                    
                    # Check for HTTPS traffic
                    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        info['protocol'] = 'HTTPS'
                
                # Extract UDP information
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    info['protocol'] = 'UDP'
                    info['source_port'] = udp_layer.sport
                    info['destination_port'] = udp_layer.dport
                    
                    # Check for DNS traffic
                    if udp_layer.dport == 53 or udp_layer.sport == 53:
                        info['protocol'] = 'DNS'
                        if DNS in packet:
                            dns_layer = packet[DNS]
                            info['payload_info'] = f"DNS Query: {dns_layer.qd.qname.decode() if dns_layer.qd else 'Unknown'}"
                
                # Extract ICMP information
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    icmp_layer = packet[ICMP]
                    info['payload_info'] = f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}"
            
            # Extract ARP information
            elif ARP in packet:
                arp_layer = packet[ARP]
                info['protocol'] = 'ARP'
                info['source_ip'] = arp_layer.psrc
                info['destination_ip'] = arp_layer.pdst
                info['payload_info'] = f"ARP {arp_layer.op}: {arp_layer.hwsrc} -> {arp_layer.hwdst}"
            
            return info if info['source_ip'] and info['destination_ip'] else None
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _analyze_packet_threat(self, packet, packet_info: Dict) -> Dict:
        """Analyze packet for potential threats"""
        threat_analysis = {
            'event_type': 'NORMAL',
            'threat_level': 'LOW',
            'confidence_score': 0.1,
            'threat_factors': []
        }
        
        try:
            source_ip = packet_info['source_ip']
            dest_ip = packet_info['destination_ip']
            dest_port = packet_info['destination_port']
            protocol = packet_info['protocol']
            
            # Track connections per IP
            if source_ip not in self.ip_connections:
                self.ip_connections[source_ip] = {'ports': set(), 'count': 0, 'last_seen': datetime.utcnow()}
            
            self.ip_connections[source_ip]['count'] += 1
            self.ip_connections[source_ip]['last_seen'] = datetime.utcnow()
            
            if dest_port:
                self.ip_connections[source_ip]['ports'].add(dest_port)
            
            # Port scan detection
            if len(self.ip_connections[source_ip]['ports']) > self.port_scan_threshold:
                threat_analysis['event_type'] = 'PORT_SCAN'
                threat_analysis['threat_level'] = 'HIGH'
                threat_analysis['confidence_score'] = 0.8
                threat_analysis['threat_factors'].append(f"Port scan detected: {len(self.ip_connections[source_ip]['ports'])} ports")
                self.suspicious_ips.add(source_ip)
            
            # Brute force detection (multiple failed connections to same port)
            if protocol == 'TCP' and packet_info.get('flags'):
                connection_key = f"{source_ip}:{dest_ip}:{dest_port}"
                if 'R' in packet_info['flags']:  # RST flag indicates failed connection
                    if connection_key not in self.failed_connections:
                        self.failed_connections[connection_key] = 0
                    self.failed_connections[connection_key] += 1
                    
                    if self.failed_connections[connection_key] > self.brute_force_threshold:
                        threat_analysis['event_type'] = 'BRUTE_FORCE'
                        threat_analysis['threat_level'] = 'HIGH'
                        threat_analysis['confidence_score'] = 0.9
                        threat_analysis['threat_factors'].append(f"Brute force detected: {self.failed_connections[connection_key]} failed attempts")
                        self.suspicious_ips.add(source_ip)
            
            # DDoS detection (high packet rate from single IP)
            if self.ip_connections[source_ip]['count'] > self.ddos_threshold:
                threat_analysis['event_type'] = 'DDoS'
                threat_analysis['threat_level'] = 'CRITICAL'
                threat_analysis['confidence_score'] = 0.95
                threat_analysis['threat_factors'].append(f"DDoS detected: {self.ip_connections[source_ip]['count']} packets")
                self.suspicious_ips.add(source_ip)
            
            # Suspicious port detection
            suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432]
            if dest_port in suspicious_ports:
                threat_analysis['confidence_score'] += 0.2
                threat_analysis['threat_factors'].append(f"Access to suspicious port: {dest_port}")
                if threat_analysis['threat_level'] == 'LOW':
                    threat_analysis['threat_level'] = 'MEDIUM'
            
            # Payload analysis for malware signatures
            payload = packet_info.get('payload_info', '')
            malware_signatures = ['cmd.exe', 'powershell', 'wget', 'curl', '/bin/sh', 'eval(']
            for signature in malware_signatures:
                if signature.lower() in payload.lower():
                    threat_analysis['event_type'] = 'MALWARE'
                    threat_analysis['threat_level'] = 'CRITICAL'
                    threat_analysis['confidence_score'] = 0.9
                    threat_analysis['threat_factors'].append(f"Malware signature detected: {signature}")
                    break
            
            # Check against blocked IPs
            if source_ip in self.blocked_ips:
                threat_analysis['threat_level'] = 'HIGH'
                threat_analysis['confidence_score'] += 0.3
                threat_analysis['threat_factors'].append("Traffic from blocked IP")
            
            advanced_analysis = analyze_advanced_threats(packet_info)
            if advanced_analysis.get('threat_detected'):
                # Merge advanced analysis results
                if advanced_analysis['threat_score'] > threat_analysis['confidence_score']:
                    threat_analysis['confidence_score'] = advanced_analysis['threat_score']
                    threat_analysis['threat_level'] = advanced_analysis['threat_level']
                    threat_analysis['threat_factors'].extend(advanced_analysis.get('threat_factors', []))
                
                # Add advanced threat information
                threat_analysis['advanced_analysis'] = {
                    'behavioral_anomaly': advanced_analysis['analysis_details'].get('behavioral_anomaly', {}),
                    'pattern_matching': advanced_analysis['analysis_details'].get('pattern_matching', {}),
                    'recommended_actions': advanced_analysis.get('recommended_actions', [])
                }
            
            # Adjust threat level based on confidence score
            if threat_analysis['confidence_score'] > 0.7:
                threat_analysis['threat_level'] = 'HIGH'
            elif threat_analysis['confidence_score'] > 0.4:
                threat_analysis['threat_level'] = 'MEDIUM'
            
        except Exception as e:
            logger.error(f"Error analyzing packet threat: {e}")
        
        return threat_analysis
    
    def _create_network_event(self, packet_info: Dict, threat_analysis: Dict) -> NetworkEvent:
        """Create NetworkEvent object from packet analysis"""
        event = NetworkEvent(
            timestamp=packet_info['timestamp'],
            source_ip=packet_info['source_ip'],
            destination_ip=packet_info['destination_ip'],
            source_port=packet_info.get('source_port'),
            destination_port=packet_info.get('destination_port'),
            protocol=packet_info['protocol'],
            event_type=threat_analysis['event_type'],
            threat_level=threat_analysis['threat_level'],
            confidence_score=threat_analysis['confidence_score'],
            packet_size=packet_info['packet_size'],
            flags=packet_info.get('flags'),
            payload_info=packet_info.get('payload_info'),
            blocked=packet_info['source_ip'] in self.blocked_ips,
            advanced_analysis=threat_analysis.get('advanced_analysis')
        )
        return event
    
    def _store_and_broadcast_event(self, event: NetworkEvent):
        """Store event in database and broadcast via WebSocket"""
        try:
            from app import app
            with app.app_context():
                db.session.add(event)
                db.session.commit()
                # Broadcast to connected clients
                broadcast_event(event.to_dict())
                # Log high-priority events
                if event.threat_level in ['HIGH', 'CRITICAL']:
                    logger.warning(f"Threat detected: {event.event_type} from {event.source_ip} - {event.threat_level}")
        except Exception as e:
            logger.error(f"Error storing/broadcasting event: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
    
    def _update_traffic_stats(self, packet_info: Dict):
        """Update traffic statistics"""
        protocol = packet_info['protocol']
        if protocol in self.protocol_stats:
            self.protocol_stats[protocol] += 1
        else:
            self.protocol_stats['Other'] += 1
        
        # Track port activity
        dest_port = packet_info.get('destination_port')
        if dest_port:
            if dest_port not in self.port_activity:
                self.port_activity[dest_port] = 0
            self.port_activity[dest_port] += 1
    
    def _update_stats_loop(self):
        """Continuously update system statistics"""
        while self.running:
            try:
                self._update_system_stats()
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                logger.error(f"Error updating stats: {e}")
    
    def _update_system_stats(self):
        """Update system statistics in database"""
        try:
            from app import app
            with app.app_context():
                # Get system performance metrics
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                memory_usage = memory.percent
                # Calculate network throughput (simplified)
                network_throughput = min(self.packet_count / 10, 100)  # Rough estimate
                # Count recent events
                one_hour_ago = datetime.utcnow() - timedelta(hours=1)
                total_events = NetworkEvent.query.filter(NetworkEvent.timestamp >= one_hour_ago).count()
                threats_detected = NetworkEvent.query.filter(
                    NetworkEvent.timestamp >= one_hour_ago,
                    NetworkEvent.threat_level.in_(['HIGH', 'CRITICAL'])
                ).count()
                # Create stats record
                stats = SystemStats(
                    total_events=total_events,
                    threats_detected=threats_detected,
                    blocked_connections=len(self.blocked_ips),
                    active_connections=len(self.ip_connections),
                    cpu_usage=cpu_usage,
                    memory_usage=memory_usage,
                    network_throughput=network_throughput
                )
                db.session.add(stats)
                db.session.commit()
                # Broadcast stats update
                broadcast_stats(stats.__dict__)
        except Exception as e:
            logger.error(f"Error updating system stats: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
    
    def start_simulation_mode(self):
        """Start simulation mode when Scapy is not available"""
        logger.info("Starting network simulation mode")
        self.running = True
        self.start_time = datetime.utcnow()
        
        simulation_thread = threading.Thread(target=self._simulate_network_traffic, daemon=True)
        simulation_thread.start()
        
        stats_thread = threading.Thread(target=self._update_stats_loop, daemon=True)
        stats_thread.start()
    
    def _simulate_network_traffic(self):
        """Simulate network traffic for demonstration"""
        import random
        
        sample_ips = [
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '10.0.0.50', '10.0.0.51', '172.16.0.10',
            '203.0.113.1', '198.51.100.1', '192.0.2.1'
        ]
        
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
        event_types = ['NORMAL', 'SUSPICIOUS', 'PORT_SCAN', 'BRUTE_FORCE', 'DDoS', 'MALWARE']
        threat_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        while self.running:
            try:
                # Generate random network event
                source_ip = random.choice(sample_ips)
                dest_ip = random.choice(sample_ips)
                protocol = random.choice(protocols)
                event_type = random.choices(event_types, weights=[70, 15, 5, 4, 3, 3])[0]
                
                # Determine threat level based on event type
                if event_type == 'NORMAL':
                    threat_level = 'LOW'
                elif event_type == 'SUSPICIOUS':
                    threat_level = random.choice(['LOW', 'MEDIUM'])
                elif event_type in ['PORT_SCAN', 'BRUTE_FORCE']:
                    threat_level = random.choice(['MEDIUM', 'HIGH'])
                else:  # DDoS, MALWARE
                    threat_level = random.choice(['HIGH', 'CRITICAL'])
                
                event = NetworkEvent(
                    timestamp=datetime.utcnow(),
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    source_port=random.randint(1024, 65535),
                    destination_port=random.choice([22, 23, 53, 80, 135, 139, 443, 445, 993, 995]),
                    protocol=protocol,
                    event_type=event_type,
                    threat_level=threat_level,
                    confidence_score=random.uniform(0.1, 1.0),
                    packet_size=random.randint(64, 1500),
                    flags='SYN' if protocol == 'TCP' else '',
                    payload_info=f"Simulated {event_type} traffic",
                    blocked=random.random() < 0.1  # 10% chance of being blocked
                )
                
                self._store_and_broadcast_event(event)
                self.packet_count += 1
                
                # Variable delay between events
                delay = random.uniform(0.5, 3.0) if event_type == 'NORMAL' else random.uniform(0.1, 0.5)
                time.sleep(delay)
                
            except Exception as e:
                logger.error(f"Error in simulation mode: {e}")
                time.sleep(1)

# Global capture instance
capture_engine = NetworkCapture()

def start_packet_capture():
    """Start packet capture - called from Flask app"""
    capture_engine.start_capture()

def stop_packet_capture():
    """Stop packet capture - called from Flask app"""
    capture_engine.stop_capture()

def get_capture_stats():
    """Get capture statistics"""
    return {
        'running': capture_engine.running,
        'packet_count': capture_engine.packet_count,
        'start_time': capture_engine.start_time.isoformat() if capture_engine.start_time else None,
        'interface': capture_engine.interface,
        'protocol_stats': capture_engine.protocol_stats,
        'suspicious_ips': list(capture_engine.suspicious_ips),
        'blocked_ips': list(capture_engine.blocked_ips)
    }

def block_ip(ip_address: str):
    """Add IP to blocked list"""
    capture_engine.blocked_ips.add(ip_address)
    logger.info(f"Blocked IP: {ip_address}")

def unblock_ip(ip_address: str):
    """Remove IP from blocked list"""
    capture_engine.blocked_ips.discard(ip_address)
    logger.info(f"Unblocked IP: {ip_address}")
