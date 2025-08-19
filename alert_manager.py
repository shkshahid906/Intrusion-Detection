#!/usr/bin/env python3
"""
Alert Management System for SecureWatch IDS
Comprehensive alert generation, escalation, and notification system
"""

import smtplib
import json
import requests
import threading
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class AlertManager:
    """Comprehensive alert management system"""
    
    def __init__(self, db, socketio, broadcast_alert_func):
        self.db = db
        self.socketio = socketio
        self.broadcast_alert = broadcast_alert_func
        self.alert_rules = self._load_default_rules()
        self.notification_config = self._load_notification_config()
        self.escalation_thread = None
        self.running = False
        
    def _load_default_rules(self) -> Dict[str, Any]:
        """Load default alert rules and thresholds"""
        return {
            'port_scan': {
                'threshold': 10,
                'time_window': 60,  # seconds
                'severity': 'HIGH',
                'auto_block': True,
                'escalate_after': 300  # 5 minutes
            },
            'brute_force': {
                'threshold': 5,
                'time_window': 300,  # 5 minutes
                'severity': 'CRITICAL',
                'auto_block': True,
                'escalate_after': 180  # 3 minutes
            },
            'ddos': {
                'threshold': 100,
                'time_window': 60,
                'severity': 'CRITICAL',
                'auto_block': True,
                'escalate_after': 120  # 2 minutes
            },
            'malware': {
                'threshold': 1,
                'time_window': 1,
                'severity': 'CRITICAL',
                'auto_block': True,
                'escalate_after': 60  # 1 minute
            },
            'anomaly': {
                'threshold': 5,
                'time_window': 300,
                'severity': 'MEDIUM',
                'auto_block': False,
                'escalate_after': 600  # 10 minutes
            }
        }
    
    def _load_notification_config(self) -> Dict[str, Any]:
        """Load notification configuration"""
        return {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'webhook': {
                'enabled': False,
                'url': '',
                'headers': {'Content-Type': 'application/json'}
            },
            'slack': {
                'enabled': False,
                'webhook_url': ''
            }
        }
    
    def start_escalation_monitor(self):
        """Start the alert escalation monitoring thread"""
        if not self.running:
            self.running = True
            self.escalation_thread = threading.Thread(target=self._escalation_monitor, daemon=True)
            self.escalation_thread.start()
            logger.info("Alert escalation monitor started")
    
    def stop_escalation_monitor(self):
        """Stop the alert escalation monitoring thread"""
        self.running = False
        logger.info("Alert escalation monitor stopped")
    
    def _escalation_monitor(self):
        """Monitor alerts for escalation"""
        while self.running:
            try:
                # Check for alerts that need escalation
                cutoff_time = datetime.utcnow() - timedelta(minutes=5)
                unresolved_alerts = self.db.session.query(self.db.Model.registry._class_registry['Alert']).filter(
                    self.db.Model.registry._class_registry['Alert'].resolved == False,
                    self.db.Model.registry._class_registry['Alert'].acknowledged == False,
                    self.db.Model.registry._class_registry['Alert'].timestamp < cutoff_time
                ).all()
                
                for alert in unresolved_alerts:
                    self._escalate_alert(alert)
                
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Error in escalation monitor: {e}")
                time.sleep(60)
    
    def generate_alert(self, event_data: Dict[str, Any], threat_analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate alert based on event data and threat analysis"""
        try:
            event_type = event_data.get('eventType', '').lower()
            threat_level = event_data.get('threatLevel', 'LOW')
            source_ip = event_data.get('sourceIP', '')
            
            # Check if alert should be generated based on rules
            if not self._should_generate_alert(event_type, source_ip, threat_analysis):
                return None
            
            # Create alert
            alert_data = self._create_alert(event_data, threat_analysis)
            
            # Store in database
            from app import Alert
            alert = Alert(
                alert_type=alert_data['alertType'],
                severity=alert_data['severity'],
                title=alert_data['title'],
                description=alert_data['description'],
                source_ip=alert_data['sourceIP'],
                event_count=alert_data['eventCount']
            )
            
            from app import app
            with app.app_context():
                self.db.session.add(alert)
                self.db.session.commit()
                alert_data['id'] = alert.id
                alert_data['timestamp'] = alert.timestamp.isoformat()
                # Broadcast alert
                self.broadcast_alert(alert_data)
            
            # Send notifications
            self._send_notifications(alert_data)
            
            # Auto-block if configured
            if self._should_auto_block(event_type, threat_analysis):
                self._auto_block_ip(source_ip, alert_data)
            
            logger.info(f"Alert generated: {alert_data['title']}")
            return alert_data
            
        except Exception as e:
            logger.error(f"Error generating alert: {e}")
            return None
    
    def _should_generate_alert(self, event_type: str, source_ip: str, threat_analysis: Dict[str, Any]) -> bool:
        """Determine if an alert should be generated"""
        if event_type not in self.alert_rules:
            return False
        
        rule = self.alert_rules[event_type]
        confidence_score = threat_analysis.get('confidence_score', 0)
        threat_factors = threat_analysis.get('threat_factors', [])
        
        # Check confidence threshold
        if confidence_score < 0.7:
            return False
        
        # Check for high-priority threat factors
        high_priority_factors = ['known_malware', 'brute_force_pattern', 'ddos_pattern']
        if any(factor in threat_factors for factor in high_priority_factors):
            return True
        
        # Check event frequency
        return self._check_event_frequency(event_type, source_ip, rule)
    
    def _check_event_frequency(self, event_type: str, source_ip: str, rule: Dict[str, Any]) -> bool:
        """Check if event frequency exceeds threshold"""
        try:
            from app import NetworkEvent
            time_window = timedelta(seconds=rule['time_window'])
            cutoff_time = datetime.utcnow() - time_window
            
            event_count = self.db.session.query(NetworkEvent).filter(
                NetworkEvent.source_ip == source_ip,
                NetworkEvent.event_type == event_type,
                NetworkEvent.timestamp >= cutoff_time
            ).count()
            
            return event_count >= rule['threshold']
        except Exception as e:
            logger.error(f"Error checking event frequency: {e}")
            return False
    
    def _create_alert(self, event_data: Dict[str, Any], threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert data structure"""
        event_type = event_data.get('eventType', '')
        source_ip = event_data.get('sourceIP', '')
        threat_level = event_data.get('threatLevel', 'LOW')
        confidence_score = threat_analysis.get('confidence_score', 0)
        threat_factors = threat_analysis.get('threat_factors', [])
        
        # Determine severity
        severity = self._determine_severity(event_type, threat_level, confidence_score, threat_factors)
        
        # Create title and description
        title = self._generate_alert_title(event_type, source_ip, severity)
        description = self._generate_alert_description(event_data, threat_analysis)
        
        return {
            'alertType': event_type,
            'severity': severity,
            'title': title,
            'description': description,
            'sourceIP': source_ip,
            'eventCount': 1,
            'confidenceScore': confidence_score,
            'threatFactors': threat_factors,
            'acknowledged': False,
            'resolved': False
        }
    
    def _determine_severity(self, event_type: str, threat_level: str, confidence_score: float, threat_factors: List[str]) -> str:
        """Determine alert severity based on multiple factors"""
        base_severity = self.alert_rules.get(event_type, {}).get('severity', 'MEDIUM')
        
        # Escalate based on confidence score
        if confidence_score >= 0.9:
            if base_severity == 'MEDIUM':
                return 'HIGH'
            elif base_severity == 'HIGH':
                return 'CRITICAL'
        
        # Escalate based on threat factors
        critical_factors = ['known_malware', 'apt_pattern', 'lateral_movement']
        if any(factor in threat_factors for factor in critical_factors):
            return 'CRITICAL'
        
        return base_severity
    
    def _generate_alert_title(self, event_type: str, source_ip: str, severity: str) -> str:
        """Generate alert title"""
        titles = {
            'port_scan': f"Port Scan Detected from {source_ip}",
            'brute_force': f"Brute Force Attack from {source_ip}",
            'ddos': f"DDoS Attack Detected from {source_ip}",
            'malware': f"Malware Communication from {source_ip}",
            'anomaly': f"Network Anomaly Detected from {source_ip}",
            'lateral_movement': f"Lateral Movement Detected from {source_ip}",
            'data_exfiltration': f"Data Exfiltration Attempt from {source_ip}"
        }
        
        base_title = titles.get(event_type, f"Security Event from {source_ip}")
        return f"[{severity}] {base_title}"
    
    def _generate_alert_description(self, event_data: Dict[str, Any], threat_analysis: Dict[str, Any]) -> str:
        """Generate detailed alert description"""
        description_parts = []
        
        # Basic event info
        description_parts.append(f"Event Type: {event_data.get('eventType', 'Unknown')}")
        description_parts.append(f"Source: {event_data.get('sourceIP', 'Unknown')}:{event_data.get('sourcePort', 'N/A')}")
        description_parts.append(f"Destination: {event_data.get('destinationIP', 'Unknown')}:{event_data.get('destinationPort', 'N/A')}")
        description_parts.append(f"Protocol: {event_data.get('protocol', 'Unknown')}")
        
        # Threat analysis
        confidence_score = threat_analysis.get('confidence_score', 0)
        description_parts.append(f"Confidence Score: {confidence_score:.2f}")
        
        threat_factors = threat_analysis.get('threat_factors', [])
        if threat_factors:
            description_parts.append(f"Threat Factors: {', '.join(threat_factors)}")
        
        recommended_actions = threat_analysis.get('recommended_actions', [])
        if recommended_actions:
            description_parts.append(f"Recommended Actions: {', '.join(recommended_actions)}")
        
        return "\n".join(description_parts)
    
    def _should_auto_block(self, event_type: str, threat_analysis: Dict[str, Any]) -> bool:
        """Determine if IP should be auto-blocked"""
        rule = self.alert_rules.get(event_type, {})
        if not rule.get('auto_block', False):
            return False
        
        confidence_score = threat_analysis.get('confidence_score', 0)
        return confidence_score >= 0.8
    
    def _auto_block_ip(self, ip_address: str, alert_data: Dict[str, Any]):
        """Automatically block IP address"""
        try:
            from network_capture import block_ip
            block_ip(ip_address)
            
            # Update alert description
            alert_data['description'] += f"\n\nAUTO-BLOCKED: IP {ip_address} has been automatically blocked."
            
            logger.info(f"Auto-blocked IP: {ip_address}")
        except Exception as e:
            logger.error(f"Error auto-blocking IP {ip_address}: {e}")
    
    def _send_notifications(self, alert_data: Dict[str, Any]):
        """Send alert notifications via configured channels"""
        try:
            # Email notifications
            if self.notification_config['email']['enabled']:
                self._send_email_notification(alert_data)
            
            # Webhook notifications
            if self.notification_config['webhook']['enabled']:
                self._send_webhook_notification(alert_data)
            
            # Slack notifications
            if self.notification_config['slack']['enabled']:
                self._send_slack_notification(alert_data)
                
        except Exception as e:
            logger.error(f"Error sending notifications: {e}")
    
    def _send_email_notification(self, alert_data: Dict[str, Any]):
        """Send email notification"""
        try:
            config = self.notification_config['email']
            
            msg = MIMEMultipart()
            msg['From'] = config['username']
            msg['To'] = ', '.join(config['recipients'])
            msg['Subject'] = f"SecureWatch IDS Alert: {alert_data['title']}"
            
            body = f"""
            SecureWatch IDS Alert
            
            Title: {alert_data['title']}
            Severity: {alert_data['severity']}
            Source IP: {alert_data['sourceIP']}
            Timestamp: {alert_data.get('timestamp', 'Unknown')}
            
            Description:
            {alert_data['description']}
            
            Please investigate this alert immediately.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
            server.starttls()
            server.login(config['username'], config['password'])
            server.send_message(msg)
            server.quit()
            
            logger.info("Email notification sent")
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
    
    def _send_webhook_notification(self, alert_data: Dict[str, Any]):
        """Send webhook notification"""
        try:
            config = self.notification_config['webhook']
            
            payload = {
                'alert': alert_data,
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'SecureWatch IDS'
            }
            
            response = requests.post(
                config['url'],
                json=payload,
                headers=config['headers'],
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Webhook notification sent")
            else:
                logger.error(f"Webhook notification failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
    
    def _send_slack_notification(self, alert_data: Dict[str, Any]):
        """Send Slack notification"""
        try:
            config = self.notification_config['slack']
            
            color_map = {
                'LOW': '#36a64f',
                'MEDIUM': '#ff9500',
                'HIGH': '#ff6b35',
                'CRITICAL': '#ff0000'
            }
            
            payload = {
                'attachments': [{
                    'color': color_map.get(alert_data['severity'], '#36a64f'),
                    'title': alert_data['title'],
                    'fields': [
                        {'title': 'Severity', 'value': alert_data['severity'], 'short': True},
                        {'title': 'Source IP', 'value': alert_data['sourceIP'], 'short': True},
                        {'title': 'Alert Type', 'value': alert_data['alertType'], 'short': True},
                        {'title': 'Confidence', 'value': f"{alert_data.get('confidenceScore', 0):.2f}", 'short': True}
                    ],
                    'text': alert_data['description'][:500] + ('...' if len(alert_data['description']) > 500 else ''),
                    'footer': 'SecureWatch IDS',
                    'ts': int(datetime.utcnow().timestamp())
                }]
            }
            
            response = requests.post(config['webhook_url'], json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info("Slack notification sent")
            else:
                logger.error(f"Slack notification failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
    
    def _escalate_alert(self, alert):
        """Escalate unresolved alert"""
        try:
            # Update alert severity
            if alert.severity == 'LOW':
                alert.severity = 'MEDIUM'
            elif alert.severity == 'MEDIUM':
                alert.severity = 'HIGH'
            elif alert.severity == 'HIGH':
                alert.severity = 'CRITICAL'
            
            # Update title to indicate escalation
            if '[ESCALATED]' not in alert.title:
                alert.title = f"[ESCALATED] {alert.title}"
            
            from app import app
            with app.app_context():
                self.db.session.commit()
                # Send escalation notification
                escalation_data = alert.to_dict()
                escalation_data['escalated'] = True
                self._send_notifications(escalation_data)
                # Broadcast escalation
                self.broadcast_alert(escalation_data)
            
            logger.info(f"Alert escalated: {alert.id}")
            
        except Exception as e:
            logger.error(f"Error escalating alert {alert.id}: {e}")
    
    def acknowledge_alert(self, alert_id: int, acknowledged_by: str) -> bool:
        """Acknowledge an alert"""
        try:
            from app import Alert
            alert = Alert.query.get(alert_id)
            if alert:
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                from app import app
                with app.app_context():
                    self.db.session.commit()
                    # Broadcast acknowledgment
                    alert_data = alert.to_dict()
                    self.broadcast_alert(alert_data)
                
                logger.info(f"Alert acknowledged: {alert_id} by {acknowledged_by}")
                return True
        except Exception as e:
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
        return False
    
    def resolve_alert(self, alert_id: int, resolved_by: str) -> bool:
        """Resolve an alert"""
        try:
            from app import Alert
            alert = Alert.query.get(alert_id)
            if alert:
                alert.resolved = True
                alert.resolved_by = resolved_by
                alert.acknowledged = True  # Auto-acknowledge when resolving
                if not alert.acknowledged_by:
                    alert.acknowledged_by = resolved_by
                from app import app
                with app.app_context():
                    self.db.session.commit()
                    # Broadcast resolution
                    alert_data = alert.to_dict()
                    self.broadcast_alert(alert_data)
                
                logger.info(f"Alert resolved: {alert_id} by {resolved_by}")
                return True
        except Exception as e:
            logger.error(f"Error resolving alert {alert_id}: {e}")
        return False
    
    def update_notification_config(self, config: Dict[str, Any]):
        """Update notification configuration"""
        self.notification_config.update(config)
        logger.info("Notification configuration updated")
    
    def update_alert_rules(self, rules: Dict[str, Any]):
        """Update alert rules"""
        self.alert_rules.update(rules)
        logger.info("Alert rules updated")
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            from app import Alert
            
            # Get counts by severity
            total_alerts = Alert.query.count()
            critical_alerts = Alert.query.filter_by(severity='CRITICAL').count()
            high_alerts = Alert.query.filter_by(severity='HIGH').count()
            medium_alerts = Alert.query.filter_by(severity='MEDIUM').count()
            low_alerts = Alert.query.filter_by(severity='LOW').count()
            
            # Get resolution stats
            resolved_alerts = Alert.query.filter_by(resolved=True).count()
            acknowledged_alerts = Alert.query.filter_by(acknowledged=True).count()
            unresolved_alerts = Alert.query.filter_by(resolved=False).count()
            
            # Get recent activity
            last_24h = datetime.utcnow() - timedelta(hours=24)
            recent_alerts = Alert.query.filter(Alert.timestamp >= last_24h).count()
            
            return {
                'total_alerts': total_alerts,
                'by_severity': {
                    'critical': critical_alerts,
                    'high': high_alerts,
                    'medium': medium_alerts,
                    'low': low_alerts
                },
                'resolution_stats': {
                    'resolved': resolved_alerts,
                    'acknowledged': acknowledged_alerts,
                    'unresolved': unresolved_alerts
                },
                'recent_activity': {
                    'last_24h': recent_alerts
                }
            }
        except Exception as e:
            logger.error(f"Error getting alert statistics: {e}")
            return {}

# Global alert manager instance
alert_manager = None

def initialize_alert_manager(db, socketio, broadcast_alert_func):
    """Initialize the global alert manager"""
    global alert_manager
    alert_manager = AlertManager(db, socketio, broadcast_alert_func)
    alert_manager.start_escalation_monitor()
    return alert_manager

def get_alert_manager():
    """Get the global alert manager instance"""
    return alert_manager
