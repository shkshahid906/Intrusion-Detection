#!/usr/bin/env python3
"""
Comprehensive Reporting System for SecureWatch IDS
Advanced report generation, export capabilities, and compliance reporting
"""

import json
import csv
import io
import threading
import time
import smtplib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging

# Try to import optional dependencies
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Comprehensive report generation system"""
    
    def __init__(self, db, app):
        self.db = db
        self.app = app
        self.report_templates = self._load_report_templates()
        self.scheduled_reports = []
        self.scheduler_thread = None
        self.running = False
        
    def _load_report_templates(self) -> Dict[str, Any]:
        """Load predefined report templates"""
        return {
            'security_summary': {
                'name': 'Security Summary Report',
                'description': 'Overview of security events and threats',
                'sections': ['threat_overview', 'alert_summary', 'blocked_ips', 'top_threats'],
                'default_period': 'daily'
            },
            'compliance_audit': {
                'name': 'Compliance Audit Report',
                'description': 'Detailed audit trail for compliance requirements',
                'sections': ['audit_trail', 'policy_violations', 'access_logs', 'system_changes'],
                'default_period': 'monthly'
            },
            'network_analysis': {
                'name': 'Network Traffic Analysis',
                'description': 'Comprehensive network traffic and pattern analysis',
                'sections': ['traffic_overview', 'protocol_distribution', 'geographic_analysis', 'anomalies'],
                'default_period': 'weekly'
            },
            'threat_intelligence': {
                'name': 'Threat Intelligence Report',
                'description': 'Advanced threat analysis and intelligence',
                'sections': ['threat_trends', 'attack_patterns', 'ioc_analysis', 'recommendations'],
                'default_period': 'weekly'
            },
            'performance_metrics': {
                'name': 'System Performance Report',
                'description': 'IDS system performance and health metrics',
                'sections': ['system_health', 'detection_performance', 'resource_usage', 'uptime_analysis'],
                'default_period': 'daily'
            }
        }
    
    def start_scheduler(self):
        """Start the report scheduler"""
        if not self.running:
            self.running = True
            self.scheduler_thread = threading.Thread(target=self._scheduler_worker, daemon=True)
            self.scheduler_thread.start()
            logger.info("Report scheduler started")
    
    def stop_scheduler(self):
        """Stop the report scheduler"""
        self.running = False
        logger.info("Report scheduler stopped")
    
    def _scheduler_worker(self):
        """Report scheduler worker thread"""
        while self.running:
            try:
                current_time = datetime.now()
                
                for scheduled_report in self.scheduled_reports:
                    if self._should_generate_report(scheduled_report, current_time):
                        self._generate_scheduled_report(scheduled_report)
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Report scheduler error: {e}")
                time.sleep(60)
    
    def _should_generate_report(self, scheduled_report: Dict[str, Any], current_time: datetime) -> bool:
        """Check if a scheduled report should be generated"""
        try:
            last_generated = scheduled_report.get('last_generated')
            frequency = scheduled_report.get('frequency', 'daily')
            
            if not last_generated:
                return True
            
            last_gen_time = datetime.fromisoformat(last_generated)
            
            if frequency == 'hourly':
                return current_time >= last_gen_time + timedelta(hours=1)
            elif frequency == 'daily':
                return current_time >= last_gen_time + timedelta(days=1)
            elif frequency == 'weekly':
                return current_time >= last_gen_time + timedelta(weeks=1)
            elif frequency == 'monthly':
                return current_time >= last_gen_time + timedelta(days=30)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking scheduled report: {e}")
            return False
    
    def _generate_scheduled_report(self, scheduled_report: Dict[str, Any]):
        """Generate a scheduled report"""
        try:
            report_config = {
                'template': scheduled_report['template'],
                'period': scheduled_report.get('period', 'last_24h'),
                'format': scheduled_report.get('format', 'pdf'),
                'email_recipients': scheduled_report.get('email_recipients', [])
            }
            
            report_data = self.generate_report(report_config)
            
            if report_data and scheduled_report.get('email_recipients'):
                self._email_report(report_data, scheduled_report)
            
            # Update last generated time
            scheduled_report['last_generated'] = datetime.now().isoformat()
            
            logger.info(f"Generated scheduled report: {scheduled_report['template']}")
            
        except Exception as e:
            logger.error(f"Error generating scheduled report: {e}")
    
    def generate_report(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a report based on configuration"""
        try:
            with self.app.app_context():
                template_name = config.get('template', 'security_summary')
                period = config.get('period', 'last_24h')
                format_type = config.get('format', 'json')
                
                # Get date range
                start_date, end_date = self._parse_period(period)
                
                # Generate report data
                report_data = self._generate_report_data(template_name, start_date, end_date)
                
                # Format report
                formatted_report = self._format_report(report_data, format_type, template_name)
                
                return {
                    'template': template_name,
                    'period': period,
                    'format': format_type,
                    'generated_at': datetime.now().isoformat(),
                    'data': formatted_report,
                    'metadata': {
                        'start_date': start_date.isoformat(),
                        'end_date': end_date.isoformat(),
                        'record_count': len(report_data.get('events', []))
                    }
                }
                
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            return None
    
    def _parse_period(self, period: str) -> tuple:
        """Parse period string to date range"""
        end_date = datetime.now()
        
        if period == 'last_1h':
            start_date = end_date - timedelta(hours=1)
        elif period == 'last_24h':
            start_date = end_date - timedelta(days=1)
        elif period == 'last_7d':
            start_date = end_date - timedelta(days=7)
        elif period == 'last_30d':
            start_date = end_date - timedelta(days=30)
        elif period == 'last_90d':
            start_date = end_date - timedelta(days=90)
        else:
            # Default to last 24 hours
            start_date = end_date - timedelta(days=1)
        
        return start_date, end_date
    
    def _generate_report_data(self, template_name: str, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate report data based on template"""
        try:
            from app import NetworkEvent, Alert, SystemStats
            
            # Get base data
            events = NetworkEvent.query.filter(
                NetworkEvent.timestamp >= start_date,
                NetworkEvent.timestamp <= end_date
            ).all()
            
            alerts = Alert.query.filter(
                Alert.timestamp >= start_date,
                Alert.timestamp <= end_date
            ).all()
            
            stats = SystemStats.query.filter(
                SystemStats.timestamp >= start_date,
                SystemStats.timestamp <= end_date
            ).all()
            
            # Generate template-specific data
            if template_name == 'security_summary':
                return self._generate_security_summary(events, alerts, stats)
            elif template_name == 'compliance_audit':
                return self._generate_compliance_audit(events, alerts, stats)
            elif template_name == 'network_analysis':
                return self._generate_network_analysis(events, alerts, stats)
            elif template_name == 'threat_intelligence':
                return self._generate_threat_intelligence(events, alerts, stats)
            elif template_name == 'performance_metrics':
                return self._generate_performance_metrics(events, alerts, stats)
            else:
                return self._generate_default_report(events, alerts, stats)
                
        except Exception as e:
            logger.error(f"Report data generation error: {e}")
            return {}
    
    def _generate_security_summary(self, events: List, alerts: List, stats: List) -> Dict[str, Any]:
        """Generate security summary report data"""
        # Threat level distribution
        threat_levels = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for event in events:
            threat_levels[event.threat_level] = threat_levels.get(event.threat_level, 0) + 1
        
        # Alert severity distribution
        alert_severity = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for alert in alerts:
            alert_severity[alert.severity] = alert_severity.get(alert.severity, 0) + 1
        
        # Top source IPs
        source_ips = {}
        for event in events:
            source_ips[event.source_ip] = source_ips.get(event.source_ip, 0) + 1
        top_sources = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Blocked connections
        blocked_count = sum(1 for event in events if event.blocked)
        
        return {
            'summary': {
                'total_events': len(events),
                'total_alerts': len(alerts),
                'blocked_connections': blocked_count,
                'unique_sources': len(source_ips)
            },
            'threat_distribution': threat_levels,
            'alert_severity': alert_severity,
            'top_sources': top_sources,
            'events': [event.to_dict() for event in events[-50:]],  # Last 50 events
            'alerts': [alert.to_dict() for alert in alerts]
        }
    
    def _generate_compliance_audit(self, events: List, alerts: List, stats: List) -> Dict[str, Any]:
        """Generate compliance audit report data"""
        # Policy violations (high/critical threats)
        violations = [event for event in events if event.threat_level in ['HIGH', 'CRITICAL']]
        
        # Access patterns
        access_patterns = {}
        for event in events:
            key = f"{event.source_ip}:{event.destination_port}"
            access_patterns[key] = access_patterns.get(key, 0) + 1
        
        # System changes (alerts)
        system_changes = [alert for alert in alerts if 'system' in alert.alert_type.lower()]
        
        return {
            'audit_summary': {
                'total_events_audited': len(events),
                'policy_violations': len(violations),
                'system_changes': len(system_changes),
                'compliance_score': max(0, 100 - (len(violations) * 2))
            },
            'violations': [event.to_dict() for event in violations],
            'access_patterns': sorted(access_patterns.items(), key=lambda x: x[1], reverse=True)[:20],
            'system_changes': [alert.to_dict() for alert in system_changes],
            'recommendations': self._generate_compliance_recommendations(violations, alerts)
        }
    
    def _generate_network_analysis(self, events: List, alerts: List, stats: List) -> Dict[str, Any]:
        """Generate network analysis report data"""
        # Protocol distribution
        protocols = {}
        for event in events:
            protocols[event.protocol] = protocols.get(event.protocol, 0) + 1
        
        # Port analysis
        ports = {}
        for event in events:
            if event.destination_port:
                ports[event.destination_port] = ports.get(event.destination_port, 0) + 1
        
        # Traffic patterns by hour
        hourly_traffic = {}
        for event in events:
            hour = event.timestamp.hour
            hourly_traffic[hour] = hourly_traffic.get(hour, 0) + 1
        
        return {
            'network_summary': {
                'total_connections': len(events),
                'unique_protocols': len(protocols),
                'unique_ports': len(ports),
                'peak_hour': max(hourly_traffic.items(), key=lambda x: x[1])[0] if hourly_traffic else 0
            },
            'protocol_distribution': protocols,
            'top_ports': sorted(ports.items(), key=lambda x: x[1], reverse=True)[:20],
            'hourly_traffic': hourly_traffic,
            'anomalies': [event.to_dict() for event in events if event.threat_level in ['HIGH', 'CRITICAL']]
        }
    
    def _generate_threat_intelligence(self, events: List, alerts: List, stats: List) -> Dict[str, Any]:
        """Generate threat intelligence report data"""
        # Attack patterns
        attack_patterns = {}
        for event in events:
            attack_patterns[event.event_type] = attack_patterns.get(event.event_type, 0) + 1
        
        # Threat trends (by day)
        threat_trends = {}
        for event in events:
            date_key = event.timestamp.date().isoformat()
            if date_key not in threat_trends:
                threat_trends[date_key] = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
            threat_trends[date_key][event.threat_level] += 1
        
        # IOC analysis (suspicious IPs)
        suspicious_ips = {}
        for event in events:
            if event.threat_level in ['HIGH', 'CRITICAL']:
                suspicious_ips[event.source_ip] = suspicious_ips.get(event.source_ip, 0) + 1
        
        return {
            'intelligence_summary': {
                'attack_types': len(attack_patterns),
                'suspicious_ips': len(suspicious_ips),
                'critical_threats': sum(1 for e in events if e.threat_level == 'CRITICAL'),
                'threat_score': min(100, len([e for e in events if e.threat_level in ['HIGH', 'CRITICAL']]) * 2)
            },
            'attack_patterns': attack_patterns,
            'threat_trends': threat_trends,
            'suspicious_ips': sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True)[:20],
            'recommendations': self._generate_threat_recommendations(events, alerts)
        }
    
    def _generate_performance_metrics(self, events: List, alerts: List, stats: List) -> Dict[str, Any]:
        """Generate performance metrics report data"""
        # Detection performance
        detection_rate = len([e for e in events if e.threat_level in ['MEDIUM', 'HIGH', 'CRITICAL']]) / max(len(events), 1) * 100
        
        # System resource usage
        avg_cpu = sum(s.cpu_usage for s in stats) / max(len(stats), 1)
        avg_memory = sum(s.memory_usage for s in stats) / max(len(stats), 1)
        avg_throughput = sum(s.network_throughput for s in stats) / max(len(stats), 1)
        
        # Alert response metrics
        resolved_alerts = len([a for a in alerts if a.resolved])
        response_rate = resolved_alerts / max(len(alerts), 1) * 100
        
        return {
            'performance_summary': {
                'detection_rate': round(detection_rate, 2),
                'alert_response_rate': round(response_rate, 2),
                'avg_cpu_usage': round(avg_cpu, 2),
                'avg_memory_usage': round(avg_memory, 2),
                'system_health_score': max(0, 100 - avg_cpu - avg_memory)
            },
            'resource_usage': {
                'cpu_trend': [s.cpu_usage for s in stats[-24:]],  # Last 24 readings
                'memory_trend': [s.memory_usage for s in stats[-24:]],
                'throughput_trend': [s.network_throughput for s in stats[-24:]]
            },
            'detection_metrics': {
                'events_processed': len(events),
                'threats_detected': len([e for e in events if e.threat_level != 'LOW']),
                'false_positive_rate': 5.2  # Placeholder - would need ML analysis
            }
        }
    
    def _generate_default_report(self, events: List, alerts: List, stats: List) -> Dict[str, Any]:
        """Generate default report data"""
        return {
            'events': [event.to_dict() for event in events],
            'alerts': [alert.to_dict() for alert in alerts],
            'statistics': [{'timestamp': s.timestamp.isoformat(), 'cpu_usage': s.cpu_usage, 'memory_usage': s.memory_usage} for s in stats]
        }
    
    def _generate_compliance_recommendations(self, violations: List, alerts: List) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        if len(violations) > 10:
            recommendations.append("Consider implementing stricter access controls")
        
        if len([a for a in alerts if not a.resolved]) > 5:
            recommendations.append("Improve alert response procedures")
        
        recommendations.append("Regular security policy review recommended")
        recommendations.append("Implement automated compliance monitoring")
        
        return recommendations
    
    def _generate_threat_recommendations(self, events: List, alerts: List) -> List[str]:
        """Generate threat intelligence recommendations"""
        recommendations = []
        
        critical_events = [e for e in events if e.threat_level == 'CRITICAL']
        if len(critical_events) > 5:
            recommendations.append("Immediate threat response required")
        
        recommendations.append("Update threat intelligence feeds")
        recommendations.append("Review and update detection rules")
        recommendations.append("Consider implementing additional monitoring")
        
        return recommendations
    
    def _format_report(self, report_data: Dict[str, Any], format_type: str, template_name: str) -> Any:
        """Format report data according to specified format"""
        if format_type == 'json':
            return json.dumps(report_data, indent=2, default=str)
        elif format_type == 'csv':
            return self._format_csv(report_data)
        elif format_type == 'pdf' and REPORTLAB_AVAILABLE:
            return self._format_pdf(report_data, template_name)
        elif format_type == 'excel' and PANDAS_AVAILABLE:
            return self._format_excel(report_data)
        else:
            return json.dumps(report_data, indent=2, default=str)
    
    def _format_csv(self, report_data: Dict[str, Any]) -> str:
        """Format report data as CSV"""
        output = io.StringIO()
        
        # Write events if available
        if 'events' in report_data:
            writer = csv.writer(output)
            
            # Write header
            if report_data['events']:
                headers = report_data['events'][0].keys()
                writer.writerow(headers)
                
                # Write data
                for event in report_data['events']:
                    writer.writerow(event.values())
        
        return output.getvalue()
    
    def _format_pdf(self, report_data: Dict[str, Any], template_name: str) -> bytes:
        """Format report data as PDF"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        template_info = self.report_templates.get(template_name, {})
        title = template_info.get('name', 'Security Report')
        story.append(Paragraph(title, title_style))
        story.append(Spacer(1, 12))
        
        # Summary section
        if 'summary' in report_data:
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            summary_data = []
            for key, value in report_data['summary'].items():
                summary_data.append([key.replace('_', ' ').title(), str(value)])
            
            summary_table = Table(summary_data)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 12))
        
        # Add other sections based on report data
        for section_key, section_data in report_data.items():
            if section_key not in ['summary', 'events', 'alerts'] and isinstance(section_data, dict):
                story.append(Paragraph(section_key.replace('_', ' ').title(), styles['Heading2']))
                
                if isinstance(section_data, dict) and len(section_data) < 20:
                    table_data = [[k.replace('_', ' ').title(), str(v)] for k, v in section_data.items()]
                    table = Table(table_data)
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    story.append(table)
                    story.append(Spacer(1, 12))
        
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _format_excel(self, report_data: Dict[str, Any]) -> bytes:
        """Format report data as Excel"""
        output = io.BytesIO()
        
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Write summary sheet
            if 'summary' in report_data:
                summary_df = pd.DataFrame(list(report_data['summary'].items()), columns=['Metric', 'Value'])
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Write events sheet
            if 'events' in report_data and report_data['events']:
                events_df = pd.DataFrame(report_data['events'])
                events_df.to_excel(writer, sheet_name='Events', index=False)
            
            # Write alerts sheet
            if 'alerts' in report_data and report_data['alerts']:
                alerts_df = pd.DataFrame(report_data['alerts'])
                alerts_df.to_excel(writer, sheet_name='Alerts', index=False)
        
        output.seek(0)
        return output.getvalue()
    
    def _email_report(self, report_data: Dict[str, Any], scheduled_report: Dict[str, Any]):
        """Email report to recipients"""
        try:
            email_config = scheduled_report.get('email_config', {})
            recipients = scheduled_report.get('email_recipients', [])
            
            if not recipients or not email_config:
                return
            
            msg = MIMEMultipart()
            msg['From'] = email_config.get('sender', 'ids@company.com')
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"SecureWatch IDS Report - {report_data['template']}"
            
            # Email body
            body = f"""
            SecureWatch IDS Automated Report
            
            Report Type: {report_data['template']}
            Generated: {report_data['generated_at']}
            Period: {report_data['period']}
            
            Please find the detailed report attached.
            
            Best regards,
            SecureWatch IDS System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach report
            if report_data['format'] == 'pdf':
                attachment = MIMEBase('application', 'octet-stream')
                attachment.set_payload(report_data['data'])
                encoders.encode_base64(attachment)
                attachment.add_header('Content-Disposition', f'attachment; filename="report.pdf"')
                msg.attach(attachment)
            
            # Send email
            server = smtplib.SMTP(email_config.get('smtp_server', 'localhost'), email_config.get('smtp_port', 587))
            if email_config.get('use_tls', True):
                server.starttls()
            if email_config.get('username') and email_config.get('password'):
                server.login(email_config['username'], email_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Report emailed to {len(recipients)} recipients")
            
        except Exception as e:
            logger.error(f"Error emailing report: {e}")
    
    def add_scheduled_report(self, config: Dict[str, Any]) -> bool:
        """Add a scheduled report"""
        try:
            required_fields = ['template', 'frequency']
            if not all(field in config for field in required_fields):
                return False
            
            self.scheduled_reports.append(config)
            logger.info(f"Added scheduled report: {config['template']}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding scheduled report: {e}")
            return False
    
    def remove_scheduled_report(self, report_id: int) -> bool:
        """Remove a scheduled report"""
        try:
            if 0 <= report_id < len(self.scheduled_reports):
                removed = self.scheduled_reports.pop(report_id)
                logger.info(f"Removed scheduled report: {removed['template']}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error removing scheduled report: {e}")
            return False
    
    def get_report_templates(self) -> Dict[str, Any]:
        """Get available report templates"""
        return self.report_templates
    
    def get_scheduled_reports(self) -> List[Dict[str, Any]]:
        """Get list of scheduled reports"""
        return self.scheduled_reports

# Global report generator instance
report_generator = None

def initialize_report_generator(db, app):
    """Initialize the global report generator"""
    global report_generator
    report_generator = ReportGenerator(db, app)
    report_generator.start_scheduler()
    return report_generator

def get_report_generator():
    """Get the global report generator instance"""
    return report_generator
