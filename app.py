#!/usr/bin/env python3
"""
SecureWatch IDS - Flask Application
Professional Intrusion Detection System with Live Network Analysis
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import threading
import json
import os
import logging
from typing import Dict, List, Any

from alert_manager import initialize_alert_manager, get_alert_manager
from database_manager import initialize_database_manager, get_database_manager
from logging_system import initialize_logging_system, get_ids_logger
from reporting_system import initialize_report_generator, get_report_generator

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database Models
class NetworkEvent(db.Model):
    """Network event model for storing detected events"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)
    confidence_score = db.Column(db.Float, default=0.0)
    packet_size = db.Column(db.Integer)
    flags = db.Column(db.String(20))
    payload_info = db.Column(db.Text)
    blocked = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'sourceIP': self.source_ip,
            'destinationIP': self.destination_ip,
            'sourcePort': self.source_port,
            'destinationPort': self.destination_port,
            'protocol': self.protocol,
            'eventType': self.event_type,
            'threatLevel': self.threat_level,
            'confidenceScore': self.confidence_score,
            'packetSize': self.packet_size,
            'flags': self.flags,
            'payloadInfo': self.payload_info,
            'blocked': self.blocked
        }

class Alert(db.Model):
    """Alert model for managing security alerts"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    source_ip = db.Column(db.String(45))
    event_count = db.Column(db.Integer, default=1)
    acknowledged = db.Column(db.Boolean, default=False)
    resolved = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.String(100))
    resolved_by = db.Column(db.String(100))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'alertType': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'sourceIP': self.source_ip,
            'eventCount': self.event_count,
            'acknowledged': self.acknowledged,
            'resolved': self.resolved,
            'acknowledgedBy': self.acknowledged_by,
            'resolvedBy': self.resolved_by
        }

class SystemStats(db.Model):
    """System statistics model"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_events = db.Column(db.Integer, default=0)
    threats_detected = db.Column(db.Integer, default=0)
    blocked_connections = db.Column(db.Integer, default=0)
    active_connections = db.Column(db.Integer, default=0)
    cpu_usage = db.Column(db.Float, default=0.0)
    memory_usage = db.Column(db.Float, default=0.0)
    network_throughput = db.Column(db.Float, default=0.0)

# Global variables for monitoring state
monitoring_active = False
packet_capture_thread = None

# Routes
@app.route('/')
def dashboard():
    """Main dashboard route"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current system statistics"""
    latest_stats = SystemStats.query.order_by(SystemStats.timestamp.desc()).first()
    if not latest_stats:
        # Create default stats if none exist
        latest_stats = SystemStats()
        db.session.add(latest_stats)
        db.session.commit()
    
    return jsonify({
        'totalEvents': latest_stats.total_events,
        'threatsDetected': latest_stats.threats_detected,
        'blockedConnections': latest_stats.blocked_connections,
        'activeConnections': latest_stats.active_connections,
        'cpuUsage': latest_stats.cpu_usage,
        'memoryUsage': latest_stats.memory_usage,
        'networkThroughput': latest_stats.network_throughput
    })

@app.route('/api/events')
def get_events():
    """Get recent network events"""
    limit = request.args.get('limit', 50, type=int)
    events = NetworkEvent.query.order_by(NetworkEvent.timestamp.desc()).limit(limit).all()
    return jsonify([event.to_dict() for event in events])

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 20, type=int)
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return jsonify([alert.to_dict() for alert in alerts])

@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    global monitoring_active, packet_capture_thread
    
    if not monitoring_active:
        monitoring_active = True
        # Import and start packet capture (will be implemented in next task)
        from network_capture import start_packet_capture
        packet_capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
        packet_capture_thread.start()
        logger.info("Network monitoring started")
        
    return jsonify({'status': 'started', 'monitoring': monitoring_active})

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    global monitoring_active
    monitoring_active = False
    from network_capture import stop_packet_capture
    stop_packet_capture()
    logger.info("Network monitoring stopped")
    return jsonify({'status': 'stopped', 'monitoring': monitoring_active})

@app.route('/api/monitoring/status')
def monitoring_status():
    """Get monitoring status"""
    return jsonify({'monitoring': monitoring_active})

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('status', {'monitoring': monitoring_active})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

def broadcast_event(event_data):
    print("[SOCKET.IO] Emitting new_event:", event_data)  # Add this line
    print("[SOCKET.IO] Emitting new_event:", event_data)
    socketio.emit('new_event', event_data)

def broadcast_alert(alert_data):
    print("[SOCKET.IO] Emitting new_alert:", alert_data)  # Add this line
    print("[SOCKET.IO] Emitting new_alert:", alert_data)
    socketio.emit('new_alert', alert_data)

def broadcast_stats(stats_data):
    """Broadcast updated stats to all connected clients"""
    socketio.emit('stats_update', stats_data)

# Initialize database
def init_db():
    """Initialize database tables"""
    with app.app_context():
        db.create_all()
        # Initialize alert manager
        initialize_alert_manager(db, socketio, broadcast_alert)
        initialize_database_manager(db, app)
        initialize_logging_system()
        initialize_report_generator(db, app)
        logger.info("Database, alert manager, logging system, and reporting system initialized")

@app.route('/api/alerts/acknowledge', methods=['POST'])
def acknowledge_alert():
    """Acknowledge an alert"""
    data = request.get_json()
    alert_id = data.get('alert_id')
    acknowledged_by = data.get('acknowledged_by', 'System')
    
    alert_mgr = get_alert_manager()
    if alert_mgr and alert_mgr.acknowledge_alert(alert_id, acknowledged_by):
        return jsonify({'status': 'success', 'message': 'Alert acknowledged'})
    return jsonify({'status': 'error', 'message': 'Failed to acknowledge alert'}), 400

@app.route('/api/alerts/resolve', methods=['POST'])
def resolve_alert():
    """Resolve an alert"""
    data = request.get_json()
    alert_id = data.get('alert_id')
    resolved_by = data.get('resolved_by', 'System')
    
    alert_mgr = get_alert_manager()
    if alert_mgr and alert_mgr.resolve_alert(alert_id, resolved_by):
        return jsonify({'status': 'success', 'message': 'Alert resolved'})
    return jsonify({'status': 'error', 'message': 'Failed to resolve alert'}), 400

@app.route('/api/alerts/statistics')
def get_alert_statistics():
    """Get alert statistics"""
    alert_mgr = get_alert_manager()
    if alert_mgr:
        stats = alert_mgr.get_alert_statistics()
        return jsonify(stats)
    return jsonify({'error': 'Alert manager not available'}), 500

@app.route('/api/alerts/config', methods=['GET', 'POST'])
def alert_config():
    """Get or update alert configuration"""
    alert_mgr = get_alert_manager()
    if not alert_mgr:
        return jsonify({'error': 'Alert manager not available'}), 500
    
    if request.method == 'GET':
        return jsonify({
            'rules': alert_mgr.alert_rules,
            'notifications': alert_mgr.notification_config
        })
    else:
        data = request.get_json()
        if 'rules' in data:
            alert_mgr.update_alert_rules(data['rules'])
        if 'notifications' in data:
            alert_mgr.update_notification_config(data['notifications'])
        return jsonify({'status': 'success', 'message': 'Configuration updated'})

@app.route('/api/capture/stats')
def get_capture_stats():
    """Get packet capture statistics"""
    from network_capture import get_capture_stats
    return jsonify(get_capture_stats())

@app.route('/api/capture/interfaces')
def get_interfaces():
    """Get available network interfaces"""
    from network_capture import capture_engine
    interfaces = capture_engine.get_available_interfaces()
    return jsonify({'interfaces': interfaces, 'current': capture_engine.interface})

@app.route('/api/capture/interface', methods=['POST'])
def set_interface():
    """Set network interface for capture"""
    data = request.get_json()
    interface = data.get('interface')
    if interface:
        from network_capture import capture_engine
        capture_engine.set_interface(interface)
        return jsonify({'status': 'success', 'interface': interface})
    return jsonify({'status': 'error', 'message': 'Interface not specified'}), 400

@app.route('/api/security/block-ip', methods=['POST'])
def block_ip_endpoint():
    """Block an IP address"""
    data = request.get_json()
    ip_address = data.get('ip')
    if ip_address:
        from network_capture import block_ip
        block_ip(ip_address)
        return jsonify({'status': 'success', 'message': f'IP {ip_address} blocked'})
    return jsonify({'status': 'error', 'message': 'IP address not specified'}), 400

@app.route('/api/security/unblock-ip', methods=['POST'])
def unblock_ip_endpoint():
    """Unblock an IP address"""
    data = request.get_json()
    ip_address = data.get('ip')
    if ip_address:
        from network_capture import unblock_ip
        unblock_ip(ip_address)
        return jsonify({'status': 'success', 'message': f'IP {ip_address} unblocked'})
    return jsonify({'status': 'error', 'message': 'IP address not specified'}), 400

@app.route('/api/database/statistics')
def get_database_statistics():
    """Get database statistics"""
    db_mgr = get_database_manager()
    if db_mgr:
        stats = db_mgr.get_database_statistics()
        return jsonify(stats)
    return jsonify({'error': 'Database manager not available'}), 500

@app.route('/api/database/export', methods=['POST'])
def export_database_data():
    """Export database data"""
    data = request.get_json()
    table_name = data.get('table')
    start_date = datetime.fromisoformat(data.get('start_date'))
    end_date = datetime.fromisoformat(data.get('end_date'))
    
    db_mgr = get_database_manager()
    if db_mgr:
        exported_data = db_mgr.export_data(table_name, start_date, end_date)
        return jsonify({'data': exported_data, 'count': len(exported_data)})
    return jsonify({'error': 'Database manager not available'}), 500

@app.route('/api/logs/recent')
def get_recent_logs():
    """Get recent logs"""
    category = request.args.get('category')
    hours = request.args.get('hours', 24, type=int)
    
    logger_instance = get_ids_logger()
    if logger_instance:
        logs = logger_instance.get_recent_logs(category, hours)
        return jsonify({'logs': logs, 'count': len(logs)})
    return jsonify({'error': 'Logging system not available'}), 500

@app.route('/api/logs/audit')
def get_audit_trail():
    """Get audit trail"""
    hours = request.args.get('hours', 24, type=int)
    
    logger_instance = get_ids_logger()
    if logger_instance:
        audit_trail = logger_instance.get_audit_trail(hours)
        return jsonify({'audit_trail': audit_trail, 'count': len(audit_trail)})
    return jsonify({'error': 'Logging system not available'}), 500

@app.route('/api/logs/export', methods=['POST'])
def export_logs():
    """Export logs"""
    data = request.get_json()
    category = data.get('category')
    start_date = datetime.fromisoformat(data.get('start_date'))
    end_date = datetime.fromisoformat(data.get('end_date'))
    
    logger_instance = get_ids_logger()
    if logger_instance:
        exported_logs = logger_instance.export_logs(category, start_date, end_date)
        return jsonify({'logs': exported_logs})
    return jsonify({'error': 'Logging system not available'}), 500

@app.route('/api/logs/statistics')
def get_log_statistics():
    """Get logging statistics"""
    logger_instance = get_ids_logger()
    if logger_instance:
        stats = logger_instance.get_log_statistics()
        return jsonify(stats)
    return jsonify({'error': 'Logging system not available'}), 500

@app.route('/api/reports/templates')
def get_report_templates():
    """Get available report templates"""
    report_gen = get_report_generator()
    if report_gen:
        templates = report_gen.get_report_templates()
        return jsonify({'templates': templates})
    return jsonify({'error': 'Report generator not available'}), 500

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Generate a report"""
    data = request.get_json()
    
    report_gen = get_report_generator()
    if not report_gen:
        return jsonify({'error': 'Report generator not available'}), 500
    
    report_data = report_gen.generate_report(data)
    if report_data:
        return jsonify({'status': 'success', 'report': report_data})
    return jsonify({'status': 'error', 'message': 'Failed to generate report'}), 400

@app.route('/api/reports/scheduled', methods=['GET', 'POST', 'DELETE'])
def manage_scheduled_reports():
    """Manage scheduled reports"""
    report_gen = get_report_generator()
    if not report_gen:
        return jsonify({'error': 'Report generator not available'}), 500
    
    if request.method == 'GET':
        scheduled = report_gen.get_scheduled_reports()
        return jsonify({'scheduled_reports': scheduled})
    
    elif request.method == 'POST':
        data = request.get_json()
        if report_gen.add_scheduled_report(data):
            return jsonify({'status': 'success', 'message': 'Scheduled report added'})
        return jsonify({'status': 'error', 'message': 'Failed to add scheduled report'}), 400
    
    elif request.method == 'DELETE':
        report_id = request.args.get('id', type=int)
        if report_id is not None and report_gen.remove_scheduled_report(report_id):
            return jsonify({'status': 'success', 'message': 'Scheduled report removed'})
        return jsonify({'status': 'error', 'message': 'Failed to remove scheduled report'}), 400

@app.route('/api/reports/export', methods=['POST'])
def export_report():
    """Export report in specified format"""
    data = request.get_json()
    
    report_gen = get_report_generator()
    if not report_gen:
        return jsonify({'error': 'Report generator not available'}), 500
    
    # Generate report with export format
    config = {
        'template': data.get('template', 'security_summary'),
        'period': data.get('period', 'last_24h'),
        'format': data.get('format', 'json')
    }
    
    report_data = report_gen.generate_report(config)
    if report_data:
        # Return appropriate response based on format
        format_type = config['format']
        if format_type == 'pdf':
            return jsonify({
                'status': 'success',
                'format': format_type,
                'data': report_data['data'].decode('latin1') if isinstance(report_data['data'], bytes) else report_data['data'],
                'filename': f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            })
        else:
            return jsonify({
                'status': 'success',
                'format': format_type,
                'data': report_data['data'],
                'filename': f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_type}"
            })
    
    return jsonify({'status': 'error', 'message': 'Failed to export report'}), 400

@app.route('/api/reports/compliance')
def get_compliance_report():
    """Get compliance-specific report"""
    period = request.args.get('period', 'last_30d')
    
    report_gen = get_report_generator()
    if not report_gen:
        return jsonify({'error': 'Report generator not available'}), 500
    
    config = {
        'template': 'compliance_audit',
        'period': period,
        'format': 'json'
    }
    
    report_data = report_gen.generate_report(config)
    if report_data:
        return jsonify({'status': 'success', 'report': report_data})
    return jsonify({'status': 'error', 'message': 'Failed to generate compliance report'}), 400

@app.route('/api/reports/threat-intelligence')
def get_threat_intelligence_report():
    """Get threat intelligence report"""
    period = request.args.get('period', 'last_7d')
    
    report_gen = get_report_generator()
    if not report_gen:
        return jsonify({'error': 'Report generator not available'}), 500
    
    config = {
        'template': 'threat_intelligence',
        'period': period,
        'format': 'json'
    }
    
    report_data = report_gen.generate_report(config)
    if report_data:
        return jsonify({'status': 'success', 'report': report_data})
    return jsonify({'status': 'error', 'message': 'Failed to generate threat intelligence report'}), 400

if __name__ == '__main__':
    init_db()
    logger.info("Starting SecureWatch IDS Flask Application")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
