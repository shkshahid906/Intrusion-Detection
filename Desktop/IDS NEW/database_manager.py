#!/usr/bin/env python3
"""
Database Management System for SecureWatch IDS
Comprehensive database operations, optimization, and maintenance
"""

import sqlite3
import threading
import time
import os
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import json

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Comprehensive database management system"""
    
    def __init__(self, db, app):
        self.db = db
        self.app = app
        self.maintenance_thread = None
        self.running = False
        self.backup_dir = 'backups'
        self.ensure_backup_directory()
        
    def ensure_backup_directory(self):
        """Ensure backup directory exists"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def start_maintenance(self):
        """Start database maintenance thread"""
        if not self.running:
            self.running = True
            self.maintenance_thread = threading.Thread(target=self._maintenance_worker, daemon=True)
            self.maintenance_thread.start()
            logger.info("Database maintenance started")
    
    def stop_maintenance(self):
        """Stop database maintenance thread"""
        self.running = False
        logger.info("Database maintenance stopped")
    
    def _maintenance_worker(self):
        """Database maintenance worker thread"""
        while self.running:
            try:
                # Run maintenance tasks every hour
                self._optimize_database()
                self._cleanup_old_records()
                self._update_statistics()
                
                # Create daily backup
                if datetime.now().hour == 2:  # 2 AM backup
                    self._create_backup()
                
                time.sleep(3600)  # Sleep for 1 hour
            except Exception as e:
                logger.error(f"Database maintenance error: {e}")
                time.sleep(300)  # Sleep 5 minutes on error
    
    def _optimize_database(self):
        """Optimize database performance"""
        try:
            with self.app.app_context():
                # Analyze and optimize tables
                self.db.engine.execute('ANALYZE')
                self.db.engine.execute('VACUUM')
                logger.info("Database optimization completed")
        except Exception as e:
            logger.error(f"Database optimization error: {e}")
    
    def _cleanup_old_records(self):
        """Clean up old records based on retention policies"""
        try:
            with self.app.app_context():
                from app import NetworkEvent, Alert, SystemStats
                
                # Clean up old network events (keep 30 days)
                cutoff_date = datetime.utcnow() - timedelta(days=30)
                old_events = NetworkEvent.query.filter(NetworkEvent.timestamp < cutoff_date).count()
                if old_events > 0:
                    NetworkEvent.query.filter(NetworkEvent.timestamp < cutoff_date).delete()
                    logger.info(f"Cleaned up {old_events} old network events")
                
                # Clean up resolved alerts (keep 90 days)
                alert_cutoff = datetime.utcnow() - timedelta(days=90)
                old_alerts = Alert.query.filter(
                    Alert.timestamp < alert_cutoff,
                    Alert.resolved == True
                ).count()
                if old_alerts > 0:
                    Alert.query.filter(
                        Alert.timestamp < alert_cutoff,
                        Alert.resolved == True
                    ).delete()
                    logger.info(f"Cleaned up {old_alerts} old resolved alerts")
                
                # Clean up old system stats (keep 7 days of detailed stats)
                stats_cutoff = datetime.utcnow() - timedelta(days=7)
                old_stats = SystemStats.query.filter(SystemStats.timestamp < stats_cutoff).count()
                if old_stats > 0:
                    SystemStats.query.filter(SystemStats.timestamp < stats_cutoff).delete()
                    logger.info(f"Cleaned up {old_stats} old system statistics")
                
                self.db.session.commit()
                
        except Exception as e:
            logger.error(f"Record cleanup error: {e}")
            self.db.session.rollback()
    
    def _update_statistics(self):
        """Update database statistics"""
        try:
            with self.app.app_context():
                from app import NetworkEvent, Alert, SystemStats
                
                # Calculate current statistics
                total_events = NetworkEvent.query.count()
                threats_detected = NetworkEvent.query.filter(
                    NetworkEvent.threat_level.in_(['HIGH', 'CRITICAL'])
                ).count()
                blocked_connections = NetworkEvent.query.filter(
                    NetworkEvent.blocked == True
                ).count()
                
                # Get recent activity
                last_hour = datetime.utcnow() - timedelta(hours=1)
                recent_events = NetworkEvent.query.filter(
                    NetworkEvent.timestamp >= last_hour
                ).count()
                
                # Create new statistics record
                stats = SystemStats(
                    total_events=total_events,
                    threats_detected=threats_detected,
                    blocked_connections=blocked_connections,
                    active_connections=recent_events,
                    cpu_usage=self._get_cpu_usage(),
                    memory_usage=self._get_memory_usage(),
                    network_throughput=self._get_network_throughput()
                )
                
                self.db.session.add(stats)
                self.db.session.commit()
                
        except Exception as e:
            logger.error(f"Statistics update error: {e}")
            self.db.session.rollback()
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=1)
        except ImportError:
            return 0.0
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage"""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            return 0.0
    
    def _get_network_throughput(self) -> float:
        """Get current network throughput"""
        try:
            import psutil
            net_io = psutil.net_io_counters()
            return (net_io.bytes_sent + net_io.bytes_recv) / 1024 / 1024  # MB
        except ImportError:
            return 0.0
    
    def _create_backup(self):
        """Create database backup"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"ids_backup_{timestamp}.db"
            backup_path = os.path.join(self.backup_dir, backup_filename)
            
            # Copy database file
            db_path = 'ids_database.db'
            if os.path.exists(db_path):
                shutil.copy2(db_path, backup_path)
                logger.info(f"Database backup created: {backup_filename}")
                
                # Clean up old backups (keep 7 days)
                self._cleanup_old_backups()
            
        except Exception as e:
            logger.error(f"Backup creation error: {e}")
    
    def _cleanup_old_backups(self):
        """Clean up old backup files"""
        try:
            cutoff_time = time.time() - (7 * 24 * 3600)  # 7 days ago
            
            for filename in os.listdir(self.backup_dir):
                if filename.startswith('ids_backup_') and filename.endswith('.db'):
                    file_path = os.path.join(self.backup_dir, filename)
                    if os.path.getctime(file_path) < cutoff_time:
                        os.remove(file_path)
                        logger.info(f"Removed old backup: {filename}")
                        
        except Exception as e:
            logger.error(f"Backup cleanup error: {e}")
    
    def create_indexes(self):
        """Create database indexes for performance"""
        try:
            with self.app.app_context():
                # Create indexes on frequently queried columns
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_network_event_timestamp ON network_event(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_network_event_source_ip ON network_event(source_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_network_event_threat_level ON network_event(threat_level)',
                    'CREATE INDEX IF NOT EXISTS idx_network_event_event_type ON network_event(event_type)',
                    'CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alert(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_alert_severity ON alert(severity)',
                    'CREATE INDEX IF NOT EXISTS idx_alert_resolved ON alert(resolved)',
                    'CREATE INDEX IF NOT EXISTS idx_alert_source_ip ON alert(source_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_system_stats_timestamp ON system_stats(timestamp)'
                ]
                
                for index_sql in indexes:
                    self.db.engine.execute(index_sql)
                
                logger.info("Database indexes created")
                
        except Exception as e:
            logger.error(f"Index creation error: {e}")
    
    def get_database_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        try:
            with self.app.app_context():
                from app import NetworkEvent, Alert, SystemStats
                
                # Table counts
                event_count = NetworkEvent.query.count()
                alert_count = Alert.query.count()
                stats_count = SystemStats.query.count()
                
                # Database file size
                db_size = 0
                if os.path.exists('ids_database.db'):
                    db_size = os.path.getsize('ids_database.db') / 1024 / 1024  # MB
                
                # Recent activity
                last_24h = datetime.utcnow() - timedelta(hours=24)
                recent_events = NetworkEvent.query.filter(NetworkEvent.timestamp >= last_24h).count()
                recent_alerts = Alert.query.filter(Alert.timestamp >= last_24h).count()
                
                # Threat distribution
                threat_distribution = {}
                for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                    count = NetworkEvent.query.filter(NetworkEvent.threat_level == level).count()
                    threat_distribution[level.lower()] = count
                
                return {
                    'table_counts': {
                        'events': event_count,
                        'alerts': alert_count,
                        'statistics': stats_count
                    },
                    'database_size_mb': round(db_size, 2),
                    'recent_activity': {
                        'events_24h': recent_events,
                        'alerts_24h': recent_alerts
                    },
                    'threat_distribution': threat_distribution
                }
                
        except Exception as e:
            logger.error(f"Database statistics error: {e}")
            return {}
    
    def export_data(self, table_name: str, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Export data from specified table within date range"""
        try:
            with self.app.app_context():
                from app import NetworkEvent, Alert, SystemStats
                
                model_map = {
                    'events': NetworkEvent,
                    'alerts': Alert,
                    'statistics': SystemStats
                }
                
                if table_name not in model_map:
                    raise ValueError(f"Unknown table: {table_name}")
                
                model = model_map[table_name]
                records = model.query.filter(
                    model.timestamp >= start_date,
                    model.timestamp <= end_date
                ).all()
                
                return [record.to_dict() for record in records]
                
        except Exception as e:
            logger.error(f"Data export error: {e}")
            return []

# Global database manager instance
database_manager = None

def initialize_database_manager(db, app):
    """Initialize the global database manager"""
    global database_manager
    database_manager = DatabaseManager(db, app)
    database_manager.create_indexes()
    database_manager.start_maintenance()
    return database_manager

def get_database_manager():
    """Get the global database manager instance"""
    return database_manager
