#!/usr/bin/env python3
"""
Comprehensive Logging System for SecureWatch IDS
Advanced logging, audit trails, and compliance features
"""

import logging
import logging.handlers
import json
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogCategory(Enum):
    """Log category enumeration"""
    SYSTEM = "SYSTEM"
    SECURITY = "SECURITY"
    NETWORK = "NETWORK"
    ALERT = "ALERT"
    USER = "USER"
    DATABASE = "DATABASE"
    AUDIT = "AUDIT"

class IDSLogger:
    """Comprehensive IDS logging system"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        self.ensure_log_directory()
        self.loggers = {}
        self.audit_logs = []
        self.log_buffer = []
        self.buffer_lock = threading.Lock()
        self.setup_loggers()
        self.start_log_processor()
    
    def ensure_log_directory(self):
        """Ensure log directory exists"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def setup_loggers(self):
        """Setup specialized loggers for different categories"""
        
        # System logger
        self.loggers['system'] = self._create_logger(
            'system',
            os.path.join(self.log_dir, 'system.log'),
            logging.INFO
        )
        
        # Security logger
        self.loggers['security'] = self._create_logger(
            'security',
            os.path.join(self.log_dir, 'security.log'),
            logging.INFO
        )
        
        # Network logger
        self.loggers['network'] = self._create_logger(
            'network',
            os.path.join(self.log_dir, 'network.log'),
            logging.INFO
        )
        
        # Alert logger
        self.loggers['alert'] = self._create_logger(
            'alert',
            os.path.join(self.log_dir, 'alerts.log'),
            logging.INFO
        )
        
        # Audit logger
        self.loggers['audit'] = self._create_logger(
            'audit',
            os.path.join(self.log_dir, 'audit.log'),
            logging.INFO
        )
        
        # Error logger
        self.loggers['error'] = self._create_logger(
            'error',
            os.path.join(self.log_dir, 'errors.log'),
            logging.ERROR
        )
    
    def _create_logger(self, name: str, filename: str, level: int) -> logging.Logger:
        """Create a specialized logger with rotation"""
        logger = logging.getLogger(f'ids_{name}')
        logger.setLevel(level)
        
        # Remove existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Create rotating file handler (10MB max, keep 5 files)
        handler = logging.handlers.RotatingFileHandler(
            filename,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        logger.propagate = False
        
        return logger
    
    def start_log_processor(self):
        """Start the log processing thread"""
        self.processing = True
        self.processor_thread = threading.Thread(target=self._process_logs, daemon=True)
        self.processor_thread.start()
    
    def stop_log_processor(self):
        """Stop the log processing thread"""
        self.processing = False
    
    def _process_logs(self):
        """Process buffered logs"""
        while self.processing:
            try:
                with self.buffer_lock:
                    if self.log_buffer:
                        logs_to_process = self.log_buffer.copy()
                        self.log_buffer.clear()
                    else:
                        logs_to_process = []
                
                for log_entry in logs_to_process:
                    self._write_log(log_entry)
                
                time.sleep(1)  # Process every second
                
            except Exception as e:
                print(f"Log processing error: {e}")
                time.sleep(5)
    
    def _write_log(self, log_entry: Dict[str, Any]):
        """Write log entry to appropriate logger"""
        try:
            category = log_entry.get('category', 'system').lower()
            level = log_entry.get('level', 'INFO')
            message = log_entry.get('message', '')
            
            # Get appropriate logger
            logger = self.loggers.get(category, self.loggers['system'])
            
            # Format message with additional context
            formatted_message = self._format_log_message(log_entry)
            
            # Write to appropriate level
            if level == 'DEBUG':
                logger.debug(formatted_message)
            elif level == 'INFO':
                logger.info(formatted_message)
            elif level == 'WARNING':
                logger.warning(formatted_message)
            elif level == 'ERROR':
                logger.error(formatted_message)
            elif level == 'CRITICAL':
                logger.critical(formatted_message)
            
        except Exception as e:
            print(f"Log writing error: {e}")
    
    def _format_log_message(self, log_entry: Dict[str, Any]) -> str:
        """Format log message with context"""
        message = log_entry.get('message', '')
        context = log_entry.get('context', {})
        
        if context:
            context_str = json.dumps(context, separators=(',', ':'))
            return f"{message} | Context: {context_str}"
        
        return message
    
    def log(self, category: LogCategory, level: LogLevel, message: str, context: Dict[str, Any] = None):
        """Log a message with specified category and level"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'category': category.value,
            'level': level.value,
            'message': message,
            'context': context or {}
        }
        
        with self.buffer_lock:
            self.log_buffer.append(log_entry)
    
    def log_system_event(self, message: str, context: Dict[str, Any] = None):
        """Log system event"""
        self.log(LogCategory.SYSTEM, LogLevel.INFO, message, context)
    
    def log_security_event(self, message: str, context: Dict[str, Any] = None):
        """Log security event"""
        self.log(LogCategory.SECURITY, LogLevel.WARNING, message, context)
    
    def log_network_event(self, message: str, context: Dict[str, Any] = None):
        """Log network event"""
        self.log(LogCategory.NETWORK, LogLevel.INFO, message, context)
    
    def log_alert(self, message: str, context: Dict[str, Any] = None):
        """Log alert event"""
        self.log(LogCategory.ALERT, LogLevel.WARNING, message, context)
    
    def log_audit(self, action: str, user: str, resource: str, result: str, context: Dict[str, Any] = None):
        """Log audit event"""
        audit_context = {
            'action': action,
            'user': user,
            'resource': resource,
            'result': result,
            'ip_address': context.get('ip_address', 'unknown') if context else 'unknown'
        }
        
        if context:
            audit_context.update(context)
        
        message = f"AUDIT: {user} {action} {resource} - {result}"
        self.log(LogCategory.AUDIT, LogLevel.INFO, message, audit_context)
        
        # Store in audit log buffer for compliance
        self.audit_logs.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'user': user,
            'resource': resource,
            'result': result,
            'context': audit_context
        })
    
    def log_error(self, message: str, exception: Exception = None, context: Dict[str, Any] = None):
        """Log error with optional exception details"""
        error_context = context or {}
        
        if exception:
            error_context.update({
                'exception_type': type(exception).__name__,
                'exception_message': str(exception)
            })
        
        self.log(LogCategory.SYSTEM, LogLevel.ERROR, message, error_context)
    
    def get_recent_logs(self, category: str = None, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent logs from specified category"""
        try:
            logs = []
            log_files = []
            
            if category:
                log_file = os.path.join(self.log_dir, f'{category}.log')
                if os.path.exists(log_file):
                    log_files.append(log_file)
            else:
                # Get all log files
                for filename in os.listdir(self.log_dir):
                    if filename.endswith('.log'):
                        log_files.append(os.path.join(self.log_dir, filename))
            
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            for log_file in log_files:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            # Parse log line
                            parts = line.strip().split(' - ', 3)
                            if len(parts) >= 4:
                                timestamp_str = parts[0]
                                log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                                
                                if log_time >= cutoff_time:
                                    logs.append({
                                        'timestamp': timestamp_str,
                                        'logger': parts[1],
                                        'level': parts[2],
                                        'message': parts[3]
                                    })
                        except Exception:
                            continue
            
            # Sort by timestamp (newest first)
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
            return logs[:1000]  # Limit to 1000 entries
            
        except Exception as e:
            print(f"Error retrieving logs: {e}")
            return []
    
    def get_audit_trail(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get audit trail for compliance"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        recent_audits = []
        for audit in self.audit_logs:
            audit_time = datetime.fromisoformat(audit['timestamp'])
            if audit_time >= cutoff_time:
                recent_audits.append(audit)
        
        return sorted(recent_audits, key=lambda x: x['timestamp'], reverse=True)
    
    def export_logs(self, category: str, start_date: datetime, end_date: datetime) -> str:
        """Export logs to JSON format"""
        try:
            log_file = os.path.join(self.log_dir, f'{category}.log')
            if not os.path.exists(log_file):
                return json.dumps([])
            
            exported_logs = []
            
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        parts = line.strip().split(' - ', 3)
                        if len(parts) >= 4:
                            timestamp_str = parts[0]
                            log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            
                            if start_date <= log_time <= end_date:
                                exported_logs.append({
                                    'timestamp': timestamp_str,
                                    'logger': parts[1],
                                    'level': parts[2],
                                    'message': parts[3]
                                })
                    except Exception:
                        continue
            
            return json.dumps(exported_logs, indent=2)
            
        except Exception as e:
            return json.dumps({'error': str(e)})
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics"""
        try:
            stats = {
                'log_files': {},
                'total_size_mb': 0,
                'recent_activity': {}
            }
            
            # Get file statistics
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log'):
                    file_path = os.path.join(self.log_dir, filename)
                    file_size = os.path.getsize(file_path) / 1024 / 1024  # MB
                    stats['log_files'][filename] = {
                        'size_mb': round(file_size, 2),
                        'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    }
                    stats['total_size_mb'] += file_size
            
            stats['total_size_mb'] = round(stats['total_size_mb'], 2)
            
            # Get recent activity counts
            for category in ['system', 'security', 'network', 'alert', 'audit']:
                recent_logs = self.get_recent_logs(category, 24)
                stats['recent_activity'][category] = len(recent_logs)
            
            return stats
            
        except Exception as e:
            return {'error': str(e)}

# Global logging system instance
ids_logger = None

def initialize_logging_system():
    """Initialize the global logging system"""
    global ids_logger
    ids_logger = IDSLogger()
    return ids_logger

def get_ids_logger():
    """Get the global IDS logger instance"""
    return ids_logger
