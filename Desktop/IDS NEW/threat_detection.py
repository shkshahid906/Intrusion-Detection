#!/usr/bin/env python3
"""
Advanced Threat Detection Engine for SecureWatch IDS
Real-time behavioral analysis and machine learning-inspired detection
"""

import threading
import time
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque
from dataclasses import dataclass
import statistics
import re

logger = logging.getLogger(__name__)

@dataclass
class ThreatPattern:
    """Represents a threat pattern for detection"""
    name: str
    pattern_type: str
    indicators: List[str]
    severity: str
    confidence_threshold: float
    description: str

@dataclass
class BehavioralProfile:
    """Behavioral profile for an IP address"""
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    total_connections: int
    unique_ports: Set[int]
    protocols_used: Set[str]
    connection_patterns: List[Tuple[datetime, str, int]]
    failed_attempts: int
    data_volume: int
    time_patterns: List[int]  # Hours of activity
    reputation_score: float

class AdvancedThreatDetector:
    """Advanced threat detection engine with behavioral analysis"""
    
    def __init__(self):
        self.behavioral_profiles = {}  # IP -> BehavioralProfile
        self.threat_patterns = self._load_threat_patterns()
        self.event_correlation_window = deque(maxlen=1000)
        self.baseline_metrics = {}
        self.anomaly_thresholds = {}
        self.threat_intelligence = {}
        
        # Advanced detection parameters
        self.learning_period = timedelta(hours=24)
        self.anomaly_sensitivity = 0.8
        self.correlation_window_size = 100
        
        # Attack scenario tracking
        self.active_scenarios = {}
        self.scenario_timeouts = {}
        
        logger.info("Advanced threat detection engine initialized")
    
    def _load_threat_patterns(self) -> List[ThreatPattern]:
        """Load predefined threat patterns"""
        patterns = [
            ThreatPattern(
                name="Advanced Persistent Threat",
                pattern_type="behavioral",
                indicators=["low_volume_persistent", "multiple_protocols", "off_hours_activity"],
                severity="CRITICAL",
                confidence_threshold=0.85,
                description="Long-term stealthy access with varied protocols"
            ),
            ThreatPattern(
                name="Lateral Movement",
                pattern_type="network",
                indicators=["internal_scanning", "credential_reuse", "privilege_escalation"],
                severity="HIGH",
                confidence_threshold=0.75,
                description="Movement across internal network segments"
            ),
            ThreatPattern(
                name="Data Exfiltration",
                pattern_type="traffic",
                indicators=["large_outbound_transfers", "encrypted_channels", "unusual_destinations"],
                severity="CRITICAL",
                confidence_threshold=0.80,
                description="Unauthorized data transfer to external locations"
            ),
            ThreatPattern(
                name="Command and Control",
                pattern_type="communication",
                indicators=["periodic_beacons", "dns_tunneling", "encrypted_c2"],
                severity="HIGH",
                confidence_threshold=0.70,
                description="Communication with external command servers"
            ),
            ThreatPattern(
                name="Insider Threat",
                pattern_type="behavioral",
                indicators=["after_hours_access", "unusual_data_access", "policy_violations"],
                severity="HIGH",
                confidence_threshold=0.75,
                description="Malicious activity from authorized users"
            )
        ]
        return patterns
    
    def analyze_event(self, event_data: Dict) -> Dict:
        """Analyze network event for advanced threats"""
        try:
            source_ip = event_data.get('source_ip')
            if not source_ip:
                return {'threat_detected': False}
            
            # Update behavioral profile
            self._update_behavioral_profile(event_data)
            
            # Add to correlation window
            self.event_correlation_window.append({
                'timestamp': datetime.utcnow(),
                'event': event_data
            })
            
            # Perform various threat analyses
            threat_results = {
                'behavioral_anomaly': self._detect_behavioral_anomaly(source_ip, event_data),
                'pattern_matching': self._match_threat_patterns(source_ip, event_data),
                'event_correlation': self._correlate_events(event_data),
                'reputation_analysis': self._analyze_reputation(source_ip),
                'scenario_detection': self._detect_attack_scenarios(event_data)
            }
            
            # Calculate overall threat score
            overall_threat = self._calculate_threat_score(threat_results)
            
            return {
                'threat_detected': overall_threat['score'] > 0.5,
                'threat_score': overall_threat['score'],
                'threat_level': overall_threat['level'],
                'threat_factors': overall_threat['factors'],
                'recommended_actions': overall_threat['actions'],
                'analysis_details': threat_results
            }
            
        except Exception as e:
            logger.error(f"Error in advanced threat analysis: {e}")
            return {'threat_detected': False, 'error': str(e)}
    
    def _update_behavioral_profile(self, event_data: Dict):
        """Update behavioral profile for source IP"""
        source_ip = event_data.get('source_ip')
        if not source_ip:
            return
        
        current_time = datetime.utcnow()
        
        if source_ip not in self.behavioral_profiles:
            self.behavioral_profiles[source_ip] = BehavioralProfile(
                ip_address=source_ip,
                first_seen=current_time,
                last_seen=current_time,
                total_connections=0,
                unique_ports=set(),
                protocols_used=set(),
                connection_patterns=[],
                failed_attempts=0,
                data_volume=0,
                time_patterns=[],
                reputation_score=0.5
            )
        
        profile = self.behavioral_profiles[source_ip]
        profile.last_seen = current_time
        profile.total_connections += 1
        
        # Update connection details
        if event_data.get('destination_port'):
            profile.unique_ports.add(event_data['destination_port'])
        
        if event_data.get('protocol'):
            profile.protocols_used.add(event_data['protocol'])
        
        # Track connection patterns
        profile.connection_patterns.append((
            current_time,
            event_data.get('protocol', 'Unknown'),
            event_data.get('destination_port', 0)
        ))
        
        # Keep only recent patterns (last 24 hours)
        cutoff_time = current_time - timedelta(hours=24)
        profile.connection_patterns = [
            pattern for pattern in profile.connection_patterns
            if pattern[0] > cutoff_time
        ]
        
        # Track time patterns
        profile.time_patterns.append(current_time.hour)
        if len(profile.time_patterns) > 100:
            profile.time_patterns = profile.time_patterns[-100:]
        
        # Update data volume
        profile.data_volume += event_data.get('packet_size', 0)
        
        # Track failed attempts
        if event_data.get('flags') and 'R' in event_data.get('flags', ''):
            profile.failed_attempts += 1
    
    def _detect_behavioral_anomaly(self, source_ip: str, event_data: Dict) -> Dict:
        """Detect behavioral anomalies using statistical analysis"""
        if source_ip not in self.behavioral_profiles:
            return {'anomaly_detected': False, 'score': 0.0}
        
        profile = self.behavioral_profiles[source_ip]
        anomaly_factors = []
        anomaly_score = 0.0
        
        try:
            # Check connection frequency anomaly
            if len(profile.connection_patterns) > 10:
                recent_connections = len([
                    p for p in profile.connection_patterns
                    if p[0] > datetime.utcnow() - timedelta(minutes=10)
                ])
                
                if recent_connections > 50:  # High frequency
                    anomaly_factors.append("High connection frequency")
                    anomaly_score += 0.3
            
            # Check port diversity anomaly
            if len(profile.unique_ports) > 20:
                anomaly_factors.append("Excessive port scanning")
                anomaly_score += 0.4
            
            # Check time pattern anomaly (off-hours activity)
            current_hour = datetime.utcnow().hour
            if current_hour < 6 or current_hour > 22:  # Off hours
                if profile.total_connections > 10:
                    anomaly_factors.append("Off-hours activity")
                    anomaly_score += 0.2
            
            # Check protocol diversity anomaly
            if len(profile.protocols_used) > 5:
                anomaly_factors.append("Multiple protocol usage")
                anomaly_score += 0.2
            
            # Check failed connection ratio
            if profile.total_connections > 0:
                failure_ratio = profile.failed_attempts / profile.total_connections
                if failure_ratio > 0.3:
                    anomaly_factors.append("High failure rate")
                    anomaly_score += 0.3
            
            # Check data volume anomaly
            if profile.data_volume > 10000000:  # 10MB
                anomaly_factors.append("Large data volume")
                anomaly_score += 0.2
            
            return {
                'anomaly_detected': anomaly_score > 0.5,
                'score': min(anomaly_score, 1.0),
                'factors': anomaly_factors,
                'profile_age': (datetime.utcnow() - profile.first_seen).total_seconds() / 3600
            }
            
        except Exception as e:
            logger.error(f"Error in behavioral anomaly detection: {e}")
            return {'anomaly_detected': False, 'score': 0.0}
    
    def _match_threat_patterns(self, source_ip: str, event_data: Dict) -> Dict:
        """Match against known threat patterns"""
        matched_patterns = []
        max_confidence = 0.0
        
        try:
            profile = self.behavioral_profiles.get(source_ip)
            if not profile:
                return {'patterns_matched': [], 'confidence': 0.0}
            
            for pattern in self.threat_patterns:
                confidence = self._calculate_pattern_confidence(pattern, profile, event_data)
                
                if confidence > pattern.confidence_threshold:
                    matched_patterns.append({
                        'name': pattern.name,
                        'type': pattern.pattern_type,
                        'severity': pattern.severity,
                        'confidence': confidence,
                        'description': pattern.description
                    })
                    max_confidence = max(max_confidence, confidence)
            
            return {
                'patterns_matched': matched_patterns,
                'confidence': max_confidence,
                'pattern_count': len(matched_patterns)
            }
            
        except Exception as e:
            logger.error(f"Error in pattern matching: {e}")
            return {'patterns_matched': [], 'confidence': 0.0}
    
    def _calculate_pattern_confidence(self, pattern: ThreatPattern, profile: BehavioralProfile, event_data: Dict) -> float:
        """Calculate confidence score for a threat pattern"""
        confidence = 0.0
        
        try:
            if pattern.name == "Advanced Persistent Threat":
                # Long-term presence with low volume
                age_hours = (datetime.utcnow() - profile.first_seen).total_seconds() / 3600
                if age_hours > 24:  # Present for more than 24 hours
                    confidence += 0.3
                
                # Low volume but persistent
                if profile.total_connections > 10 and profile.total_connections < 100:
                    confidence += 0.2
                
                # Multiple protocols
                if len(profile.protocols_used) >= 3:
                    confidence += 0.2
                
                # Off-hours activity
                off_hours_activity = sum(1 for hour in profile.time_patterns if hour < 6 or hour > 22)
                if off_hours_activity > len(profile.time_patterns) * 0.3:
                    confidence += 0.3
            
            elif pattern.name == "Lateral Movement":
                # Internal IP scanning
                if len(profile.unique_ports) > 10:
                    confidence += 0.4
                
                # Multiple internal destinations (simulated)
                if profile.total_connections > 20:
                    confidence += 0.3
                
                # Failed authentication attempts
                if profile.failed_attempts > 5:
                    confidence += 0.3
            
            elif pattern.name == "Data Exfiltration":
                # Large data volume
                if profile.data_volume > 50000000:  # 50MB
                    confidence += 0.5
                
                # Encrypted protocols
                if 'HTTPS' in profile.protocols_used or 'TLS' in profile.protocols_used:
                    confidence += 0.2
                
                # Unusual destinations (high port numbers)
                high_ports = [port for port in profile.unique_ports if port > 8000]
                if len(high_ports) > 3:
                    confidence += 0.3
            
            elif pattern.name == "Command and Control":
                # Periodic connections (simplified detection)
                if len(profile.connection_patterns) > 20:
                    time_intervals = []
                    for i in range(1, len(profile.connection_patterns)):
                        interval = (profile.connection_patterns[i][0] - profile.connection_patterns[i-1][0]).total_seconds()
                        time_intervals.append(interval)
                    
                    if time_intervals:
                        avg_interval = statistics.mean(time_intervals)
                        if 300 < avg_interval < 3600:  # 5 minutes to 1 hour intervals
                            confidence += 0.4
                
                # DNS usage
                if 'DNS' in profile.protocols_used:
                    confidence += 0.2
                
                # Encrypted communication
                if 'HTTPS' in profile.protocols_used:
                    confidence += 0.2
            
            elif pattern.name == "Insider Threat":
                # After hours access
                off_hours = sum(1 for hour in profile.time_patterns if hour < 6 or hour > 22)
                if off_hours > len(profile.time_patterns) * 0.4:
                    confidence += 0.4
                
                # Unusual data access patterns
                if profile.data_volume > 20000000:  # 20MB
                    confidence += 0.3
                
                # Multiple protocol usage
                if len(profile.protocols_used) > 4:
                    confidence += 0.3
            
        except Exception as e:
            logger.error(f"Error calculating pattern confidence: {e}")
        
        return min(confidence, 1.0)
    
    def _correlate_events(self, event_data: Dict) -> Dict:
        """Correlate events to detect complex attack scenarios"""
        try:
            if len(self.event_correlation_window) < 10:
                return {'correlation_detected': False, 'score': 0.0}
            
            source_ip = event_data.get('source_ip')
            recent_events = [
                event for event in self.event_correlation_window
                if event['event'].get('source_ip') == source_ip and
                event['timestamp'] > datetime.utcnow() - timedelta(minutes=30)
            ]
            
            correlation_factors = []
            correlation_score = 0.0
            
            # Check for reconnaissance followed by exploitation
            event_types = [event['event'].get('event_type', 'NORMAL') for event in recent_events]
            
            if 'PORT_SCAN' in event_types and 'BRUTE_FORCE' in event_types:
                correlation_factors.append("Reconnaissance followed by brute force")
                correlation_score += 0.6
            
            if 'SUSPICIOUS' in event_types and len(set(event_types)) > 3:
                correlation_factors.append("Multiple attack vectors")
                correlation_score += 0.4
            
            # Check for escalating threat levels
            threat_levels = [event['event'].get('threat_level', 'LOW') for event in recent_events]
            if 'LOW' in threat_levels and 'HIGH' in threat_levels:
                correlation_factors.append("Escalating threat pattern")
                correlation_score += 0.3
            
            return {
                'correlation_detected': correlation_score > 0.5,
                'score': min(correlation_score, 1.0),
                'factors': correlation_factors,
                'related_events': len(recent_events)
            }
            
        except Exception as e:
            logger.error(f"Error in event correlation: {e}")
            return {'correlation_detected': False, 'score': 0.0}
    
    def _analyze_reputation(self, source_ip: str) -> Dict:
        """Analyze IP reputation using various indicators"""
        try:
            reputation_score = 0.5  # Neutral starting point
            reputation_factors = []
            
            # Check against known bad IP patterns
            if self._is_suspicious_ip_pattern(source_ip):
                reputation_score -= 0.3
                reputation_factors.append("Suspicious IP pattern")
            
            # Check behavioral history
            if source_ip in self.behavioral_profiles:
                profile = self.behavioral_profiles[source_ip]
                
                # High failure rate indicates malicious activity
                if profile.total_connections > 0:
                    failure_ratio = profile.failed_attempts / profile.total_connections
                    if failure_ratio > 0.5:
                        reputation_score -= 0.4
                        reputation_factors.append("High failure rate")
                
                # Excessive port scanning
                if len(profile.unique_ports) > 50:
                    reputation_score -= 0.3
                    reputation_factors.append("Excessive port scanning")
                
                # Update profile reputation
                profile.reputation_score = reputation_score
            
            # Simulate threat intelligence lookup
            if source_ip in self.threat_intelligence:
                intel = self.threat_intelligence[source_ip]
                reputation_score = min(reputation_score, intel.get('reputation', 0.5))
                reputation_factors.extend(intel.get('factors', []))
            
            return {
                'reputation_score': max(0.0, min(1.0, reputation_score)),
                'reputation_level': self._get_reputation_level(reputation_score),
                'factors': reputation_factors
            }
            
        except Exception as e:
            logger.error(f"Error in reputation analysis: {e}")
            return {'reputation_score': 0.5, 'reputation_level': 'UNKNOWN', 'factors': []}
    
    def _is_suspicious_ip_pattern(self, ip: str) -> bool:
        """Check if IP matches suspicious patterns"""
        try:
            # Check for common malicious IP patterns
            suspicious_patterns = [
                r'^192\.168\.1\.1$',  # Default router (if external)
                r'^10\.0\.0\.1$',     # Default router (if external)
                r'^172\.16\.0\.1$',   # Default router (if external)
            ]
            
            for pattern in suspicious_patterns:
                if re.match(pattern, ip):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _get_reputation_level(self, score: float) -> str:
        """Convert reputation score to level"""
        if score >= 0.8:
            return 'TRUSTED'
        elif score >= 0.6:
            return 'GOOD'
        elif score >= 0.4:
            return 'NEUTRAL'
        elif score >= 0.2:
            return 'SUSPICIOUS'
        else:
            return 'MALICIOUS'
    
    def _detect_attack_scenarios(self, event_data: Dict) -> Dict:
        """Detect complex multi-stage attack scenarios"""
        try:
            source_ip = event_data.get('source_ip')
            scenario_key = f"{source_ip}_scenario"
            
            if scenario_key not in self.active_scenarios:
                self.active_scenarios[scenario_key] = {
                    'stages': [],
                    'start_time': datetime.utcnow(),
                    'confidence': 0.0
                }
            
            scenario = self.active_scenarios[scenario_key]
            event_type = event_data.get('event_type', 'NORMAL')
            
            # Add current event to scenario
            scenario['stages'].append({
                'timestamp': datetime.utcnow(),
                'event_type': event_type,
                'threat_level': event_data.get('threat_level', 'LOW')
            })
            
            # Keep only recent stages (last 2 hours)
            cutoff_time = datetime.utcnow() - timedelta(hours=2)
            scenario['stages'] = [
                stage for stage in scenario['stages']
                if stage['timestamp'] > cutoff_time
            ]
            
            # Analyze scenario progression
            scenario_analysis = self._analyze_scenario_progression(scenario['stages'])
            scenario['confidence'] = scenario_analysis['confidence']
            
            # Clean up old scenarios
            self._cleanup_old_scenarios()
            
            return {
                'scenario_detected': scenario_analysis['confidence'] > 0.7,
                'scenario_type': scenario_analysis['type'],
                'confidence': scenario_analysis['confidence'],
                'stages_detected': len(scenario['stages']),
                'progression': scenario_analysis['progression']
            }
            
        except Exception as e:
            logger.error(f"Error in scenario detection: {e}")
            return {'scenario_detected': False, 'confidence': 0.0}
    
    def _analyze_scenario_progression(self, stages: List[Dict]) -> Dict:
        """Analyze the progression of attack stages"""
        if len(stages) < 3:
            return {'confidence': 0.0, 'type': 'UNKNOWN', 'progression': []}
        
        stage_types = [stage['event_type'] for stage in stages]
        progression = []
        confidence = 0.0
        scenario_type = 'UNKNOWN'
        
        # Check for kill chain progression
        if 'PORT_SCAN' in stage_types:
            progression.append('Reconnaissance')
            confidence += 0.2
            
            if 'BRUTE_FORCE' in stage_types:
                progression.append('Initial Access')
                confidence += 0.3
                scenario_type = 'TARGETED_ATTACK'
                
                if 'SUSPICIOUS' in stage_types:
                    progression.append('Execution')
                    confidence += 0.2
                    
                    if 'MALWARE' in stage_types:
                        progression.append('Persistence')
                        confidence += 0.3
                        scenario_type = 'ADVANCED_PERSISTENT_THREAT'
        
        # Check for data exfiltration scenario
        high_volume_events = [stage for stage in stages if stage.get('data_volume', 0) > 1000000]
        if len(high_volume_events) > 2:
            progression.append('Data Collection')
            confidence += 0.4
            scenario_type = 'DATA_EXFILTRATION'
        
        return {
            'confidence': min(confidence, 1.0),
            'type': scenario_type,
            'progression': progression
        }
    
    def _cleanup_old_scenarios(self):
        """Clean up old attack scenarios"""
        cutoff_time = datetime.utcnow() - timedelta(hours=4)
        scenarios_to_remove = []
        
        for scenario_key, scenario in self.active_scenarios.items():
            if scenario['start_time'] < cutoff_time:
                scenarios_to_remove.append(scenario_key)
        
        for key in scenarios_to_remove:
            del self.active_scenarios[key]
    
    def _calculate_threat_score(self, threat_results: Dict) -> Dict:
        """Calculate overall threat score and recommendations"""
        try:
            # Weight different analysis components
            weights = {
                'behavioral_anomaly': 0.25,
                'pattern_matching': 0.30,
                'event_correlation': 0.20,
                'reputation_analysis': 0.15,
                'scenario_detection': 0.10
            }
            
            total_score = 0.0
            threat_factors = []
            
            # Behavioral anomaly contribution
            if threat_results['behavioral_anomaly'].get('anomaly_detected'):
                score = threat_results['behavioral_anomaly']['score'] * weights['behavioral_anomaly']
                total_score += score
                threat_factors.extend(threat_results['behavioral_anomaly'].get('factors', []))
            
            # Pattern matching contribution
            if threat_results['pattern_matching']['patterns_matched']:
                score = threat_results['pattern_matching']['confidence'] * weights['pattern_matching']
                total_score += score
                for pattern in threat_results['pattern_matching']['patterns_matched']:
                    threat_factors.append(f"Pattern: {pattern['name']}")
            
            # Event correlation contribution
            if threat_results['event_correlation'].get('correlation_detected'):
                score = threat_results['event_correlation']['score'] * weights['event_correlation']
                total_score += score
                threat_factors.extend(threat_results['event_correlation'].get('factors', []))
            
            # Reputation analysis contribution
            reputation_score = threat_results['reputation_analysis']['reputation_score']
            if reputation_score < 0.5:  # Poor reputation increases threat score
                score = (0.5 - reputation_score) * 2 * weights['reputation_analysis']
                total_score += score
                threat_factors.extend(threat_results['reputation_analysis'].get('factors', []))
            
            # Scenario detection contribution
            if threat_results['scenario_detection'].get('scenario_detected'):
                score = threat_results['scenario_detection']['confidence'] * weights['scenario_detection']
                total_score += score
                threat_factors.append(f"Attack scenario: {threat_results['scenario_detection'].get('scenario_type', 'Unknown')}")
            
            # Determine threat level
            if total_score >= 0.8:
                threat_level = 'CRITICAL'
            elif total_score >= 0.6:
                threat_level = 'HIGH'
            elif total_score >= 0.4:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
            
            # Generate recommended actions
            actions = self._generate_recommended_actions(total_score, threat_factors)
            
            return {
                'score': min(total_score, 1.0),
                'level': threat_level,
                'factors': threat_factors,
                'actions': actions
            }
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return {'score': 0.0, 'level': 'LOW', 'factors': [], 'actions': []}
    
    def _generate_recommended_actions(self, threat_score: float, threat_factors: List[str]) -> List[str]:
        """Generate recommended actions based on threat analysis"""
        actions = []
        
        if threat_score >= 0.8:
            actions.extend([
                "IMMEDIATE: Block source IP address",
                "IMMEDIATE: Alert security team",
                "Investigate all related network activity",
                "Review system logs for compromise indicators",
                "Consider network isolation"
            ])
        elif threat_score >= 0.6:
            actions.extend([
                "Block source IP address",
                "Monitor closely for escalation",
                "Review recent network activity",
                "Update threat intelligence"
            ])
        elif threat_score >= 0.4:
            actions.extend([
                "Increase monitoring for source IP",
                "Log detailed activity",
                "Review security policies"
            ])
        else:
            actions.append("Continue monitoring")
        
        # Add specific actions based on threat factors
        if any("port scan" in factor.lower() for factor in threat_factors):
            actions.append("Implement port scan detection rules")
        
        if any("brute force" in factor.lower() for factor in threat_factors):
            actions.append("Enable account lockout policies")
        
        if any("data" in factor.lower() for factor in threat_factors):
            actions.append("Review data loss prevention policies")
        
        return actions
    
    def get_threat_summary(self) -> Dict:
        """Get summary of current threat landscape"""
        try:
            total_profiles = len(self.behavioral_profiles)
            suspicious_ips = len([
                ip for ip, profile in self.behavioral_profiles.items()
                if profile.reputation_score < 0.4
            ])
            
            active_scenarios = len(self.active_scenarios)
            
            # Calculate average threat levels
            threat_distribution = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
            for profile in self.behavioral_profiles.values():
                if profile.reputation_score >= 0.6:
                    threat_distribution['LOW'] += 1
                elif profile.reputation_score >= 0.4:
                    threat_distribution['MEDIUM'] += 1
                elif profile.reputation_score >= 0.2:
                    threat_distribution['HIGH'] += 1
                else:
                    threat_distribution['CRITICAL'] += 1
            
            return {
                'total_monitored_ips': total_profiles,
                'suspicious_ips': suspicious_ips,
                'active_attack_scenarios': active_scenarios,
                'threat_distribution': threat_distribution,
                'patterns_loaded': len(self.threat_patterns),
                'correlation_window_size': len(self.event_correlation_window)
            }
            
        except Exception as e:
            logger.error(f"Error generating threat summary: {e}")
            return {}

# Global threat detector instance
threat_detector = AdvancedThreatDetector()

def analyze_advanced_threats(event_data: Dict) -> Dict:
    """Main function to analyze events for advanced threats"""
    return threat_detector.analyze_event(event_data)

def get_threat_intelligence_summary() -> Dict:
    """Get threat intelligence summary"""
    return threat_detector.get_threat_summary()

def update_threat_intelligence(ip: str, intelligence_data: Dict):
    """Update threat intelligence for an IP"""
    threat_detector.threat_intelligence[ip] = intelligence_data
    logger.info(f"Updated threat intelligence for {ip}")
