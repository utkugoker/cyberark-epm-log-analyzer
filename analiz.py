#!/usr/bin/env python3
"""
CyberArk EPM Log Analyzer - Part 1: Core Parser ve Flask App
Multi-platform CyberArk Endpoint Privilege Manager log analysis tool
"""

from flask import Flask, request, jsonify, Response
import re
import json
import os
import io
import csv
from datetime import datetime
from collections import defaultdict, Counter

# Flask app configuration
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

class CyberArkLogParser:
    """Multi-platform CyberArk EPM log parser"""
    
    def __init__(self):
        self.log_entries = []
        self.parsed_data = {
            'process_starts': [],
            'zero_touch_events': [],
            'errors': [],
            'agent_events': [],
            'system_events': [],
            'statistics': {}
        }
    
    def detect_log_format(self, file_content):
        """Log formatını tespit et (Windows vs Mac vs Mixed)"""
        lines = file_content.split('\n')[:50]  # İlk 50 satırı kontrol et
        
        mac_indicators = 0
        windows_indicators = 0
        
        for line in lines:
            # Mac indicators
            if any(indicator in line for indicator in [
                'com.cyberark.CyberArkEPM', '+0300', '/usr/', '/System/', 
                '/Library/', '/Applications/', 'signing id:', 'team id:',
                'EndpointSecurityExtension', 'NetworkExtension', 'try to exec'
            ]):
                mac_indicators += 1
            
            # Windows indicators  
            if any(indicator in line for indicator in [
                'PID:', 'TID:', 'CvfProcessStartRights', '.exe', 'C:\\',
                'PROCSTART', 'ZeroTouchEvent', 'PASP version', 'Agent'
            ]):
                windows_indicators += 1
        
        if mac_indicators > windows_indicators * 2:
            return 'mac'
        elif windows_indicators > mac_indicators * 2:
            return 'windows'
        else:
            return 'mixed'
    
    def parse_log_file(self, file_content):
        """Ana log parsing fonksiyonu"""
        print(f"Parsing file with {len(file_content)} characters")
        
        # Log formatını tespit et
        log_format = self.detect_log_format(file_content)
        print(f"Detected log format: {log_format}")
        
        lines = file_content.split('\n')
        print(f"Found {len(lines)} lines")
        
        for line_num, line in enumerate(lines):
            if not line.strip():
                continue
                
            entry = None
            
            if log_format == 'mac' or log_format == 'mixed':
                # Mac formatını dene
                entry = self._parse_mac_log_line(line)
            
            if not entry and (log_format == 'windows' or log_format == 'mixed'):
                # Windows formatını dene
                entry = self._parse_windows_log_line(line)
            
            if entry:
                self.log_entries.append(entry)
                self._categorize_entry(entry)
                
            if line_num % 1000 == 0:
                print(f"Processed {line_num} lines...")
        
        print(f"Total parsed entries: {len(self.log_entries)}")
        self._calculate_statistics()
        return self.parsed_data
    
    def _parse_windows_log_line(self, line):
        """Windows log satırını parse et"""
        if line.startswith('D_Lib:'):
            return None
            
        # Windows log format: YYYY.MM.DD HH:MM:SS PID:xxx TID:xxx Message
        pattern = r'(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}) PID:(\d+) TID:(\d+) (.+)'
        match = re.match(pattern, line)
        
        if not match:
            return None
            
        timestamp_str, pid, tid, message = match.groups()
        
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y.%m.%d %H:%M:%S')
        except ValueError:
            timestamp = None
            
        return {
            'timestamp': timestamp,
            'timestamp_str': timestamp_str,
            'pid': int(pid),
            'tid': int(tid),
            'message': message,
            'raw_line': line,
            'platform': 'windows'
        }
    
    def _parse_mac_log_line(self, line):
        """Mac log satırını parse et"""
        # Mac log format: Timestamp Thread Type Activity PID TTL Message
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\+\d{4})\s+(\w+)\s+(\w+)\s+(\w+)\s+(\d+)\s+(\d+)\s+(.+)'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        timestamp_str, thread_id, log_type, activity, pid, ttl, message = match.groups()
        
        try:
            # Mac timestamp format: 2025-06-29 13:42:31.905966+0300
            timestamp = datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            timestamp = None
        
        return {
            'timestamp': timestamp,
            'timestamp_str': timestamp_str,
            'thread_id': thread_id,
            'log_type': log_type,
            'activity': activity,
            'pid': int(pid),
            'ttl': int(ttl),
            'message': message,
            'raw_line': line,
            'platform': 'mac'
        }

    def _categorize_entry(self, entry):
        """Log entry'yi kategorize et"""
        message = entry['message']
        platform = entry.get('platform', 'windows')
        
        if platform == 'mac':
            self._categorize_mac_entry(entry)
        else:
            self._categorize_windows_entry(entry)

    def _categorize_mac_entry(self, entry):
        """Mac log entry'yi kategorize et"""
        message = entry['message']
        
        # CyberArk EPM Launch Events
        if 'Did launch:' in message:
            launch_info = self._parse_mac_launch_event(entry)
            if launch_info:
                self.parsed_data['agent_events'].append(launch_info)
        
        # Policy Events (Process execution attempts)
        elif 'try to exec' in message and 'ac_' in message:
            policy_info = self._parse_mac_policy_event(entry)
            if policy_info:
                self.parsed_data['process_starts'].append(policy_info)
        
        # System Configuration Events
        elif any(keyword in message for keyword in [
            'Did configure', 'Did restore', 'Synchronized', 'Auxiliary', 
            'Suppressed', 'Muted paths'
        ]):
            system_info = self._parse_mac_system_event(entry)
            if system_info:
                self.parsed_data['system_events'].append(system_info)
        
        # Error Events
        elif any(keyword in message.lower() for keyword in [
            'error', 'failed', 'exception', 'timeout', 'denied'
        ]):
            self.parsed_data['errors'].append(entry)
        
        # Zero Touch Events
        elif any(keyword in message for keyword in [
            'ZeroTouch', 'zero touch', 'privilege escalation', 'elevation'
        ]):
            zt_info = self._parse_mac_zero_touch_event(entry)
            if zt_info:
                self.parsed_data['zero_touch_events'].append(zt_info)

    def _categorize_windows_entry(self, entry):
        """Windows log entry'yi kategorize et"""
        message = entry['message']
        
        # Process Start Events
        if 'CvfProcessStartRights::PROCSTART' in message:
            proc_info = self._parse_windows_process_start(entry)
            if proc_info:
                self.parsed_data['process_starts'].append(proc_info)
        
        # Zero Touch Events
        elif 'ZeroTouchEvent' in message:
            zt_info = self._parse_windows_zero_touch_event(entry)
            if zt_info:
                self.parsed_data['zero_touch_events'].append(zt_info)
        
        # Agent Events
        elif any(keyword in message for keyword in [
            'Agent', 'restart', 'started', 'stopped', 'service', 'version', 
            'SendInterval', 'WhatsUpV2', 'GetNextAction', 'FullMeshScanner',
            'AWS_COM_KIT', 'PASP version', 'SendZeroTouchEvents'
        ]):
            agent_info = self._parse_windows_agent_event(entry)
            if agent_info:
                self.parsed_data['agent_events'].append(agent_info)
        
        # System Events
        elif any(keyword in message for keyword in [
            'DRV queue timeout', 'Pool use', 'Scan thread', 'INFO:', 'WARNING:'
        ]):
            system_info = self._parse_windows_system_event(entry)
            if system_info:
                self.parsed_data['system_events'].append(system_info)
        
        # Error Events
        elif 'ERROR' in message or 'failed' in message.lower():
            self.parsed_data['errors'].append(entry)

    # Mac Parsing Methods
    def _parse_mac_launch_event(self, entry):
        """Mac CyberArk launch event'ini parse et"""
        message = entry['message']
        
        # Version bilgisini çıkar
        version_match = re.search(r"Did launch: '([^']+)'", message)
        version = version_match.group(1) if version_match else 'Unknown'
        
        # Extension tipini belirle
        if 'EndpointSecurityExtension' in message:
            extension_type = 'Endpoint Security'
        elif 'NetworkExtension' in message:
            extension_type = 'Network Extension'
        else:
            extension_type = 'Unknown Extension'
        
        return {
            'timestamp': entry['timestamp'],
            'timestamp_str': entry['timestamp_str'],
            'event_type': 'AGENT_START',
            'message': f"CyberArk {extension_type} launched - Version: {version}",
            'version': version,
            'extension_type': extension_type,
            'log_pid': entry['pid'],
            'thread_id': entry['thread_id'],
            'platform': 'mac'
        }

    def _parse_mac_policy_event(self, entry):
        """Mac policy/process execution event'ini parse et"""
        message = entry['message']
        
        # Activity Code
        ac_match = re.search(r'(ac_\d+):', message)
        activity_code = ac_match.group(1) if ac_match else 'Unknown'
        
        # Source executable
        source_exec_match = re.search(r"'([^']+)'\s+\(", message)
        source_executable = source_exec_match.group(1) if source_exec_match else 'Unknown'
        
        # Target executable
        target_exec_match = re.search(r"try to exec '([^']+)'", message)
        target_executable = target_exec_match.group(1) if target_exec_match else 'Unknown'
        
        # Process IDs
        pid_pattern = r'\((\d+):\d+:\d+:'
        source_pid_match = re.search(pid_pattern, message)
        source_pid = int(source_pid_match.group(1)) if source_pid_match else 0
        
        # Parent PID
        parent_match = re.search(r'parent: (\d+):', message)
        parent_pid = int(parent_match.group(1)) if parent_match else 0
        
        # Signing ID
        signing_id_match = re.search(r"signing id: '([^']*)'", message)
        signing_id = signing_id_match.group(1) if signing_id_match else 'Unknown'
        
        # Team ID
        team_id_match = re.search(r"team id: '([^']*)'", message)
        team_id = team_id_match.group(1) if team_id_match else 'Unknown'
        
        # Decision and timing
        decision_match = re.search(r'- (defer|allow|deny)', message)
        decision = decision_match.group(1) if decision_match else 'unknown'
        
        time_match = re.search(r'decision time ([\d.]+) secs', message)
        decision_time = float(time_match.group(1)) if time_match else 0.0
        
        # Policy result
        policy_result = 'no policy found' if 'no policy found' in message else 'policy applied'
        
        return {
            'timestamp': entry['timestamp'],
            'timestamp_str': entry['timestamp_str'],
            'activity_code': activity_code,
            'source_executable': source_executable,
            'target_executable': target_executable,
            'executable': target_executable,
            'command_line': f"{source_executable} -> {target_executable}",
            'process_pid': source_pid,
            'parent_pid': parent_pid,
            'signing_id': signing_id,
            'team_id': team_id,
            'decision': decision,
            'decision_time': decision_time,
            'policy_result': policy_result,
            'policy_name': f"Mac Policy ({decision})",
            'action_name': decision.upper(),
            'execute_user': 'mac_user',
            'log_pid': entry['pid'],
            'thread_id': entry['thread_id'],
            'platform': 'mac'
        }

    def _parse_mac_system_event(self, entry):
        """Mac sistem event'ini parse et"""
        message = entry['message']
        
        # Event tipini belirle
        if 'Did configure' in message:
            event_type = 'MAC_SYSTEM_CONFIG'
        elif 'Did restore' in message:
            event_type = 'MAC_SYSTEM_RESTORE'
        elif 'Synchronized' in message:
            event_type = 'MAC_SYSTEM_SYNC'
        elif 'Auxiliary' in message:
            event_type = 'MAC_SYSTEM_USER'
        elif 'Suppressed' in message:
            event_type = 'MAC_SYSTEM_SUPPRESS'
        elif 'Muted paths' in message:
            event_type = 'MAC_SYSTEM_MUTE'
        else:
            event_type = 'MAC_SYSTEM_OTHER'
        
        return {
            'timestamp': entry['timestamp'],
            'timestamp_str': entry['timestamp_str'],
            'event_type': event_type,
            'message': message,
            'log_pid': entry['pid'],
            'thread_id': entry['thread_id'],
            'platform': 'mac'
        }

    def _parse_mac_zero_touch_event(self, entry):
        """Mac zero touch event'ini parse et"""
        message = entry['message']
        
        return {
            'timestamp': entry['timestamp'],
            'timestamp_str': entry['timestamp_str'],
            'event_type': 'MacZeroTouchEvent',
            'content': message,
            'log_pid': entry['pid'],
            'thread_id': entry['thread_id'],
            'platform': 'mac'
        }

    def _parse_windows_process_start(self, entry):
        """Windows process start event'ini parse et"""
        message = entry['message']
        
        # PROCSTART pattern
        pattern = r'pid=(\d+), parent=(\d+), exe=\[([^\]]+)\], cmdLine=\[([^\]]+)\], policyId=(\d+), action=(\d+) \(([^)]+)\), policyName=\[([^\]]+)\], executeUser=\[([^\]]+)\]'
        match = re.search(pattern, message)
        
        if not match:
            return None
            
        return {
            'timestamp': entry['timestamp'],
            'timestamp_str': entry['timestamp_str'],
            'process_pid': int(match.group(1)),
            'parent_pid': int(match.group(2)),
            'executable': match.group(3),
            'command_line': match.group(4),
            'policy_id': int(match.group(5)),
            'action_code': int(match.group(6)),
            'action_name': match.group(7),
            'policy_name': match.group(8),
            'execute_user': match.group(9),
            'log_pid': entry['pid'],
            'log_tid': entry['tid'],
            'platform': 'windows'
        }

    def _parse_windows_zero_touch_event(self, entry):
        """Windows zero touch event'ini parse et"""
        message = entry['message']
        
        # ZeroTouchEvent XML içeriğini parse et
        xml_match = re.search(r'<ZeroTouchEvent[^>]*>(.*?)</ZeroTouchEvent>', message, re.DOTALL)
        if xml_match:
            return {
                'timestamp': entry['timestamp'],
                'timestamp_str': entry['timestamp_str'],
                'event_type': 'ZeroTouchEvent',
                'content': xml_match.group(0),
                'log_pid': entry['pid'],
                'log_tid': entry['tid'],
                'platform': 'windows'
            }
        
        # ZeroTouchEvent mesajlarını da kontrol et
        if 'ZeroTouchEvent' in message:
            return {
                'timestamp': entry['timestamp'],
                'timestamp_str': entry['timestamp_str'],
                'event_type': 'ZeroTouchEvent',
                'content': message,
                'log_pid': entry['pid'],
                'log_tid': entry['tid'],
                'platform': 'windows'
            }
        
        return None

    def _parse_windows_agent_event(self, entry):
        """Windows agent event'lerini parse et"""
        message = entry['message']
        
        # Event tipini belirle
        if 'PASP version' in message:
            event_type = 'AGENT_VERSION'
        elif any(keyword in message for keyword in ['SendInterval', 'WhatsUpV2', 'GetNextAction']):
            event_type = 'AGENT_COMMUNICATION'
        elif 'FullMeshScanner' in message or 'Scan thread' in message:
            event_type = 'AGENT_SCANNING'
        elif 'AWS_COM_KIT' in message:
            event_type = 'AGENT_IOT'
        elif 'restart' in message.lower():
            event_type = 'AGENT_RESTART'
        elif 'started' in message.lower():
            event_type = 'AGENT_START'
        elif 'stopped' in message.lower():
            event_type = 'AGENT_STOP'
        else:
            event_type = 'AGENT_OTHER'
        
        return {
            'timestamp': entry['timestamp'],
            'timestamp_str': entry['timestamp_str'],
            'event_type': event_type,
            'message': message,
            'log_pid': entry['pid'],
            'log_tid': entry['tid'],
            'platform': 'windows'
        }

    def _parse_windows_system_event(self, entry):
        """Windows sistem event'lerini parse et"""
        message = entry['message']
        
        # Event tipini belirle
        if 'DRV queue timeout' in message:
            event_type = 'SYSTEM_PERFORMANCE'
        elif 'Pool use' in message:
            event_type = 'SYSTEM_MEMORY'
        elif 'Scan thread' in message:
            event_type = 'SYSTEM_THREAD'
        elif 'INFO:' in message:
            event_type = 'SYSTEM_INFO'
        elif 'WARNING:' in message:
            event_type = 'SYSTEM_WARNING'
        else:
            event_type = 'SYSTEM_OTHER'
        
        return {
            'timestamp': entry['timestamp'],
            'timestamp_str': entry['timestamp_str'],
            'event_type': event_type,
            'message': message,
            'log_pid': entry['pid'],
            'log_tid': entry['tid'],
            'platform': 'windows'
        }

    def _calculate_statistics(self):
        """İstatistikleri hesapla"""
        print("Calculating statistics...")
        
        # Platform dağılımını hesapla
        platform_distribution = Counter()
        for entry in self.log_entries:
            platform = entry.get('platform', 'windows')
            platform_distribution[platform] += 1
        
        stats = {
            'total_entries': len(self.log_entries),
            'process_starts': len(self.parsed_data['process_starts']),
            'zero_touch_events': len(self.parsed_data['zero_touch_events']),
            'errors': len(self.parsed_data['errors']),
            'agent_events': len(self.parsed_data['agent_events']),
            'system_events': len(self.parsed_data['system_events']),
            'platform_distribution': dict(platform_distribution),
            'time_range': self._get_time_range(),
            'top_processes': self._get_top_processes(),
            'top_users': self._get_top_users(),
            'policy_distribution': self._get_policy_distribution(),
            'policy_colors': self._generate_policy_colors(),
            'hourly_activity': self._get_hourly_activity(),
            'mac_statistics': self._get_mac_statistics()
        }
        
        print(f"Statistics: {stats}")
        self.parsed_data['statistics'] = stats

    def _get_mac_statistics(self):
        """Mac specific istatistikler"""
        mac_stats = {
            'mac_process_events': 0,
            'mac_agent_events': 0,
            'mac_system_events': 0,
            'top_mac_applications': [],
            'signing_id_distribution': {},
            'decision_distribution': {}
        }
        
        # Mac process events
        mac_processes = [p for p in self.parsed_data['process_starts'] 
                        if p.get('platform') == 'mac']
        mac_stats['mac_process_events'] = len(mac_processes)
        
        # Mac agent events  
        mac_agents = [a for a in self.parsed_data['agent_events'] 
                    if a.get('platform') == 'mac']
        mac_stats['mac_agent_events'] = len(mac_agents)
        
        # Mac system events
        mac_systems = [s for s in self.parsed_data['system_events'] 
                    if s.get('platform') == 'mac']
        mac_stats['mac_system_events'] = len(mac_systems)
        
        # Top Mac applications
        app_counter = Counter()
        for proc in mac_processes:
            if 'target_executable' in proc:
                app_name = proc['target_executable'].split('/')[-1]
                app_counter[app_name] += 1
        mac_stats['top_mac_applications'] = app_counter.most_common(10)
        
        # Signing ID distribution
        signing_counter = Counter()
        for proc in mac_processes:
            if 'signing_id' in proc:
                signing_counter[proc['signing_id']] += 1
        mac_stats['signing_id_distribution'] = dict(signing_counter.most_common(10))
        
        # Decision distribution
        decision_counter = Counter()
        for proc in mac_processes:
            if 'decision' in proc:
                decision_counter[proc['decision']] += 1
        mac_stats['decision_distribution'] = dict(decision_counter)
        
        return mac_stats

    def _generate_policy_colors(self):
        """Policy'ler için dinamik renk kodları oluştur"""
        policies = list(self._get_policy_distribution().keys())
        colors = ['#dc3545', '#28a745', '#17a2b8', '#ffc107', '#6f42c1', '#fd7e14', '#20c997', '#e83e8c']
        
        policy_colors = {}
        for i, policy in enumerate(policies):
            color = colors[i % len(colors)]
            # Risk keywords için kırmızı öncelik
            if any(keyword in policy.lower() for keyword in ['kontrol', 'block', 'deny', 'restrict']):
                policy_colors[policy] = '#dc3545'
            # Güvenli keywords için yeşil
            elif any(keyword in policy.lower() for keyword in ['whitelist', 'allow', 'trust', 'elevate']):
                policy_colors[policy] = '#28a745'
            # Monitor keywords için sarı
            elif any(keyword in policy.lower() for keyword in ['monitor', 'detect', 'watch']):
                policy_colors[policy] = '#ffc107'
            else:
                policy_colors[policy] = color
        
        return policy_colors

    def _get_time_range(self):
        """Zaman aralığını hesapla"""
        if not self.log_entries:
            return None
        timestamps = [entry['timestamp'] for entry in self.log_entries if entry['timestamp']]
        if not timestamps:
            return None
        return {
            'start': min(timestamps).strftime('%Y-%m-%d %H:%M:%S'),
            'end': max(timestamps).strftime('%Y-%m-%d %H:%M:%S'),
            'duration_minutes': (max(timestamps) - min(timestamps)).total_seconds() / 60
        }

    def _get_top_processes(self):
        """En çok kullanılan process'leri bul"""
        process_counter = Counter()
        for proc in self.parsed_data['process_starts']:
            if proc.get('platform') == 'mac':
                exe_name = proc.get('target_executable', '').split('/')[-1] if proc.get('target_executable') else 'Unknown'
            else:
                exe_name = os.path.basename(proc.get('executable', ''))
            process_counter[exe_name] += 1
        return process_counter.most_common(10)

    def _get_top_users(self):
        """En aktif kullanıcıları bul"""
        user_counter = Counter()
        for proc in self.parsed_data['process_starts']:
            user_counter[proc.get('execute_user', 'Unknown')] += 1
        return user_counter.most_common(5)

    def _get_policy_distribution(self):
        """Policy dağılımını hesapla"""
        policy_counter = Counter()
        for proc in self.parsed_data['process_starts']:
            policy_counter[proc.get('policy_name', 'Unknown')] += 1
        return dict(policy_counter)

    def _get_hourly_activity(self):
        """Saatlik aktivite dağılımı"""
        hourly_activity = defaultdict(int)
        for entry in self.log_entries:
            if entry['timestamp']:
                hour = entry['timestamp'].hour
                hourly_activity[hour] += 1
        return dict(hourly_activity)

# Global parser instance
log_parser = CyberArkLogParser()

@app.route('/upload', methods=['POST', 'OPTIONS'])
def upload_log():
    """Log dosyası yükle ve parse et"""
    print("📤 Upload endpoint called")
    
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded', 'success': False}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected', 'success': False}), 400
        
        print(f"📄 Processing file: {file.filename}")
        
        # Reset parser
        global log_parser
        log_parser = CyberArkLogParser()
        
        # Read and decode file content
        file.seek(0)
        content = file.read()
        
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content_str = content.decode('latin-1')
            except UnicodeDecodeError:
                content_str = content.decode('utf-8', errors='ignore')
        
        print(f"📄 Content length: {len(content_str)} characters")
        
        # Parse content
        parsed_data = log_parser.parse_log_file(content_str)
        
        # Create success message
        stats = parsed_data['statistics']
        platform_dist = stats.get('platform_distribution', {})
        
        success_message = create_success_message(stats, platform_dist)
        
        response_data = {
            'success': True,
            'message': success_message,
            'statistics': stats,
            'file_info': {
                'filename': file.filename,
                'size': len(content_str),
                'detected_platforms': list(platform_dist.keys()) if platform_dist else ['windows']
            }
        }
        
        return jsonify(response_data)
    
    except Exception as e:
        print(f"❌ Error in upload: {str(e)}")
        return jsonify({
            'error': f'Dosya analiz hatası: {str(e)}', 
            'success': False
        }), 500

def create_success_message(stats, platform_dist):
    """Success mesajı oluştur"""
    total_entries = stats.get('total_entries', 0)
    
    if not platform_dist:
        return f'Log dosyası başarıyla analiz edildi. {total_entries} kayıt bulundu.'
    
    platforms = list(platform_dist.keys())
    
    if len(platforms) == 1:
        platform = platforms[0].title()
        return f'{platform} EPM log dosyası başarıyla analiz edildi. {total_entries} kayıt bulundu.'
    else:
        platform_details = []
        for platform, count in platform_dist.items():
            platform_details.append(f"{platform.title()}: {count}")
        
        platform_str = ", ".join(platform_details)
        return f'Multi-platform log analizi tamamlandı! {platform_str} events'

@app.route('/api/process_starts')
def get_process_starts():
    """Process start event'lerini getir"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        search = request.args.get('search', '')
        
        process_starts = log_parser.parsed_data['process_starts']
        
        # Search filter
        if search:
            process_starts = [p for p in process_starts 
                             if search.lower() in (p.get('executable', '') or '').lower() 
                             or search.lower() in (p.get('target_executable', '') or '').lower()
                             or search.lower() in (p.get('execute_user', '') or '').lower()
                             or search.lower() in (p.get('policy_name', '') or '').lower()]
        
        # Pagination
        start = (page - 1) * per_page
        end = start + per_page
        
        return jsonify({
            'data': process_starts[start:end],
            'total': len(process_starts),
            'page': page,
            'per_page': per_page,
            'total_pages': (len(process_starts) + per_page - 1) // per_page if process_starts else 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mac_events')
def get_mac_events():
    """Mac event'lerini getir"""
    try:
        mac_events = []
        
        # Mac process events
        mac_processes = [p for p in log_parser.parsed_data['process_starts'] 
                        if p.get('platform') == 'mac']
        mac_events.extend(mac_processes)
        
        # Mac agent events
        mac_agents = [a for a in log_parser.parsed_data['agent_events'] 
                     if a.get('platform') == 'mac']
        mac_events.extend(mac_agents)
        
        # Mac system events
        mac_systems = [s for s in log_parser.parsed_data['system_events'] 
                      if s.get('platform') == 'mac']
        mac_events.extend(mac_systems)
        
        # Sort by timestamp
        mac_events.sort(key=lambda x: x.get('timestamp_str', ''), reverse=True)
        
        return jsonify(mac_events)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/errors')
def get_errors():
    """Error event'lerini getir"""
    try:
        return jsonify(log_parser.parsed_data['errors'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zerotuch')
def get_zerotuch():
    """Zero Touch event'lerini getir"""
    try:
        return jsonify(log_parser.parsed_data['zero_touch_events'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent_events')
def get_agent_events():
    """Agent event'lerini getir"""
    try:
        return jsonify(log_parser.parsed_data['agent_events'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system_events')
def get_system_events():
    """Sistem event'lerini getir"""
    try:
        return jsonify(log_parser.parsed_data['system_events'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def get_statistics():
    """İstatistikleri getir"""
    try:
        return jsonify(log_parser.parsed_data['statistics'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/test')
def test():
    """Test endpoint"""
    platform_dist = {}
    if log_parser.parsed_data.get('statistics'):
        platform_dist = log_parser.parsed_data['statistics'].get('platform_distribution', {})
    
    return jsonify({
        'status': 'OK',
        'message': 'CyberArk EPM Log Analyzer (Multi-Platform) çalışıyor!',
        'version': '2.0.0',
        'port': 3000,
        'supported_platforms': ['Windows', 'macOS'],
        'features': [
            'Multi-platform log parsing',
            'Automatic platform detection',
            'Mixed log file support',
            'Platform comparison analysis',
            'Real-time statistics',
            'CSV export capabilities'
        ],
        'parser_status': {
            'total_entries': len(log_parser.log_entries),
            'process_starts': len(log_parser.parsed_data['process_starts']),
            'errors': len(log_parser.parsed_data['errors']),
            'agent_events': len(log_parser.parsed_data['agent_events']),
            'system_events': len(log_parser.parsed_data['system_events']),
            'zero_touch_events': len(log_parser.parsed_data['zero_touch_events']),
            'platform_distribution': platform_dist,
            'multi_platform_support': True
        }
    })

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Part 5: Export Functions
# Bu kodları API endpoint'lerden sonra ekleyin

@app.route('/api/export/csv')
def export_csv():
    """Process start verilerini CSV olarak export et"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'Timestamp', 'Platform', 'Process/Application', 'Command Line', 
            'PID', 'Parent PID', 'User', 'Policy', 'Action/Decision'
        ])
        
        for proc in log_parser.parsed_data['process_starts']:
            platform = proc.get('platform', 'windows')
            if platform == 'mac':
                process_name = proc.get('target_executable', 'Unknown')
                action = proc.get('decision', 'unknown')
            else:
                process_name = proc.get('executable', 'Unknown')
                action = proc.get('action_name', 'unknown')
            
            writer.writerow([
                proc.get('timestamp_str', ''),
                platform.title(),
                process_name,
                proc.get('command_line', ''),
                proc.get('process_pid', ''),
                proc.get('parent_pid', ''),
                proc.get('execute_user', ''),
                proc.get('policy_name', ''),
                action
            ])
        
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cyberark_process_events.csv'}
        )
        
        return response
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/export/mac_csv')
def export_mac_csv():
    """Mac event'lerini CSV olarak export et"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'Timestamp', 'Event Type', 'Activity Code', 'Source Executable', 
            'Target Executable', 'Decision', 'Decision Time', 'Signing ID', 
            'Team ID', 'PID', 'Thread ID', 'Message'
        ])
        
        # Mac process events
        mac_processes = [p for p in log_parser.parsed_data['process_starts'] 
                        if p.get('platform') == 'mac']
        
        for proc in mac_processes:
            writer.writerow([
                proc.get('timestamp_str', ''),
                'Process Execution',
                proc.get('activity_code', ''),
                proc.get('source_executable', ''),
                proc.get('target_executable', ''),
                proc.get('decision', ''),
                proc.get('decision_time', ''),
                proc.get('signing_id', ''),
                proc.get('team_id', ''),
                proc.get('process_pid', ''),
                proc.get('thread_id', ''),
                proc.get('command_line', '')
            ])
        
        # Mac agent events
        mac_agents = [a for a in log_parser.parsed_data['agent_events'] 
                     if a.get('platform') == 'mac']
        
        for agent in mac_agents:
            writer.writerow([
                agent.get('timestamp_str', ''),
                'Agent Event',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                agent.get('log_pid', ''),
                agent.get('thread_id', ''),
                agent.get('message', '')
            ])
        
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cyberark_mac_events.csv'}
        )
        
        return response
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/export/errors_csv')
def export_errors_csv():
    """Hataları CSV olarak export et"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Timestamp', 'Platform', 'PID', 'TID/Thread', 'Error Message'])
        
        for error in log_parser.parsed_data['errors']:
            platform = error.get('platform', 'windows')
            tid = error.get('tid') or error.get('thread_id', '')
            pid = error.get('pid') or error.get('log_pid', '')
            
            writer.writerow([
                error.get('timestamp_str', ''),
                platform.title(),
                pid,
                tid,
                error.get('message', '')
            ])
        
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cyberark_errors.csv'}
        )
        
        return response
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/export/zerotuch_csv')
def export_zerotuch_csv():
    """Zero Touch event'lerini CSV olarak export et"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Timestamp', 'Platform', 'Event Type', 'PID', 'TID/Thread', 'Content'])
        
        for event in log_parser.parsed_data['zero_touch_events']:
            platform = event.get('platform', 'windows')
            tid = event.get('log_tid') or event.get('thread_id', '')
            pid = event.get('log_pid') or event.get('pid', '')
            
            writer.writerow([
                event.get('timestamp_str', ''),
                platform.title(),
                event.get('event_type', ''),
                pid,
                tid,
                event.get('content', '')
            ])
        
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cyberark_zerotuch_events.csv'}
        )
        
        return response
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/export/agent_csv')
def export_agent_csv():
    """Agent event'lerini CSV olarak export et"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Timestamp', 'Platform', 'Event Type', 'PID', 'TID/Thread', 'Extension Type', 'Version', 'Message'])
        
        for event in log_parser.parsed_data['agent_events']:
            platform = event.get('platform', 'windows')
            tid = event.get('log_tid') or event.get('thread_id', '')
            pid = event.get('log_pid') or event.get('pid', '')
            
            writer.writerow([
                event.get('timestamp_str', ''),
                platform.title(),
                event.get('event_type', ''),
                pid,
                tid,
                event.get('extension_type', ''),
                event.get('version', ''),
                event.get('message', '')
            ])
        
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cyberark_agent_events.csv'}
        )
        
        return response
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/export/system_csv')
def export_system_csv():
    """Sistem event'lerini CSV olarak export et"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Timestamp', 'Platform', 'Event Type', 'PID', 'TID/Thread', 'Message'])
        
        for event in log_parser.parsed_data['system_events']:
            platform = event.get('platform', 'windows')
            tid = event.get('log_tid') or event.get('thread_id', '')
            pid = event.get('log_pid') or event.get('pid', '')
            
            writer.writerow([
                event.get('timestamp_str', ''),
                platform.title(),
                event.get('event_type', ''),
                pid,
                tid,
                event.get('message', '')
            ])
        
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cyberark_system_events.csv'}
        )
        
        return response
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

# Part 6: HTML Template
# Bu kodu ana sayfa route'u olarak ekleyin

@app.route('/')
def index():
    """Ana sayfa"""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>CyberArk EPM Log Analyzer - Multi-Platform</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
            margin: 40px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .version-badge {
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            margin: 0 5px;
            font-size: 12px;
            font-weight: bold;
        }
        .upload-area { 
            border: 2px dashed #007bff; 
            padding: 40px; 
            text-align: center; 
            margin: 20px 0; 
            border-radius: 15px; 
            background: linear-gradient(135deg, #f8f9ff 0%, #f0f8ff 100%);
            transition: all 0.3s ease;
        }
        .upload-area:hover {
            border-color: #28a745;
            background: linear-gradient(135deg, #f8fff8 0%, #f0fff0 100%);
            transform: translateY(-2px);
        }
        .platform-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 20px 0;
            text-align: left;
        }
        .platform-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 5px solid;
            transition: transform 0.3s ease;
        }
        .platform-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .platform-card.windows {
            border-left-color: #007bff;
        }
        .platform-card.mac {
            border-left-color: #28a745;
        }
        .btn { 
            background: #007bff; 
            color: white; 
            padding: 15px 30px; 
            border: none; 
            cursor: pointer; 
            border-radius: 8px; 
            font-size: 16px; 
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,123,255,0.3);
        }
        .btn:hover { 
            background: #0056b3; 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,123,255,0.4);
        }
        .btn:disabled { 
            background: #ccc; 
            cursor: not-allowed; 
            transform: none;
            box-shadow: none;
        }
        .btn-sm { 
            padding: 8px 16px; 
            font-size: 14px; 
        }
        .alert { 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 8px; 
            border-left: 4px solid;
        }
        .alert-success { 
            background: #d4edda; 
            color: #155724; 
            border-left-color: #28a745; 
        }
        .alert-danger { 
            background: #f8d7da; 
            color: #721c24; 
            border-left-color: #dc3545; 
        }
        .alert-info { 
            background: #d1ecf1; 
            color: #0c5460; 
            border-left-color: #17a2b8; 
        }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); 
            gap: 20px; 
            margin: 30px 0; 
        }
        .stat-card { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 30px; 
            border-radius: 15px; 
            text-align: center; 
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card h3 { 
            margin: 0; 
            font-size: 3em; 
            font-weight: bold; 
        }
        .stat-card p { 
            margin: 15px 0 0 0; 
            opacity: 0.9; 
            font-size: 1.1em;
        }
        .hidden { 
            display: none; 
        }
        .loading { 
            color: #007bff; 
            font-weight: bold; 
            font-size: 18px;
        }
        .tabs { 
            display: flex; 
            gap: 5px; 
            margin: 30px 0; 
            border-bottom: 2px solid #ddd; 
            flex-wrap: wrap; 
        }
        .tab-btn { 
            padding: 15px 25px; 
            border: none; 
            background: #f8f9fa; 
            cursor: pointer; 
            border-radius: 10px 10px 0 0; 
            font-weight: bold; 
            transition: all 0.3s; 
            font-size: 14px;
        }
        .tab-btn.active { 
            background: #007bff; 
            color: white; 
            box-shadow: 0 -3px 10px rgba(0,123,255,0.3);
        }
        .tab-btn:hover:not(.active) { 
            background: #e9ecef; 
            transform: translateY(-2px);
        }
        .tab-content { 
            margin: 30px 0; 
        }
        .tab-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 20px; 
            flex-wrap: wrap; 
            gap: 15px; 
        }
        .error-item { 
            background: #fff5f5; 
            border: 1px solid #fed7d7; 
            border-radius: 10px; 
            padding: 20px; 
            margin: 15px 0; 
            border-left: 5px solid #e53e3e; 
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .error-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            background: #fff;
        }
        .error-time { 
            font-weight: bold; 
            color: #c53030; 
            font-size: 14px; 
        }
        .error-message { 
            margin-top: 10px; 
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace; 
            font-size: 13px; 
            background: #f7fafc; 
            padding: 10px; 
            border-radius: 5px; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            background: white; 
            border-radius: 10px; 
            overflow: hidden; 
            box-shadow: 0 5px 15px rgba(0,0,0,0.08); 
        }
        th { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
            padding: 18px 15px; 
            text-align: left; 
            font-weight: bold; 
            color: #495057; 
            border-bottom: 2px solid #dee2e6; 
        }
        td { 
            padding: 15px; 
            border-bottom: 1px solid #dee2e6; 
        }
        tr:hover { 
            background: #f8f9fa; 
        }
        .badge { 
            padding: 6px 12px; 
            border-radius: 20px; 
            font-size: 11px; 
            font-weight: bold; 
            display: inline-block;
        }
        .search-box { 
            padding: 10px 15px; 
            border: 2px solid #ddd; 
            border-radius: 8px; 
            width: 250px; 
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        .search-box:focus {
            border-color: #007bff;
            outline: none;
            box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        .debug { 
            background: #f8f9fa; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 8px; 
            font-family: 'SF Mono', Monaco, monospace; 
            white-space: pre-wrap; 
            font-size: 12px; 
            max-height: 400px; 
            overflow: auto; 
            border-left: 4px solid #6c757d;
        }
        .mixed-platform-info {
            background: #e3f2fd;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 4px solid #2196f3;
        }
        .upload-tips {
            margin-top: 20px;
            font-size: 14px;
            color: #6c757d;
            text-align: left;
        }
        .upload-tips ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        
        /* Platform specific stat cards */
        .stat-card.windows {
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
        }
        .stat-card.mac {
            background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%);
        }
        .stat-card.mixed {
            background: linear-gradient(135deg, #6f42c1 0%, #5a2d91 100%);
        }
        .stat-card.danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }
        .stat-card.warning {
            background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);
            color: #212529;
        }
        .stat-card.info {
            background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
        }
        .stat-card.success {
            background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%);
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            body { margin: 20px; }
            .container { padding: 20px; }
            .platform-grid { grid-template-columns: 1fr; }
            .tabs { flex-direction: column; }
            .tab-header { flex-direction: column; align-items: stretch; }
            .search-box { width: 100%; margin-bottom: 10px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CyberArk EPM Log Analyzer</h1>
            <p style="margin: 10px 0; font-size: 1.2em; opacity: 0.9;">Multi-Platform Endpoint Privilege Manager Log Analysis</p>
            <div style="margin-top: 20px;">
                <span class="version-badge">v2.0</span>
                <span class="version-badge">🖥️ Windows</span>
                <span class="version-badge">🍎 macOS</span>
                <span class="version-badge">🔄 Mixed Logs</span>
            </div>
        </div>
        
        <div class="upload-area">
            <h3>📁 CyberArk EPM Log Dosyası Yükle</h3>
            <p style="color: #6c757d; margin-bottom: 20px;">
                Desteklenen formatlar ve platformlar:
            </p>
            
            <div class="platform-grid">
                <div class="platform-card windows">
                    <h4 style="margin: 0 0 15px 0; color: #007bff;">🖥️ Windows EPM Logs</h4>
                    <ul style="margin: 0; padding-left: 20px; font-size: 14px;">
                        <li>Process execution events</li>
                        <li>Zero Touch events</li>
                        <li>Agent communication</li>
                        <li>System events & errors</li>
                    </ul>
                    <p style="margin: 15px 0 0 0; font-size: 12px; color: #6c757d;">
                        <strong>Format:</strong> .trace, .log, .txt dosyaları
                    </p>
                </div>
                
                <div class="platform-card mac">
                    <h4 style="margin: 0 0 15px 0; color: #28a745;">🍎 Mac EPM Logs</h4>
                    <ul style="margin: 0; padding-left: 20px; font-size: 14px;">
                        <li>Process execution policies</li>
                        <li>Endpoint Security events</li>
                        <li>System configuration</li>
                        <li>Agent launch events</li>
                    </ul>
                    <p style="margin: 15px 0 0 0; font-size: 12px; color: #6c757d;">
                        <strong>Format:</strong> Structured timestamp logs
                    </p>
                </div>
            </div>
            
            <div class="mixed-platform-info">
                <h4 style="margin: 0 0 10px 0; color: #1976d2;">🔄 Mixed Platform Support</h4>
                <p style="margin: 0; font-size: 14px;">
                    ✅ Tek dosyada hem Windows hem Mac logları<br>
                    ✅ Otomatik platform detection<br>
                    ✅ Karşılaştırmalı analiz ve raporlama
                </p>
            </div>
            
            <input type="file" id="fileInput" accept=".trace,.log,.txt" style="margin: 20px 0;" />
            <br>
            <button class="btn" onclick="uploadFile()" id="uploadBtn">
                📤 Dosyayı Yükle ve Analiz Et
            </button>
            <div id="loading" class="loading hidden">⏳ Dosya analiz ediliyor...</div>
            
            <div class="upload-tips">
                <p><strong>💡 İpuçları:</strong></p>
                <ul>
                    <li>Maksimum dosya boyutu: 50MB</li>
                    <li>Desteklenen uzantılar: .trace, .log, .txt</li>
                    <li>Hem Windows hem Mac logları aynı anda analiz edilebilir</li>
                    <li>Platform otomatik olarak tespit edilir</li>
                </ul>
            </div>
        </div>
        
        <div id="results" class="hidden">
            <div id="message"></div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3 id="totalEntries">0</h3>
                    <p>📄 Toplam Log Entry</p>
                </div>
                <div class="stat-card success">
                    <h3 id="processStarts">0</h3>
                    <p>⚙️ Process Events</p>
                </div>
                <div class="stat-card info">
                    <h3 id="zeroTouch">0</h3>
                    <p>👆 Zero Touch Events</p>
                </div>
                <div class="stat-card danger">
                    <h3 id="errors">0</h3>
                    <p>🚨 Error Events</p>
                </div>
                <div class="stat-card warning">
                    <h3 id="agentEvents">0</h3>
                    <p>🤖 Agent Events</p>
                </div>
                <div class="stat-card">
                    <h3 id="systemEvents">0</h3>
                    <p>🖥️ System Events</p>
                </div>
            </div>
            
            <!-- Platform Stats (sadece mixed logs'da görünür) -->
            <div class="stats hidden" id="platformStats">
                <div class="stat-card windows">
                    <h3 id="windowsEvents">0</h3>
                    <p>🖥️ Windows Events</p>
                </div>
                <div class="stat-card mac">
                    <h3 id="macEvents">0</h3>
                    <p>🍎 Mac Events</p>
                </div>
                <div class="stat-card mixed">
                    <h3 id="platformRatio">0%</h3>
                    <p>📊 Platform Mix</p>
                </div>
            </div>
            
            <div class="tabs">
                <button class="tab-btn active" onclick="showTab('process')">📊 Process Events</button>
                <button class="tab-btn" onclick="showTab('errors')">🚨 Errors</button>
                <button class="tab-btn" onclick="showTab('zerotuch')">👆 Zero Touch</button>
                <button class="tab-btn" onclick="showTab('agent')">🤖 Agent Events</button>
                <button class="tab-btn" onclick="showTab('system')">🖥️ System Events</button>
                <button class="tab-btn hidden" onclick="showTab('mac')" id="macTab">🍎 Mac Events</button>
                <button class="tab-btn hidden" onclick="showTab('platform')" id="platformTab">📊 Platform Comparison</button>
            </div>
            
            <!-- Process Events Tab -->
            <div id="processTab" class="tab-content">
                <div class="tab-header">
                    <h3>📊 Process Execution Events</h3>
                    <div>
                        <input type="text" class="search-box" id="processSearch" placeholder="🔍 Process ara...">
                        <button class="btn btn-sm" onclick="searchProcesses()">🔍 Ara</button>
                        <button class="btn btn-sm" onclick="exportCSV()">💾 CSV Export</button>
                    </div>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Zaman</th>
                            <th>Platform</th>
                            <th>Process/Application</th>
                            <th>PID</th>
                            <th>Kullanıcı</th>
                            <th>Policy/Decision</th>
                            <th>Aksiyon</th>
                        </tr>
                    </thead>
                    <tbody id="processBody">
                    </tbody>
                </table>
            </div>
            
            <!-- Mac Events Tab -->
            <div id="macTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>🍎 Mac CyberArk EPM Events</h3>
                    <div>
                        <select id="macFilter" onchange="filterMacEvents()" style="padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 5px;">
                            <option value="all">All Mac Events</option>
                            <option value="process">🔄 Process Events</option>
                            <option value="agent">🤖 Agent Events</option>
                            <option value="system">🖥️ System Events</option>
                        </select>
                        <button class="btn btn-sm" onclick="exportMacCSV()">💾 Mac Export</button>
                    </div>
                </div>
                
                <div id="macProcessSection">
                    <h4>🔄 Mac Process Execution Events</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Zaman</th>
                                <th>Activity Code</th>
                                <th>Source → Target</th>
                                <th>Decision</th>
                                <th>Signing ID</th>
                                <th>Decision Time</th>
                            </tr>
                        </thead>
                        <tbody id="macProcessBody">
                        </tbody>
                    </table>
                </div>
                
                <div id="macAgentSection" style="margin-top: 30px;">
                    <h4>🤖 Mac Agent Events</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Zaman</th>
                                <th>Event Type</th>
                                <th>Extension</th>
                                <th>Version</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody id="macAgentBody">
                        </tbody>
                    </table>
                </div>
                
                <div id="macSystemSection" style="margin-top: 30px;">
                    <h4>🖥️ Mac System Events</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Zaman</th>
                                <th>Event Type</th>
                                <th>PID</th>
                                <th>Thread</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody id="macSystemBody">
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Platform Comparison Tab -->
            <div id="platformTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>📊 Windows vs Mac Platform Comparison</h3>
                </div>
                
                <div class="stats">
                    <div class="stat-card windows">
                        <h3 id="windowsTotal">0</h3>
                        <p>🖥️ Windows Events</p>
                    </div>
                    <div class="stat-card mac">
                        <h3 id="macTotal">0</h3>
                        <p>🍎 Mac Events</p>
                    </div>
                    <div class="stat-card mixed">
                        <h3 id="platformPercentage">0%</h3>
                        <p>📈 Mac Percentage</p>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-top: 30px;">
                    <div>
                        <h4>🖥️ Top Windows Processes</h4>
                        <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Process</th>
                                        <th>Count</th>
                                    </tr>
                                </thead>
                                <tbody id="windowsProcessTable">
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <div>
                        <h4>🍎 Top Mac Applications</h4>
                        <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Application</th>
                                        <th>Count</th>
                                    </tr>
                                </thead>
                                <tbody id="macProcessTable">
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Errors Tab -->
            <div id="errorsTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>🚨 System Errors</h3>
                    <button class="btn btn-sm" onclick="exportErrorsCSV()">💾 Export Errors</button>
                </div>
                <div id="errorsList">
                    <p>Loading errors...</p>
                </div>
            </div>
            
            <!-- Zero Touch Tab -->
            <div id="zerotouchTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>👆 Zero Touch Events</h3>
                    <button class="btn btn-sm" onclick="exportZeroTouchCSV()">💾 Zero Touch Export</button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Zaman</th>
                            <th>Platform</th>
                            <th>Event Type</th>
                            <th>PID</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody id="zerotouchBody">
                    </tbody>
                </table>
            </div>
            
            <!-- Agent Events Tab -->
            <div id="agentTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>🤖 CyberArk Agent Events</h3>
                    <button class="btn btn-sm" onclick="exportAgentCSV()">💾 Agent Events Export</button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Zaman</th>
                            <th>Platform</th>
                            <th>Event Type</th>
                            <th>PID</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody id="agentBody">
                    </tbody>
                </table>
            </div>
            
            <!-- System Events Tab -->
            <div id="systemTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>🖥️ System Events</h3>
                    <button class="btn btn-sm" onclick="exportSystemCSV()">💾 System Events Export</button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Zaman</th>
                            <th>Platform</th>
                            <th>Event Type</th>
                            <th>PID</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody id="systemBody">
                    </tbody>
                </table>
            </div>
        </div>
        
        <div id="debug" class="debug hidden"></div>
    </div>

    <!-- JavaScript kodu Part 7'de gelecek -->
    <script>
        // JavaScript fonksiyonları Part 7'de eklenecek
        // Part 7: JavaScript Frontend
// Bu kodu HTML template'indeki <script> tagları arasına ekleyin

// Global variables
let allProcesses = [];
let allErrors = [];
let allMacEvents = [];
let currentStats = {};

function uploadFile() {
    console.log('🚀 Upload function called');
    
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    
    if (!file) {
        showMessage('⚠️ Lütfen bir dosya seçin!', 'danger');
        return;
    }
    
    console.log('📄 File selected:', file.name, 'Size:', file.size);
    
    // File type hint
    const fileName = file.name.toLowerCase();
    if (fileName.includes('mac') || fileName.includes('endpoint')) {
        showMessage('🍎 Mac EPM log dosyası yükleniyor...', 'info');
    } else if (fileName.includes('trace') || fileName.includes('windows')) {
        showMessage('🖥️ Windows EPM log dosyası yükleniyor...', 'info');
    } else {
        showMessage('📄 Multi-platform log analizi başlıyor...', 'info');
    }
    
    document.getElementById('uploadBtn').disabled = true;
    document.getElementById('loading').classList.remove('hidden');
    
    const formData = new FormData();
    formData.append('file', file);
    
    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        console.log('📡 Response:', response.status);
        return response.json();
    })
    .then(data => {
        console.log('✅ Upload successful:', data);
        
        document.getElementById('uploadBtn').disabled = false;
        document.getElementById('loading').classList.add('hidden');
        
        if (data.success) {
            updateResults(data.statistics);
            loadAllData();
        } else {
            showMessage('❌ ' + (data.error || 'Bilinmeyen hata'), 'danger');
        }
        
        document.getElementById('debug').textContent = JSON.stringify(data, null, 2);
        document.getElementById('debug').classList.remove('hidden');
    })
    .catch(error => {
        console.error('❌ Upload error:', error);
        document.getElementById('uploadBtn').disabled = false;
        document.getElementById('loading').classList.add('hidden');
        showMessage('❌ Upload hatası: ' + error.message, 'danger');
    });
}

function showMessage(message, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
    
    // Auto-hide non-error messages
    if (type !== 'danger') {
        setTimeout(() => {
            messageDiv.innerHTML = '';
        }, 5000);
    }
}

function updateResults(stats) {
    currentStats = stats;
    
    // Update main statistics
    document.getElementById('totalEntries').textContent = stats.total_entries || 0;
    document.getElementById('processStarts').textContent = stats.process_starts || 0;
    document.getElementById('zeroTouch').textContent = stats.zero_touch_events || 0;
    document.getElementById('errors').textContent = stats.errors || 0;
    document.getElementById('agentEvents').textContent = stats.agent_events || 0;
    document.getElementById('systemEvents').textContent = stats.system_events || 0;
    
    // Platform distribution
    if (stats.platform_distribution) {
        const macCount = stats.platform_distribution.mac || 0;
        const windowsCount = stats.platform_distribution.windows || 0;
        const totalPlatform = macCount + windowsCount;
        
        console.log(`Platform distribution - Windows: ${windowsCount}, Mac: ${macCount}`);
        
        if (macCount > 0) {
            // Show platform stats
            document.getElementById('platformStats').classList.remove('hidden');
            document.getElementById('windowsEvents').textContent = windowsCount;
            document.getElementById('macEvents').textContent = macCount;
            
            const macRatio = totalPlatform > 0 ? Math.round((macCount / totalPlatform) * 100) : 0;
            document.getElementById('platformRatio').textContent = macRatio + '%';
            
            // Show Mac and Platform tabs
            document.getElementById('macTab').classList.remove('hidden');
            document.getElementById('platformTab').classList.remove('hidden');
            
            // Update platform comparison stats
            document.getElementById('windowsTotal').textContent = windowsCount;
            document.getElementById('macTotal').textContent = macCount;
            document.getElementById('platformPercentage').textContent = macRatio + '%';
            
            // Success message for mixed platform
            if (windowsCount > 0) {
                showMessage(`✅ Multi-platform analizi tamamlandı! Windows: ${windowsCount}, Mac: ${macCount} events`, 'success');
            } else {
                showMessage(`✅ Mac EPM log analizi tamamlandı! ${macCount} events bulundu`, 'success');
            }
        } else if (windowsCount > 0) {
            showMessage(`✅ Windows EPM log analizi tamamlandı! ${windowsCount} events bulundu`, 'success');
        }
    }
    
    document.getElementById('results').classList.remove('hidden');
}

function loadAllData() {
    loadProcessData();
    loadErrorsData();
    loadZeroTouchData();
    loadAgentData();
    loadSystemData();
    loadMacData();
    loadPlatformComparison();
}

function loadProcessData() {
    fetch('/api/process_starts?per_page=1000')
    .then(response => response.json())
    .then(data => {
        allProcesses = data.data || [];
        displayProcesses(allProcesses);
    });
}

function displayProcesses(processes) {
    const tbody = document.getElementById('processBody');
    tbody.innerHTML = '';
    
    if (!processes || processes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 40px;">Process event bulunamadı</td></tr>';
        return;
    }
    
    processes.forEach(proc => {
        const row = tbody.insertRow();
        const platform = proc.platform || 'windows';
        const platformIcon = platform === 'mac' ? '🍎' : '🖥️';
        const platformColor = platform === 'mac' ? '#28a745' : '#007bff';
        
        let processName, policyAction, user;
        
        if (platform === 'mac') {
            processName = proc.target_executable ? proc.target_executable.split('/').pop() : 'Unknown';
            policyAction = proc.decision || 'unknown';
            user = proc.execute_user || 'mac_user';
        } else {
            processName = proc.executable ? proc.executable.split('\\').pop() : 'Unknown';
            policyAction = proc.action_name || 'unknown';
            user = proc.execute_user || 'Unknown';
        }
        
        const actionColor = getActionColor(policyAction);
        
        row.innerHTML = `
            <td><small>${proc.timestamp_str || 'N/A'}</small></td>
            <td><span class="badge" style="background: ${platformColor}; color: white;">${platformIcon} ${platform.toUpperCase()}</span></td>
            <td><strong>${processName}</strong></td>
            <td><span class="badge" style="background: #6c757d; color: white;">${proc.process_pid || 'N/A'}</span></td>
            <td><span class="badge" style="background: #17a2b8; color: white;">${user}</span></td>
            <td><span class="badge" style="background: #6c757d; color: white;">${proc.policy_name || 'N/A'}</span></td>
            <td><span class="badge" style="background: ${actionColor}; color: white;">${policyAction}</span></td>
        `;
    });
}

function getActionColor(action) {
    const actionLower = action.toLowerCase();
    if (actionLower.includes('allow') || actionLower.includes('normal_run')) return '#28a745';
    if (actionLower.includes('deny') || actionLower.includes('block')) return '#dc3545';
    if (actionLower.includes('defer') || actionLower.includes('monitor')) return '#ffc107';
    return '#6c757d';
}

function loadMacData() {
    fetch('/api/mac_events')
    .then(response => response.json())
    .then(data => {
        allMacEvents = data || [];
        displayMacEvents(data);
    });
}

function displayMacEvents(events) {
    // Mac Process Events
    const macProcesses = events.filter(e => e.platform === 'mac' && e.target_executable);
    displayMacProcessEvents(macProcesses);
    
    // Mac Agent Events
    const macAgents = events.filter(e => e.platform === 'mac' && e.extension_type);
    displayMacAgentEvents(macAgents);
    
    // Mac System Events
    const macSystems = events.filter(e => e.platform === 'mac' && e.event_type && e.event_type.startsWith('MAC_SYSTEM'));
    displayMacSystemEvents(macSystems);
}

function displayMacProcessEvents(processes) {
    const tbody = document.getElementById('macProcessBody');
    tbody.innerHTML = '';
    
    if (!processes || processes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">Mac process event bulunamadı</td></tr>';
        return;
    }
    
    processes.forEach(proc => {
        const row = tbody.insertRow();
        const sourceApp = proc.source_executable ? proc.source_executable.split('/').pop() : 'Unknown';
        const targetApp = proc.target_executable ? proc.target_executable.split('/').pop() : 'Unknown';
        
        const decisionColor = {
            'defer': '#ffc107',
            'allow': '#28a745',
            'deny': '#dc3545'
        }[proc.decision] || '#6c757d';
        
        row.innerHTML = `
            <td><small>${proc.timestamp_str || 'N/A'}</small></td>
            <td><span class="badge" style="background: #17a2b8; color: white;">${proc.activity_code || 'N/A'}</span></td>
            <td>
                <strong>${sourceApp}</strong> 
                <span style="color: #007bff;">→</span> 
                <strong style="color: #28a745;">${targetApp}</strong>
            </td>
            <td><span class="badge" style="background: ${decisionColor}; color: white;">${proc.decision || 'N/A'}</span></td>
            <td><small style="font-family: monospace; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${proc.signing_id || 'N/A'}</small></td>
            <td><small>${proc.decision_time || 0}s</small></td>
        `;
    });
}

function displayMacAgentEvents(agents) {
    const tbody = document.getElementById('macAgentBody');
    tbody.innerHTML = '';
    
    if (!agents || agents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">Mac agent event bulunamadı</td></tr>';
        return;
    }
    
    agents.forEach(agent => {
        const row = tbody.insertRow();
        
        const extensionColor = {
            'Endpoint Security': '#dc3545',
            'Network Extension': '#17a2b8'
        }[agent.extension_type] || '#6c757d';
        
        row.innerHTML = `
            <td><small>${agent.timestamp_str || 'N/A'}</small></td>
            <td><span class="badge" style="background: #28a745; color: white;">🚀 ${agent.event_type}</span></td>
            <td><span class="badge" style="background: ${extensionColor}; color: white;">${agent.extension_type || 'N/A'}</span></td>
            <td><span class="badge" style="background: #6f42c1; color: white;">${agent.version || 'N/A'}</span></td>
            <td><small>${agent.message || 'N/A'}</small></td>
        `;
    });
}

function displayMacSystemEvents(systems) {
    const tbody = document.getElementById('macSystemBody');
    tbody.innerHTML = '';
    
    if (!systems || systems.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">Mac system event bulunamadı</td></tr>';
        return;
    }
    
    systems.forEach(system => {
        const row = tbody.insertRow();
        
        const eventTypeColors = {
            'MAC_SYSTEM_CONFIG': '#17a2b8',
            'MAC_SYSTEM_RESTORE': '#28a745',
            'MAC_SYSTEM_SYNC': '#ffc107',
            'MAC_SYSTEM_USER': '#6f42c1',
            'MAC_SYSTEM_SUPPRESS': '#fd7e14',
            'MAC_SYSTEM_MUTE': '#6c757d'
        };
        
        const eventColor = eventTypeColors[system.event_type] || '#6c757d';
        
        row.innerHTML = `
            <td><small>${system.timestamp_str || 'N/A'}</small></td>
            <td><span class="badge" style="background: ${eventColor}; color: white;">${system.event_type}</span></td>
            <td>${system.log_pid || 'N/A'}</td>
            <td>${system.thread_id || 'N/A'}</td>
            <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;" title="${system.message || ''}">${(system.message || '').substring(0, 100)}${system.message && system.message.length > 100 ? '...' : ''}</td>
        `;
    });
}

function loadPlatformComparison() {
    if (!currentStats.platform_distribution) return;
    
    const macCount = currentStats.platform_distribution.mac || 0;
    const windowsCount = currentStats.platform_distribution.windows || 0;
    
    if (macCount === 0 || windowsCount === 0) return;
    
    // Load top processes for comparison
    const windowsProcesses = allProcesses.filter(p => p.platform !== 'mac');
    const macProcesses = allProcesses.filter(p => p.platform === 'mac');
    
    displayPlatformComparison(windowsProcesses, macProcesses);
}

function displayPlatformComparison(windowsProcesses, macProcesses) {
    // Windows processes count
    const windowsCount = {};
    windowsProcesses.forEach(proc => {
        const exe = proc.executable ? proc.executable.split('\\').pop() : 'Unknown';
        windowsCount[exe] = (windowsCount[exe] || 0) + 1;
    });
    
    // Mac processes count
    const macCount = {};
    macProcesses.forEach(proc => {
        const app = proc.target_executable ? proc.target_executable.split('/').pop() : 'Unknown';
        macCount[app] = (macCount[app] || 0) + 1;
    });
    
    // Display Windows top processes
    const windowsTable = document.getElementById('windowsProcessTable');
    windowsTable.innerHTML = '';
    Object.entries(windowsCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .forEach(([process, count]) => {
            const row = windowsTable.insertRow();
            row.innerHTML = `
                <td><strong>${process}</strong></td>
                <td><span class="badge" style="background: #007bff; color: white;">${count}</span></td>
            `;
        });
    
    // Display Mac top processes
    const macTable = document.getElementById('macProcessTable');
    macTable.innerHTML = '';
    Object.entries(macCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .forEach(([app, count]) => {
            const row = macTable.insertRow();
            row.innerHTML = `
                <td><strong>${app}</strong></td>
                <td><span class="badge" style="background: #28a745; color: white;">${count}</span></td>
            `;
        });
}

function loadErrorsData() {
    fetch('/api/errors')
    .then(response => response.json())
    .then(data => {
        allErrors = data || [];
        displayErrors(data);
    });
}

function displayErrors(errors) {
    const errorsList = document.getElementById('errorsList');
    
    if (!errors || errors.length === 0) {
        errorsList.innerHTML = '<p style="color: #28a745; text-align: center; padding: 40px;">✅ Hata bulunamadı!</p>';
        return;
    }
    
    errorsList.innerHTML = errors.map((error, index) => {
        const platform = error.platform || 'windows';
        const platformIcon = platform === 'mac' ? '🍎' : '🖥️';
        
        return `
            <div class="error-item">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                    <div class="error-time">
                        🕐 ${error.timestamp_str || 'Zaman bilinmiyor'}
                    </div>
                    <span class="badge" style="background: #dc3545; color: white;">
                        ${platformIcon} ${platform.toUpperCase()} ERROR
                    </span>
                </div>
                <div style="margin-bottom: 8px;">
                    <strong>PID:</strong> ${error.pid || error.log_pid || 'N/A'} | 
                    <strong>TID:</strong> ${error.tid || error.thread_id || 'N/A'}
                </div>
                <div class="error-message">
                    ${(error.message || 'Mesaj bulunamadı').substring(0, 200)}${(error.message || '').length > 200 ? '...' : ''}
                </div>
            </div>
        `;
    }).join('');
}

function loadZeroTouchData() {
    fetch('/api/zerotuch')
    .then(response => response.json())
    .then(data => {
        displayZeroTouch(data);
    });
}

function displayZeroTouch(events) {
    const tbody = document.getElementById('zerotouchBody');
    tbody.innerHTML = '';
    
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">Zero Touch event bulunamadı</td></tr>';
        return;
    }
    
    events.forEach(event => {
        const row = tbody.insertRow();
        const platform = event.platform || 'windows';
        const platformIcon = platform === 'mac' ? '🍎' : '🖥️';
        const platformColor = platform === 'mac' ? '#28a745' : '#007bff';
        
        row.innerHTML = `
            <td><small>${event.timestamp_str || 'N/A'}</small></td>
            <td><span class="badge" style="background: ${platformColor}; color: white;">${platformIcon} ${platform.toUpperCase()}</span></td>
            <td><span class="badge" style="background: #ffc107; color: black;">${event.event_type || 'ZeroTouchEvent'}</span></td>
            <td>${event.log_pid || event.pid || 'N/A'}</td>
            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="${event.content || ''}">${(event.content || '').substring(0, 100)}${event.content && event.content.length > 100 ? '...' : ''}</td>
        `;
    });
}

function loadAgentData() {
    fetch('/api/agent_events')
    .then(response => response.json())
    .then(data => {
        displayAgentEvents(data);
    });
}

function displayAgentEvents(events) {
    const tbody = document.getElementById('agentBody');
    tbody.innerHTML = '';
    
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">Agent event bulunamadı</td></tr>';
        return;
    }
    
    events.forEach(event => {
        const row = tbody.insertRow();
        const platform = event.platform || 'windows';
        const platformIcon = platform === 'mac' ? '🍎' : '🖥️';
        const platformColor = platform === 'mac' ? '#28a745' : '#007bff';
        
        row.innerHTML = `
            <td><small>${event.timestamp_str || 'N/A'}</small></td>
            <td><span class="badge" style="background: ${platformColor}; color: white;">${platformIcon} ${platform.toUpperCase()}</span></td>
            <td><span class="badge" style="background: #17a2b8; color: white;">🤖 ${event.event_type}</span></td>
            <td>${event.log_pid || event.pid || 'N/A'}</td>
            <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">${(event.message || '').substring(0, 100)}${event.message && event.message.length > 100 ? '...' : ''}</td>
        `;
    });
}

function loadSystemData() {
    fetch('/api/system_events')
    .then(response => response.json())
    .then(data => {
        displaySystemEvents(data);
    });
}

function displaySystemEvents(events) {
    const tbody = document.getElementById('systemBody');
    tbody.innerHTML = '';
    
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">System event bulunamadı</td></tr>';
        return;
    }
    
    events.forEach(event => {
        const row = tbody.insertRow();
        const platform = event.platform || 'windows';
        const platformIcon = platform === 'mac' ? '🍎' : '🖥️';
        const platformColor = platform === 'mac' ? '#28a745' : '#007bff';
        
        row.innerHTML = `
            <td><small>${event.timestamp_str || 'N/A'}</small></td>
            <td><span class="badge" style="background: ${platformColor}; color: white;">${platformIcon} ${platform.toUpperCase()}</span></td>
            <td><span class="badge" style="background: #6f42c1; color: white;">🖥️ ${event.event_type}</span></td>
            <td>${event.log_pid || event.pid || 'N/A'}</td>
            <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">${(event.message || '').substring(0, 100)}${event.message && event.message.length > 100 ? '...' : ''}</td>
        `;
    });
}

function searchProcesses() {
    const searchTerm = document.getElementById('processSearch').value.toLowerCase();
    const filteredProcesses = allProcesses.filter(proc => {
        const searchFields = [
            proc.executable || '',
            proc.target_executable || '',
            proc.execute_user || '',
            proc.policy_name || '',
            proc.signing_id || ''
        ].join(' ').toLowerCase();
        
        return searchFields.includes(searchTerm);
    });
    
    displayProcesses(filteredProcesses);
}

function filterMacEvents() {
    const filter = document.getElementById('macFilter').value;
    
    // Show/hide sections based on filter
    document.getElementById('macProcessSection').style.display = 
        (filter === 'all' || filter === 'process') ? 'block' : 'none';
    document.getElementById('macAgentSection').style.display = 
        (filter === 'all' || filter === 'agent') ? 'block' : 'none';
    document.getElementById('macSystemSection').style.display = 
        (filter === 'all' || filter === 'system') ? 'block' : 'none';
}

function showTab(tabName) {
    // Update active tab
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
    
    // Update active content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });
    
    const activeContent = document.getElementById(`${tabName}Tab`);
    if (activeContent) {
        activeContent.classList.remove('hidden');
    }
}

// Export functions
function exportCSV() {
    window.open('/api/export/csv', '_blank');
}

function exportMacCSV() {
    window.open('/api/export/mac_csv', '_blank');
}

function exportErrorsCSV() {
    window.open('/api/export/errors_csv', '_blank');
}

function exportZeroTouchCSV() {
    window.open('/api/export/zerotuch_csv', '_blank');
}

function exportAgentCSV() {
    window.open('/api/export/agent_csv', '_blank');
}

function exportSystemCSV() {
    window.open('/api/export/system_csv', '_blank');
}

// Enter key support for search
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('processSearch');
    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                searchProcesses();
            }
        });
    }
});

// Test connection on load
window.addEventListener('load', function() {
    fetch('/test')
    .then(response => response.json())
    .then(data => {
        console.log('✅ Connection test OK:', data);
        console.log('🎯 Multi-platform support:', data.supported_platforms);
    })
    .catch(error => {
        showMessage('❌ Sunucu bağlantısı kurulamadı', 'danger');
    });
});

    </script>
</body>
</html>
    '''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)