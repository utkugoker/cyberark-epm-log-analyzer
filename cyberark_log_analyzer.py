from flask import Flask, request, jsonify, Response
import re
import json
from datetime import datetime
from collections import defaultdict, Counter
import io
import csv
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

class CyberArkLogParser:
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
    
    def parse_log_file(self, file_content):
        """Ana log parsing fonksiyonu"""
        print(f"Parsing file with {len(file_content)} characters")
        lines = file_content.split('\n')
        print(f"Found {len(lines)} lines")
        
        for line_num, line in enumerate(lines):
            if not line.strip() or line.startswith('D_Lib:'):
                continue
                
            entry = self._parse_log_line(line)
            if entry:
                self.log_entries.append(entry)
                self._categorize_entry(entry)
                
            if line_num % 1000 == 0:
                print(f"Processed {line_num} lines...")
        
        print(f"Total parsed entries: {len(self.log_entries)}")
        self._calculate_statistics()
        return self.parsed_data
    
    def _parse_log_line(self, line):
        """Tek log satırını parse et"""
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
            'raw_line': line
        }
    
    def _categorize_entry(self, entry):
        """Log entry'yi kategorize et"""
        message = entry['message']
        
        # Process Start Events
        if 'CvfProcessStartRights::PROCSTART' in message:
            proc_info = self._parse_process_start(entry)
            if proc_info:
                self.parsed_data['process_starts'].append(proc_info)
        
        # Zero Touch Events
        elif 'ZeroTouchEvent' in message:
            zt_info = self._parse_zero_touch_event(entry)
            if zt_info:
                self.parsed_data['zero_touch_events'].append(zt_info)
        
        # Agent Events
        elif any(keyword in message for keyword in [
            'Agent', 'restart', 'started', 'stopped', 'service', 'version', 
            'SendInterval', 'WhatsUpV2', 'GetNextAction', 'FullMeshScanner',
            'AWS_COM_KIT', 'PASP version', 'SendZeroTouchEvents'
        ]):
            agent_info = self._parse_agent_event(entry)
            if agent_info:
                self.parsed_data['agent_events'].append(agent_info)
        
        # System Events
        elif any(keyword in message for keyword in [
            'DRV queue timeout', 'Pool use', 'Scan thread', 'INFO:', 'WARNING:'
        ]):
            system_info = self._parse_system_event(entry)
            if system_info:
                self.parsed_data['system_events'].append(system_info)
        
        # Error Events
        elif 'ERROR' in message or 'failed' in message.lower():
            self.parsed_data['errors'].append(entry)
    
    def _parse_process_start(self, entry):
        """Process start event'ini parse et"""
        message = entry['message']
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
            'log_tid': entry['tid']
        }
    
    def _parse_zero_touch_event(self, entry):
        """Zero touch event'ini parse et"""
        message = entry['message']
        
        # ZeroTouchEvent XML içeriğini parse et
        xml_match = re.search(r'<ZeroTouchEvent[^>]*>(.*?)</ZeroTouchEvent>', message, re.DOTALL)
        if xml_match:
            print(f"👆 Found ZeroTouchEvent XML: {xml_match.group(0)[:100]}...")
            return {
                'timestamp': entry['timestamp'],
                'timestamp_str': entry['timestamp_str'],
                'event_type': 'ZeroTouchEvent',
                'content': xml_match.group(0),
                'log_pid': entry['pid'],
                'log_tid': entry['tid']
            }
        
        # ZeroTouchEvent mesajlarını da kontrol et
        if 'ZeroTouchEvent' in message:
            print(f"👆 Found ZeroTouchEvent message: {message[:100]}...")
            return {
                'timestamp': entry['timestamp'],
                'timestamp_str': entry['timestamp_str'],
                'event_type': 'ZeroTouchEvent',
                'content': message,
                'log_pid': entry['pid'],
                'log_tid': entry['tid']
            }
        
        return None
    
    def _parse_agent_event(self, entry):
        """Agent event'lerini parse et"""
        message = entry['message']
        
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
            'log_tid': entry['tid']
        }
    
    def _parse_system_event(self, entry):
        """Sistem event'lerini parse et"""
        message = entry['message']
        
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
            'log_tid': entry['tid']
        }
    
    def _calculate_statistics(self):
        """İstatistikleri hesapla"""
        print("Calculating statistics...")
        stats = {
            'total_entries': len(self.log_entries),
            'process_starts': len(self.parsed_data['process_starts']),
            'zero_touch_events': len(self.parsed_data['zero_touch_events']),
            'errors': len(self.parsed_data['errors']),
            'agent_events': len(self.parsed_data['agent_events']),
            'system_events': len(self.parsed_data['system_events']),
            'time_range': self._get_time_range(),
            'top_processes': self._get_top_processes(),
            'top_users': self._get_top_users(),
            'policy_distribution': self._get_policy_distribution(),
            'policy_colors': self._generate_policy_colors(),
            'hourly_activity': self._get_hourly_activity()
        }
        
        print(f"Statistics: {stats}")
        self.parsed_data['statistics'] = stats
    
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
            exe_name = os.path.basename(proc['executable'])
            process_counter[exe_name] += 1
        return process_counter.most_common(10)
    
    def _get_top_users(self):
        """En aktif kullanıcıları bul"""
        user_counter = Counter()
        for proc in self.parsed_data['process_starts']:
            user_counter[proc['execute_user']] += 1
        return user_counter.most_common(5)
    
    def _get_policy_distribution(self):
        """Policy dağılımını hesapla"""
        policy_counter = Counter()
        for proc in self.parsed_data['process_starts']:
            policy_counter[proc['policy_name']] += 1
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

@app.route('/')
def index():
    """Ana sayfa"""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>CyberArk Log Analyzer</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .upload-area { border: 2px dashed #007bff; padding: 40px; text-align: center; margin: 20px 0; border-radius: 10px; background: #f8f9ff; }
        .btn { background: #007bff; color: white; padding: 12px 24px; border: none; cursor: pointer; border-radius: 5px; font-size: 14px; }
        .btn:hover { background: #0056b3; }
        .btn:disabled { background: #ccc; cursor: not-allowed; }
        .btn-sm { padding: 6px 12px; font-size: 12px; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .stat-card h3 { margin: 0; font-size: 2.5em; font-weight: bold; }
        .stat-card p { margin: 10px 0 0 0; opacity: 0.9; }
        .hidden { display: none; }
        .loading { color: #007bff; font-weight: bold; }
        .tabs { display: flex; gap: 5px; margin: 20px 0; border-bottom: 2px solid #ddd; flex-wrap: wrap; }
        .tab-btn { padding: 12px 24px; border: none; background: #f8f9fa; cursor: pointer; border-radius: 8px 8px 0 0; font-weight: bold; transition: all 0.3s; }
        .tab-btn.active { background: #007bff; color: white; }
        .tab-btn:hover:not(.active) { background: #e9ecef; }
        .tab-content { margin: 20px 0; }
        .tab-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .pagination-info { margin: 10px 0; padding: 15px; background: #e3f2fd; border-radius: 8px; text-align: center; border-left: 5px solid #2196f3; }
        .error-item { background: #fff5f5; border: 1px solid #fed7d7; border-radius: 8px; padding: 20px; margin: 15px 0; border-left: 5px solid #e53e3e; }
        .error-time { font-weight: bold; color: #c53030; font-size: 14px; }
        .error-message { margin-top: 10px; font-family: 'Courier New', monospace; font-size: 13px; background: #f7fafc; padding: 10px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th { background: #f8f9fa; padding: 15px 12px; text-align: left; font-weight: bold; color: #495057; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        tr:hover { background: #f8f9fa; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .search-box { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; width: 200px; }
        .debug { background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 8px; font-family: monospace; white-space: pre-wrap; font-size: 12px; max-height: 300px; overflow: auto; }
        .process-hierarchy { font-family: 'Courier New', monospace; }
        .process-level-0 { padding-left: 0px; }
        .process-level-1 { padding-left: 20px; }
        .process-level-2 { padding-left: 40px; }
        .process-level-3 { padding-left: 60px; }
        .process-level-4 { padding-left: 80px; }
        .process-level-5 { padding-left: 100px; }
        .process-parent { font-weight: bold; color: #2c3e50; }
        .process-child { color: #7f8c8d; }
        .hierarchy-connector::before { content: "├─ "; color: #95a5a6; }
        .hierarchy-connector.last::before { content: "└─ "; color: #95a5a6; }
        .hierarchy-root::before { content: "🔸 "; }
        .parent-process { background: #f8f9fa !important; border-left: 3px solid #007bff; }
        .child-process { background: #ffffff !important; }
        
        /* Error Modal Styles */
        .error-modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
        .error-modal-content { background-color: #fefefe; margin: 5% auto; padding: 0; border-radius: 10px; width: 90%; max-width: 800px; max-height: 80%; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .error-modal-header { background: linear-gradient(135deg, #dc3545, #c82333); color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }
        .error-modal-header h3 { margin: 0; }
        .error-close { color: white; font-size: 28px; font-weight: bold; cursor: pointer; }
        .error-close:hover { color: #ccc; }
        .error-modal-body { padding: 20px; max-height: 500px; overflow-y: auto; }
        .error-detail { margin-bottom: 15px; }
        .error-detail strong { color: #dc3545; }
        .error-message-full { background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 13px; white-space: pre-wrap; word-break: break-all; border-left: 4px solid #dc3545; }
        
        /* Error Card Improvements */
        .error-item { background: #fff5f5; border: 1px solid #fed7d7; border-radius: 8px; padding: 20px; margin: 15px 0; border-left: 5px solid #e53e3e; cursor: pointer; transition: all 0.3s; }
        .error-item:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); background: #fff; }
        .error-preview { max-height: 60px; overflow: hidden; position: relative; }
        .error-preview::after { content: ""; position: absolute; bottom: 0; left: 0; height: 20px; width: 100%; background: linear-gradient(transparent, #fff5f5); }
        .error-expand-hint { color: #007bff; font-size: 12px; font-weight: bold; margin-top: 10px; }
        /* Agent & System Events Accordion Styles */
        .event-row { cursor: pointer; transition: all 0.3s; }
        .event-row:hover { background: #f8f9fa; }
        .event-row.expanded { background: #e3f2fd; border-left: 4px solid #2196f3; }
        .event-preview { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .event-expand-icon { transition: transform 0.3s; font-size: 12px; color: #007bff; }
        .event-expand-icon.expanded { transform: rotate(90deg); }
        .event-details { display: none; padding: 15px; background: #f8f9fa; border-top: 1px solid #dee2e6; }
        .event-details.show { display: block; }
        .event-full-message { background: white; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; border: 1px solid #dee2e6; max-height: 300px; overflow-y: auto; }
        .event-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 15px; }
        .event-meta-item { background: white; padding: 10px; border-radius: 5px; border: 1px solid #dee2e6; }
        .event-meta-item strong { color: #495057; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CyberArk Log Analyzer</h1>
        <p style="color: #6c757d; margin-bottom: 30px;">CyberArk Endpoint Privilege Manager log dosyalarını analiz edin</p>
        
        <div class="upload-area">
            <h3>📁 Log Dosyası Yükle</h3>
            <p style="color: #6c757d;">CyberArk .trace, .log veya .txt dosyalarını destekler (Max: 50MB)</p>
            <input type="file" id="fileInput" accept=".trace,.log,.txt" style="margin: 15px 0;" />
            <br>
            <button class="btn" onclick="uploadFile()" id="uploadBtn">
                📤 Dosyayı Yükle ve Analiz Et
            </button>
            <div id="loading" class="loading hidden">⏳ Dosya analiz ediliyor...</div>
        </div>
        
        <div id="results" class="hidden">
            <div id="message"></div>
            
            <div class="stats">
                <div class="stat-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                    <h3 id="totalEntries">0</h3>
                    <p>📄 Toplam Log</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                    <h3 id="processStarts">0</h3>
                    <p>⚙️ Process Başlatma</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                    <h3 id="zeroTouch">0</h3>
                    <p>👆 Zero Touch</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
                    <h3 id="errors">0</h3>
                    <p>🚨 Hatalar</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);">
                    <h3 id="agentEvents">0</h3>
                    <p>🤖 Agent Events</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);">
                    <h3 id="systemEvents">0</h3>
                    <p>🖥️ Sistem Events</p>
                </div>
            </div>
            
            <div class="tabs">
                <button class="tab-btn active" onclick="showTab('process')">📊 Process Olayları</button>
                <button class="tab-btn" onclick="showTab('errors')">🚨 Hatalar</button>
                <button class="tab-btn" onclick="showTab('zerotuch')">👆 Zero Touch</button>
                <button class="tab-btn" onclick="showTab('agent')">🤖 Agent Events</button>
                <button class="tab-btn" onclick="showTab('system')">🖥️ Sistem Events</button>
            </div>
            
            <!-- Process Events Tab -->
            <div id="processTab" class="tab-content">
                <div class="tab-header">
                    <h3>📊 Process Başlatma Olayları</h3>
                    <div>
                        <input type="text" class="search-box" id="processSearch" placeholder="🔍 Process ara...">
                        <button class="btn btn-sm" onclick="searchProcesses()">🔍 Ara</button>
                        <button class="btn btn-sm" onclick="toggleViewMode()" id="viewModeBtn">🌳 Hiyerarşik Görünüm</button>
                        <button class="btn btn-sm" onclick="exportCSV()">💾 CSV Export</button>
                    </div>
                </div>
                
                <!-- View Mode Toggle Info -->
                <div id="viewModeInfo" class="pagination-info" style="display: none;">
                    <strong>🌳 Hiyerarşik Görünüm:</strong> Process'ler parent-child ilişkisine göre düzenlenmiştir. 
                    Girintiler parent-child hiyerarşisini gösterir.
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Zaman</th>
                            <th>Process Hiyerarşisi</th>
                            <th>PID → Parent PID</th>
                            <th>Kullanıcı</th>
                            <th>Policy</th>
                            <th>Aksiyon</th>
                        </tr>
                    </thead>
                    <tbody id="processBody">
                    </tbody>
                </table>
            </div>
            
            <!-- Errors Tab -->
            <div id="errorsTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>🚨 Sistem Hataları</h3>
                    <div>
                        <select id="errorFilter" onchange="filterErrors()" style="padding: 5px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px;">
                            <option value="all">Tüm Hatalar</option>
                            <option value="critical">Kritik Hatalar</option>
                            <option value="failed">Failed İçeren</option>
                            <option value="error">Error İçeren</option>
                        </select>
                        <button class="btn btn-sm" onclick="exportErrorsCSV()">💾 Hataları Export Et</button>
                    </div>
                </div>
                <div id="errorsList">
                    <p>Hatalar yükleniyor...</p>
                </div>
            </div>
            
            <!-- Error Detail Modal -->
            <div id="errorModal" class="error-modal">
                <div class="error-modal-content">
                    <div class="error-modal-header">
                        <h3>🚨 Hata Detayları</h3>
                        <span class="error-close" onclick="closeErrorModal()">&times;</span>
                    </div>
                    <div class="error-modal-body">
                        <div class="error-detail">
                            <strong>🕐 Zaman:</strong> <span id="modalErrorTime"></span>
                        </div>
                        <div class="error-detail">
                            <strong>🆔 Process ID:</strong> <span id="modalErrorPID"></span>
                        </div>
                        <div class="error-detail">
                            <strong>🧵 Thread ID:</strong> <span id="modalErrorTID"></span>
                        </div>
                        <div class="error-detail">
                            <strong>📄 Tam Hata Mesajı:</strong>
                        </div>
                        <div id="modalErrorMessage" class="error-message-full"></div>
                        <div class="error-detail" style="margin-top: 20px;">
                            <strong>📝 Raw Log Satırı:</strong>
                        </div>
                        <div id="modalErrorRaw" class="error-message-full"></div>
                    </div>
                </div>
            </div>
            
            <!-- Zero Touch Tab -->
            <div id="zerotouchTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>👆 Zero Touch Olayları</h3>
                    <button class="btn btn-sm" onclick="exportZeroTouchCSV()">💾 Zero Touch Export</button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Zaman</th>
                            <th>Event Type</th>
                            <th>PID</th>
                            <th>TID</th>
                            <th>Detaylar</th>
                        </tr>
                    </thead>
                    <tbody id="zerotouchBody">
                    </tbody>
                </table>
            </div>
            
            <!-- Agent Events Tab -->
            <div id="agentTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>🤖 CyberArk Agent Olayları</h3>
                    <div>
                        <select id="agentFilter" onchange="filterAgentEvents()" style="padding: 5px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px;">
                            <option value="all">Tüm Agent Events</option>
                            <option value="AGENT_RESTART">🔄 Restart</option>
                            <option value="AGENT_START">▶️ Start</option>
                            <option value="AGENT_STOP">⏹️ Stop</option>
                            <option value="AGENT_VERSION">📋 Version</option>
                            <option value="AGENT_COMMUNICATION">📡 Communication</option>
                            <option value="AGENT_SCANNING">🔍 Scanning</option>
                            <option value="AGENT_IOT">☁️ IoT</option>
                            <option value="error">🚨 Sadece Hatalar</option>
                            <option value="warning">⚠️ Sadece Uyarılar</option>
                            <option value="success">✅ Sadece Başarılı</option>
                        </select>
                        <button class="btn btn-sm" onclick="expandAllAgentEvents()">📖 Tümünü Aç</button>
                        <button class="btn btn-sm" onclick="collapseAllAgentEvents()">📕 Tümünü Kapat</button>
                        <button class="btn btn-sm" onclick="exportAgentCSV()">💾 Agent Events Export</button>
                    </div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th width="15%">Zaman</th>
                            <th width="15%">Event Tipi</th>
                            <th width="8%">PID</th>
                            <th width="8%">TID</th>
                            <th width="50%">Mesaj Önizleme</th>
                            <th width="4%">🔽</th>
                        </tr>
                    </thead>
                    <tbody id="agentBody">
                    </tbody>
                </table>
            </div>
            
            <!-- System Events Tab -->
            <div id="systemTab" class="tab-content hidden">
                <div class="tab-header">
                    <h3>🖥️ Sistem Olayları</h3>
                    <div>
                        <select id="systemFilter" onchange="filterSystemEvents()" style="padding: 5px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px;">
                            <option value="all">Tüm Sistem Events</option>
                            <option value="SYSTEM_PERFORMANCE">⚡ Performance</option>
                            <option value="SYSTEM_MEMORY">💾 Memory</option>
                            <option value="SYSTEM_THREAD">🧵 Thread</option>
                            <option value="SYSTEM_INFO">ℹ️ Info</option>
                            <option value="SYSTEM_WARNING">⚠️ Warning</option>
                            <option value="error">🚨 Sadece Hatalar</option>
                            <option value="warning">⚠️ Sadece Uyarılar</option>
                            <option value="timeout">⏳ Sadece Timeout</option>
                            <option value="high">📈 Sadece Yüksek Kullanım</option>
                        </select>
                        <button class="btn btn-sm" onclick="expandAllSystemEvents()">📖 Tümünü Aç</button>
                        <button class="btn btn-sm" onclick="collapseAllSystemEvents()">📕 Tümünü Kapat</button>
                        <button class="btn btn-sm" onclick="exportSystemCSV()">💾 Sistem Events Export</button>
                    </div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th width="15%">Zaman</th>
                            <th width="15%">Event Tipi</th>
                            <th width="8%">PID</th>
                            <th width="8%">TID</th>
                            <th width="50%">Mesaj Önizleme</th>
                            <th width="4%">🔽</th>
                        </tr>
                    </thead>
                    <tbody id="systemBody">
                    </tbody>
                </table>
            </div>
        </div>
        
        <div id="debug" class="debug hidden"></div>
    </div>

    <script>
        function uploadFile() {
            console.log('🚀 Upload function called');
            
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            
            if (!file) {
                showMessage('⚠️ Lütfen bir dosya seçin!', 'danger');
                return;
            }
            
            console.log('📄 File selected:', file.name, 'Size:', file.size);
            
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
                    showMessage('✅ ' + data.message, 'success');
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
        }
        
        // Global variables
        let isHierarchicalView = false;
        let allProcesses = [];
        let allErrors = [];
        let allAgentEvents = [];
        let allSystemEvents = [];
        
        function updateResults(stats) {
            document.getElementById('totalEntries').textContent = stats.total_entries || 0;
            document.getElementById('processStarts').textContent = stats.process_starts || 0;
            document.getElementById('zeroTouch').textContent = stats.zero_touch_events || 0;
            document.getElementById('errors').textContent = stats.errors || 0;
            document.getElementById('agentEvents').textContent = stats.agent_events || 0;
            document.getElementById('systemEvents').textContent = stats.system_events || 0;
            
            window.policyColors = stats.policy_colors || {};
            document.getElementById('results').classList.remove('hidden');
        }
        
        function loadAllData() {
            loadProcessData();
            loadErrorsData();
            loadZeroTouchData();
            loadAgentData();
            loadSystemData();
        }
        
        function loadProcessData() {
            fetch('/api/process_starts?per_page=1000')
            .then(response => response.json())
            .then(data => {
                allProcesses = data.data || [];
                updateProcessTable(allProcesses);
                updatePagination(data);
            });
        }
        
        function toggleViewMode() {
            isHierarchicalView = !isHierarchicalView;
            const btn = document.getElementById('viewModeBtn');
            const info = document.getElementById('viewModeInfo');
            
            if (isHierarchicalView) {
                btn.textContent = '📋 Liste Görünümü';
                btn.style.background = '#28a745';
                info.style.display = 'block';
                updateProcessTable(buildProcessHierarchy(allProcesses));
            } else {
                btn.textContent = '🌳 Hiyerarşik Görünüm';
                btn.style.background = '#007bff';
                info.style.display = 'none';
                updateProcessTable(allProcesses);
            }
        }
        
        function buildProcessHierarchy(processes) {
            console.log('🌳 Building process hierarchy...');
            
            // PID'ye göre process map oluştur
            const processMap = {};
            processes.forEach(proc => {
                processMap[proc.process_pid] = {
                    ...proc,
                    children: []
                };
            });
            
            // Parent-child ilişkilerini kur
            const roots = [];
            processes.forEach(proc => {
                const parent = processMap[proc.parent_pid];
                if (parent && parent.process_pid !== proc.process_pid) {
                    parent.children.push(processMap[proc.process_pid]);
                } else {
                    // Root process (parent bulunamadı)
                    roots.push(processMap[proc.process_pid]);
                }
            });
            
            // Hiyerarşik listeyi düzleştir
            const hierarchicalList = [];
            
            function addToHierarchy(process, level = 0, isLast = true) {
                hierarchicalList.push({
                    ...process,
                    hierarchy_level: level,
                    is_last: isLast,
                    is_parent: process.children.length > 0
                });
                
                process.children.forEach((child, index) => {
                    const isLastChild = index === process.children.length - 1;
                    addToHierarchy(child, level + 1, isLastChild);
                });
            }
            
            // Root process'leri zamana göre sırala
            roots.sort((a, b) => new Date(a.timestamp_str) - new Date(b.timestamp_str));
            
            roots.forEach((root, index) => {
                addToHierarchy(root, 0, index === roots.length - 1);
            });
            
            console.log(`🌳 Built hierarchy with ${hierarchicalList.length} processes`);
            return hierarchicalList;
        }
        
        function updatePagination(data) {
            const processTab = document.getElementById('processTab');
            let paginationInfo = processTab.querySelector('.pagination-info:not(#viewModeInfo)');
            
            if (!paginationInfo) {
                paginationInfo = document.createElement('div');
                paginationInfo.className = 'pagination-info';
                const viewModeInfo = document.getElementById('viewModeInfo');
                processTab.insertBefore(paginationInfo, viewModeInfo.nextSibling);
            }
            
            paginationInfo.innerHTML = `
                <strong>📊 Toplam: ${data.total} process event</strong> 
                | Gösterilen: ${data.data ? data.data.length : 0} kayıt 
                ${data.total > data.data.length ? '<button class="btn btn-sm" onclick="loadAllProcessData()" style="margin-left: 10px;">📋 Tümünü Göster</button>' : ''}
                ${isHierarchicalView ? ' | <strong>🌳 Hiyerarşik görünümde parent-child ilişkileri gösteriliyor</strong>' : ''}
            `;
        }
        
        function updateProcessTable(processes) {
            const tbody = document.getElementById('processBody');
            tbody.innerHTML = '';
            
            if (!processes || processes.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">Veri bulunamadı</td></tr>';
                return;
            }
            
            const getPolicyColor = (policyName) => {
                const colors = window.policyColors || {};
                return colors[policyName] || '#6c757d';
            };
            
            processes.forEach(proc => {
                const row = tbody.insertRow();
                const exe = proc.executable ? proc.executable.split('\\\\').pop() : 'N/A';
                
                // Hiyerarşik görünüm kontrolü
                let processDisplay = '';
                let pidDisplay = '';
                let rowClass = '';
                
                if (isHierarchicalView && proc.hierarchy_level !== undefined) {
                    // Hiyerarşik görünüm
                    const indent = '&nbsp;'.repeat(proc.hierarchy_level * 4);
                    const connector = proc.hierarchy_level === 0 ? 
                        '<span class="hierarchy-root"></span>' : 
                        `<span class="hierarchy-connector ${proc.is_last ? 'last' : ''}"></span>`;
                    
                    processDisplay = `
                        <div class="process-hierarchy process-level-${Math.min(proc.hierarchy_level, 5)}">
                            ${indent}${connector}<strong>${exe}</strong>
                            ${proc.is_parent ? ' <span style="color: #007bff;">👨‍👩‍👧‍👦</span>' : ' <span style="color: #6c757d;">👤</span>'}
                            <br>
                            <small style="color: #6c757d; margin-left: ${(proc.hierarchy_level * 4) + 4}ch;">
                                ${proc.command_line ? proc.command_line.substring(0, 60) + '...' : ''}
                            </small>
                        </div>
                    `;
                    
                    pidDisplay = `
                        <div style="text-align: center;">
                            <span class="badge" style="background: #6c757d; color: white; display: block; margin: 2px 0;">${proc.process_pid}</span>
                            <small style="color: #95a5a6;">↑</small>
                            <span class="badge" style="background: #95a5a6; color: white; display: block; margin: 2px 0;">${proc.parent_pid}</span>
                        </div>
                    `;
                    
                    rowClass = proc.is_parent ? 'parent-process' : 'child-process';
                } else {
                    // Normal liste görünümü
                    processDisplay = `
                        <strong>${exe}</strong>
                        <br><small style="color: #6c757d;">${proc.command_line ? proc.command_line.substring(0, 50) + '...' : ''}</small>
                    `;
                    
                    pidDisplay = `<span class="badge" style="background: #6c757d; color: white;">${proc.process_pid || 'N/A'}</span>`;
                }
                
                if (rowClass) {
                    row.className = rowClass;
                }
                
                row.innerHTML = `
                    <td><small>${proc.timestamp_str || 'N/A'}</small></td>
                    <td>${processDisplay}</td>
                    <td>${pidDisplay}</td>
                    <td><span class="badge" style="background: #17a2b8; color: white;">${proc.execute_user || 'N/A'}</span></td>
                    <td><span class="badge" style="background: ${getPolicyColor(proc.policy_name || '')}; color: white;">${proc.policy_name || 'N/A'}</span></td>
                    <td><span class="badge" style="background: ${proc.action_name === 'NORMAL_RUN' ? '#28a745' : proc.action_name === 'COLLECT_ZERO_TOUCH' ? '#ffc107' : '#dc3545'}; color: ${proc.action_name === 'COLLECT_ZERO_TOUCH' ? 'black' : 'white'};">${proc.action_name || 'N/A'}</span></td>
                `;
            });
        }
        
        function searchProcesses() {
            const searchTerm = document.getElementById('processSearch').value;
            let url = '/api/process_starts?per_page=1000';
            if (searchTerm) {
                url += '&search=' + encodeURIComponent(searchTerm);
            }
            
            fetch(url)
            .then(response => response.json())
            .then(data => {
                allProcesses = data.data || [];
                if (isHierarchicalView) {
                    updateProcessTable(buildProcessHierarchy(allProcesses));
                } else {
                    updateProcessTable(allProcesses);
                }
                updatePagination(data);
            });
        }
        
        function loadAllProcessData() {
            fetch('/api/process_starts?per_page=10000')
            .then(response => response.json())
            .then(data => {
                allProcesses = data.data || [];
                if (isHierarchicalView) {
                    updateProcessTable(buildProcessHierarchy(allProcesses));
                } else {
                    updateProcessTable(allProcesses);
                }
                updatePagination(data);
            });
        }
        
        function loadErrorsData() {
            fetch('/api/errors')
            .then(response => response.json())
            .then(data => {
                allErrors = data;
                displayErrors(data);
            });
        }
        
        function filterErrors() {
            const filter = document.getElementById('errorFilter').value;
            let filteredErrors = allErrors;
            
            switch(filter) {
                case 'critical':
                    filteredErrors = allErrors.filter(error => 
                        error.message.toLowerCase().includes('critical') || 
                        error.message.toLowerCase().includes('fatal') ||
                        error.message.toLowerCase().includes('crash')
                    );
                    break;
                case 'failed':
                    filteredErrors = allErrors.filter(error => 
                        error.message.toLowerCase().includes('failed')
                    );
                    break;
                case 'error':
                    filteredErrors = allErrors.filter(error => 
                        error.message.toLowerCase().includes('error')
                    );
                    break;
                default:
                    filteredErrors = allErrors;
            }
            
            displayErrors(filteredErrors);
        }
        
        function displayErrors(errors) {
            const errorsList = document.getElementById('errorsList');
            
            if (!errors || errors.length === 0) {
                errorsList.innerHTML = '<p style="color: #28a745; text-align: center; padding: 40px;">✅ Filtreye uygun hata bulunamadı!</p>';
                return;
            }
            
            // Hata seviyesine göre sınıflandır
            const getErrorSeverity = (message) => {
                const msg = message.toLowerCase();
                if (msg.includes('critical') || msg.includes('fatal') || msg.includes('crash')) return 'critical';
                if (msg.includes('error')) return 'error';
                if (msg.includes('failed')) return 'failed';
                if (msg.includes('warning')) return 'warning';
                return 'info';
            };
            
            const getSeverityColor = (severity) => {
                switch(severity) {
                    case 'critical': return '#dc3545';
                    case 'error': return '#fd7e14';
                    case 'failed': return '#ffc107';
                    case 'warning': return '#17a2b8';
                    default: return '#6c757d';
                }
            };
            
            const getSeverityIcon = (severity) => {
                switch(severity) {
                    case 'critical': return '💥';
                    case 'error': return '🚨';
                    case 'failed': return '❌';
                    case 'warning': return '⚠️';
                    default: return 'ℹ️';
                }
            };
            
            errorsList.innerHTML = errors.map((error, index) => {
                const severity = getErrorSeverity(error.message || '');
                const previewMessage = (error.message || 'Mesaj bulunamadı').substring(0, 150);
                const isLong = (error.message || '').length > 150;
                
                return `
                    <div class="error-item" onclick="showErrorModal(${index})" data-error-index="${index}">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                            <div class="error-time">
                                🕐 ${error.timestamp_str || 'Zaman bilinmiyor'}
                            </div>
                            <span style="background: ${getSeverityColor(severity)}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px;">
                                ${getSeverityIcon(severity)} ${severity.toUpperCase()}
                            </span>
                        </div>
                        <div style="margin-bottom: 8px;">
                            <strong>PID:</strong> ${error.pid} | <strong>TID:</strong> ${error.tid}
                        </div>
                        <div class="error-preview">
                            <div class="error-message" style="font-family: 'Courier New', monospace; font-size: 13px; color: #2c3e50;">
                                ${previewMessage}${isLong ? '...' : ''}
                            </div>
                        </div>
                        ${isLong ? '<div class="error-expand-hint">👆 Tam mesajı görmek için tıklayın</div>' : ''}
                    </div>
                `;
            }).join('');
        }
        
        function showErrorModal(errorIndex) {
            const error = allErrors[errorIndex];
            if (!error) return;
            
            document.getElementById('modalErrorTime').textContent = error.timestamp_str || 'Bilinmiyor';
            document.getElementById('modalErrorPID').textContent = error.pid || 'N/A';
            document.getElementById('modalErrorTID').textContent = error.tid || 'N/A';
            document.getElementById('modalErrorMessage').textContent = error.message || 'Mesaj bulunamadı';
            document.getElementById('modalErrorRaw').textContent = error.raw_line || 'Raw log satırı bulunamadı';
            
            document.getElementById('errorModal').style.display = 'block';
        }
        
        function closeErrorModal() {
            document.getElementById('errorModal').style.display = 'none';
        }
        
        // Modal dışına tıklanınca kapat
        window.onclick = function(event) {
            const modal = document.getElementById('errorModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }
        
        function loadZeroTouchData() {
            console.log('👆 Loading zero touch data...');
            fetch('/api/zerotuch')
            .then(response => {
                console.log('👆 Zero touch response status:', response.status);
                return response.json();
            })
            .then(data => {
                console.log('👆 Zero touch data loaded:', data);
                console.log('👆 Data length:', data.length);
                if (data.length > 0) {
                    console.log('👆 First event:', data[0]);
                }
                displayZeroTouch(data);
            })
            .catch(error => {
                console.error('❌ Error loading zero touch data:', error);
            });
        }
        
        function displayZeroTouch(events) {
            const tbody = document.getElementById('zerotouchBody');
            tbody.innerHTML = '';
            
            console.log('👆 Displaying zero touch events:', events);
            
            if (!events || events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px; color: #6c757d;">Zero Touch event bulunamadı</td></tr>';
                console.log('👆 No zero touch events to display');
                return;
            }
            
            console.log(`👆 Displaying ${events.length} zero touch events`);
            
            events.forEach((event, index) => {
                console.log(`👆 Processing event ${index}:`, event);
                const row = tbody.insertRow();
                row.innerHTML = `
                    <td><small>${event.timestamp_str || 'N/A'}</small></td>
                    <td><span class="badge" style="background: #ffc107; color: black;">${event.event_type || 'ZeroTouchEvent'}</span></td>
                    <td>${event.log_pid || 'N/A'}</td>
                    <td>${event.log_tid || 'N/A'}</td>
                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="${event.content || ''}">${(event.content || '').substring(0, 100)}${event.content && event.content.length > 100 ? '...' : ''}</td>
                `;
            });
            
            console.log(`👆 Successfully added ${events.length} rows to table`);
        }
        
        function loadAgentData() {
            fetch('/api/agent_events')
            .then(response => response.json())
            .then(data => {
                allAgentEvents = data;
                displayAgentEvents(data);
            });
        }
        
        function filterAgentEvents() {
            const filter = document.getElementById('agentFilter').value;
            let filteredEvents = allAgentEvents;
            
            if (filter !== 'all') {
                filteredEvents = allAgentEvents.filter(event => event.event_type === filter);
            }
            
            displayAgentEvents(filteredEvents);
        }
        
        function displayAgentEvents(events) {
            const tbody = document.getElementById('agentBody');
            tbody.innerHTML = '';
            
            if (!events || events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">Agent event bulunamadı</td></tr>';
                return;
            }
            
            const getEventColor = (eventType, message) => {
                // Önce mesaj içeriğine göre renk belirle (error durumları için)
                const msg = (message || '').toLowerCase();
                if (msg.includes('error') || msg.includes('failed') || msg.includes('exception')) {
                    return '#dc3545'; // Kırmızı - Hata
                }
                if (msg.includes('warning') || msg.includes('warn')) {
                    return '#ffc107'; // Sarı - Uyarı
                }
                if (msg.includes('timeout') || msg.includes('disconnect') || msg.includes('unable')) {
                    return '#fd7e14'; // Turuncu - Problem
                }
                
                // Sonra event tipine göre varsayılan renk
                const colors = {
                    'AGENT_RESTART': '#dc3545',
                    'AGENT_START': '#28a745',
                    'AGENT_STOP': '#dc3545',
                    'AGENT_VERSION': '#17a2b8',
                    'AGENT_COMMUNICATION': '#28a745', // Başarılı iletişim için yeşil
                    'AGENT_SCANNING': '#6f42c1',
                    'AGENT_IOT': '#17a2b8'
                };
                return colors[eventType] || '#6c757d';
            };
            
            const getStatusIcon = (message) => {
                const msg = (message || '').toLowerCase();
                if (msg.includes('error') || msg.includes('failed') || msg.includes('exception')) {
                    return '🚨'; // Hata
                }
                if (msg.includes('warning') || msg.includes('warn')) {
                    return '⚠️'; // Uyarı
                }
                if (msg.includes('timeout') || msg.includes('disconnect') || msg.includes('unable')) {
                    return '⏳'; // Problem
                }
                if (msg.includes('success') || msg.includes('completed') || msg.includes('started')) {
                    return '✅'; // Başarılı
                }
                return '📋'; // Normal
            };
            
            events.forEach((event, index) => {
                const eventId = `agent-event-${index}`;
                const previewMessage = (event.message || '').substring(0, 80);
                const isLong = (event.message || '').length > 80;
                const eventColor = getEventColor(event.event_type, event.message);
                const statusIcon = getStatusIcon(event.message);
                
                // Ana satır
                const row = tbody.insertRow();
                row.className = 'event-row';
                row.onclick = () => toggleEventDetails(eventId, 'agent');
                
                // Hata içeren satırları vurgula
                const msg = (event.message || '').toLowerCase();
                if (msg.includes('error') || msg.includes('failed') || msg.includes('exception')) {
                    row.style.backgroundColor = '#fff5f5';
                    row.style.borderLeft = '4px solid #dc3545';
                } else if (msg.includes('warning') || msg.includes('warn')) {
                    row.style.backgroundColor = '#fffbf0';
                    row.style.borderLeft = '4px solid #ffc107';
                }
                
                row.innerHTML = `
                    <td><small>${event.timestamp_str || 'N/A'}</small></td>
                    <td>
                        <span class="badge" style="background: ${eventColor}; color: white;">
                            ${statusIcon} ${event.event_type}
                        </span>
                    </td>
                    <td>${event.log_pid}</td>
                    <td>${event.log_tid}</td>
                    <td>
                        <div class="event-preview">${previewMessage}${isLong ? '...' : ''}</div>
                        ${isLong ? '<small style="color: #007bff;">📄 Tam mesaj için tıklayın</small>' : ''}
                    </td>
                    <td><span class="event-expand-icon" id="icon-${eventId}">▶️</span></td>
                `;
                
                // Detay satırı
                if (isLong) {
                    const detailRow = tbody.insertRow();
                    detailRow.innerHTML = `
                        <td colspan="6">
                            <div class="event-details" id="details-${eventId}">
                                <div class="event-meta">
                                    <div class="event-meta-item">
                                        <strong>🕐 Tam Zaman:</strong><br>
                                        ${event.timestamp_str || 'N/A'}
                                    </div>
                                    <div class="event-meta-item">
                                        <strong>🎯 Event Tipi:</strong><br>
                                        ${statusIcon} ${event.event_type}
                                    </div>
                                    <div class="event-meta-item">
                                        <strong>🆔 Process ID:</strong><br>
                                        ${event.log_pid}
                                    </div>
                                    <div class="event-meta-item">
                                        <strong>🧵 Thread ID:</strong><br>
                                        ${event.log_tid}
                                    </div>
                                </div>
                                <div>
                                    <strong>📄 Tam Mesaj:</strong>
                                    <div class="event-full-message" style="border-left: 4px solid ${eventColor};">${event.message || 'Mesaj bulunamadı'}</div>
                                </div>
                            </div>
                        </td>
                    `;
                }
            });
        }
        
        function loadSystemData() {
            fetch('/api/system_events')
            .then(response => response.json())
            .then(data => {
                allSystemEvents = data;
                displaySystemEvents(data);
            });
        }
        
        function filterSystemEvents() {
            const filter = document.getElementById('systemFilter').value;
            let filteredEvents = allSystemEvents;
            
            if (filter !== 'all') {
                filteredEvents = allSystemEvents.filter(event => event.event_type === filter);
            }
            
            displaySystemEvents(filteredEvents);
        }
        
        function displaySystemEvents(events) {
            const tbody = document.getElementById('systemBody');
            tbody.innerHTML = '';
            
            if (!events || events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">Sistem event bulunamadı</td></tr>';
                return;
            }
            
            const getSystemColor = (eventType, message) => {
                // Önce mesaj içeriğine göre renk belirle (error durumları için)
                const msg = (message || '').toLowerCase();
                if (msg.includes('error') || msg.includes('failed') || msg.includes('exception')) {
                    return '#dc3545'; // Kırmızı - Hata
                }
                if (msg.includes('warning') || msg.includes('warn')) {
                    return '#ffc107'; // Sarı - Uyarı
                }
                if (msg.includes('timeout') || msg.includes('disconnect') || msg.includes('unable')) {
                    return '#fd7e14'; // Turuncu - Problem
                }
                if (msg.includes('high') || msg.includes('overload') || msg.includes('limit')) {
                    return '#e83e8c'; // Pembe - Kaynak problemi
                }
                
                // Sonra event tipine göre varsayılan renk
                const colors = {
                    'SYSTEM_PERFORMANCE': '#17a2b8', // Normal performans için mavi
                    'SYSTEM_MEMORY': '#28a745', // Normal memory için yeşil
                    'SYSTEM_THREAD': '#6f42c1',
                    'SYSTEM_INFO': '#28a745',
                    'SYSTEM_WARNING': '#ffc107'
                };
                return colors[eventType] || '#6c757d';
            };
            
            const getStatusIcon = (message) => {
                const msg = (message || '').toLowerCase();
                if (msg.includes('error') || msg.includes('failed') || msg.includes('exception')) {
                    return '🚨'; // Hata
                }
                if (msg.includes('warning') || msg.includes('warn')) {
                    return '⚠️'; // Uyarı
                }
                if (msg.includes('timeout') || msg.includes('disconnect') || msg.includes('unable')) {
                    return '⏳'; // Problem
                }
                if (msg.includes('high') || msg.includes('overload') || msg.includes('limit')) {
                    return '📈'; // Kaynak problemi
                }
                if (msg.includes('started') || msg.includes('created') || msg.includes('initialized')) {
                    return '🟢'; // Başlatıldı
                }
                if (msg.includes('stopped') || msg.includes('terminated') || msg.includes('finished')) {
                    return '🔴'; // Durduruldu
                }
                return '📊'; // Normal sistem
            };
            
            events.forEach((event, index) => {
                const eventId = `system-event-${index}`;
                const previewMessage = (event.message || '').substring(0, 80);
                const isLong = (event.message || '').length > 80;
                const eventColor = getSystemColor(event.event_type, event.message);
                const statusIcon = getStatusIcon(event.message);
                
                // Ana satır
                const row = tbody.insertRow();
                row.className = 'event-row';
                row.onclick = () => toggleEventDetails(eventId, 'system');
                
                // Hata içeren satırları vurgula
                const msg = (event.message || '').toLowerCase();
                if (msg.includes('error') || msg.includes('failed') || msg.includes('exception')) {
                    row.style.backgroundColor = '#fff5f5';
                    row.style.borderLeft = '4px solid #dc3545';
                } else if (msg.includes('warning') || msg.includes('warn')) {
                    row.style.backgroundColor = '#fffbf0';
                    row.style.borderLeft = '4px solid #ffc107';
                } else if (msg.includes('timeout') || msg.includes('high') || msg.includes('overload')) {
                    row.style.backgroundColor = '#fff8f0';
                    row.style.borderLeft = '4px solid #fd7e14';
                }
                
                row.innerHTML = `
                    <td><small>${event.timestamp_str || 'N/A'}</small></td>
                    <td>
                        <span class="badge" style="background: ${eventColor}; color: white;">
                            ${statusIcon} ${event.event_type}
                        </span>
                    </td>
                    <td>${event.log_pid}</td>
                    <td>${event.log_tid}</td>
                    <td>
                        <div class="event-preview">${previewMessage}${isLong ? '...' : ''}</div>
                        ${isLong ? '<small style="color: #007bff;">📄 Tam mesaj için tıklayın</small>' : ''}
                    </td>
                    <td><span class="event-expand-icon" id="icon-${eventId}">▶️</span></td>
                `;
                
                // Detay satırı
                if (isLong) {
                    const detailRow = tbody.insertRow();
                    detailRow.innerHTML = `
                        <td colspan="6">
                            <div class="event-details" id="details-${eventId}">
                                <div class="event-meta">
                                    <div class="event-meta-item">
                                        <strong>🕐 Tam Zaman:</strong><br>
                                        ${event.timestamp_str || 'N/A'}
                                    </div>
                                    <div class="event-meta-item">
                                        <strong>🎯 Event Tipi:</strong><br>
                                        ${statusIcon} ${event.event_type}
                                    </div>
                                    <div class="event-meta-item">
                                        <strong>🆔 Process ID:</strong><br>
                                        ${event.log_pid}
                                    </div>
                                    <div class="event-meta-item">
                                        <strong>🧵 Thread ID:</strong><br>
                                        ${event.log_tid}
                                    </div>
                                </div>
                                <div>
                                    <strong>📄 Tam Mesaj:</strong>
                                    <div class="event-full-message" style="border-left: 4px solid ${eventColor};">${event.message || 'Mesaj bulunamadı'}</div>
                                </div>
                            </div>
                        </td>
                    `;
                }
            });
        }
        
        function toggleEventDetails(eventId, eventType) {
            const details = document.getElementById(`details-${eventId}`);
            const icon = document.getElementById(`icon-${eventId}`);
            const row = details ? details.closest('tr').previousElementSibling : null;
            
            if (details) {
                if (details.classList.contains('show')) {
                    details.classList.remove('show');
                    icon.textContent = '▶️';
                    icon.classList.remove('expanded');
                    if (row) row.classList.remove('expanded');
                } else {
                    details.classList.add('show');
                    icon.textContent = '🔽';
                    icon.classList.add('expanded');
                    if (row) row.classList.add('expanded');
                }
            }
        }
        
        function expandAllAgentEvents() {
            document.querySelectorAll('#agentBody .event-details').forEach(details => {
                const eventId = details.id.replace('details-', '');
                const icon = document.getElementById(`icon-${eventId}`);
                const row = details.closest('tr').previousElementSibling;
                
                details.classList.add('show');
                if (icon) {
                    icon.textContent = '🔽';
                    icon.classList.add('expanded');
                }
                if (row) row.classList.add('expanded');
            });
        }
        
        function collapseAllAgentEvents() {
            document.querySelectorAll('#agentBody .event-details').forEach(details => {
                const eventId = details.id.replace('details-', '');
                const icon = document.getElementById(`icon-${eventId}`);
                const row = details.closest('tr').previousElementSibling;
                
                details.classList.remove('show');
                if (icon) {
                    icon.textContent = '▶️';
                    icon.classList.remove('expanded');
                }
                if (row) row.classList.remove('expanded');
            });
        }
        
        function expandAllSystemEvents() {
            document.querySelectorAll('#systemBody .event-details').forEach(details => {
                const eventId = details.id.replace('details-', '');
                const icon = document.getElementById(`icon-${eventId}`);
                const row = details.closest('tr').previousElementSibling;
                
                details.classList.add('show');
                if (icon) {
                    icon.textContent = '🔽';
                    icon.classList.add('expanded');
                }
                if (row) row.classList.add('expanded');
            });
        }
        
        function collapseAllSystemEvents() {
            document.querySelectorAll('#systemBody .event-details').forEach(details => {
                const eventId = details.id.replace('details-', '');
                const icon = document.getElementById(`icon-${eventId}`);
                const row = details.closest('tr').previousElementSibling;
                
                details.classList.remove('show');
                if (icon) {
                    icon.textContent = '▶️';
                    icon.classList.remove('expanded');
                }
                if (row) row.classList.remove('expanded');
            });
        }
        
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            
            document.getElementById(tabName + 'Tab').classList.remove('hidden');
            event.target.classList.add('active');
        }
        
        // Export functions
        function exportCSV() {
            window.open('/api/export/csv', '_blank');
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
            })
            .catch(error => {
                showMessage('❌ Sunucu bağlantısı kurulamadı', 'danger');
            });
        });
    </script>
</body>
</html>
    '''

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
        
        response_data = {
            'success': True,
            'message': f'Log dosyası başarıyla analiz edildi. {parsed_data["statistics"]["total_entries"]} kayıt bulundu.',
            'statistics': parsed_data['statistics']
        }
        
        return jsonify(response_data)
    
    except Exception as e:
        print(f"❌ Error in upload: {str(e)}")
        return jsonify({
            'error': f'Dosya analiz hatası: {str(e)}', 
            'success': False
        }), 500

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
                             if search.lower() in p['executable'].lower() 
                             or search.lower() in p['execute_user'].lower()
                             or search.lower() in p['policy_name'].lower()]
        
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
        print("👆 get_zerotuch called")
        zerotuch_events = log_parser.parsed_data['zero_touch_events']
        print(f"👆 Found {len(zerotuch_events)} zero touch events")
        print(f"👆 Sample events: {zerotuch_events[:2] if zerotuch_events else 'None'}")
        return jsonify(zerotuch_events)
    except Exception as e:
        print(f"❌ Error in get_zerotuch: {str(e)}")
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

@app.route('/api/export/csv')
def export_csv():
    """Process start verilerini CSV olarak export et"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'Timestamp', 'Process PID', 'Parent PID', 'Executable', 
            'Command Line', 'Policy Name', 'Action', 'Execute User'
        ])
        
        for proc in log_parser.parsed_data['process_starts']:
            writer.writerow([
                proc['timestamp_str'],
                proc['process_pid'],
                proc['parent_pid'],
                proc['executable'],
                proc['command_line'],
                proc['policy_name'],
                proc['action_name'],
                proc['execute_user']
            ])
        
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cyberark_process_starts.csv'}
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
        
        writer.writerow(['Timestamp', 'PID', 'TID', 'Error Message', 'Raw Line'])
        
        for error in log_parser.parsed_data['errors']:
            writer.writerow([
                error['timestamp_str'],
                error['pid'],
                error['tid'],
                error['message'],
                error['raw_line']
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
        
        writer.writerow(['Timestamp', 'Event Type', 'Log PID', 'Log TID', 'Content'])
        
        for event in log_parser.parsed_data['zero_touch_events']:
            writer.writerow([
                event['timestamp_str'],
                event['event_type'],
                event['log_pid'],
                event['log_tid'],
                event['content']
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
        
        writer.writerow(['Timestamp', 'Event Type', 'Log PID', 'Log TID', 'Message'])
        
        for event in log_parser.parsed_data['agent_events']:
            writer.writerow([
                event['timestamp_str'],
                event['event_type'],
                event['log_pid'],
                event['log_tid'],
                event['message']
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
        
        writer.writerow(['Timestamp', 'Event Type', 'Log PID', 'Log TID', 'Message'])
        
        for event in log_parser.parsed_data['system_events']:
            writer.writerow([
                event['timestamp_str'],
                event['event_type'],
                event['log_pid'],
                event['log_tid'],
                event['message']
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

@app.route('/test')
def test():
    """Test endpoint"""
    return jsonify({
        'status': 'OK',
        'message': 'CyberArk Log Analyzer çalışıyor!',
        'port': 3000,
        'endpoints': [
            'GET /',
            'POST /upload',
            'GET /api/process_starts',
            'GET /api/errors',
            'GET /api/zerotuch',
            'GET /api/agent_events',
            'GET /api/system_events',
            'GET /api/statistics',
            'GET /api/export/csv',
            'GET /api/export/errors_csv',
            'GET /api/export/zerotuch_csv',
            'GET /api/export/agent_csv',
            'GET /api/export/system_csv',
            'GET /test'
        ],
        'parser_status': {
            'total_entries': len(log_parser.log_entries),
            'process_starts': len(log_parser.parsed_data['process_starts']),
            'errors': len(log_parser.parsed_data['errors']),
            'agent_events': len(log_parser.parsed_data['agent_events']),
            'system_events': len(log_parser.parsed_data['system_events'])
        }
    })

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    print("🚀 CyberArk Log Analyzer Başlatılıyor...")
    print("🌐 Sunucu adresi: http://localhost:3000")
    print("🧪 Test endpoint: http://localhost:3000/test")
    print("📁 .trace, .log, .txt dosyalarını yükleyebilirsiniz")
    print("-" * 60)
    app.run(debug=True, host='0.0.0.0', port=3000)