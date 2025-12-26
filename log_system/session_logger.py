import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import asyncio
from enum import Enum

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class AttackType(Enum):
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PORT_SCAN = "port_scan"
    MALWARE = "malware"
    DOS = "dos"
    PHISHING = "phishing"
    XSS = "xss"
    CSRF = "csrf"

class SessionLogger:
    
    def __init__(self, log_dir: str = "logs", max_file_size: int = 10485760):
        self.log_dir = Path(log_dir)
        self.max_file_size = max_file_size
        
        self.log_dir.mkdir(exist_ok=True)
        
        self.setup_logging()
        
        self.active_sessions = {}
        self.session_counter = 0
    
    def setup_logging(self):
        self.logger = logging.getLogger('mimic')
        self.logger.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler = logging.FileHandler(self.log_dir / 'honeypot.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def create_session(self, ip: str, port: int, service: str) -> str:
        session_id = f"sess_{self.session_counter:08d}"
        self.session_counter += 1
        
        session_data = {
            'session_id': session_id,
            'ip': ip,
            'port': port,
            'service': service,
            'start_time': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'commands': [],
            'threats': [],
            'ended': False
        }
        
        self.active_sessions[session_id] = session_data
        
        # Log da sessão
        self.log_session_event(session_id, 'SESSION_START', {
            'ip': ip,
            'port': port,
            'service': service
        })
        
        return session_id
    
    def log_session_event(self, session_id: str, event_type: str, data: Dict[str, Any]):
        """Regista evento de sessão"""
        if session_id not in self.active_sessions:
            self.logger.warning(f"Unknown session: {session_id}")
            return
        
        session = self.active_sessions[session_id]
        session['last_activity'] = datetime.now().isoformat()
        
        event = {
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'event_type': event_type,
            'data': data
        }
        
        # Adiciona à sessão
        if event_type == 'COMMAND':
            session['commands'].append(data.get('command'))
        elif event_type == 'THREAT_DETECTED':
            session['threats'].append(data.get('threat_type'))
        
        # Escreve no log
        self.write_json_log('session_events', event)
        
        # Log no console se for importante
        if event_type in ['THREAT_DETECTED', 'SESSION_END']:
            self.logger.info(f"Session {session_id}: {event_type} - {data}")
    
    def log_command(self, session_id: str, command: str):
        """Regista comando executado"""
        self.log_session_event(session_id, 'COMMAND', {
            'command': command,
            'timestamp': datetime.now().isoformat()
        })
    
    def log_threat(self, session_id: str, threat_type: AttackType, 
                  details: Dict[str, Any]):
        """Regista ameaça detectada"""
        self.log_session_event(session_id, 'THREAT_DETECTED', {
            'threat_type': threat_type.value,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        
        # Também log como alerta
        self.log_alert(threat_type, details)
    
    def log_alert(self, alert_type: AttackType, data: Dict[str, Any]):
        """Regista alerta de segurança"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type.value,
            'level': self.get_threat_level(alert_type).value,
            'data': data
        }
        
        self.write_json_log('alerts', alert)
        self.logger.warning(f"ALERT: {alert_type.value} - {data}")
    
    def get_threat_level(self, threat_type: AttackType) -> LogLevel:
        """Determina nível de ameaça"""
        threat_levels = {
            AttackType.BRUTE_FORCE: LogLevel.WARNING,
            AttackType.PORT_SCAN: LogLevel.INFO,
            AttackType.SQL_INJECTION: LogLevel.ERROR,
            AttackType.COMMAND_INJECTION: LogLevel.ERROR,
            AttackType.MALWARE: LogLevel.CRITICAL,
            AttackType.DOS: LogLevel.WARNING,
            AttackType.PHISHING: LogLevel.WARNING,
            AttackType.XSS: LogLevel.ERROR,
            AttackType.CSRF: LogLevel.WARNING
        }
        return threat_levels.get(threat_type, LogLevel.WARNING)
    
    def end_session(self, session_id: str, reason: str = "normal"):
        """Termina sessão"""
        if session_id not in self.active_sessions:
            return
        
        session = self.active_sessions[session_id]
        session['ended'] = True
        session['end_time'] = datetime.now().isoformat()
        session['end_reason'] = reason
        
        # Log do fim da sessão
        self.log_session_event(session_id, 'SESSION_END', {
            'reason': reason,
            'duration': self.calculate_session_duration(session_id),
            'total_commands': len(session['commands']),
            'total_threats': len(session['threats'])
        })
        
        # Move para histórico
        self.archive_session(session_id)
    
    def calculate_session_duration(self, session_id: str) -> float:
        """Calcula duração da sessão"""
        session = self.active_sessions.get(session_id)
        if not session:
            return 0
        
        start_time = datetime.fromisoformat(session['start_time'])
        end_time = datetime.fromisoformat(session.get('end_time', datetime.now().isoformat()))
        
        return (end_time - start_time).total_seconds()
    
    def archive_session(self, session_id: str):
        """Arquiva sessão terminada"""
        if session_id not in self.active_sessions:
            return
        
        session = self.active_sessions[session_id]
        
        # Escreve resumo da sessão
        summary = {
            'session_id': session_id,
            'ip': session['ip'],
            'port': session['port'],
            'service': session['service'],
            'start_time': session['start_time'],
            'end_time': session.get('end_time'),
            'duration': self.calculate_session_duration(session_id),
            'total_commands': len(session['commands']),
            'commands': session['commands'][-100:],  # Últimos 100 comandos
            'threats': session['threats'],
            'end_reason': session.get('end_reason', 'unknown')
        }
        
        self.write_json_log('session_summaries', summary)
        
        # Remove da memória
        del self.active_sessions[session_id]
    
    def write_json_log(self, log_type: str, data: Dict[str, Any]):
        """Escreve log em formato JSON"""
        log_file = self.log_dir / f"{log_type}.jsonl"
        
        # Rotaciona arquivo se muito grande
        if log_file.exists() and log_file.stat().st_size > self.max_file_size:
            self.rotate_log_file(log_file)
        
        # Escreve linha JSON
        with open(log_file, 'a') as f:
            json.dump(data, f)
            f.write('\n')
    
    def rotate_log_file(self, log_file: Path):
        """Rotaciona arquivo de log"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = log_file.parent / f"{log_file.stem}_{timestamp}.jsonl"
        
        # Renomeia arquivo atual
        if log_file.exists():
            log_file.rename(backup_file)
        
        # Limpa backups antigos (mantém últimos 10)
        self.cleanup_old_backups(log_file)
    
    def cleanup_old_backups(self, log_file: Path, keep_count: int = 10):
        """Limpa backups antigos"""
        pattern = f"{log_file.stem}_*.jsonl"
        backups = sorted(log_file.parent.glob(pattern))
        
        if len(backups) > keep_count:
            for old_backup in backups[:-keep_count]:
                old_backup.unlink()
    
    def get_session_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Obtém estatísticas de sessões"""
        # Em produção, leria do arquivo de logs
        return {
            'total_sessions': len(self.active_sessions),
            'active_sessions': sum(1 for s in self.active_sessions.values() 
                                  if not s.get('ended', False)),
            'threats_today': 0,  # Seria calculado
            'top_attackers': self.get_top_attackers(hours)
        }
    
    def get_top_attackers(self, hours: int = 24) -> list:
        """Obtém top atacantes"""
        # Em produção, agregaria dos logs
        return [
            {'ip': '192.168.1.100', 'count': 45},
            {'ip': '10.0.0.25', 'count': 32},
            {'ip': '172.16.0.5', 'count': 21}
        ]
    
    def export_logs(self, start_date: datetime, end_date: datetime, 
                   format: str = 'json') -> str:
        """Exporta logs em formato específico"""
        # Em produção, filtraria logs por data
        return json.dumps({'message': 'Export feature not implemented'}, indent=2)