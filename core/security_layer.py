import ipaddress
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict
import logging
from enum import Enum

class BlockAction(Enum):
    NONE = "none"
    TEMPORARY = "temporary"
    PERMANENT = "permanent"
    REDIRECT = "redirect"

class SecurityLayer:
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.DEBUG)  # Aumentar nível de log para DEBUG
        
        self.enabled = config.get('enabled', True)
        self.logger.debug(f"Security layer enabled: {self.enabled}")

        # Adicionar handler para console
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('[SECURITY] %(levelname)s: %(message)s')
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        self.blocked_ips: Set[str] = set()
        self.temp_blocked: Dict[str, datetime] = {}
        self.failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.connection_counts: Dict[str, List[datetime]] = defaultdict(list)
        
        self.rate_limit_config = config.get('rate_limits', {})
        self.block_config = config.get('ip_blocking', {})
        self.geo_block_list = config.get('geo_block', [])
        
        self.logger.debug(f"Security layer initialized with config: {self.rate_limit_config}")
        self.logger.debug(f"Max failed logins: {self.rate_limit_config.get('max_failed_logins', 10)}")
        
        # Se segurança desabilitada, limpa todos os bloqueios
        if not self.enabled:
            self.logger.info("Security disabled - clearing all blocks")
            self.blocked_ips.clear()
            self.temp_blocked.clear()
            self.failed_attempts.clear()
        
        self.cleanup_task = asyncio.create_task(self.periodic_cleanup())
    
    def validate_port(self, port: int) -> bool:
        if port < 1024:
            print(f"Port {port} may require root privileges")
        
        dangerous_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 443: 'https', 3306: 'mysql',
            3389: 'rdp', 5900: 'vnc', 8080: 'http-proxy'
        }
        
        if port in dangerous_ports:
            self.logger.info(f"Opening known service port: {port} ({dangerous_ports[port]})")
        
        return 1 <= port <= 65535
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Verifica se IP está autorizado"""
        self.logger.debug(f"Checking if IP {ip} is allowed")
        
        if not self.enabled:
            self.logger.debug(f"Security disabled, allowing IP {ip}")
            return True

        if ip in self.blocked_ips:
            self.logger.warning(f"IP {ip} is permanently blocked")
            return False
        
        if ip in self.temp_blocked:
            block_until = self.temp_blocked[ip]
            if datetime.now() < block_until:
                remaining = block_until - datetime.now()
                self.logger.warning(f"IP {ip} is temporarily blocked for {remaining.total_seconds():.0f} more seconds")
                return False
            else:
                del self.temp_blocked[ip]
                self.logger.info(f"Temporary block for IP {ip} has expired")
        
        if not self.check_rate_limit(ip):
            self.logger.warning(f"IP {ip} exceeded rate limit - blocking connection")
            return False
        
        self.logger.debug(f"IP {ip} is allowed")
        return True
    
    def check_rate_limit(self, ip: str) -> bool:
        """Verifica rate limiting por IP"""
        if not self.enabled:
            self.logger.debug(f"Security disabled, rate limit check passed for IP {ip}")
            return True
        
        now = datetime.now()
        
        # Limpa tentativas antigas
        window_seconds = self.rate_limit_config.get('window_seconds', 60)
        window_start = now - timedelta(seconds=window_seconds)
        
        # Filtra tentativas recentes
        recent_failures = [
            attempt for attempt in self.failed_attempts[ip]
            if attempt > window_start
        ]
        self.failed_attempts[ip] = recent_failures
        
        max_failures = self.rate_limit_config.get('max_failed_logins', 10)
        self.logger.debug(f"IP {ip}: {len(recent_failures)} failed attempts in last {window_seconds}s (max: {max_failures})")
        
        # Verifica limite de falhas
        if len(recent_failures) >= max_failures:
            self.logger.warning(f"IP {ip} exceeded max failed logins ({len(recent_failures)} >= {max_failures})")
            return False
        
        # Verifica limite de conexões
        max_connections = self.rate_limit_config.get('max_connections_per_minute', 60)
        recent_connections = [
            conn for conn in self.connection_counts[ip]
            if conn > window_start
        ]
        self.connection_counts[ip] = recent_connections
        
        if len(recent_connections) >= max_connections:
            self.logger.warning(f"IP {ip} exceeded max connections ({len(recent_connections)} >= {max_connections})")
            return False
        
        return True
    
    def record_connection(self, ip: str):
        """Regista uma nova conexão"""
        self.connection_counts[ip].append(datetime.now())
        self.logger.debug(f"Recorded connection from IP {ip}")
    
    def record_failed_attempt(self, ip: str):
        """Regista tentativa falhada"""
        if not self.enabled:
            self.logger.debug(f"Security disabled, not recording failed attempt from {ip}")
            return
        
        self.failed_attempts[ip].append(datetime.now())
        recent_count = len([attempt for attempt in self.failed_attempts[ip] 
                           if attempt > datetime.now() - timedelta(seconds=60)])
        
        self.logger.warning(f"Recorded failed attempt from IP {ip} (total recent: {recent_count})")
        
        # Auto-block se muitas tentativas (APENAS se security enabled)
        auto_block_threshold = self.block_config.get('auto_block_failed_logins', 
                                                    self.rate_limit_config.get('max_failed_logins', 10))
        
        if recent_count >= auto_block_threshold:
            self.logger.warning(f"Auto-blocking IP {ip} for too many failed attempts ({recent_count} >= {auto_block_threshold})")
            block_duration = self.rate_limit_config.get('block_duration_minutes', 60)
            self.temp_block_ip(ip, minutes=block_duration)
    
    def temp_block_ip(self, ip: str, minutes: int = 60):
        """Bloqueia IP temporariamente"""
        if not self.enabled:
            self.logger.debug(f"Security disabled, not blocking IP {ip}")
            return
            
        block_duration = self.rate_limit_config.get('block_duration_minutes', minutes)
        block_until = datetime.now() + timedelta(minutes=block_duration)
        self.temp_blocked[ip] = block_until
        self.logger.warning(f"Temporarily blocked IP {ip} until {block_until.strftime('%H:%M:%S')} ({block_duration} minutes)")
    
    def perm_block_ip(self, ip: str):
        """Bloqueia IP permanentemente"""
        self.blocked_ips.add(ip)
        self.logger.critical(f"Permanently blocked IP {ip}")
    
    def unblock_ip(self, ip: str):
        """Remove bloqueio de IP"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        
        if ip in self.temp_blocked:
            del self.temp_blocked[ip]
        
        self.logger.info(f"Unblocked IP {ip}")
    
    def detect_attack_pattern(self, ip: str, data: Dict) -> Optional[str]:
        """Deteça padrões de ataque"""
        attack_types = [
            self.detect_brute_force,
            self.detect_port_scan,
            self.detect_sql_injection,
            self.detect_command_injection,
            self.detect_dos_attempt
        ]
        
        for detector in attack_types:
            result = detector(ip, data)
            if result:
                return result
        
        return None
    
    def detect_brute_force(self, ip: str, data: Dict) -> Optional[str]:
        """Deteça tentativas de brute force"""
        if 'password_attempts' in data:
            attempts = data['password_attempts']
            if attempts >= 5:  # Limite para deteção
                return 'brute_force'
        
        # Verifica falhas rápidas
        recent_failures = self.failed_attempts.get(ip, [])
        if len(recent_failures) >= 3:
            # Verifica se foram em rápido sucessão
            if len(recent_failures) >= 3:
                time_diff = (recent_failures[-1] - recent_failures[0]).total_seconds()
                if time_diff < 10:  # 3 falhas em menos de 10 segundos
                    return 'brute_force'
        
        return None
    
    def detect_port_scan(self, ip: str, data: Dict) -> Optional[str]:
        """Deteça port scanning"""
        if 'ports_accessed' in data:
            ports = data['ports_accessed']
            if len(ports) >= 5:  # Múltiplas portas
                return 'port_scan'
        
        return None
    
    def detect_sql_injection(self, ip: str, data: Dict) -> Optional[str]:
        """Deteça SQL injection"""
        sql_keywords = ['SELECT', 'UNION', 'INSERT', 'DELETE', 'DROP', 
                       'UPDATE', 'OR', 'AND', '--', '/*', '*/']
        
        if 'query' in data:
            query = data['query'].upper()
            if any(keyword in query for keyword in sql_keywords):
                # Verifica se é injection (não apenas query normal)
                suspicious_patterns = [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "'; DROP TABLE",
                    "UNION SELECT"
                ]
                if any(pattern in query for pattern in suspicious_patterns):
                    return 'sql_injection'
        
        return None
    
    def detect_command_injection(self, ip: str, data: Dict) -> Optional[str]:
        """Deteça command injection"""
        dangerous_commands = [
            ';', '|', '&', '`', '$', '(', ')', '<', '>',
            'cat /etc/passwd',
            'rm -rf',
            'wget', 'curl',
            'python', 'perl', 'bash', 'sh'
        ]
        
        if 'command' in data:
            command = data['command']
            for dangerous in dangerous_commands:
                if dangerous in command:
                    return 'command_injection'
        
        return None
    
    def detect_dos_attempt(self, ip: str, data: Dict) -> Optional[str]:
        """Deteça tentativas de DoS"""
        # Verifica muitas conexões em pouco tempo
        recent_connections = self.connection_counts.get(ip, [])
        if len(recent_connections) >= 20:  # 20 conexões
            # Verifica se foram em rápido sucessão
            if len(recent_connections) >= 20:
                time_diff = (recent_connections[-1] - recent_connections[0]).total_seconds()
                if time_diff < 5:  # 20 conexões em menos de 5 segundos
                    return 'dos_attempt'
        
        return None
    
    async def periodic_cleanup(self):
        """Limpeza periódica de estado"""
        while True:
            await asyncio.sleep(300)  # 5 minutos
            
            now = datetime.now()
            cleanup_threshold = timedelta(hours=1)
            
            # Limpa tentativas falhadas antigas
            for ip in list(self.failed_attempts.keys()):
                self.failed_attempts[ip] = [
                    attempt for attempt in self.failed_attempts[ip]
                    if now - attempt < cleanup_threshold
                ]
                if not self.failed_attempts[ip]:
                    del self.failed_attempts[ip]
            
            # Limpa contagens de conexão antigas
            for ip in list(self.connection_counts.keys()):
                self.connection_counts[ip] = [
                    conn for conn in self.connection_counts[ip]
                    if now - conn < cleanup_threshold
                ]
                if not self.connection_counts[ip]:
                    del self.connection_counts[ip]
            
            # Limpa bloqueios temporários expirados
            expired_ips = [
                ip for ip, block_until in self.temp_blocked.items()
                if now >= block_until
            ]
            for ip in expired_ips:
                del self.temp_blocked[ip]
            
            self.logger.debug("Security layer cleanup completed")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Obtém estatísticas de segurança"""
        return {
            'blocked_ips_count': len(self.blocked_ips),
            'temp_blocked_count': len(self.temp_blocked),
            'monitored_ips_count': len(self.failed_attempts),
            'recent_blocks': list(self.temp_blocked.keys())[:10]
        }
    
    def get_block_message(self, ip: str) -> str:
        """Retorna mensagem de bloqueio para o IP"""
        if ip in self.blocked_ips:
            return f"IP {ip} permanently blocked"
        
        if ip in self.temp_blocked:
            block_until = self.temp_blocked[ip]
            remaining = block_until - datetime.now()
            minutes = int(remaining.total_seconds() / 60)
            return f"IP {ip} temporarily blocked for {minutes} more minutes"
        
        return "IP not blocked"