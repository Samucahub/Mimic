import asyncio
import yaml
from typing import Dict, Any
from core.port_manager import PortManager
from core.security_layer import SecurityLayer
from log_system.session_logger import SessionLogger

class MIMICController:
    def __init__(self, config_path: str = "config/honeypot.yaml"):
        self.config = self.load_config(config_path)
        self.security = SecurityLayer(self.config.get('security', {}))
        self.port_manager = PortManager()
        self.logger = SessionLogger()
        self.services = {}
        self.running = False
        
    def load_config(self, path: str) -> Dict[str, Any]:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    
    async def start_service(self, port: int, service_config: Dict):
        service_type = service_config.get('type', 'generic')
        service = None
        
        enriched_config = service_config.copy()
        enriched_config.update({
            'hostname': self.config.get('system', {}).get('hostname', 'ubuntu-server'),
            'username': self.config.get('system', {}).get('username', 'admin'),
            'password': self.config.get('system', {}).get('password', 'admin123'),
            'os_template': self.config.get('system', {}).get('os_template', 'Ubuntu'),
            'any_auth': self.config.get('options', {}).get('any_auth', True),
            'human_patterns': self.config.get('options', {}).get('human_patterns', True)
        })
        
        try:
            if service_type == 'ssh':
                from core.service_emulator.ssh_emulator import SSHService
                service = SSHService(port, enriched_config)
            elif service_type == 'http':
                from core.service_emulator.http_emulator import HTTPService
                service = HTTPService(port, service_config)
            elif service_type == 'ftp':
                from core.service_emulator.ftp_emulator import FTPService
                service = FTPService(port, service_config)
            elif service_type == 'mysql':
                from core.service_emulator.mysql_emulator import MySQLService
                service = MySQLService(port, service_config)
            elif service_type == 'telnet':
                from core.service_emulator.telnet_emulator import TelnetService
                service = TelnetService(port, service_config)
            else:
                print(f"[!] Unknown service type: {service_type}")
                return
                
            if service:
                task = asyncio.create_task(service.start())
                service.server_task = task
                self.services[port] = service
                print(f"[OK] Started {service_type} on port {port}")
            else:
                print(f"[!] Failed to create service {service_type}")
                
        except ImportError as e:
            print(f"[!] Failed to load service {service_type}: {e}")
        except Exception as e:
            print(f"[!] Error starting service {service_type}: {e}")
    
    async def start_all_services(self):
        if 'services' not in self.config:
            print("[!] No services configured")
            return

        enabled_services = {
            port: config for port, config in self.config['services'].items()
            if config.get('enabled', True)
        }

        print(f"[*] Found {len(enabled_services)} service(s) to start")

        for port, config in enabled_services.items():
            port_int = int(port)
            if self.security.validate_port(port_int):
                await self.start_service(port_int, config)
                await asyncio.sleep(0.1)

        self.running = True
        print("\n[OK] MIMIC Honeypot READY")
    
    async def stop(self):
        print("\n[*] Stopping services...")
        
        for port, service in self.services.items():
            if service.server_task and not service.server_task.done():
                service.server_task.cancel()
                
        await asyncio.sleep(0.2)
        
        stop_tasks = []
        for port, service in self.services.items():
            if hasattr(service, 'stop'):
                stop_tasks.append(service.stop())
                
        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)
            
        self.services.clear()
        self.running = False
        print("[OK] All services stopped")