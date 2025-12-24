import asyncio
import random
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import logging

class BaseService(ABC):
    
    def __init__(self, port: int, config: Dict[str, Any]):
        self.port = port
        self.config = config
        self.name = config.get('name', 'Unknown Service')
        self.banner = config.get('banner', '')
        self.is_running = False
        self.connections = 0
        self.logger = logging.getLogger(f'service.{port}')
        self.server = None
        self.server_task = None
        
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        service_type = config.get('type', 'generic').lower()
        self.json_log_path = log_dir / f"{service_type}_honeypot.jsonl"
        
        # Configuração de comportamento
        self.response_delay = config.get('response_delay', {'min': 0.1, 'max': 1.0})
        self.error_rate = config.get('error_rate', 0.05)  # 5% de erro
        self.session_timeout = config.get('session_timeout', 300)
        
    async def start(self):
        """Inicia o serviço"""
        self.is_running = True
        self.server = None
        self.logger.info(f"Starting {self.name} on port {self.port}")
        
        try:
            # Cria servidor assíncrono
            self.server = await asyncio.start_server(
                self.handle_connection,
                host='0.0.0.0',
                port=self.port,
                reuse_address=True
            )
            
            self.logger.info(f"{self.name} listening on port {self.port}")
            # Mantém servidor rodando
            async with self.server:
                await self.server.serve_forever()
                
        except asyncio.CancelledError:
            self.logger.info(f"{self.name} cancelled")
        except Exception as e:
            self.logger.error(f"Failed to start {self.name}: {e}")
            raise
    
    async def stop(self):
        """Para o serviço"""
        self.is_running = False
        self.logger.info(f"Stopping {self.name} on port {self.port}")
        if self.server:
            self.server.close()
            await self.server.wait_closed()
    
    @abstractmethod
    async def handle_connection(self, reader: asyncio.StreamReader, 
                               writer: asyncio.StreamWriter):
        """Manipula uma nova conexão (implementar em subclasses)"""
        pass
    
    def simulate_human_delay(self):
        """Simula delay humano"""
        if self.response_delay.get('random', True):
            delay = random.uniform(
                self.response_delay.get('min', 0.1),
                self.response_delay.get('max', 1.0)
            )
            return asyncio.sleep(delay)
        return asyncio.sleep(self.response_delay.get('fixed', 0.5))
    
    def should_generate_error(self) -> bool:
        """Determina se deve gerar um erro"""
        return random.random() < self.error_rate
    
    def generate_error_response(self) -> str:
        """Gera uma resposta de erro"""
        errors = [
            "Connection timed out",
            "Protocol error",
            "Invalid command",
            "Access denied",
            "Service unavailable",
            "Internal server error"
        ]
        return random.choice(errors)
    
    def log_connection(self, ip: str):
        """Regista uma nova conexão"""
        self.connections += 1
        self.logger.info(f"New connection from {ip} to {self.name}")
        
        # Log estruturado em JSON
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "connection",
            "service": self.config.get('type', 'generic'),
            "port": self.port,
            "source_ip": ip,
            "connection_number": self.connections
        }
        self._write_json_log(log_entry)
    
    def log_command(self, ip: str, command: str):
        """Regista um comando executado"""
        self.logger.debug(f"Command from {ip}: {command}")
        
        # Log estruturado em JSON
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "command",
            "service": self.config.get('type', 'generic'),
            "port": self.port,
            "source_ip": ip,
            "command": command
        }
        self._write_json_log(log_entry)
    
    def _write_json_log(self, log_entry: Dict):
        """Escreve entrada de log em formato JSON"""
        try:
            with open(self.json_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write JSON log: {e}")
    
    def get_fake_response(self, command: str) -> str:
        """Retorna resposta simulada baseada no comando"""
        # Implementação base - pode ser sobrescrita
        return f"Response to: {command}"