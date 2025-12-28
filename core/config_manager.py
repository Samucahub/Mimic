import yaml
import json
import os
from typing import Dict, Any, Optional
from pathlib import Path
import logging

class ConfigManager:
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "honeypot.yaml"
        self.config_cache = None
        self.logger = logging.getLogger('config')
        
        self.config_dir.mkdir(exist_ok=True)
        
        if not self.config_file.exists():
            self.create_default_config()
    
    def create_default_config(self):
        default_config = {
            'version': '1.0',
            'name': 'MIMIC Honeypot',
            'system': {
                'username': 'admin',
                'password': 'admin123',
                'hostname': 'dev-server',
                'os_template': 'Ubuntu'
            },
            'options': {
                'any_auth': True,
                'human_patterns': True,
                'enable_logging': True,
                'log_retention_days': 7
            },
            'security': {
                'enabled': True,
                'rate_limits': {
                    'max_connections_per_minute': 60,
                    'max_failed_logins': 10,
                    'block_duration_minutes': 60,
                    'window_seconds': 60
                },
                'ip_blocking': {
                    'auto_block_failed_logins': 10
                }
            },
            'services': {
                22: {
                    'type': 'ssh',
                    'enabled': True,
                    'banner': 'SSH-2.0-OpenSSH_7.6p1',
                    'enable_scp': True,
                    'command_timeout': 30,
                    'max_session_time': 3600
                }
            },
            'behavior': {
                'response_delay': {'min': 0.1, 'max': 1.0},
                'error_rate': 0.05
            }
        }
        
        self.save_config(default_config)
        self.logger.info("Created default configuration")
    
    def load_config(self, force_reload: bool = False) -> Dict[str, Any]:
        """Carrega configuração do arquivo"""
        if self.config_cache is not None and not force_reload:
            return self.config_cache
        
        try:
            with open(self.config_file, 'r') as f:
                self.config_cache = yaml.safe_load(f)
            
            self.validate_config()
            
            # Garantir que as seções obrigatórias existam
            required_sections = ['system', 'options', 'security', 'services']
            for section in required_sections:
                if section not in self.config_cache:
                    if section == 'system':
                        self.config_cache[section] = {
                            'username': 'admin',
                            'password': 'admin123',
                            'hostname': 'dev-server',
                            'os_template': 'Ubuntu'
                        }
                    elif section == 'options':
                        self.config_cache[section] = {
                            'any_auth': True,
                            'human_patterns': True,
                            'enable_logging': True,
                            'log_retention_days': 7
                        }
                    elif section == 'security':
                        self.config_cache[section] = {
                            'enabled': True,
                            'rate_limits': {
                                'max_connections_per_minute': 60,
                                'max_failed_logins': 10,
                                'block_duration_minutes': 60,
                                'window_seconds': 60
                            }
                        }
                    elif section == 'services':
                        self.config_cache[section] = {}
            
            return self.config_cache
            
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            # Criar configuração padrão se houver erro
            self.create_default_config()
            return self.load_config(force_reload=True)
    
    def save_config(self, config: Dict[str, Any]):
        """Salva configuração no arquivo"""
        try:
            # Valida antes de salvar
            self.validate_config_structure(config)
            
            # Garantir que a estrutura de segurança está completa
            if 'security' in config:
                if 'rate_limits' not in config['security']:
                    config['security']['rate_limits'] = {}
                
                rate_limits = config['security']['rate_limits']
                if 'max_failed_logins' not in rate_limits:
                    rate_limits['max_failed_logins'] = 10
                if 'block_duration_minutes' not in rate_limits:
                    rate_limits['block_duration_minutes'] = 60
                if 'window_seconds' not in rate_limits:
                    rate_limits['window_seconds'] = 60
            
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            self.config_cache = config
            self.logger.info("Configuration saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            raise
    
    def update_config(self, section: str, key: str, value: Any):
        """Atualiza uma configuração específica"""
        config = self.load_config()
        
        if section not in config:
            config[section] = {}
        
        config[section][key] = value
        self.save_config(config)
    
    def get_service_config(self, port: int) -> Optional[Dict[str, Any]]:
        """Obtém configuração de um serviço específico"""
        config = self.load_config()
        services = config.get('services', {})
        return services.get(str(port)) or services.get(port)
    
    def get_all_services(self) -> Dict[int, Dict[str, Any]]:
        """Obtém configuração de todos os serviços"""
        config = self.load_config()
        services = config.get('services', {})
        
        # Converte chaves string para int se necessário
        result = {}
        for port, service_config in services.items():
            try:
                port_int = int(port)
                result[port_int] = service_config
            except ValueError:
                continue
        
        return result
    
    def add_service(self, port: int, service_config: Dict[str, Any]):
        """Adiciona um novo serviço"""
        config = self.load_config()
        
        if 'services' not in config:
            config['services'] = {}
        
        config['services'][port] = service_config
        self.save_config(config)
    
    def remove_service(self, port: int):
        """Remove um serviço"""
        config = self.load_config()
        
        if 'services' in config and port in config['services']:
            del config['services'][port]
            self.save_config(config)
    
    def validate_config(self):
        """Valida configuração carregada"""
        if self.config_cache is None:
            return
        
        self.validate_config_structure(self.config_cache)
        
        # Valida serviços
        services = self.config_cache.get('services', {})
        for port, config in services.items():
            try:
                port_int = int(port)
                if port_int < 1 or port_int > 65535:
                    raise ValueError(f"Invalid port: {port}")
                
                # Valida tipo de serviço
                service_type = config.get('type', '')
                if service_type not in ['ssh', 'http', 'ftp', 'mysql', 'telnet', 'rdp']:
                    self.logger.warning(f"Unknown service type: {service_type}")
                    
            except ValueError as e:
                self.logger.error(f"Invalid service configuration: {e}")
    
    def validate_config_structure(self, config: Dict[str, Any]):
        """Valida estrutura básica da configuração"""
        required_sections = ['system', 'options', 'security', 'services']
        
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required section: {section}")
    
    def export_config(self, format: str = 'yaml') -> str:
        """Exporta configuração em formato específico"""
        config = self.load_config()
        
        if format.lower() == 'json':
            return json.dumps(config, indent=2, default=str)
        elif format.lower() == 'yaml':
            return yaml.dump(config, default_flow_style=False, sort_keys=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def import_config(self, config_data: str, format: str = 'yaml'):
        """Importa configuração de string"""
        try:
            if format.lower() == 'json':
                config = json.loads(config_data)
            elif format.lower() == 'yaml':
                config = yaml.safe_load(config_data)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            self.validate_config_structure(config)
            self.save_config(config)
            
        except Exception as e:
            self.logger.error(f"Failed to import config: {e}")
            raise
    
    def backup_config(self, backup_name: str = None):
        """Cria backup da configuração atual"""
        import shutil
        from datetime import datetime
        
        if backup_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"honeypot_backup_{timestamp}.yaml"
        
        backup_path = self.config_dir / "backups" / backup_name
        backup_path.parent.mkdir(exist_ok=True)
        
        shutil.copy2(self.config_file, backup_path)
        self.logger.info(f"Configuration backed up to {backup_path}")
    
    def list_backups(self) -> list:
        """Lista backups disponíveis"""
        backups_dir = self.config_dir / "backups"
        
        if not backups_dir.exists():
            return []
        
        backups = []
        for file in backups_dir.glob("*.yaml"):
            backups.append({
                'name': file.name,
                'path': str(file),
                'size': file.stat().st_size,
                'modified': file.stat().st_mtime
            })
        
        return sorted(backups, key=lambda x: x['modified'], reverse=True)