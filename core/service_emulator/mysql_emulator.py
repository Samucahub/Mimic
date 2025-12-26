"""
Emulador de servidor MySQL
"""
import asyncio
import random
import struct
from typing import Dict, Any
from .base_service import BaseService

class MySQLService(BaseService):
    """Emula um servidor MySQL"""
    
    def __init__(self, port: int, config: Dict[str, Any]):
        super().__init__(port, config)
        self.name = "MySQL Server"
        self.version = config.get('version', '5.7.33')
        self.banner = config.get('banner', f'5.7.33 MySQL Community Server')
        self.databases = config.get('databases', ['test', 'information_schema'])
        self.users = config.get('users', {'root': '', 'admin': 'password'})
        
    async def handle_connection(self, reader, writer):
        """Manipula conexão MySQL"""
        client_ip = writer.get_extra_info('peername')[0]
        self.log_connection(client_ip)
        
        try:
            # Handshake inicial
            await self.send_handshake(writer)
            
            # Loop de processamento
            while self.is_running:
                packet = await self.read_packet(reader)
                if not packet:
                    break
                
                await self.process_packet(packet, reader, writer, client_ip)
                
        except Exception as e:
            self.logger.error(f"MySQL error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def send_handshake(self, writer):
        """Envia handshake inicial MySQL"""
        # Packet header
        packet_length = 78
        sequence_id = 0
        
        # Protocol version (10 = handshake)
        protocol_version = 10
        
        # Server version
        server_version = self.banner.encode() + b'\x00'
        
        # Connection ID
        connection_id = random.randint(1, 65535)
        
        # Auth plugin data
        auth_plugin_data = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'
        
        # Capability flags
        capability_flags = 0xf7ff
        
        # Character set
        character_set = 33  # utf8
        
        # Status flags
        status_flags = 0x0002
        
        # Build packet
        packet = bytearray()
        packet.extend(struct.pack('<I', packet_length)[:3])  # Length
        packet.append(sequence_id)  # Sequence ID
        packet.append(protocol_version)  # Protocol
        packet.extend(server_version)  # Server version
        packet.extend(struct.pack('<I', connection_id))  # Connection ID
        packet.extend(auth_plugin_data[:8])  # Auth plugin data part 1
        packet.append(0)  # Filler
        packet.extend(struct.pack('<H', capability_flags & 0xffff))  # Lower capability flags
        packet.append(character_set)  # Character set
        packet.extend(struct.pack('<H', status_flags))  # Status flags
        packet.extend(struct.pack('<H', (capability_flags >> 16) & 0xffff))  # Upper capability flags
        packet.append(21)  # Auth plugin data length
        packet.extend(b'\x00' * 10)  # Reserved
        packet.extend(auth_plugin_data[8:])  # Auth plugin data part 2
        packet.append(0)  # Auth plugin name
        packet.append(0)  # Terminator
        
        writer.write(packet)
        await writer.drain()
    
    async def read_packet(self, reader) -> bytes:
        """Lê um pacote MySQL"""
        header = await reader.read(4)
        if len(header) < 4:
            return b''
        
        length = struct.unpack('<I', header[:3] + b'\x00')[0]
        sequence_id = header[3]
        
        data = await reader.read(length)
        return data
    
    async def process_packet(self, packet: bytes, reader, writer, client_ip: str):
        """Processa pacote MySQL"""
        if len(packet) < 1:
            return
        
        command = packet[0]
        payload = packet[1:] if len(packet) > 1 else b''
        
        self.log_command(client_ip, f"MySQL Command: {command}")
        
        if command == 1:  # COM_QUIT
            await self.send_ok_packet(writer)
            
        elif command == 3:  # COM_QUERY
            query = payload.decode('utf-8', errors='ignore').strip()
            self.logger.info(f"MySQL query from {client_ip}: {query}")
            
            # Detecta SQL injection
            if self.detect_sql_injection(query):
                self.logger.warning(f"SQL injection attempt from {client_ip}: {query}")
                await self.send_error_packet(writer, "1064", "You have an error in your SQL syntax")
            else:
                # Simula resposta de query
                await self.send_query_response(writer, query)
        
        elif command == 14:  # COM_PING
            await self.send_ok_packet(writer)
        
        else:
            # Comando não suportado
            await self.send_error_packet(writer, "1047", "Unknown command")
    
    def detect_sql_injection(self, query: str) -> bool:
        """Detecta tentativas de SQL injection"""
        query_lower = query.lower()
        
        dangerous_patterns = [
            'union select',
            'sleep(',
            'benchmark(',
            'load_file(',
            'into outfile',
            'into dumpfile',
            'information_schema',
            '--',
            '/*',
            '*/',
            "' or '1'='1",
            "' or 1=1--"
        ]
        
        return any(pattern in query_lower for pattern in dangerous_patterns)
    
    async def send_query_response(self, writer, query: str):
        """Envia resposta fake para query"""
        query_lower = query.lower()
        
        if 'show databases' in query_lower:
            await self.send_resultset(writer, ['Database'], self.databases)
        
        elif 'select user()' in query_lower or 'select current_user' in query_lower:
            await self.send_resultset(writer, ['user()'], ['root@localhost'])
        
        elif 'select version()' in query_lower:
            await self.send_resultset(writer, ['version()'], [self.version])
        
        elif 'select' in query_lower and 'from' in query_lower:
            # Query SELECT genérica
            columns = ['id', 'name', 'email', 'created_at']
            rows = [
                ['1', 'admin', 'admin@example.com', '2023-01-01'],
                ['2', 'user', 'user@example.com', '2023-01-02'],
                ['3', 'test', 'test@example.com', '2023-01-03']
            ]
            await self.send_resultset(writer, columns, rows)
        
        else:
            # Query não reconhecida
            await self.send_ok_packet(writer, affected_rows=0)
    
    async def send_resultset(self, writer, columns: list, rows: list):
        """Envia um resultset fake"""
        # Número de colunas
        col_count = len(columns)
        col_count_packet = struct.pack('<I', col_count)[:1]
        await self.write_packet(writer, col_count_packet, 1)
        
        # Definições das colunas
        for i, col in enumerate(columns):
            col_def = self.build_column_definition(col, i)
            await self.write_packet(writer, col_def, 2 + i)
        
        # EOF packet
        eof_packet = b'\xfe\x00\x00\x02\x00'
        await self.write_packet(writer, eof_packet, 2 + col_count)
        
        # Dados das linhas
        for i, row in enumerate(rows):
            row_data = self.build_row_data(row)
            await self.write_packet(writer, row_data, 3 + col_count + i)
        
        # EOF final
        await self.write_packet(writer, eof_packet, 3 + col_count + len(rows))
    
    def build_column_definition(self, name: str, seq: int) -> bytes:
        """Constrói definição de coluna"""
        # Implementação simplificada
        catalog = b'def'
        schema = b''
        table = b''
        org_table = b''
        col_name = name.encode()
        org_col_name = name.encode()
        charset = 33  # utf8
        length = 255
        type_code = 253  # VARCHAR
        flags = 0
        decimals = 0
        
        # Serializa campos (simplificado)
        parts = []
        parts.append(struct.pack('<B', len(catalog)))
        parts.append(catalog)
        parts.append(struct.pack('<B', len(schema)))
        parts.append(schema)
        parts.append(struct.pack('<B', len(table)))
        parts.append(table)
        parts.append(struct.pack('<B', len(org_table)))
        parts.append(org_table)
        parts.append(struct.pack('<B', len(col_name)))
        parts.append(col_name)
        parts.append(struct.pack('<B', len(org_col_name)))
        parts.append(org_col_name)
        parts.append(b'\x0c')  # Length of following fields
        parts.append(struct.pack('<H', charset))
        parts.append(struct.pack('<I', length))
        parts.append(struct.pack('<B', type_code))
        parts.append(struct.pack('<H', flags))
        parts.append(struct.pack('<B', decimals))
        parts.append(b'\x00\x00')  # Filler
        
        return b''.join(parts)
    
    def build_row_data(self, row: list) -> bytes:
        """Constrói dados de linha"""
        data = bytearray()
        for value in row:
            if value is None:
                data.append(0xfb)  # NULL
            else:
                str_val = str(value).encode()
                data.extend(struct.pack('<I', len(str_val))[:1])
                data.extend(str_val)
        return bytes(data)
    
    async def send_ok_packet(self, writer, affected_rows: int = 0):
        """Envia pacote OK"""
        ok_packet = bytearray()
        ok_packet.append(0)  # Header
        ok_packet.extend(struct.pack('<I', affected_rows))
        ok_packet.extend(struct.pack('<I', 0))  # Last insert ID
        ok_packet.extend(struct.pack('<H', 2))  # Server status
        ok_packet.extend(struct.pack('<H', 0))  # Warning count
        ok_packet.extend(b'')  # Message
        
        await self.write_packet(writer, ok_packet)
    
    async def send_error_packet(self, writer, error_code: str, message: str):
        """Envia pacote de erro"""
        error_packet = bytearray()
        error_packet.append(0xff)  # Error packet header
        error_packet.extend(struct.pack('<H', int(error_code)))
        error_packet.append(0x23)  # SQL state marker '#'
        error_packet.extend(b'42000')  # SQL state
        error_packet.extend(message.encode())
        
        await self.write_packet(writer, error_packet)
    
    async def write_packet(self, writer, data: bytes, sequence_id: int = 0):
        """Escreve pacote MySQL"""
        length = len(data)
        header = struct.pack('<I', length)[:3] + struct.pack('<B', sequence_id)
        
        writer.write(header + data)
        await writer.drain()