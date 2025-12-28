import pygame
import sys
import yaml
import math
import random
import subprocess
import threading
import time
import platform
from pathlib import Path

pygame.init()

COLORS = {
    'bg': (5, 5, 5),
    'bg_alt': (20, 20, 20),
    'white': (255, 255, 255),
    'gray': (130, 130, 130),
    'gray_dark': (50, 50, 50),
    'gray_light': (200, 200, 200),
    'red': (180, 0, 0),
    'green': (0, 180, 0),
    'blue': (100, 150, 255),
}

WIDTH, HEIGHT = 1400, 900
FPS = 60

class Button:
    def __init__(self, x, y, w, h, text, action=None):
        self.rect = pygame.Rect(x, y, w, h)
        self.text = text
        self.action = action
        self.hovered = False

    def draw(self, screen, font):
        offset = random.randint(-2, 2) if self.hovered else 0
        r = self.rect.move(offset, offset)

        pygame.draw.rect(screen, COLORS['white'] if self.hovered else COLORS['gray'], r, 3)
        if self.hovered:
            pygame.draw.rect(screen, COLORS['white'], r)

        txt = font.render(self.text, True, COLORS['bg'] if self.hovered else COLORS['white'])
        screen.blit(txt, txt.get_rect(center=r.center))

    def handle_event(self, e):
        if e.type == pygame.MOUSEMOTION:
            self.hovered = self.rect.collidepoint(e.pos)
        if e.type == pygame.MOUSEBUTTONDOWN and self.hovered:
            if self.action:
                self.action()


class InputBox:
    def __init__(self, x, y, w, h, label, default=""):
        self.rect = pygame.Rect(x, y, w, h)
        self.label = label
        self.text = default
        self.active = False

    def draw(self, screen, font):
        label = font.render(self.label, True, COLORS['gray_light'])
        screen.blit(label, (self.rect.x, self.rect.y - 25))

        pygame.draw.rect(screen, COLORS['bg'], self.rect)
        pygame.draw.rect(screen, COLORS['white'] if self.active else COLORS['gray_dark'], self.rect, 2)

        txt = font.render(self.text, True, COLORS['white'])
        screen.blit(txt, (self.rect.x + 8, self.rect.y + 8))

    def handle_event(self, e):
        if e.type == pygame.MOUSEBUTTONDOWN:
            self.active = self.rect.collidepoint(e.pos)
        if e.type == pygame.KEYDOWN and self.active:
            if e.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            elif e.key == pygame.K_RETURN:
                self.active = False
            else:
                if len(self.text) < 30:
                    self.text += e.unicode


class Checkbox:
    def __init__(self, x, y, label, checked=False):
        self.rect = pygame.Rect(x, y, 22, 22)
        self.label = label
        self.checked = checked

    def draw(self, screen, font):
        pygame.draw.rect(screen, COLORS['bg'], self.rect)
        pygame.draw.rect(screen, COLORS['white'], self.rect, 2)

        if self.checked:
            pygame.draw.line(screen, COLORS['white'], self.rect.topleft, self.rect.bottomright, 3)
            pygame.draw.line(screen, COLORS['white'], self.rect.topright, self.rect.bottomleft, 3)

        txt = font.render(self.label, True, COLORS['gray_light'])
        screen.blit(txt, (self.rect.x + 35, self.rect.y - 2))

    def handle_event(self, e):
        if e.type == pygame.MOUSEBUTTONDOWN and self.rect.collidepoint(e.pos):
            self.checked = not self.checked


class ServiceCard:
    def __init__(self, x, y, w, h, name, port, icon, enabled=False):
        self.rect = pygame.Rect(x, y, w, h)
        self.name = name
        self.port = port
        self.icon = icon
        self.enabled = enabled
        self.hovered = False

    def draw(self, screen, font, small):
        offset = random.randint(-2, 2) if self.hovered else 0
        draw_rect = self.rect.move(offset, 0)

        bg = (245, 245, 245) if self.enabled else COLORS['bg_alt']
        fg = COLORS['bg'] if self.enabled else COLORS['white']

        shadow = draw_rect.move(5, 5)
        pygame.draw.rect(screen, (0, 0, 0), shadow)

        pygame.draw.rect(screen, bg, draw_rect)
        pygame.draw.rect(screen, COLORS['white'], draw_rect, 3)

        if not self.enabled:
            screen.set_clip(draw_rect)
            for i in range(-draw_rect.height, draw_rect.width + draw_rect.height, 20):
                start = (draw_rect.x + i, draw_rect.y)
                end = (draw_rect.x + i + draw_rect.height, draw_rect.y + draw_rect.height)
                pygame.draw.line(screen, COLORS['gray_dark'], start, end, 1)
            screen.set_clip(None)

        screen.blit(font.render(self.icon, True, fg), (draw_rect.x + 15, draw_rect.y + 18))
        screen.blit(font.render(self.name, True, fg), (draw_rect.x + 60, draw_rect.y + 15))
        screen.blit(small.render(f":{self.port}", True, COLORS['gray']), (draw_rect.x + 60, draw_rect.y + 45))

        status_x = draw_rect.right - 40
        status_y = draw_rect.centery

        if self.enabled:
            pygame.draw.circle(screen, COLORS['bg'], (status_x, status_y), 10)
            pygame.draw.circle(screen, COLORS['green'], (status_x, status_y), 6)
        else:
            pygame.draw.line(screen, COLORS['red'], (status_x-8, status_y-8), (status_x+8, status_y+8), 3)
            pygame.draw.line(screen, COLORS['red'], (status_x+8, status_y-8), (status_x-8, status_y+8), 3)

    def handle_event(self, e):
        if e.type == pygame.MOUSEMOTION:
            self.hovered = self.rect.collidepoint(e.pos)
        elif e.type == pygame.MOUSEBUTTONDOWN and self.rect.collidepoint(e.pos):
            self.enabled = not self.enabled


class MimicConfigurator:
    def __init__(self):
        self.screen = pygame.display.set_mode((WIDTH, HEIGHT))
        pygame.display.set_caption("MIMIC — Raise the Curtain")
        self.clock = pygame.time.Clock()
        self.running = True
        self.current_screen = 1

        self.font_big = pygame.font.Font(None, 80)
        self.font = pygame.font.Font(None, 32)
        self.small = pygame.font.Font(None, 22)

        self.username = InputBox(100, 240, 200, 35, "USERNAME", "admin")
        self.password = InputBox(320, 240, 200, 35, "PASSWORD", "admin123")
        self.hostname = InputBox(540, 240, 240, 35, "HOSTNAME", "stage-server")
        
        self.os_templates = ["Ubuntu", "Debian", "CentOS", "Windows", "Kali"]
        self.selected_os = 0

        self.services = [
            ServiceCard(100, 350, 380, 75, "SSH", "22", "[S]", True),
            ServiceCard(500, 350, 380, 75, "FTP", "21", "[F]"),
            ServiceCard(900, 350, 380, 75, "HTTP", "80", "[H]"),
            ServiceCard(100, 440, 380, 75, "TELNET", "23", "[T]"),
            ServiceCard(500, 440, 380, 75, "MYSQL", "3306", "[M]"),
            ServiceCard(900, 440, 380, 75, "RDP", "3389", "[R]"),
        ]

        self.any_auth = Checkbox(100, 575, "Accept any credentials (honeypot)")
        self.human = Checkbox(100, 605, "Simulate human hesitation")
        
        self.enable_security = Checkbox(700, 575, "Enable security features", True)
        self.block_duration = InputBox(950, 575, 80, 30, "Block (min)", "60")
        self.max_failed_logins = InputBox(1050, 575, 80, 30, "Max fails", "10")
        self.max_connections = InputBox(1150, 575, 80, 30, "Max/min", "60")
        
        self.enable_logging = Checkbox(700, 645, "Enable detailed logging", True)
        self.log_retention = InputBox(950, 640, 80, 30, "Days", "7")

        self.next_btn = Button(WIDTH - 230, HEIGHT - 80, 160, 50, "NEXT", self.go_to_screen2)

        # Configurações SSH (apenas se SSH estiver habilitado)
        self.ssh_banner = InputBox(100, 240, 470, 35, "SSH Banner", "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3")
        self.command_timeout = InputBox(100, 370, 150, 30, "Cmd timeout (s)", "30")
        self.session_time = InputBox(270, 370, 150, 30, "Max session (s)", "3600")
        
        # REMOVIDO: Simulation Features (agora são automáticas)
        
        self.back_btn = Button(WIDTH - 580, HEIGHT - 80, 140, 50, "BACK", self.go_to_screen1)
        self.save_btn = Button(WIDTH - 430, HEIGHT - 80, 140, 50, "SAVE", self.save_config)
        self.start_btn = Button(WIDTH - 280, HEIGHT - 80, 230, 50, "Let The Show Begin!", self.start_honeypot)

        self.honeypot_process = None
        self.honeypot_running = False
        self.log_messages = []

    def go_to_screen2(self):
        enabled_services = [s for s in self.services if s.enabled]
        if not enabled_services:
            print("[MIMIC] Select at least one service")
            return
        
        self.current_screen = 2
        print(f"[MIMIC] Going to service configuration screen")

    def go_to_screen1(self):
        self.current_screen = 1
        print(f"[MIMIC] Going back to basic configuration")

    def draw_curtains(self):
        for y in range(0, HEIGHT, 20):
            wave = int(math.sin((y + pygame.time.get_ticks()*0.3)*0.02)*6)
            pygame.draw.rect(self.screen, COLORS['gray_dark'], (wave, y, 60, 20))
            pygame.draw.rect(self.screen, COLORS['gray_dark'], (WIDTH-60+wave, y, 60, 20))

    def draw_spotlight(self):
        light = pygame.Surface((WIDTH, HEIGHT), pygame.SRCALPHA)
        for r in range(600, 0, -30):
            pygame.draw.circle(light, (255,255,255,4), (WIDTH//2, HEIGHT//2), r)
        self.screen.blit(light, (0,0))

    def draw_eyes(self):
        blink = abs(math.sin(pygame.time.get_ticks()*0.004))*8
        for dx in (-80, 80):
            pygame.draw.ellipse(
                self.screen, COLORS['white'],
                (WIDTH//2+dx-20, 60+blink, 40, 18-blink)
            )

    def draw_header(self):
        title = self.font_big.render("M I M I C", True, COLORS['white'])
        self.screen.blit(title, (50, 40))
        self.draw_eyes()

        sub = self.small.render("Every port is a mask.", True, COLORS['gray_light'])
        self.screen.blit(sub, (50, 105))
    
    def draw_screen1(self):
        identity_label = self.font.render("IDENTITY", True, COLORS['white'])
        self.screen.blit(identity_label, (100, 185))

        self.username.draw(self.screen, self.small)
        self.password.draw(self.screen, self.small)
        self.hostname.draw(self.screen, self.small)

        services_label = self.font.render("SERVICES", True, COLORS['white'])
        self.screen.blit(services_label, (100, 305))
        pygame.draw.line(self.screen, COLORS['gray_dark'], (100, 332), (WIDTH - 100, 332), 1)

        for s in self.services:
            s.draw(self.screen, self.font, self.small)

        options_label = self.font.render("OPTIONS", True, COLORS['white'])
        self.screen.blit(options_label, (100, 535))

        self.any_auth.draw(self.screen, self.small)
        self.human.draw(self.screen, self.small)
        
        self.enable_security.draw(self.screen, self.small)
        if self.enable_security.checked:
            self.block_duration.draw(self.screen, self.small)
            self.max_failed_logins.draw(self.screen, self.small)
            self.max_connections.draw(self.screen, self.small)
        
        self.enable_logging.draw(self.screen, self.small)
        if self.enable_logging.checked:
            self.log_retention.draw(self.screen, self.small)
        
        os_label = self.font.render("OS TEMPLATE", True, COLORS['white'])
        self.screen.blit(os_label, (100, 700))
        
        mouse_pos = pygame.mouse.get_pos()
        for i, os_name in enumerate(self.os_templates):
            x = 100 + i * 120
            y = 750
            os_btn_rect = pygame.Rect(x, y, 110, 35)
            
            is_selected = (i == self.selected_os)
            is_hovered = os_btn_rect.collidepoint(mouse_pos)
            
            if is_selected:
                pygame.draw.rect(self.screen, COLORS['white'], os_btn_rect)
                pygame.draw.rect(self.screen, COLORS['white'], os_btn_rect, 2)
            else:
                pygame.draw.rect(self.screen, COLORS['gray_dark'], os_btn_rect)
                pygame.draw.rect(self.screen, COLORS['gray'] if is_hovered else COLORS['gray_dark'], os_btn_rect, 2)
            
            os_text = self.small.render(os_name, True, COLORS['bg'] if is_selected else COLORS['gray_light'])
            text_rect = os_text.get_rect(center=os_btn_rect.center)
            self.screen.blit(os_text, text_rect)

        phrase = random.choice([
            "The stage is set.",
            "The actor is watching.",
            "Silence is also a response.",
            "The system will imitate you."
        ])
        warn = self.small.render(phrase, True, COLORS['gray'])
        self.screen.blit(warn, warn.get_rect(center=(WIDTH//2, HEIGHT-40)))

        self.next_btn.draw(self.screen, self.font)

    def draw_screen2(self):
        enabled_services = [s.name for s in self.services if s.enabled]
        ssh_enabled = "SSH" in enabled_services
        
        if ssh_enabled:
            title = self.font_big.render("SSH CONFIGURATION", True, COLORS['white'])
            self.screen.blit(title, (50, 40))
            
            subtitle = self.small.render("Configuring SSH service (Port: 22)", True, COLORS['gray_light'])
            self.screen.blit(subtitle, (50, 110))
        
        pygame.draw.line(self.screen, COLORS['gray_dark'], (50, 140), (WIDTH - 50, 140), 2)
        
        if ssh_enabled:
            ssh_label = self.font.render("SSH SETTINGS", True, COLORS['white'])
            self.screen.blit(ssh_label, (100, 175))
            
            self.ssh_banner.draw(self.screen, self.small)
            
            session_label = self.font.render("SESSION SETTINGS", True, COLORS['white'])
            self.screen.blit(session_label, (100, 300))
            
            self.command_timeout.draw(self.screen, self.small)
            self.session_time.draw(self.screen, self.small)
        
        services_label = self.font.render("SELECTED SERVICES", True, COLORS['white'])
        services_x = 850 if ssh_enabled else 100
        self.screen.blit(services_label, (services_x, 175))
        
        y_offset = 220
        for service in self.services:
            if service.enabled:
                service_text = self.small.render(f"[OK] {service.name} :{service.port}", True, COLORS['green'])
                self.screen.blit(service_text, (services_x, y_offset))
                y_offset += 30
        
        info_label = self.font.render("SYSTEM INFO", True, COLORS['white'])
        self.screen.blit(info_label, (services_x, y_offset + 20))
        
        info_texts = [
            f"OS: {self.os_templates[self.selected_os]}",
            f"Hostname: {self.hostname.text}",
            f"User: {self.username.text}",
            f"Security: {'ON' if self.enable_security.checked else 'OFF'}",
            f"Logging: {'ON' if self.enable_logging.checked else 'OFF'}"
        ]
        
        for i, text in enumerate(info_texts):
            info_line = self.small.render(text, True, COLORS['gray_light'])
            self.screen.blit(info_line, (services_x, y_offset + 50 + i*25))
        
        phrase = random.choice([
            "Ready to deceive.",
            "The trap is set.",
            "Waiting for visitors.",
            "All masks in place."
        ])
        warn = self.small.render(phrase, True, COLORS['gray'])
        self.screen.blit(warn, warn.get_rect(center=(WIDTH//2, HEIGHT-40)))
        
        self.back_btn.draw(self.screen, self.font)
        self.save_btn.draw(self.screen, self.font)
        self.start_btn.draw(self.screen, self.font)

    def draw_logs_screen(self):
        title = self.font_big.render("THE SHOW IS ON", True, COLORS['white'])
        self.screen.blit(title, (50, 40))
        
        subtitle = self.small.render("Honeypot is running. Watching for visitors...", True, COLORS['gray_light'])
        self.screen.blit(subtitle, (50, 105))
        
        log_area = pygame.Rect(60, 160, WIDTH - 120, HEIGHT - 300)
        pygame.draw.rect(self.screen, COLORS['bg_alt'], log_area)
        pygame.draw.rect(self.screen, COLORS['white'], log_area, 2)
        
        logs_title = self.font.render("LIVE ACTIVITY", True, COLORS['white'])
        self.screen.blit(logs_title, (75, 170))
        
        y_offset = 210
        visible_logs = self.log_messages[-15:]
        for msg in visible_logs:
            log_text = self.small.render(msg[:120], True, COLORS['gray_light'])
            self.screen.blit(log_text, (75, y_offset))
            y_offset += 28
        
        close_rect = pygame.Rect(WIDTH//2 - 150, HEIGHT - 100, 300, 60)
        mouse_pos = pygame.mouse.get_pos()
        is_hovered = close_rect.collidepoint(mouse_pos)
        offset = random.randint(-2, 2) if is_hovered else 0
        btn_rect = close_rect.move(offset, offset)
        
        pygame.draw.rect(self.screen, COLORS['white'] if is_hovered else COLORS['gray'], btn_rect, 3)
        if is_hovered:
            pygame.draw.rect(self.screen, COLORS['white'], btn_rect)
        
        txt = self.font.render("Close the curtains", True, COLORS['bg'] if is_hovered else COLORS['white'])
        self.screen.blit(txt, txt.get_rect(center=btn_rect.center))
        
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                self.stop_honeypot()
                self.running = False
            elif e.type == pygame.MOUSEBUTTONDOWN:
                if close_rect.collidepoint(e.pos):
                    self.stop_honeypot()

    def run(self):
        while self.running:
            if self.honeypot_running:
                for e in pygame.event.get():
                    if e.type == pygame.QUIT:
                        self.stop_honeypot()
                        self.running = False
                    elif e.type == pygame.MOUSEBUTTONDOWN:
                        mouse_pos = pygame.mouse.get_pos()
                        close_rect = pygame.Rect(WIDTH//2 - 150, HEIGHT - 100, 300, 60)
                        if close_rect.collidepoint(mouse_pos):
                            self.stop_honeypot()
                
                self.screen.fill(COLORS['bg'])
                self.draw_curtains()
                self.draw_spotlight()
                self.draw_logs_screen()
                pygame.display.flip()
                self.clock.tick(FPS)
                continue

            for e in pygame.event.get():
                if e.type == pygame.QUIT:
                    self.running = False
                
                if e.type == pygame.MOUSEBUTTONDOWN and self.current_screen == 1:
                    for i, os_name in enumerate(self.os_templates):
                        os_btn_rect = pygame.Rect(100 + i * 120, 690, 110, 35)
                        if os_btn_rect.collidepoint(e.pos):
                            self.selected_os = i

                if self.current_screen == 1:
                    self.username.handle_event(e)
                    self.password.handle_event(e)
                    self.hostname.handle_event(e)
                    for s in self.services:
                        s.handle_event(e)
                    self.any_auth.handle_event(e)
                    self.human.handle_event(e)
                    self.enable_security.handle_event(e)
                    self.block_duration.handle_event(e)
                    self.max_failed_logins.handle_event(e)
                    self.max_connections.handle_event(e)
                    self.enable_logging.handle_event(e)
                    self.log_retention.handle_event(e)
                    self.next_btn.handle_event(e)
                
                elif self.current_screen == 2:
                    # Apenas processar eventos SSH se SSH estiver habilitado
                    ssh_enabled = any(s.name == "SSH" and s.enabled for s in self.services)
                    if ssh_enabled:
                        self.ssh_banner.handle_event(e)
                        self.command_timeout.handle_event(e)
                        self.session_time.handle_event(e)
                    self.back_btn.handle_event(e)
                    self.save_btn.handle_event(e)
                    self.start_btn.handle_event(e)

            self.screen.fill(COLORS['bg'])
            self.draw_curtains()
            self.draw_spotlight()

            if self.current_screen == 1:
                self.draw_header()

            if self.current_screen == 1:
                self.draw_screen1()
            elif self.current_screen == 2:
                self.draw_screen2()

            pygame.display.flip()
            self.clock.tick(FPS)

        pygame.quit()
        sys.exit()

    def save_config(self):
        config = {
            "system": {
                "username": self.username.text,
                "password": self.password.text,
                "hostname": self.hostname.text,
                "os_template": self.os_templates[self.selected_os]
            },
            "options": {
                "any_auth": self.any_auth.checked,
                "human_patterns": self.human.checked,
                "enable_logging": self.enable_logging.checked,
                "log_retention_days": int(self.log_retention.text) if self.log_retention.text.isdigit() else 7
            },
            "security": {
                "enabled": self.enable_security.checked,
                "rate_limits": {
                    "max_connections_per_minute": int(self.max_connections.text) if self.max_connections.text.isdigit() else 60,
                    "max_failed_logins": int(self.max_failed_logins.text) if self.max_failed_logins.text.isdigit() else 10,
                    "block_duration_minutes": int(self.block_duration.text) if self.block_duration.text.isdigit() else 60,
                    "window_seconds": 60
                },
                "ip_blocking": {
                    "auto_block_failed_logins": int(self.max_failed_logins.text) if self.max_failed_logins.text.isdigit() else 10
                }
            },
            "services": {}
        }
        
        for s in self.services:
            if s.enabled:
                port = int(s.port)
                service_config = {
                    "type": s.name.lower(),
                    "enabled": True,
                    "banner": self._clean_banner(self.ssh_banner.text if s.name == "SSH" else self._get_service_banner(s.name))
                }
                
                if s.name == "SSH":
                    service_config.update({
                        "command_timeout": int(self.command_timeout.text) if self.command_timeout.text.isdigit() else 30,
                        "max_session_time": int(self.session_time.text) if self.session_time.text.isdigit() else 3600
                    })
                
                config["services"][str(port)] = service_config
        
        Path("config").mkdir(exist_ok=True)
        with open("config/honeypot.yaml", "w") as f:
            yaml.dump(config, f)
        
        print(f"[MIMIC] Configuration saved successfully")
        print(f"[MIMIC] Services: {[(s.name, s.port) for s in self.services if s.enabled]}")
        return True

    def _clean_banner(self, banner: str) -> str:
        if not banner:
            return "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"

        if not banner.startswith('SSH-2.0-'):
            banner = 'SSH-2.0-' + banner

        import string
        printable = set(string.printable)
        cleaned = ''.join(filter(lambda x: x in printable, banner))
        
        cleaned = cleaned.replace('\r', '').replace('\n', ' ').strip()
        
        cleaned = ' '.join(cleaned.split())
        
        if len(cleaned) > 255:
            cleaned = cleaned[:255]
        
        return cleaned

    def _get_service_banner(self, service_name):
        banners = {
            "SSH": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
            "FTP": "220 ProFTPD 1.3.5 Server",
            "HTTP": "Apache/2.4.29 (Ubuntu)",
            "TELNET": "Ubuntu 18.04.6 LTS",
            "MYSQL": "5.7.35 - MySQL Community Server",
            "RDP": "Microsoft Terminal Services"
        }
        return banners.get(service_name, "Unknown")

    def start_honeypot(self):
        if not self.save_config():
            return
        
        self.log_messages = ["[MIMIC] Starting honeypot..."]
        self.honeypot_running = True
        
        def run_honeypot():
            try:
                import os
                
                log_file_path = "logs/honeypot_output.log"
                Path("logs").mkdir(exist_ok=True)
                log_file = open(log_file_path, "w", encoding='utf-8', errors='replace')
                
                python_exe = sys.executable
                
                self.log_messages.append(f"[INFO] Using Python: {python_exe}")
                self.log_messages.append(f"[INFO] Platform: {platform.system()}")
                
                env = os.environ.copy()
                env['PYTHONIOENCODING'] = 'utf-8'
                
                kwargs = {
                    'stdout': log_file,
                    'stderr': subprocess.STDOUT,
                    'text': True,
                    'bufsize': 1,
                    'env': env
                }
                
                if platform.system() == 'Windows':
                    kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                
                self.honeypot_process = subprocess.Popen([python_exe, "main.py"], **kwargs)
                
                self.log_messages.append("[OK] Honeypot started successfully")
                self.log_messages.append("[WAIT] Watching log file...")
                
                def read_logs():
                    try:
                        time.sleep(1)
                        with open(log_file_path, "r", encoding='utf-8', errors='replace') as f:
                            f.seek(0, 2)
                            while self.honeypot_running:
                                line = f.readline()
                                if line:
                                    timestamp = time.strftime("%H:%M:%S")
                                    clean_line = ''.join(char if ord(char) < 128 else '?' for char in line.strip())
                                    if clean_line:
                                        self.log_messages.append(f"[{timestamp}] {clean_line[:100]}")
                                else:
                                    time.sleep(0.1)
                                    
                                if self.honeypot_process and self.honeypot_process.poll() is not None:
                                    self.log_messages.append("[ERROR] Honeypot stopped unexpectedly")
                                    break
                    except Exception as e:
                        self.log_messages.append(f"[LOG ERROR] {str(e)[:50]}")
                
                log_thread = threading.Thread(target=read_logs, daemon=True)
                log_thread.start()
                
                time.sleep(2)
                if self.honeypot_process.poll() is not None:
                    self.log_messages.append("[ERROR] Honeypot stopped unexpectedly")
                    self.log_messages.append("[ERROR] Check logs/honeypot_output.log for details")
                
            except Exception as e:
                self.log_messages.append(f"[ERROR] {str(e)}")
        
        thread = threading.Thread(target=run_honeypot, daemon=True)
        thread.start()
    
    def stop_honeypot(self):
        if self.honeypot_process:
            self.log_messages.append("[INFO] Stopping honeypot...")
            
            self.honeypot_process.terminate()
            
            try:
                self.honeypot_process.wait(timeout=3)
                self.log_messages.append("[OK] Honeypot stopped")
            except:
                self.log_messages.append("[WARN] Force killing honeypot...")
                self.honeypot_process.kill()
                try:
                    self.honeypot_process.wait(timeout=2)
                    self.log_messages.append("[OK] Honeypot killed")
                except:
                    self.log_messages.append("[ERROR] Could not kill process")
                    
            self.honeypot_process = None
        
        self.log_messages.append("[INFO] Killing processes on honeypot ports...")
        try:
            import os
            import signal
            
            if platform.system() == 'Windows':
                os.system('taskkill /F /FI "WINDOWTITLE eq main.py*" >nul 2>&1')
                
                ports = [21, 22, 23, 80, 3306, 3389]
                for port in ports:
                    result = os.popen(f'netstat -ano | findstr ":{port} "').read()
                    for line in result.split('\n'):
                        if 'LISTENING' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                pid = parts[-1]
                                try:
                                    os.system(f'taskkill /F /PID {pid} >nul 2>&1')
                                    self.log_messages.append(f"[OK] Killed process on port {port} (PID: {pid})")
                                except:
                                    pass
            else:
                os.system('pkill -f "main.py" 2>/dev/null')
                
                ports = [21, 22, 23, 80, 3306, 3389]
                for port in ports:
                    result = os.popen(f'lsof -ti:{port} 2>/dev/null').read().strip()
                    if result:
                        for pid in result.split('\n'):
                            if pid:
                                try:
                                    os.kill(int(pid), signal.SIGKILL)
                                    self.log_messages.append(f"[OK] Killed process on port {port} (PID: {pid})")
                                except:
                                    pass
        except Exception as e:
            self.log_messages.append(f"[WARN] Error killing port processes: {str(e)[:50]}")
            
        self.honeypot_running = False
        time.sleep(0.5)


if __name__ == "__main__":
    MimicConfigurator().run()