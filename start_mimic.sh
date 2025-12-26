#!/bin/bash
# Script de inicialização do MIMIC Honeypot para Linux

echo "MIMIC Honeypot - Linux Launcher"
echo "================================"

# Verifica se Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Verifica dependências
echo "Checking dependencies..."
python3 -c "import pygame" 2>/dev/null || { echo "Installing pygame..."; pip3 install pygame; }
python3 -c "import yaml" 2>/dev/null || { echo "Installing pyyaml..."; pip3 install pyyaml; }
python3 -c "import asyncssh" 2>/dev/null || { echo "Installing asyncssh..."; pip3 install asyncssh; }

# Verifica permissões para portas baixas
if [ "$EUID" -ne 0 ]; then 
    echo ""
    echo "Warning: Not running as root!"
    echo "Ports below 1024 (SSH:22, FTP:21, HTTP:80, Telnet:23) require root privileges."
    echo "To run with sudo: sudo ./start_mimic.sh"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Inicia o configurador
echo "Starting MIMIC configurator..."
python3 configurator.py
