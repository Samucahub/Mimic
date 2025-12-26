#!/bin/bash
# Script para matar todos os processos do honeypot MIMIC (Linux)
echo "Killing all MIMIC honeypot processes..."

# Mata processos Python rodando main.py
pkill -f "main.py"

# Mata qualquer processo escutando nas portas do honeypot (21, 22, 23, 80, 3306, 3389)
ports=(21 22 23 80 3306 3389)
for port in "${ports[@]}"; do
    pid=$(lsof -ti:$port 2>/dev/null)
    if [ ! -z "$pid" ]; then
        echo "Killing process on port $port (PID: $pid)"
        kill -9 $pid 2>/dev/null
    fi
done

echo "Done!"
