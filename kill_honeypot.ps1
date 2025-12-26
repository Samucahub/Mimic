# Script para matar todos os processos do honeypot MIMIC
Write-Host "Killing all MIMIC honeypot processes..." -ForegroundColor Yellow

# Mata processos Python rodando main.py
Get-Process python* -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*main.py*"
} | ForEach-Object {
    Write-Host "Killing process $($_.Id): $($_.ProcessName)" -ForegroundColor Red
    Stop-Process -Id $_.Id -Force
}

# Mata qualquer processo escutando nas portas do honeypot (21, 22, 23, 80, 3306, 3389)
$ports = @(21, 22, 23, 80, 3306, 3389)
foreach ($port in $ports) {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connection) {
        $processId = $connection.OwningProcess
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process -and $process.ProcessName -like "*python*") {
            Write-Host "Killing process on port ${port}: $($process.ProcessName) (PID: $processId)" -ForegroundColor Red
            Stop-Process -Id $processId -Force
        }
    }
}

Write-Host "Done!" -ForegroundColor Green
