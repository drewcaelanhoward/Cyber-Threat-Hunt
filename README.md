# Cyber-Threat-Hunt

🛡️ Cyber Threat Hunt Report
Reconstruction of Suspicious “Support Session” Activity on gab-intern-vm

Analyst: Drew Howard
Host: gab-intern-vm
Account: g4bri3lintern

Flag-by-Flag Findings

🚩 Flag 1 – Initial Execution Detection

Summary: Identify the earliest suspicious execution originating from Downloads.

Query Purpose:
Find the first PowerShell execution of a suspicious tool launched from the Downloads folder.

Why This Query Is Best:
DeviceProcessEvents shows command-line parameters and time ordering needed to locate the earliest anomalous execution.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FolderPath has "Downloads" or ProcessCommandLine has  "Downloads"
| project TimeGenerated, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName
```
<img width="1334" height="264" alt="Screenshot 2025-12-08 Flag 1" src="https://github.com/user-attachments/assets/51de2b05-6b42-4492-9942-704548be1cc1" />

Answer: -ExecutionPolicy

🚩 Flag 2 – Defense Disabling Attempt

Summary: Identify tamper-related artifacts created or opened.

Query Purpose:
Locate any manually accessed Defender-related shortcut files indicating simulated tamper activity.

Why This Query Is Best:
FileEvents reveal user interaction with files, which is ideal for spotting staged artifacts.
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName contains "Defender"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath 
```
<img width="1334" height="265" alt="Screenshot 2025-12-08 flag 2" src="https://github.com/user-attachments/assets/0100b97a-a714-4abb-ab6f-1c25b2826f5b" />

Answer: DefenderTamperArtifact.lnk

🚩 Flag 3 – Quick Data Probe

Summary: Detect attempts to quickly check clipboard contents.

Query Purpose:
Search for clipboard-related PowerShell commands executed by the user.

Why This Query Is Best:
ProcessCommandLine directly exposes clipboard-harvesting attempts.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("Clip", "Clipboard")
| project TimeGenerated, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName
```
<img width="1334" height="104" alt="Screenshot 2025-12-08 f3" src="https://github.com/user-attachments/assets/6a07fb91-b698-44f1-9212-762dd200fd70" />

Answer:
"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

🚩 Flag 4 – Host Context Recon

Summary: Identify the last recon command used to gather host/user context.

Query Purpose:
Find recon processes matching unusual “qwi” pattern.

Why This Query Is Best:
Sorting descending reveals the final recon attempt within the activity chain.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```
<img width="1334" height="272" alt="Screenshot 2025-12-08 f4" src="https://github.com/user-attachments/assets/3fb0400c-a661-4aaa-b8b8-9516acfab75d" />

Answer: 2025-10-09T12:51:44.3425653Z

🚩 Flag 5 – Storage Surface Mapping

Summary: Identify commands used to enumerate system storage.

Query Purpose:
Search for WMIC disk enumeration commands.

Why This Query Is Best:
WMIC commands are a common method for attackers to perform quick drive mapping.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("disk", "Drive", "logicaldisk")
| project TimeGenerated, AccountName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName
```
<img width="1334" height="228" alt="f5" src="https://github.com/user-attachments/assets/f13c177a-145e-4be8-90d1-1badcb79e963" />

Answer:
"cmd.exe" /c wmic logicaldisk get name,freespace,size

🚩 Flag 6 – Connectivity & Name Resolution

Summary: Identify the parent process initiating network reachability checks.

Query Purpose:
Find the process responsible for DNS/network testing.

Why This Query Is Best:
Process ancestry is best viewed in DeviceProcessEvents, especially for network-triggered actions.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where AccountName == "g4bri3lintern"
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine !contains "msedgewebview2.exe"
| where ProcessCommandLine has_any ("nslookup","Resolve-DnsName","ping ","tracert","traceroute","Test-NetConnection","Invoke-WebRequest","curl","net use","net view","Get-SmbSession","Get-SmbConnection","ipconfig /displaydns","ipconfig /all","netstat")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, InitiatingProcessParentFileName
| order by TimeGenerated desc
```
<img width="1334" height="249" alt="f6" src="https://github.com/user-attachments/assets/c5e6f217-cd4a-424e-ba8d-6a9c7a341441" />

Answer: RuntimeBroker.exe

🚩 Flag 7 – Interactive Session Discovery

Summary: Detect attempts to enumerate active or interactive user sessions.

Query Purpose:
Locate session-query commands and extract their process IDs.

Why This Query Is Best:
DeviceProcessEvents exposes unique process identifiers associated with session enumeration.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where AccountName == "g4bri3lintern"
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine !contains "msedgewebview2.exe"
| where ProcessCommandLine has_any ("nslookup","Resolve-DnsName","ping ","tracert","traceroute","Test-NetConnection","Invoke-WebRequest","curl","net use","net view","Get-SmbSession","Get-SmbConnection","ipconfig /displaydns","ipconfig /all","netstat")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, InitiatingProcessParentFileName, InitiatingProcessUniqueId
| order by TimeGenerated desc
```
<img width="1146" height="212" alt="Screenshot 2025-12-11 at 12 07 26 PM" src="https://github.com/user-attachments/assets/a934af11-77bb-4036-930d-205146c6296d" />
Answer: 2533274790397065

🚩 Flag 8 – Runtime Application Inventory

Summary: Identify enumeration of running applications/services.

Query Purpose:
Search for tasklist.exe invocations.

Why This Query Is Best:
Tasklist is the most common Windows-native tool for runtime inventory.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where AccountName == "g4bri3lintern"
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine !contains "backgroundTaskHost"
| where ProcessCommandLine !contains "msedgewebview2.exe"
| where ProcessCommandLine contains ("Task") or ProcessCommandLine contains ("List") or ProcessCommandLine contains "Last"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, InitiatingProcessParentFileName, InitiatingProcessUniqueId
| order by TimeGenerated desc
```
![image](https://github.com/user-attachments/assets/c2b6d26a-c584-4738-9fe6-1c90d64a14a3)

Answer: tasklist.exe

🚩 Flag 9 – Privilege Surface Check

Summary: Detect attempts to query user privileges or token information.

Query Purpose:
Locate early whoami queries.

Why This Query Is Best:
Sorting ascending gives the earliest privilege-related command in the chain.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where AccountName == "g4bri3lintern"
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine !contains "backgroundTaskHost"
| where ProcessCommandLine !contains "msedgewebview2.exe"
| where ProcessCommandLine contains ("Priv") or ProcessCommandLine contains ("Privilege") or ProcessCommandLine contains "Group"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, InitiatingProcessParentFileName, InitiatingProcessUniqueId
| order by TimeGenerated desc
```
![image](https://github.com/user-attachments/assets/2100efc9-2bd1-45fc-94d0-1ce481aa2795)

Answer: 2025-10-09T12:52:14.3135459Z

🚩 Flag 10 – Proof-of-Access & Egress Validation

Summary: Identify the first outbound connectivity validation endpoint.

Query Purpose:
Search for common test URLs used for connectivity checks.

Why This Query Is Best:
DeviceNetworkEvents stores URLs and timestamps, enabling clear identification of the earliest outbound attempt.
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-9) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc 
```
![image](https://github.com/user-attachments/assets/62ff4b3d-2d8e-45b8-8f2d-74acae3ca3f5)

Answer: www.msftconnecttest.com

🚩 Flag 11 – Artifact Staging

Summary: Identify where staged recon artifacts were first stored.

Query Purpose:
Search for archive creation or drop events referencing ReconArtifacts.zip.

Why This Query Is Best:
FileEvents provide definitive drop paths and creation activity.
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ActionType =~ "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".csv" or FileName endswith ".7z"
| project TimeGenerated, FileName, FileSize, InitiatingProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by TimeGenerated asc
```
![image](https://github.com/user-attachments/assets/1d4d4d4b-79fc-453d-a47b-7d4375b280ff)

Answer:
C:\Users\Public\ReconArtifacts.zip

🚩 Flag 12 – Outbound Transfer Attempt

Summary: Identify the IP of the last suspicious outbound connection.

Query Purpose:
Sort outbound connections to find the most recent unusual IP contact.

Why This Query Is Best:
NetworkEvents capture IPs even when URLs are not present.
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-1) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ActionType in ("ConnectionSuccess", "ConnectionAttempted")
| where InitiatingProcessFileName in ("powershell.exe", "curl.exe", "wget.exe", "python.exe", "cmd.exe")
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, LocalPort, Protocol, InitiatingProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/9097d1a8-1c91-4069-b322-9752ce2e4d8b)

Answer: 100.29.147.161

🚩 Flag 13 – Scheduled Re-Execution Persistence

Summary: Find scheduled tasks created for persistent execution.

Query Purpose:
Locate schtasks-based persistence activity.

Why This Query Is Best:
ProcessCommandLine reveals exact tasknames used in persistence mechanisms.
```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "schtasks"
```

Answer: SupportToolUpdater

🚩 Flag 14 – Autorun Fallback Persistence

Summary: Identify registry-based autorun persistence.

Query Purpose:
Search for Run key modifications referencing the attacker’s tooling.

Why This Query Is Best:
DeviceRegistryEvents directly logs Run key insertions.
```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains "Run"
```

Answer: RemoteAssistUpdater

🚩 Flag 15 – Planted Narrative / Cover Artifact

Summary: Identify a user-facing file dropped to justify suspicious activity.

Query Purpose:
Search for help-themed .lnk files opened/created near suspicious activity.

Why This Query Is Best:
FileEvents reveal timestamp correlation between execution and planted artifacts.
```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where FileName contains "SupportChat"
```

Answer: SupportChat_log.lnk
