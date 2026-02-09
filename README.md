# DarkHav0c Ransomware Memory Forensics Challenge

## Challenge Overview
**Objective**: Perform memory forensics on a Windows memory dump to identify a suspicious executable running in memory, determine its characteristics, extract indicators of compromise (IOC), and analyze ransomware behavior.

**Malware Family**: DarkHav0c (ransomware variant)  
**Execution Context**: Masqueraded as `SpotifySetup.exe` (likely a trojanized installer dropped in Downloads folder)  
**Key Behaviors**:
- Runs directly from user Downloads (not Program Files)
- Child process of `explorer.exe`
- Encrypts files with `.Hav0c` extension
- Attempts C2 communication to a suspicious IP/port

**Tools Used**:
- Volatility (memory analysis framework)
- ExifTool (for dumping/analyzing embedded data in memory artifacts)
- Filescan, pslist/pstree, netscan plugins (Volatility)
- Basic terminal commands for output redirection

## Step-by-Step Analysis

### 1. Identify Suspicious Process in Memory
- Used Volatility's `pslist` or `pstree` to enumerate running processes.
- Identified `SpotifySetup.exe` as suspicious due to:
  - Running as a child of `explorer.exe` (common for malware that injects or drops from explorer)
  - Not in expected Program Files path — typical of droppers/trojans that execute payloads immediately without full installation.

<img width="970" height="518" alt="pstree" src="https://github.com/user-attachments/assets/0e7d3aa3-019d-4628-926a-2c9188d26031" />

<img width="926" height="538" alt="SpotifySetup exe" src="https://github.com/user-attachments/assets/aec36281-1f96-47c9-a53c-3364724dd1e3" />

<img width="1336" height="833" alt="full path of malicious file" src="https://github.com/user-attachments/assets/eaaa1b8a-7c20-4ed8-866e-f043e1a249e9" />

<img width="1102" height="633" alt="PID" src="https://github.com/user-attachments/assets/628d63b5-78a0-43e4-be42-131dbbc7853d" />


**Key Findings**:
- **Process Name**: SpotifySetup.exe (masqueraded legitimate app)
- **Internal/Malware Name**: DarkHav0c
- **Full Path**: `C:\Users\Zifrana\Downloads\SpotifySetup.exe`
- **PID**: 6816
- **Execution Time**: 2025-02-24 10:51:16

### 2. Memory Dump Extraction & Analysis
- Created a memory dump for PID 6816.
- Dragged and dropped the dump into **ExifTool** (Exfiltool variant?) to inspect embedded metadata/sections.
- This revealed additional details about the payload (e.g., custom tag names or binary sections containing executable data)
  
<img width="895" height="160" alt="Created dumpfile for PID 6816" src="https://github.com/user-attachments/assets/cc682c21-66ac-4f36-8afe-7ec2b850fba0" />

<img width="750" height="389" alt="drag and drop dump into exif" src="https://github.com/user-attachments/assets/ea96be5f-055c-4373-aaf3-513ba5292d22" />


### 3. Ransomware Encryption Extension
- Ran Volatility `filescan` plugin to scan for file objects in memory.
- Identified encrypted files using the custom extension: **.Hav0c**

This is a strong IOC — searching disk or memory for files ending in `.Hav0c` would confirm infection scope.

<img width="579" height="379" alt="DarkHav0c" src="https://github.com/user-attachments/assets/da58fefa-c941-4104-be6e-70b1c39f4812" />

### 4. Network Activity & C2 Detection
- Used Volatility `netscan` or `connscan` to enumerate network connections from the infected process/memory.
- Discovered attempted outbound communication to:
  - **IP**: 104.152.52.238
  - **Port**: 6548
  
<img width="941" height="172" alt="IP and Port discovery" src="https://github.com/user-attachments/assets/b180a5fb-caa9-4083-a49b-6305b4766102" />

This IP/port is likely the ransomware's command-and-control (C2) server for exfiltration, key retrieval, or status reporting.



## Indicators of Compromise (IOCs)
| Category       | Value                              | Notes                              |
|----------------|------------------------------------|------------------------------------|
| File Name      | SpotifySetup.exe                  | Masqueraded dropper                |
| Malware Name   | DarkHav0c                         | Internal name from analysis        |
| Full Path      | C:\Users\Zifrana\Downloads\SpotifySetup.exe | Non-standard install location     |
| PID            | 6816                              | At time of dump                    |
| Execution Time | 2025-02-24 10:51:16               | From process creation time         |
| Encryption Ext | .Hav0c                            | Ransomware marker                  |
| C2 IP:Port     | 104.152.52.238:6548               | Outbound connection attempt        |

## Recommendations / Lessons Learned
- Avoid executing installers directly from Downloads — verify sources and use sandboxing.
- Monitor for child processes of explorer.exe spawning unusual binaries.
- Block suspicious IPs/ports at firewall level.
- Enable EDR/memory forensics for rapid ransomware detection.
- User awareness: Fake "setup" files (e.g., Spotify) are common phishing vectors.

This challenge demonstrates classic memory forensics workflow for identifying fileless/malware-in-memory threats and ransomware IOCs.

**Tools & References**:
- Volatility 3 Documentation: https://volatility3.readthedocs.io/
- ExifTool: https://exiftool.org/
- General ransomware analysis techniques (similar to samples in CTFs like Huntress, CyberDefenders)
