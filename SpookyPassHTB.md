# HTB Challenge Writeup - Reverse Engineering

## Challenge Information

- **Platform**: Hack The Box
- **Category**: Reverse Engineering
- **Difficulty**: Easy
- **Challenge Type**: Binary Analysis

## Executive Summary

This writeup documents the solution to an HTB reverse engineering challenge involving a password-protected executable. The challenge was solved using static analysis techniques to extract hardcoded credentials from the binary and obtain the flag.

## File Analysis

The challenge provided a ZIP archive containing an executable file named `pass`:

![Challenge Files](images/Captura%20de%20pantalla%202025-08-17%20230058.png)

### Initial Execution

Running the executable revealed a password authentication prompt:

![Password Authentication](images/Captura%20de%20pantalla%2020250817230418.png)

The program displays a themed message about a "SPOOKIEST party" and requests a password for authentication.

## Solution

### Static Analysis Approach

Since no password hints were provided, I used the `strings` command to extract readable text from the binary:

```bash
strings pass
```

### Critical Discovery

The string analysis revealed the hardcoded password embedded in the binary:

```bash
❯ strings pass
[...]
Welcome to the 
[1;3mSPOOKIEST
[0m party of the year.
Before we let you in, you'll need to give us the password: 
s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
You're not a real ghost; clear off!
[...]
```

**Password Found**: `s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5`

### Flag Extraction

Using the discovered password, authentication was bypassed and the flag was revealed:

![Flag Revealed](images/Pasted%20image%2020250817230853.png)

## Technical Analysis

**Binary Details**:

- C program compiled with GCC 14.2.1
- x86_64 Linux executable
- Uses `strcmp()` for password validation
- Hardcoded credentials stored in plaintext

**Vulnerability**: The authentication mechanism relies on a hardcoded password stored directly in the binary, making it trivially extractable through static analysis.

## Key Lessons

1. **Static Analysis Effectiveness**: Simple tools like `strings` can reveal critical information
2. **Hardcoded Credentials**: Never store sensitive data directly in binaries
3. **Client-Side Security**: Avoid relying on client-side validation for authentication
4. **Basic RE Skills**: Many challenges can be solved with fundamental reverse engineering techniques

## Conclusion

This challenge demonstrated a common security vulnerability where hardcoded credentials in binaries can be easily extracted using basic static analysis tools. The solution required minimal reverse engineering skills and highlighted the importance of secure coding practices in real-world applications.
