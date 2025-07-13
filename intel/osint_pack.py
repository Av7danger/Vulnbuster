"""
OSINT Pack
Pulls LinkedIn, GitHub repos, breached dumps, pastebin mentions.
Usage: --osint NAME
"""
import requests
import sys

def github_repos(name):
    resp = requests.get(f'https://api.github.com/users/{name}/repos')
    if resp.status_code == 200:
        return [repo['html_url'] for repo in resp.json()]
    return []

def linkedin_search(name):
    # Stub: LinkedIn API is private, so just simulate
    return [f'https://www.linkedin.com/in/{name}']

def pastebin_mentions(name):
    # Stub: In production, use Pastebin scraping/API
    return [f'https://pastebin.com/u/{name}']

def breached_dumps(name):
    # Stub: In production, use HaveIBeenPwned or similar
    return [f'{name}@example.com:password123']

def main():
    import argparse
    parser = argparse.ArgumentParser(description="OSINT Pack")
    parser.add_argument('--osint', metavar='NAME', help='Name to search OSINT for')
    args = parser.parse_args()
    if args.osint:
        print(f"[+] OSINT for {args.osint}")
        print("[GitHub]", github_repos(args.osint))
        print("[LinkedIn]", linkedin_search(args.osint))
        print("[Pastebin]", pastebin_mentions(args.osint))
        print("[Breached Dumps]", breached_dumps(args.osint))

if __name__ == "__main__":
    main() 