"""
Header Cloaking / Impersonation
Rotates headers to impersonate browsers, crawlers, or whitelisted bots.
Usage: --cloak-agent, --impersonate-agent NAME
"""
import random

AGENTS = {
    'chrome': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
    },
    'firefox': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Accept-Language': 'en-US,en;q=0.9',
    },
    'googlebot': {
        'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'From': 'googlebot(at)googlebot.com',
    },
    'bingbot': {
        'User-Agent': 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    },
    'yandex': {
        'User-Agent': 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
    },
}

DEFAULTS = ['chrome', 'firefox', 'googlebot', 'bingbot', 'yandex']

def get_headers(agent=None, rotate=False):
    if rotate:
        agent = random.choice(DEFAULTS)
    if agent and agent in AGENTS:
        return AGENTS[agent]
    return AGENTS[random.choice(DEFAULTS)]

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Header Cloaking / Impersonation")
    parser.add_argument('--cloak-agent', action='store_true', help='Rotate agent headers')
    parser.add_argument('--impersonate-agent', choices=DEFAULTS, help='Impersonate a specific agent')
    args = parser.parse_args()
    headers = get_headers(agent=args.impersonate_agent, rotate=args.cloak_agent)
    print("[Headers]")
    for k, v in headers.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    main() 