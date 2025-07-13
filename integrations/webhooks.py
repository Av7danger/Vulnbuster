"""
Slack/Discord Webhook Alerts
Sends alerts to Slack/Discord when critical vulns or shells detected.
Usage: --alert-slack WEBHOOK
"""
import requests

def send_alert(webhook_url, message):
    data = {'text': message}
    resp = requests.post(webhook_url, json=data)
    return resp.status_code == 200

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Slack/Discord Webhook Alerts")
    parser.add_argument('--alert-slack', metavar='WEBHOOK', help='Slack/Discord webhook URL')
    parser.add_argument('--message', required=True, help='Alert message')
    args = parser.parse_args()
    if args.alert_slack:
        ok = send_alert(args.alert_slack, args.message)
        if ok:
            print("[+] Alert sent successfully.")
        else:
            print("[!] Failed to send alert.")

if __name__ == "__main__":
    main() 