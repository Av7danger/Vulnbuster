"""
TLS/SSL Analyzer
Checks for weak ciphers, expired certs, self-signed certs, wildcard abuse.
"""
import ssl
import socket
import datetime
import OpenSSL

def analyze_tls(host, port=443):
    findings = []
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            # Expiry
            not_after = cert['notAfter']
            expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            if expire_date < datetime.datetime.utcnow():
                findings.append('Certificate expired')
            # Wildcard abuse
            subject = dict(x[0] for x in cert['subject'])
            if 'CN' in subject and subject['CN'].startswith('*.'):
                findings.append('Wildcard certificate in use')
    # Self-signed check
    try:
        cert = ssl.get_server_certificate((host, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issuer = x509.get_issuer()
        subject = x509.get_subject()
        if issuer.CN == subject.CN:
            findings.append('Self-signed certificate')
    except Exception:
        findings.append('Could not verify self-signed status')
    # Weak ciphers
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers('LOW:EXP:NULL')
        with socket.create_connection((host, port), timeout=5) as sock:
            try:
                ctx.wrap_socket(sock, server_hostname=host)
                findings.append('Weak cipher accepted')
            except ssl.SSLError:
                pass
    except Exception:
        findings.append('Could not test weak ciphers')
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="TLS/SSL Analyzer")
    parser.add_argument('--host', required=True, help='Target host')
    parser.add_argument('--port', type=int, default=443, help='Target port')
    args = parser.parse_args()
    findings = analyze_tls(args.host, args.port)
    print("[TLS/SSL Analysis Results]")
    for f in findings:
        print(f" - {f}")

if __name__ == "__main__":
    main() 