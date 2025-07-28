import ssl
import socket

def check_ssl_certificate(self, domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert["issuer"])
                return issuer.get("organizationName") not in ["Google Trust Services", "DigiCert Inc."]
    except:
        return True  # Assume phishing if SSL check fails
