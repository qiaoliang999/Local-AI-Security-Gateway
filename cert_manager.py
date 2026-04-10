from OpenSSL import crypto, SSL
from pathlib import Path
import os
import datetime

CERTS_DIR = Path("certs")

def generate_ca():
    """Generates a root CA certificate and private key if they don't exist."""
    CERTS_DIR.mkdir(exist_ok=True)
    ca_key_path = CERTS_DIR / "ca.key"
    ca_crt_path = CERTS_DIR / "ca.crt"

    if ca_key_path.exists() and ca_crt_path.exists():
        return

    print("Generating new Root CA...")
    # Generate CA key
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Generate CA cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "CA"
    cert.get_subject().L = "San Francisco"
    cert.get_subject().O = "Local AI Security Gateway"
    cert.get_subject().OU = "Security Team"
    cert.get_subject().CN = "Local AI Gateway Root CA"
    
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60) # Valid for 10 years
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    
    # Add extension to mark it as a CA
    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
    ])
    
    cert.sign(k, 'sha256')

    with open(ca_key_path, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    with open(ca_crt_path, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        
    print(f"Root CA generated at {ca_crt_path}")
    print("IMPORTANT: You MUST install and trust this CA certificate in your OS for MITM interception to work without warnings!")

def generate_domain_cert(domain: str):
    """Generates a certificate for a specific domain signed by our Root CA."""
    domain_key_path = CERTS_DIR / f"{domain}.key"
    domain_crt_path = CERTS_DIR / f"{domain}.crt"

    if domain_key_path.exists() and domain_crt_path.exists():
        return str(domain_crt_path), str(domain_key_path)

    print(f"Generating certificate for {domain}...")
    
    # Load CA
    with open(CERTS_DIR / "ca.key", "rt") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    with open(CERTS_DIR / "ca.crt", "rt") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    # Generate domain key
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Generate domain cert request
    req = crypto.X509Req()
    req.get_subject().CN = domain
    req.set_pubkey(k)
    req.sign(k, 'sha256')

    # Generate domain cert
    cert = crypto.X509()
    cert.set_subject(req.get_subject())
    cert.set_serial_number(int(datetime.datetime.now().timestamp()))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60) # Valid for 1 year
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(req.get_pubkey())
    
    # Subject Alternative Name is required by modern browsers/clients
    san_b = f"DNS:{domain}".encode("ascii")
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, san_b)
    ])

    cert.sign(ca_key, 'sha256')

    with open(domain_key_path, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    with open(domain_crt_path, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

    return str(domain_crt_path), str(domain_key_path)

if __name__ == "__main__":
    generate_ca()
