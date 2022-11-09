import sys
import datetime
from typing import Tuple
from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import os
import socket
import ssl

hostname = '127.0.0.1'


def get_public_certificate() -> Tuple[str, str]:

    pub_cert = ssl.get_server_certificate(addr=(hostname, 6467))
    (priv_key, priv_cert) = generate_self_signed_certificate()
    write_certificate_to_disk(priv_key, pub_cert, priv_cert)
    return "Fertig"



def generate_self_signed_certificate() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    #Generate an X.509 Certificate with the given Common Name.
    cn = "atvremote"
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Inc.")
    ])

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    certificate = x509.CertificateBuilder().subject_name(name
    ).issuer_name(
        name
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            DNSName(cn)
        ]), False
    ).sign(private_key, hashes.SHA256(), default_backend())

    return private_key, certificate 


def write_certificate_to_disk(private_key, pub_cert, priv_cert):
    os.makedirs("cert", exist_ok=True)
    # Write our key to disk for safe keeping
    with open("cert/key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    # Write our certificate out to disk.
    with open("cert/priv_cert.pem", "wb") as f:
        f.write(priv_cert.public_bytes(serialization.Encoding.PEM))
    with open("cert/pub_cert.pem", "w") as f:
        f.write(pub_cert)

def pair_with_android_tv():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('cert/pub_cert.pem')
    context.verify_mode = context.verify_mode.CERT_OPTIONAL
    context.check_hostname = False
    with socket.create_connection((hostname, 6467)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print(ssock.version())


def main() -> int:

    get_public_certificate()
    pair_with_android_tv()
    
    return 0




if __name__ == '__main__':
    sys.exit(main())  # next section explains the use of sys.exit