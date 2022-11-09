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


def get_public_certificate() -> str:

    """ context : SSL.Context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    #s.connect("localhost", 6467)
    connection = SSL.Connection(context, s)
    connection.connect(("localhost",6467))
    connection.
    test = connection.get_state_string() """
    hostname = 'localhost'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    pub_cert = ssl.get_server_certificate(addr=(hostname, 6467))
    (priv_key, priv_cert) = generate_self_signed_certificate()
    write_certificate_to_disk(priv_key, pub_cert, priv_cert)
    #with socket.create_connection((hostname, 6467)) as sock:
    #with context.wrap_socket(sock, server_hostname=hostname) as ssock:
    #        print(ssock.version())
    return "Fertig"



def generate_self_signed_certificate() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    #Generate an X.509 Certificate with the given Common Name.
    cn = "home_assistant_remote"
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test")
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


def main() -> int:

    print(get_public_certificate())
    
    return 0




if __name__ == '__main__':
    sys.exit(main())  # next section explains the use of sys.exit