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
import pair.proto.pairing_pb2 as pairing
import os
import logging
import socket
import ssl
import pair.messages as messages
from remote.remote import Remote

hostname = '127.0.0.1'
port = 6467


def get_public_certificate():
    if(os.path.exists("cert/priv_cert.pem")):
        cert_creation_time = os.path.getmtime("cert/priv_cert.pem")
        if datetime.datetime.utcnow().timestamp() - cert_creation_time < datetime.timedelta(days=355).total_seconds():
            return
    (priv_key, priv_cert) = generate_self_signed_certificate()
    write_certificate_to_disk(priv_key, "test", priv_cert)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain('cert/priv_cert.pem','cert/key.pem', password=b"password")
    context.check_hostname = False
    context.verify_mode = context.verify_mode.CERT_NONE
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
            dercert = sslsock.getpeercert(True)
    pub_cert = ssl.DER_cert_to_PEM_cert(dercert)
    write_certificate_to_disk(priv_key, pub_cert, priv_cert)



def generate_self_signed_certificate() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    #Generate an X.509 Certificate with the given Common Name.
    print("Generating new client certificate")
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
            encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
        ))
    # Write our certificate out to disk.
    with open("cert/priv_cert.pem", "wb") as f:
        f.write(priv_cert.public_bytes(serialization.Encoding.PEM))
    with open("cert/pub_cert.pem", "w") as f:
        f.write(pub_cert)

def pair_with_android_tv() -> int:
    get_public_certificate()
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    #context.load_verify_locations('cert/pub_cert.pem')
    
    context.load_cert_chain('cert/priv_cert.pem','cert/key.pem', password=b"password")
    context.check_hostname = False
    context.verify_mode = context.verify_mode.CERT_NONE
    with socket.create_connection((hostname, 6467)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            logging.info("Sending pairing request")
            status = messages.PairingRequestMessage().send(ssock)
            if status != pairing.PairingMessage.Status.STATUS_OK:
                logging.error(f"Pairing request failed with code {status}")
                return -1
            logging.info("Pairing request succesful")

            logging.info("Sending pairing options")
            status = messages.PairingOptionsMessage().send(ssock)
            if status != pairing.PairingMessage.Status.STATUS_OK:
                logging.error(f"Setting pairing options failed with code {status}")
                return -1
            logging.info("Setting pairing options succesful")

            logging.info("Sending pairing configuration")
            status = messages.PairingConfigurationMessage().send(ssock)
            if status != pairing.PairingMessage.Status.STATUS_OK:
                logging.error(f"Setting pairing configuration failed with code {status}")
                return -1
            logging.info("Setting pairing configuration succesful")

            code = input("Code:")
            logging.info("Sending pairing secret")
            status = messages.PairingSecretMessage(ssock, code).send(ssock)
            if status != pairing.PairingMessage.Status.STATUS_OK:
                logging.error(f"Setting pairing secret failed with code {status}")
                return -1
            logging.info("Setting pairing secret succesful")
            return 0

            #status = pairing_messages.PairingSecretMessage(ssock).send((ssock))
            

def main() -> int:
    logging.basicConfig(level=logging.DEBUG)
    #pair_with_android_tv()
    remote = Remote(hostname)
    remote.loop()
    return 0




if __name__ == '__main__':
    sys.exit(main())  # next section explains the use of sys.exit