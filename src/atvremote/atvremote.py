import ssl
import datetime
import logging
import os
from typing import Callable
from atvremote import messages
from atvremote.proto import pairing_pb2 as pairing
from atvremote.proto import commands_pb2 as commands
import asyncio
from typing import Tuple
from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

class ATVRemote():

    def __init__(self, hostname: str, receive_callback: Callable[[commands.RemoteMessage], None]) -> None:
        self.hostname = hostname
        self.receive_callback = receive_callback
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.load_client_certificate()
        self.hostname = hostname
        self.pairing_port = 6467
        self.connection_port = 6466

    def load_client_certificate(self):
        (self.private_key, self.client_cert) = self.generate_self_signed_certificate()
        self.write_certificate_to_disk()
        self.context.load_cert_chain('cert/client_cert.pem','cert/key.pem')

    def write_certificate_to_disk(self):
        os.makedirs("cert", exist_ok=True)
        # Write our key to disk for safe keeping
        with open("cert/key.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        # Write our certificate out to disk.
        with open("cert/client_cert.pem", "wb") as f:
            f.write(self.client_cert.public_bytes(serialization.Encoding.PEM))

    async def pair(self, input_code_callback: Callable[[None], str]) -> bool:
        #get_public_certificate()
        reader, writer = await asyncio.open_connection(self.hostname, self.pairing_port, ssl= self.context)
        socket: ssl.SSLSocket = writer.get_extra_info('ssl_object')
        self.server_cert = socket.getpeercert(binary_form=True)
        logging.info("Sending pairing request")
        status = await messages.PairingRequestMessage().send(reader, writer)
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Pairing request failed with code {status}")
            return False
        logging.info("Pairing request succesful")

        logging.info("Sending pairing options")
        status = await messages.PairingOptionsMessage().send(reader, writer)
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Setting pairing options failed with code {status}")
            return False
        logging.info("Setting pairing options succesful")

        logging.info("Sending pairing configuration")
        status = await messages.PairingConfigurationMessage().send(reader, writer)
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Setting pairing configuration failed with code {status}")
            return False
        logging.info("Setting pairing configuration succesful")

        code = input_code_callback()
        logging.info("Sending pairing secret")
        status = await messages.PairingSecretMessage(self.server_cert, code).send(reader, writer)
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Setting pairing secret failed with code {status}")
            return False
        logging.info("Setting pairing secret succesful")
        writer.close()
        return True
            

    def generate_self_signed_certificate(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        #Generate an X.509 Certificate with the given Common Name.
        logging.info("Generating new client certificate")
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
            datetime.datetime.utcnow() + datetime.timedelta(days=365*100)
        ).add_extension(
            x509.SubjectAlternativeName([
                DNSName(cn)
            ]), False
        ).sign(private_key, hashes.SHA256(), default_backend())

        return private_key, certificate

    async def connect(self) -> bool:
        self.context.load_cert_chain('cert/client_cert.pem','cert/key.pem')
        self.reader, self.writer = await asyncio.open_connection(self.hostname, self.connection_port, ssl=self.context)
        logger.debug("Connected to android tv")
        try:
            await messages.CommandMessage.receive_response(self.reader)
            await messages.ConfigurationMessage().send(self.writer)
            await messages.CommandMessage.receive_response(self.reader)
            await messages.SetActiveMessage().send(self.writer)
        except RuntimeError as exception:
            logger.exception("Error while establishing connection", exception)
            self.writer.close()
            return False
        return True

    async def disconnect(self):
        self.writer.close()
        

    async def key_down(self, key_code):
        await messages.KeypressMessage(key_code, commands.RemoteDirection.START_LONG).send(self.writer)

    async def key_up(self, key_code):
        await messages.KeypressMessage(key_code, commands.RemoteDirection.END_LONG).send(self.writer)

    async def key_press(self, key_code):
        await messages.KeypressMessage(key_code, commands.RemoteDirection.SHORT).send(self.writer)

    async def listen_forever(self):
        while True:
            try:
                msg = await messages.CommandMessage.receive_response(self.reader)
            except RuntimeError as exception:
                logger.exception("Error in atv-remote communication", exception)
                self.writer.close()
                raise
            if msg.HasField('remote_ping_request'):
                await messages.PingResponseMessage(msg.remote_ping_request.val1).send(self.writer)
            else:
                self.receive_callback(msg)