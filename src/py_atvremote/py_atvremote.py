import ssl
import datetime
import time
import logging
import os
from typing import Callable
from py_atvremote import messages
from py_atvremote.proto import pairing_pb2 as pairing
from py_atvremote.proto import commands_pb2 as commands
import asyncio
from typing import Tuple
from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from py_atvremote.constants import APPS

logger = logging.getLogger(__name__)

class ATVRemote():

    def __init__(self, hostname: str) -> None:
        self.hostname = hostname
        
        self.hostname = hostname
        self.pairing_port = 6467
        self.connection_port = 6466
        self.listen_task = None
        self.timeout_seconds = 30
        self.activity = "Standby"
        self.update_callback: Callable[[None], None] = None
        self.device_info: commands.RemoteDeviceInfo = None

    def create_context()-> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ATVRemote.load_client_certificate(context)
        return context

    def load_client_certificate(context: ssl.SSLContext):
        if not (os.path.isfile('cert/client_cert.pem') and os.path.isfile('cert/key.pem')):
            (private_key, client_cert) = ATVRemote.generate_self_signed_certificate()
            ATVRemote.write_certificate_to_disk(private_key, client_cert)
        context.load_cert_chain('cert/client_cert.pem','cert/key.pem')

    def write_certificate_to_disk(private_key, client_cert):
        os.makedirs("cert", exist_ok=True)
        # Write our key to disk for safe keeping
        with open("cert/key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        # Write our certificate out to disk.
        with open("cert/client_cert.pem", "wb") as f:
            f.write(client_cert.public_bytes(serialization.Encoding.PEM))

    async def start_pairing(self) -> bool:
        context = ATVRemote.create_context()
        self.reader, self.writer = await asyncio.open_connection(self.hostname, self.pairing_port, ssl= context)
        socket: ssl.SSLSocket = self.writer.get_extra_info('ssl_object')
        server_certificate_data = socket.getpeercert(binary_form=True)
        self.server_certificate = x509.load_der_x509_certificate(server_certificate_data)
        self.unique_id = self.server_certificate.fingerprint(hashes.SHA1()).hex()
        logging.info("Sending pairing request")
        status = await messages.PairingRequestMessage().send(self.reader, self.writer)
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Pairing request failed with code {status}")
            return False
        logging.info("Pairing request succesful")

        logging.info("Sending pairing options")
        status = await messages.PairingOptionsMessage().send(self.reader, self.writer)
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Setting pairing options failed with code {status}")
            return False
        logging.info("Setting pairing options succesful")

        logging.info("Sending pairing configuration")
        status = await messages.PairingConfigurationMessage().send(self.reader, self.writer)
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Setting pairing configuration failed with code {status}")
            return False
        logging.info("Setting pairing configuration succesful")
        return True

    async def finish_pairing(self, code: str) -> bool:
        logging.info("Sending pairing secret")
        status = await messages.PairingSecretMessage(self.server_certificate, code).send(self.reader, self.writer)
        self.server_certificate = None
        if status != pairing.PairingMessage.Status.STATUS_OK:
            logging.error(f"Setting pairing secret failed with code {status}")
            return False
        logging.info("Setting pairing secret succesful")
        self.writer.close()
        return True
            

    def generate_self_signed_certificate() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
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

        context = ATVRemote.create_context()
        self.reader, self.writer = await asyncio.open_connection(self.hostname, self.connection_port, ssl=context)
        socket: ssl.SSLSocket = self.writer.get_extra_info('ssl_object')
        server_certificate_data = socket.getpeercert(binary_form=True)
        server_certificate = x509.load_der_x509_certificate(server_certificate_data)
        self.unique_id = server_certificate.fingerprint(hashes.SHA1()).hex()
        logger.debug("Connected to android tv")
        try:
            config_message = await messages.CommandMessage.receive_response(self.reader)
            self.device_info = config_message.remote_configure.device_info
            await messages.ConfigurationMessage().send(self.writer)
            await messages.CommandMessage.receive_response(self.reader)
            await messages.SetActiveMessage().send(self.writer)
        except RuntimeError as exception:
            logger.exception("Error while establishing connection", exception)
            self.disconnect()
            return False
        return True

    def disconnect(self):
        if self.listen_task != None and not self.listen_task.done():
            self.listen_task.cancel()
        self.writer.close()

    def update(self, message: commands.RemoteMessage):
        if not message.HasField("remote_ime_key_inject"):
            return
        logger.info(message)
        package = message.remote_ime_key_inject.app_info.app_package
        self.activity = APPS.get(package, package)
        self.update_callback()

    def get_activity(self) -> str:
        return self.activity


        

    async def key_down(self, key_code):
        await self.ensure_connection()
        await messages.KeypressMessage(key_code, commands.RemoteDirection.START_LONG).send(self.writer)

    async def key_up(self, key_code):
        await self.ensure_connection()
        await messages.KeypressMessage(key_code, commands.RemoteDirection.END_LONG).send(self.writer)

    async def key_press(self, key_code):
        await self.ensure_connection()
        await messages.KeypressMessage(key_code, commands.RemoteDirection.SHORT).send(self.writer)

    async def listen_forever(self):
        self.last_ping = time.time()
        while True:
            try:
                msg = await asyncio.wait_for(messages.CommandMessage.receive_response(self.reader), self.timeout_seconds)
            except RuntimeError as exception:
                logger.exception("Error in atv-remote communication", exception)
                self.disconnect()
                return
            except TimeoutError as exception:
                logger.exception(f"No response in more than {self.timeout_seconds} seconds", exception)
                self.disconnect()
                return
            if msg.HasField('remote_ping_request'):
                await messages.PingResponseMessage(msg.remote_ping_request.val1).send(self.writer)
                self.last_ping = time.time()
            else:
                if time.time() - self.last_ping > self.timeout_seconds:
                    logger.exception(f"No ping response in more than {self.timeout_seconds} seconds")
                    self.disconnect()
                    return
                self.update(msg)

    async def ensure_connection(self):
        if not self.listen_task.done():
            return
        await self.reestablish_connection()

    async def reestablish_connection(self):
        if not await self.connect():
            return
        self.listen_task = asyncio.create_task(self.listen_forever())

    async def establish_connection(self, update_callback: Callable[[None], None], timeout_seconds: int = 30):
        self.timeout_seconds = timeout_seconds
        self.update_callback = update_callback
        await self.reestablish_connection()
        