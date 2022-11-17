import pair.proto.pairing_pb2 as pairing
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import ssl
import logging

logger = logging.getLogger(__name__)

def debug_print_bytes(bytes):
    bytestring = ""
    for byte in bytes:
        bytestring += "{0:02x} ".format(byte)
    logger.debug(bytestring)

class PairingMessage:
    def __init__(self):
        self.message = pairing.PairingMessage()
        self.message.status = pairing.PairingMessage.Status.STATUS_OK
        self.message.protocol_version = 2
        self.response : pairing.PairingMessage = None

    def serialize(self) -> bytes:
        serialized_message = self.message.SerializeToString()
        len_bytes = len(serialized_message).to_bytes(1,'little')
        return len_bytes + serialized_message

    def send(self, socket: ssl.SSLSocket) -> pairing.PairingMessage.Status:
        socket.send(self.serialize())
        self.response = PairingMessage.receive_response(socket)
        return self.response.status

    def receive_response(socket: ssl.SSLSocket) -> pairing.PairingMessage:
        data = socket.recv(2048)
        message_len = data[0]
        logger.debug(f"Receiving message with length {message_len}")
        data = data[1:len(data)]
        while len(data) != message_len:
            data += socket.recv(2048)
        pairing_message = pairing.PairingMessage()
        pairing_message.ParseFromString(data)
        logger.debug("Received message from android tv:")
        logger.debug(pairing_message)
        return pairing_message



class PairingRequestMessage(PairingMessage):
    def __init__(self):
        super().__init__()
        self.message.pairing_request.client_name = "homeassistant"
        self.message.pairing_request.service_name = "atv.homeassistant.remote"

class PairingOptionsMessage(PairingMessage):
    def __init__(self):
        super().__init__()
        self.message.pairing_option.preferred_role = pairing.ROLE_TYPE_INPUT
        self.message.pairing_option.input_encodings.add()
        self.message.pairing_option.input_encodings[0].type = pairing.PairingEncoding.ENCODING_TYPE_HEXADECIMAL
        self.message.pairing_option.input_encodings[0].symbol_length = 6

class PairingConfigurationMessage(PairingMessage):
    def __init__(self):
        super().__init__()
        self.message.pairing_configuration.client_role = pairing.ROLE_TYPE_INPUT
        self.message.pairing_configuration.encoding.type = pairing.PairingEncoding.ENCODING_TYPE_HEXADECIMAL
        self.message.pairing_configuration.encoding.symbol_length = 6

class PairingSecretMessage(PairingMessage):
    def __init__(self, socket: ssl.SSLSocket, code: str):
        super().__init__()
        der_cert = socket.getpeercert(True)
        self.secret = PairingSecretMessage.calculate_secret(der_cert, code)
        self.message.pairing_secret.secret = self.secret

    def calculate_secret(server_cert_data: bytes, code: str) -> bytes:

        with open("cert/priv_cert.pem", "rb") as f:
            data = f.read()
            client_cert = x509.load_pem_x509_certificate(data)

        server_cert = x509.load_der_x509_certificate(server_cert_data)
        client_pub_key: rsa.RSAPublicKey = client_cert.public_key()
        server_pub_key: rsa.RSAPublicKey = server_cert.public_key()
    
        client_modulus = client_pub_key.public_numbers().n.to_bytes(256, 'big')
        client_exponent = client_pub_key.public_numbers().e.to_bytes(3, 'big')
        server_modulus = server_pub_key.public_numbers().n.to_bytes(256, 'big')
        server_exponent = server_pub_key.public_numbers().e.to_bytes(3, 'big')

        logger.debug(client_modulus)
        logger.debug(client_exponent)
        logger.debug(server_modulus)
        logger.debug(server_exponent)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(client_modulus)
        digest.update(client_exponent)
        digest.update(server_modulus)
        digest.update(server_exponent)

        code_bin = bytes.fromhex(code[2:len(code)])
        logger.debug(code_bin)
        logger.info(f"Sending code {code[2:len(code)]}")
        digest.update(code_bin)
        hash = digest.finalize()
        logger.debug(len(hash))
        logger.debug(hash)
        logger.debug(bytes.fromhex(code))
        if hash[0] != bytes.fromhex(code)[0]:
            raise BaseException("Wrong Code")
        return hash






        

        


