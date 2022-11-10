# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: proto/pairing.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13proto/pairing.proto\x12\x07pairing\";\n\x0ePairingRequest\x12\x13\n\x0b\x63lient_name\x18\x02 \x01(\t\x12\x14\n\x0cservice_name\x18\x01 \x01(\t\"(\n\x11PairingRequestAck\x12\x13\n\x0bserver_name\x18\x01 \x01(\t\"\x98\x02\n\x0fPairingEncoding\x12\x33\n\x04type\x18\x01 \x01(\x0e\x32%.pairing.PairingEncoding.EncodingType\x12\x15\n\rsymbol_length\x18\x02 \x01(\r\"\xb8\x01\n\x0c\x45ncodingType\x12\x19\n\x15\x45NCODING_TYPE_UNKNOWN\x10\x00\x12\x1e\n\x1a\x45NCODING_TYPE_ALPHANUMERIC\x10\x01\x12\x19\n\x15\x45NCODING_TYPE_NUMERIC\x10\x02\x12\x1d\n\x19\x45NCODING_TYPE_HEXADECIMAL\x10\x03\x12\x18\n\x14\x45NCODING_TYPE_QRCODE\x10\x04\x12\x19\n\x0cUNRECOGNIZED\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\"\xa1\x01\n\rPairingOption\x12\x31\n\x0finput_encodings\x18\x01 \x03(\x0b\x32\x18.pairing.PairingEncoding\x12\x32\n\x10output_encodings\x18\x02 \x03(\x0b\x32\x18.pairing.PairingEncoding\x12)\n\x0epreferred_role\x18\x03 \x01(\x0e\x32\x11.pairing.RoleType\"j\n\x14PairingConfiguration\x12*\n\x08\x65ncoding\x18\x01 \x01(\x0b\x32\x18.pairing.PairingEncoding\x12&\n\x0b\x63lient_role\x18\x02 \x01(\x0e\x32\x11.pairing.RoleType\"\x19\n\x17PairingConfigurationAck\"\x1f\n\rPairingSecret\x12\x0e\n\x06secret\x18\x01 \x01(\x0c\"\"\n\x10PairingSecretAck\x12\x0e\n\x06secret\x18\x01 \x01(\x0c\"\x82\x05\n\x0ePairingMessage\x12\x18\n\x10protocol_version\x18\x01 \x01(\x05\x12.\n\x06status\x18\x02 \x01(\x0e\x32\x1e.pairing.PairingMessage.Status\x12\x14\n\x0crequest_case\x18\x03 \x01(\x05\x12\x30\n\x0fpairing_request\x18\n \x01(\x0b\x32\x17.pairing.PairingRequest\x12\x37\n\x13pairing_request_ack\x18\x0b \x01(\x0b\x32\x1a.pairing.PairingRequestAck\x12.\n\x0epairing_option\x18\x14 \x01(\x0b\x32\x16.pairing.PairingOption\x12<\n\x15pairing_configuration\x18\x1e \x01(\x0b\x32\x1d.pairing.PairingConfiguration\x12\x43\n\x19pairing_configuration_ack\x18\x1f \x01(\x0b\x32 .pairing.PairingConfigurationAck\x12.\n\x0epairing_secret\x18( \x01(\x0b\x32\x16.pairing.PairingSecret\x12\x35\n\x12pairing_secret_ack\x18) \x01(\x0b\x32\x19.pairing.PairingSecretAck\"\x8a\x01\n\x06Status\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x0e\n\tSTATUS_OK\x10\xc8\x01\x12\x11\n\x0cSTATUS_ERROR\x10\x90\x03\x12\x1d\n\x18STATUS_BAD_CONFIGURATION\x10\x91\x03\x12\x16\n\x11STATUS_BAD_SECRET\x10\x92\x03\x12\x19\n\x0cUNRECOGNIZED\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01*g\n\x08RoleType\x12\x15\n\x11ROLE_TYPE_UNKNOWN\x10\x00\x12\x13\n\x0fROLE_TYPE_INPUT\x10\x01\x12\x14\n\x10ROLE_TYPE_OUTPUT\x10\x02\x12\x19\n\x0cUNRECOGNIZED\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'proto.pairing_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _ROLETYPE._serialized_start=1431
  _ROLETYPE._serialized_end=1534
  _PAIRINGREQUEST._serialized_start=32
  _PAIRINGREQUEST._serialized_end=91
  _PAIRINGREQUESTACK._serialized_start=93
  _PAIRINGREQUESTACK._serialized_end=133
  _PAIRINGENCODING._serialized_start=136
  _PAIRINGENCODING._serialized_end=416
  _PAIRINGENCODING_ENCODINGTYPE._serialized_start=232
  _PAIRINGENCODING_ENCODINGTYPE._serialized_end=416
  _PAIRINGOPTION._serialized_start=419
  _PAIRINGOPTION._serialized_end=580
  _PAIRINGCONFIGURATION._serialized_start=582
  _PAIRINGCONFIGURATION._serialized_end=688
  _PAIRINGCONFIGURATIONACK._serialized_start=690
  _PAIRINGCONFIGURATIONACK._serialized_end=715
  _PAIRINGSECRET._serialized_start=717
  _PAIRINGSECRET._serialized_end=748
  _PAIRINGSECRETACK._serialized_start=750
  _PAIRINGSECRETACK._serialized_end=784
  _PAIRINGMESSAGE._serialized_start=787
  _PAIRINGMESSAGE._serialized_end=1429
  _PAIRINGMESSAGE_STATUS._serialized_start=1291
  _PAIRINGMESSAGE_STATUS._serialized_end=1429
# @@protoc_insertion_point(module_scope)
