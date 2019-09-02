from base64 import b64decode, b64encode

import Crypto.Hash
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from wacryptolib.utilities import split_as_chunks

RSA_OAEP_CHUNKS_SIZE = 60
RSA_OAEP_HASH_ALGO = Crypto.Hash.SHA256


def _get_encryption_type_conf(encryption_type):
    encryption_type = encryption_type.upper()
    if encryption_type not in ENCRYPTION_TYPES_REGISTRY:
        raise ValueError("Unknown cipher type '%s'" % encryption_type)

    encryption_type_conf = ENCRYPTION_TYPES_REGISTRY[encryption_type]
    return encryption_type_conf


def encrypt_bytestring(plaintext: bytes, encryption_type: str, key: bytes, ) -> dict:
    """Encrypt a bytestring with the selected algorithm for the given payload,
    using the provided key (which must be of a compatible type and length).

    :return: dictionary with encryption data, and
        a "type" field echoing `encryption_type`."""
    encryption_type_conf = _get_encryption_type_conf(encryption_type=encryption_type)
    encryption_function = encryption_type_conf["encryption_function"]
    encryption = encryption_function(key=key, plaintext=plaintext)
    encryption["type"] = encryption_type
    return encryption


def decrypt_bytestring(encryption: dict, key: bytes) -> bytes:
    """Decrypt a bytestring with the selected algorithm for the given encryption data dict,
    using the provided key (which must be of a compatible type and length).

    :return: dictionary with encryption data."""
    encryption_type = encryption["type"]
    encryption_type_conf = _get_encryption_type_conf(encryption_type)
    decryption_function = encryption_type_conf["decryption_function"]
    plaintext = decryption_function(key=key, encryption=encryption)
    return plaintext


def _encrypt_via_aes_cbc(plaintext: bytes, key: bytes) -> dict:
    """Encrypt a bytestring using AES (CBC mode).

    :param key: AES cryptographic key. It must be 16, 24 or 32 bytes long
        (respectively for *AES-128*, *AES-192* or *AES-256*).
    :param plaintext: the bytes to cipher

    :return: dict with fields "iv" and "ciphertext" as base64 strings"""

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, block_size=AES.block_size))
    encryption = {"iv": b64encode(iv), "ciphertext": b64encode(ciphertext)}
    return encryption


def _decrypt_via_aes_cbc(encryption: dict, key: bytes) -> bytes:
    """Decrypt a bytestring using AES (CBC mode).

    :param key: the cryptographic key used to decipher
    :param encryption: dict with fields "iv" and "ciphertext" as base64 strings

    :return: the decrypted bytestring"""

    iv = encryption["iv"]
    ciphertext = encryption["ciphertext"]
    decipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
    plaintext = unpad(
        decipher.decrypt(b64decode(ciphertext)), block_size=AES.block_size
    )
    return plaintext


def _encrypt_via_aes_eax(plaintext: bytes, key: bytes) -> dict:
    """Encrypt a bytestring using AES (EAX mode).

    :param key: AES cryptographic key. It must be 16, 24 or 32 bytes long
        (respectively for *AES-128*, *AES-192* or *AES-256*).
    :param plaintext: the bytes to cipher

    :return: dict with fields "ciphertext", "tag" and "nonce" as base64 strings"""

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encryption = {
        "ciphertext": b64encode(ciphertext),
        "tag": b64encode(tag),
        "nonce": b64encode(nonce),
    }
    return encryption


def _decrypt_via_aes_eax(encryption: dict, key: bytes) -> bytes:
    """Decrypt a bytestring using AES (EAX mode).

    :param key: the cryptographic key used to decipher
    :param encryption: dict with fields "ciphertext", "tag" and "nonce" as base64 strings

    :return: the decrypted bytestring"""

    decipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(encryption["nonce"]))
    plaintext = decipher.decrypt(b64decode(encryption["ciphertext"]))
    decipher.verify(b64decode(encryption["tag"]))
    return plaintext


def _encrypt_via_chacha20_poly1305(
        plaintext: bytes, key: bytes, aad: bytes = b"header"
) -> dict:
    """Encrypt a bytestring with the stream cipher ChaCha20.

    Additional cleartext data can be provided so that the
    generated mac tag also verifies its integrity.

    :param key: 32 bytes long cryptographic key
    :param plaintext: the bytes to cipher
    :param aad: optional "additional authenticated data"

    :return: dict with fields "ciphertext", "tag", "nonce" and "header" as base64 strings"""

    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    encryption = {
        "ciphertext": b64encode(ciphertext),
        "tag": b64encode(tag),
        "nonce": b64encode(nonce),
        "aad": b64encode(aad),
    }
    return encryption


def _decrypt_via_chacha20_poly1305(encryption: dict, key: bytes) -> bytes:
    """Decrypt a bytestring with the stream cipher ChaCha20.

    :param key: the cryptographic key used to decipher
    :param encryption: dict with fields "ciphertext", "tag", "nonce" and "header" as base64 strings

    :return: the decrypted bytestring"""

    decipher = ChaCha20_Poly1305.new(key=key, nonce=b64decode(encryption["nonce"]))
    decipher.update(b64decode(encryption["aad"]))
    plaintext = decipher.decrypt_and_verify(
        ciphertext=b64decode(encryption["ciphertext"]),
        received_mac_tag=b64decode(encryption["tag"]),
    )
    return plaintext


def _encrypt_via_rsa_oaep(plaintext: bytes, key: RSA.RsaKey) -> dict:
    """Encrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param key: public RSA key
    :param plaintext: the bytes to cipher

    :return: a dict with field `digest_list`, containing base64-encoded chunks of variable width."""

    cipher = PKCS1_OAEP.new(key=key, hashAlgo=RSA_OAEP_HASH_ALGO)
    chunks = split_as_chunks(
        plaintext,
        chunk_size=RSA_OAEP_CHUNKS_SIZE,
        must_pad=False,
        accept_incomplete_chunk=True,
    )

    encrypted_chunks = []
    for chunk in chunks:
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_chunks.append(b64encode(encrypted_chunk))
    return dict(digest_list=encrypted_chunks)


def _decrypt_via_rsa_oaep(encryption: dict, key: RSA.RsaKey) -> bytes:
    """Decrypt a bytestring with PKCS#1 RSA OAEP (asymmetric algo).

    :param key: private RSA key
    :param encryption: list of base64-encoded ciphertext chunks

    :return: the decrypted bytestring"""

    decipher = PKCS1_OAEP.new(key, hashAlgo=RSA_OAEP_HASH_ALGO)

    encrypted_chunk = encryption["digest_list"]

    chunks = [b64decode(chunk) for chunk in encrypted_chunk]

    decrypted_chunks = []
    for chunk in chunks:
        decrypted_chunk = decipher.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)
    return b"".join(decrypted_chunks)


ENCRYPTION_TYPES_REGISTRY = dict(
    AES_CBC={
        "encryption_function": _encrypt_via_aes_cbc,
        "decryption_function": _decrypt_via_aes_cbc,
    },
    AES_EAX={
        "encryption_function": _encrypt_via_aes_eax,
        "decryption_function": _decrypt_via_aes_eax,
    },
    CHACHA20_POLY1305={
        "encryption_function": _encrypt_via_chacha20_poly1305,
        "decryption_function": _decrypt_via_chacha20_poly1305,
    },
    RSA_OAEP={
        "encryption_function": _encrypt_via_rsa_oaep,
        "decryption_function": _decrypt_via_rsa_oaep,
    },
)

#: These values can be used as 'encryption_type'.
SUPPORTED_ENCRYPTION_TYPES = sorted(ENCRYPTION_TYPES_REGISTRY.keys())