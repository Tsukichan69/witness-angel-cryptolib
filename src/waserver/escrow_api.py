import random
import uuid
from base64 import b64decode, b64encode

from wacryptolib.encryption import _decrypt_via_rsa_oaep
from wacryptolib.key_generation import generate_asymmetric_keypair
from wacryptolib.signature import sign_message


def get_public_key(uid: uuid.UUID, key_type: str) -> str:
    """
    Return a public key in PEM format, that caller shall use to encrypt its own symmetric keys.
    """
    assert key_type.upper() == "RSA"  # Only supported asymmetric cipher for now
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=True)
    del keypair["private_key"]  # Security
    return keypair["public_key"]


def get_message_signature(
    uid: uuid.UUID, plaintext: bytes, key_type: str, signature_type: str
) -> dict:
    """
    Return a signature structure corresponding to the provided key and signature types.
    """
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=False)
    private_key = keypair["private_key"]
    signature = sign_message(
        plaintext=plaintext, signature_type=signature_type, key=private_key
    )
    return signature


def unravel_secret(uid: uuid.UUID, key_type: str, cipherdict: dict) -> str:
    """
    Return the message (probably a symmetric key) decrypted with the corresponding key,
    as base64-encoded string.
    """
    assert key_type.upper() == "RSA"  # Only supported asymmetric cipher for now
    keypair = generate_asymmetric_keypair(uid=uid, key_type=key_type, serialize=False)
    private_key = keypair["private_key"]
    secret = _decrypt_via_rsa_oaep(cipherdict=cipherdict, key=private_key)
    return b64encode(secret)