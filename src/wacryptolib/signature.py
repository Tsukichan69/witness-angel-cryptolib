from datetime import datetime
from typing import Union

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS

KNOWN_KEY_TYPES = Union[RSA.RsaKey, DSA.DsaKey, ECC.EccKey]


def sign_bytestring(plaintext: bytes, signature_type: str, key:KNOWN_KEY_TYPES) -> dict:
    """
    Return a timestamped signature of the chosen type for the given payload,
    with the provided key (which must be of a compatible type).

    :return: dictionary with signature data."""

    assert signature_type, signature_type
    signature_conf = SIGNATURE_TYPES_REGISTRY.get(signature_type)
    if signature_conf is None:
        raise ValueError("Unrecognized signature type '%s'" % signature_type)
    if not isinstance(key, signature_conf["compatible_key_types"]):
        raise ValueError("Incompatible key type %s for %s signature" % (type(key), signature_type))
    signature_function = signature_conf["signature_function"]
    signature = signature_function(key=key, plaintext=plaintext)
    assert signature.get("type")
    return signature


def _sign_with_pss(key: RSA.RsaKey, plaintext: bytes) -> dict:
    """Sign a bytes message with a private RSA key.

    :param private_key: the private key
    :param plaintext: the bytestring to signure_function": sign_with_ps

    :return: dict with keys "digest" (bytestring), "timestamp_utc" (integer) and "type" (string) of signature"""

    timestamp_utc = _get_utc_timestamp()
    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=timestamp_utc
    )
    signer = pss.new(key)
    digest = signer.sign(hash_payload)
    signature = {"type": "PSS", "timestamp_utc": timestamp_utc, "digest": digest}
    return signature


def _sign_with_dss(
    key: Union[DSA.DsaKey, ECC.EccKey], plaintext: bytes
) -> dict:
    """Sign a bytes message with a private DSA or ECC key.

    We use the `fips-186-3` mode for the signer because signature is randomized,
    while it is not the case for the mode `deterministic-rfc6979`.

    :param private_key: the private key
    :param plaintext: the bytestring to sign

    :return: dict with keys "digest" (bytestring), "timestamp_utc" (integer) and "type" (string) of signature"""

    timestamp = _get_utc_timestamp()
    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=timestamp
    )
    signer = DSS.new(key, "fips-186-3")
    digest = signer.sign(hash_payload)
    signature = {
        "type": "DSS",
        "timestamp_utc": timestamp,
        "digest": digest,
    }
    return signature


def verify_signature(
    plaintext: bytes,
    signature: dict,
    key: Union[KNOWN_KEY_TYPES],
):
    """Verify the authenticity of a signature.

    Raises if signature is invalid.

    :param public_key: the cryptographic key used to verify the signature
    :param plaintext: the text which was signed
    :param signature: dict describing the signature
    """

    hash_payload = _compute_timestamped_hash(
        plaintext=plaintext, timestamp_utc=signature["timestamp_utc"]
    )
    if signature["type"] == "PSS":
        verifier = pss.new(key)
    elif signature["type"] == "DSS":
        verifier = DSS.new(key, "fips-186-3")
    else:
        raise ValueError("Unknown signature type '%s'" % signature["type"])
    verifier.verify(hash_payload, signature["digest"])


def _get_utc_timestamp():
    """Get current UTC timestamp.

    :return: timestamp as an integer
    """
    timestamp_utc = int(datetime.utcnow().timestamp())
    return timestamp_utc


def _compute_timestamped_hash(plaintext: bytes, timestamp_utc: int):
    """Create a hash of content, including the timestamp.

    :param plaintext: text to sign
    :param timestamp: integer UTC timestamp

    :return: stdlib hash object
    """
    hash_plaintext = SHA256.new(plaintext)
    timestamp_bytes = str(timestamp_utc).encode("ascii")
    payload_digest = SHA256.SHA256Hash.digest(hash_plaintext) + timestamp_bytes
    payload_hash = SHA256.new(payload_digest)
    return payload_hash


SIGNATURE_TYPES_REGISTRY = dict(
        PSS={
            "signature_function": _sign_with_pss,
            "compatible_key_types": (RSA.RsaKey),
        },
        DSS={
            "signature_function": _sign_with_dss,
            "compatible_key_types": (DSA.DsaKey, ECC.EccKey),
        },
    )

SUPPORTED_SIGNATURE_TYPES = sorted(SIGNATURE_TYPES_REGISTRY.keys())
