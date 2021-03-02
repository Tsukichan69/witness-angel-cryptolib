
from wacryptolib.container import (LOCAL_ESCROW_MARKER, SHARED_SECRET_MARKER,)
from wacryptolib.encryption import (SUPPORTED_ENCRYPTION_ALGOS)
from wacryptolib.signature import (SUPPORTED_SIGNATURE_ALGOS)
from wacryptolib.utilities import (SUPPORTED_HASH_ALGOS)
from wacryptolib.key_generation import (ASYMMETRIC_KEY_TYPES_REGISTRY)
from schema import Schema, Optional, Or, And, SchemaError, Const
from uuid import UUID
import json
import math
from json_schema import json_schema

""" Pieces of the global Schema for containers :

First "CONTAINER_PIECE" is piece of the simple container
Secund "SHAMIR_CONTAINER_PIECE" is piece of the Shamir container, can be recursive """
CONTAINER_PIECE = {
            "key_encryption_algo" : Or(*ASYMMETRIC_KEY_TYPES_REGISTRY), 
            "key_escrow": Const(LOCAL_ESCROW_MARKER),
            Optional("keychain_uid"): object}

RECURSIVE_SHAMIR=[]
SHAMIR_CONTAINER_PIECE = Schema({
    "key_encryption_algo": SHARED_SECRET_MARKER,
    "key_shared_secret_threshold": And(int, lambda n: 0 < n < math.inf),
    "key_shared_secret_escrows": [{ 
                "key_encryption_strata": Or([{
                    "key_encryption_algo": Or(*ASYMMETRIC_KEY_TYPES_REGISTRY),
                    "key_escrow": Const(LOCAL_ESCROW_MARKER),
                    Optional("keychain_uid"): object}], RECURSIVE_SHAMIR),
}]}, name= "Recursive_shamir", as_reference=True)
RECURSIVE_SHAMIR.append(SHAMIR_CONTAINER_PIECE)

""" Schema = Creation of a Schema for the containers, depending on the level of complexity, some elements are optional"""
SCHEMA_CONTAINER = Schema({
    "data_encryption_strata" : [{
        "data_encryption_algo": Or(*SUPPORTED_ENCRYPTION_ALGOS),
        "key_encryption_strata": [SHAMIR_CONTAINER_PIECE, CONTAINER_PIECE],
        Optional("data_signatures"): [{
            "message_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
            "signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS), 
            "signature_escrow": Const(LOCAL_ESCROW_MARKER),
            Optional("keychain_uid"): object}]
        }]})

""" Some conf to check Schema """
#Complex container without Shamir
COMPLEX_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"), keychain_uid=UUID("0e8e861e-f0f7-e54b-18ea-34798d5daaaa"))
            ],
            data_signatures=[
                dict(message_digest_algo="SHA3_512", signature_algo="DSA_DSS", signature_escrow=dict(escrow_type="local"))
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local")),
                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local")),
            ],
            data_signatures=[
                dict(message_digest_algo="SHA3_256", signature_algo="RSA_PSS", signature_escrow=dict(escrow_type="local")),
                dict(
                    message_digest_algo="SHA512",
                    signature_algo="ECC_DSS",
                    signature_escrow=dict(escrow_type="local"),
                    keychain_uid=UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb"),
                ),
            ],
        ),
    ])

#Complex container with Shamir
COMPLEX_SHAMIR_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            data_signatures=[
                dict(message_digest_algo="SHA3_512", signature_algo="DSA_DSS", signature_escrow=LOCAL_ESCROW_MARKER)
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(
                    key_encryption_algo=SHARED_SECRET_MARKER,
                    key_shared_secret_threshold=2,
                    key_shared_secret_escrows=[
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER),
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid=UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb"))],),
                    ],
                )
            ],
            data_signatures=[
                dict(
                    message_digest_algo="SHA3_256",
                    signature_algo="RSA_PSS",
                    signature_escrow=LOCAL_ESCROW_MARKER,
                    keychain_uid=UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb"),
                ),
                dict(message_digest_algo="SHA512", signature_algo="ECC_DSS", signature_escrow=LOCAL_ESCROW_MARKER),
            ],
        ),
    ])

#Complex container with recursive Shamir
COMPLEX_STRATAS_SHAMIR_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            data_signatures=[
                dict(message_digest_algo="SHA3_512", signature_algo="DSA_DSS", signature_escrow=LOCAL_ESCROW_MARKER)
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(
                    key_encryption_algo=SHARED_SECRET_MARKER,
                    key_shared_secret_threshold=2,
                    key_shared_secret_escrows=[
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER),
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                        dict(key_encryption_strata=[dict(
                                key_encryption_algo=SHARED_SECRET_MARKER,
                                key_shared_secret_threshold=2,
                                key_shared_secret_escrows=[
                                    dict(key_encryption_strata=[
                                            dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER),
                                            dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                                    dict(key_encryption_strata=[
                                            dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                                    dict(key_encryption_strata=[
                                            dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],),
                                    dict(key_encryption_strata=[
                                            dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid=UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb"))],),],)]),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid=UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb"))],),
                    ],
                )
            ],
            data_signatures=[
                dict(
                    message_digest_algo="SHA3_256",
                    signature_algo="RSA_PSS",
                    signature_escrow=LOCAL_ESCROW_MARKER,
                    keychain_uid=UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb"),
                ),
                dict(message_digest_algo="SHA512", signature_algo="ECC_DSS", signature_escrow=LOCAL_ESCROW_MARKER),
            ],
        ),
    ])

def checkSchema(conf_schema, conf):
    """ To check that the Schema is compatible with the configuration """
    try:
        conf_schema.validate(conf)
        return True
    except SchemaError as exc:
        raise
        print("<<<", exc)
        return False

#Easy way to check the Schema
#print(checkSchema(SCHEMA_CONTAINER, COMPLEX_STRATAS_SHAMIR_CONTAINER_CONF))

""" json_schema + json.dumps = To create the Json file """
json_schema_tree = json.dumps(SCHEMA_CONTAINER.json_schema("Schema_container"), indent=4)
#print(json_schema_tree)

if __name__ == "__main__":
    print("hello")

