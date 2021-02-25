
import pprint
from wacryptolib.container import (LOCAL_ESCROW_MARKER, SHARED_SECRET_MARKER,)
from schema import Schema, Optional, Or, SchemaError
from uuid import UUID
import json
from json_schema import json_schema

""" Schema = Creation of a Schema for the containers, depending on the level of complexity, some elements are optional"""
SCHEMA_CONTAINER = Schema({
    "data_encryption_strata" : [{
        "data_encryption_algo": str,
        "key_encryption_strata": [{
            "key_encryption_algo" : str, 
            "key_escrow": {"escrow_type": str},
            Optional("keychain_uid"): object,}, 
            {
            Optional("key_encryption_algo"): str,
            Optional("key_escrow"): {"escrow_type": str}
            }],
        Optional("data_signatures"): [{
            "message_digest_algo": str,
            "signature_algo": str, 
            "signature_escrow": {"escrow_type": str},
            Optional("keychain_uid"): object},
            {
            Optional("message_digest_algo"): str,
            Optional("signature_algo"): str,
            Optional("signature_escrow") : {"escrow_type": str},
            Optional("keychain_uid"): object}],
        }]
})

SIMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],
            data_signatures=[
                dict(message_digest_algo="SHA256", signature_algo="DSA_DSS", signature_escrow=dict(escrow_type="local"))
            ],
        )
    ]
)

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
    ]
)

def checkSchema(conf_schema, conf):
    """ To check that the Schema is compatible with the configuration """
    try:
        conf_schema.validate(conf)
        return True
    except SchemaError as exc:
        raise
        print("<<<", exc)
        return False
""" print(checkSchema(SCHEMA_CONTAINER, COMPLEX_CONTAINER_CONF)) """

""" json_schema = To create the Json_schema file
    dumps = To create the Json file """
json_container_schema_tree = json.dumps(SCHEMA_CONTAINER.json_schema("Schema_container"), indent=4)


SCHEMA_SHAMIR_CONTAINER = Schema({
    "data_encryption_strata": [{
        "data_encryption_algo": str,
        "key_encryption_strata": [{
            "key_encryption_algo": str,
            Optional("key_shared_secret_threshold"): int,
            Optional("key_escrow"): {"escrow_type": str},
            Optional("key_shared_secret_escrows"): [{
                "key_encryption_strata": [{
                    "key_encryption_algo": str,
                    "key_escrow": {"escrow_type": str},
                    Optional("keychain_uid"): object
                                        }]
                                    }]}],
        Optional("data_signatures"): [{
            "message_digest_algo": str,
            "signature_algo": str,
            "signature_escrow": {"escrow_type": str},
            Optional("keychain_uid"): object},
            {
            Optional("message_digest_algo"): str,
            Optional("signature_algo"):str,
            Optional("signature_escrow"): {"escrow_type": str}}]
    }]
    })

SIMPLE_SHAMIR_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[
                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local")),
                dict(
                    key_encryption_algo="[SHARED_SECRET]",
                    key_shared_secret_threshold=3,
                    key_shared_secret_escrows=[
                        dict(key_encryption_strata=[
                                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],),
                        dict(key_encryption_strata=[
                                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],),
                        dict(key_encryption_strata=[
                                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],),
                        dict(key_encryption_strata=[
                                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],),
                        dict(key_encryption_strata=[
                                dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"), keychain_uid=UUID("0e8e861e-f0f7-e54b-18ea-34798d5daaaa"))],),
                    ],
                ),
            ],
            data_signatures=[
                dict(message_digest_algo="SHA256", signature_algo="DSA_DSS", signature_escrow=dict(escrow_type="local"))
            ],
        )
    ]
) 

COMPLEX_SHAMIR_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],
            data_signatures=[
                dict(message_digest_algo="SHA3_512", signature_algo="DSA_DSS", signature_escrow=dict(escrow_type="local"))
            ],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(
                    key_encryption_algo="[SHARED_SECRET]",
                    key_shared_secret_threshold=2,
                    key_shared_secret_escrows=[
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local")),
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],),
                        dict(key_encryption_strata=[
                                 dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"), keychain_uid=UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb"))],),
                    ],
                )
            ],
            data_signatures=[
                dict(
                    message_digest_algo="SHA3_256",
                    signature_algo="RSA_PSS",
                    signature_escrow=dict(escrow_type="local"),
                    keychain_uid=UUID("0e8e861e-f0f7-e54b-18ea-34798d5daaaa"),
                ),
                dict(message_digest_algo="SHA512", signature_algo="ECC_DSS", signature_escrow=dict(escrow_type="local")),
            ],
        ),
    ]
)

""" print(check(SCHEMA_SHAMIR_CONTAINER, COMPLEX_SHAMIR_CONTAINER_CONF)) """

""" json_schema = To create the Json file """
json_shamir_container_schema_tree = json.dumps(SCHEMA_SHAMIR_CONTAINER.json_schema("Schema_container"), indent=4)
print(json_shamir_container_schema_tree)

def generate_container_schema():
    pass

# IMPORTANT : rester json-schema compatible

if __name__ == "__main__":
    print("hello")

