
from wacryptolib.container import (LOCAL_ESCROW_MARKER, SHARED_SECRET_MARKER,)
from wacryptolib.encryption import (SUPPORTED_ENCRYPTION_ALGOS)
from wacryptolib.signature import (SUPPORTED_SIGNATURE_ALGOS)
from wacryptolib.utilities import (SUPPORTED_HASH_ALGOS)
from wacryptolib.key_generation import (ASYMMETRIC_KEY_TYPES_REGISTRY)
from schema import Schema, Optional, Or, And, SchemaError, Const, Regex
from uuid import UUID
import json
import math
import jsonschema
from jsonschema import validate

micro_schema_binary = {
    "$binary": [{
                "base64": And(str, Regex('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')),
                "subType": Or("00","03")
    }]
}
micro_schema_timestamp = {
    "$numberInt": Or(str, int)
}

for_container= True

if for_container:
    extra_params_container = {
        "container_format": "WA_0.1a",
        "container_uid": [{
            **micro_schema_binary
            }],
        "data_ciphertext": [{
            **micro_schema_binary
    }]}
    extra_cyphertext ={
        "key_ciphertext": [{**micro_schema_binary}]
    }
    extra_signature ={
        "signature_value": [{
            "digest": [{**micro_schema_binary}],
        "timestamp_utc": [{
            **micro_schema_timestamp
        }]}]
    }
    extra_keychain={
        "keychain_uid" : [{**micro_schema_binary}]
    }
else :
    extra_params_container={}
    extra_cyphertext ={}
    extra_signature={}
    extra_keychain={}

    """ 
    Pieces of the global Schema for containers :

    First "CONTAINER_PIECE" is piece of the simple container
    Secund "SHAMIR_CONTAINER_PIECE" is piece of the Shamir container, can be recursive 
    """
CONTAINER_PIECE = {
                "key_encryption_algo" : Or(*ASYMMETRIC_KEY_TYPES_REGISTRY), 
                "key_escrow": Const(LOCAL_ESCROW_MARKER),
                Optional("keychain_uid"): And(str, Regex('[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'))}

RECURSIVE_SHAMIR=[]
SHAMIR_CONTAINER_PIECE = Schema({
        "key_encryption_algo": SHARED_SECRET_MARKER,
        "key_shared_secret_threshold": And(int, lambda n: 0 < n < math.inf),
        "key_shared_secret_escrows": [{ 
                    "key_encryption_strata": Or([{
                        "key_encryption_algo": Or(*ASYMMETRIC_KEY_TYPES_REGISTRY),
                        "key_escrow": Const(LOCAL_ESCROW_MARKER),
                        Optional("keychain_uid"): And(str, Regex('[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'))}], RECURSIVE_SHAMIR)}]}, name= "Recursive_shamir", as_reference=True)
RECURSIVE_SHAMIR.append(SHAMIR_CONTAINER_PIECE)

""" Schema = Creation of a Schema for the containers, depending on the level of complexity, some elements are optional"""
SCHEMA_CONTAINER = Schema({**extra_params_container,
    "data_encryption_strata" : [{
        "data_encryption_algo": Or(*SUPPORTED_ENCRYPTION_ALGOS),
        "key_encryption_strata": [SHAMIR_CONTAINER_PIECE, CONTAINER_PIECE],
        **extra_cyphertext,
        Optional("data_signatures"): [{
            "message_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
            "signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS), 
            "signature_escrow": Const(LOCAL_ESCROW_MARKER),
            **extra_signature,
            Optional("keychain_uid"): And(str, Regex('[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'))}]
        }],
        **extra_keychain,
        Optional("metadata"): str})


def checkSchema(conf_schema, conf):
        """ To check that the Schema is compatible with the configuration """
        try:
            conf_schema.validate(conf)
            return True
        except SchemaError as exc:
            raise
            print("<<<", exc)
            return False


""" 
Here is just for testing
"""

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
                    dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"), keychain_uid="0e8e861e-f0f7-e54b-18ea-34798d5daaaa")
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
                        keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb",
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
                                    dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb")],),
                        ],
                    )
                ],
                data_signatures=[
                    dict(
                        message_digest_algo="SHA3_256",
                        signature_algo="RSA_PSS",
                        signature_escrow=LOCAL_ESCROW_MARKER,
                        keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb",
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
                                                dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb")],),],)]),
                            dict(key_encryption_strata=[
                                    dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb")],),
                        ],
                    )
                ],
                data_signatures=[
                    dict(
                        message_digest_algo="SHA3_256",
                        signature_algo="RSA_PSS",
                        signature_escrow=LOCAL_ESCROW_MARKER,
                        keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb",
                    ),
                    dict(message_digest_algo="SHA512", signature_algo="ECC_DSS", signature_escrow=LOCAL_ESCROW_MARKER),
                ],
            ),
        ])

#Complex container with recursive Shamir WITH AN ERROR
ERROR_COMPLEX_STRATAS_SHAMIR_CONTAINER_CONF = dict(
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
                                    dict(key_encryption_algo="", key_escrow=LOCAL_ESCROW_MARKER)],), #Here the error
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
                                                dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb")],),],)]),
                            dict(key_encryption_strata=[
                                    dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER, keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb")],),
                        ],
                    )
                ],
                data_signatures=[
                    dict(
                        message_digest_algo="SHA3_256",
                        signature_algo="RSA_PSS",
                        signature_escrow=LOCAL_ESCROW_MARKER,
                        keychain_uid="65dbbe4f-0bd5-4083-a274-3c76efeebbbb",
                    ),
                    dict(message_digest_algo="SHA512", signature_algo="ECC_DSS", signature_escrow=LOCAL_ESCROW_MARKER),
                ],
            ),
        ])

"""
End of Test Configuration
"""

"""
Test container
"""
CONTAINER_TEST = dict(
        container_format= "WA_0.1a",
        container_uid= [{
                "$binary": [dict(
                    base64= "DlYx92FIAAkm8ncnLoDO4Q==",
                    subType= "03")]
                    }],
        data_ciphertext= [{
            "$binary": [dict(
                base64= "eyJjaXBoZXJ0ZXh0IjogeyIkYmluYXJ5IjogeyJiYXNlNjQiOiAibEZFVWw3Qm1aRExXNkZTSDlsaDVrTjVPYkpYQ2RJN0RIWnlxcm9kSktob20rZmEza0JOYzM3K2NKTzBaay9MUnlId3lhSExlK20yclpsMm1tNXJtd24zMGNmNlZYNTdlNlVFcDVKWkc4MXNNcHpsQ2N6UmZBRUpmM1o4ZUFBdXo0UnJ1ZTROYnFmQml3TjkxbnRkaDhjcFRVVnRsVnZoWFc1VGZSdU9ROCtCR284R1EreHkvS1I0WE9QNlJFbkdhR1dXdjJ2bElaT2Flcm42dytqN3lhQnVEWXZESW1oMWNyK0hGSWIwaXZNYz0iLCAic3ViVHlwZSI6ICIwMCJ9fSwgIml2IjogeyIkYmluYXJ5IjogeyJiYXNlNjQiOiAiM280eXAvcG5lamFZRWtkTjlSOXNUUT09IiwgInN1YlR5cGUiOiAiMDAifX19",
                subType= "00"
            )]}],
        data_encryption_strata=[
            dict(
                data_encryption_algo="AES_EAX",
                key_ciphertext= [{
                    "$binary": [dict(
                        base64= "eyJkaWdlc3RfbGlzdCI6IFt7IiRiaW5hcnkiOiB7ImJhc2U2NCI6ICJCOXowVkF4anpKdDhrcGRod1MzcEdieVhZMk9xZ2NjZjMyUWQyYlJPMmNoRkMrZitQUEJFM2hEUVFPbW4wUDF4V1ZjeUFjQi9ueDFYek9kRUJ4QU9JVHlEWEwyTGFPbVpWdmQ4UUt1OW9LMyt2RTBxdFY0WUt1RHZqcmdPUS92aHRnWnRBQmxORjdrME9Rd1dtNXpvM3NEb3drTG5IaUN2YVJ4OHhUd2FNL2w0UUxTNEg2bVFPMGxiZkJISVQ2aTFIT21FV251TkFJVDMrNi9iWnd2aEJRUjlLbG04eVcrUnJTM1NUa1ZGLytCRHhnQjhhU0pka1ZnbnBwenF0UTlmamhETTd4Z2NRSUxlazl2cnl6QVdxOXRuZXl5OW5HODNrSFZkZXZOWlA5Ty81R29HR3ZtUGtGVGVPeng2cFoxYmx3RDlPWlB0YVNRMG5jNU11QVZKVHc9PSIsICJzdWJUeXBlIjogIjAwIn19XX0=",
                        subType= "00"
                    )]
                }],
                key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=dict(escrow_type="local"))],
                data_signatures=[
                    dict(message_digest_algo="SHA3_256", signature_algo="RSA_PSS", signature_escrow=dict(escrow_type="local"),
                    signature_value= [dict(
                        digest= [{
                            "$binary": [dict(
                                base64= "PDVJ2+UXnFsQy4JRisXOJW3cwMyX4PDanVoA6q7+hORZsMN8yK7ndpUqLMQNNFcpWAWFw+gtzCM=",
                                subType= "00"
                            )]
                        }],
                        timestamp_utc= [{
                            "$numberInt": "1576333246"
                        }]
                    )])],
            ),
        ],
        keychain_uid= [{
            "$binary": [dict(
                base64= "DlYx92FIysgcjOsbL4J+DQ==",
                subType= "03"
            )]
        }])

#Easy way to check the Schema
#print(checkSchema(SCHEMA_CONTAINER, COMPLEX_STRATAS_SHAMIR_CONTAINER_CONF))

""" json_schema + json.dumps = To create the Json file """
json_schema_tree = SCHEMA_CONTAINER.json_schema("Schema_container")
#print(json_schema_tree)
json_tree= json.dumps(json_schema_tree, indent=4)


def validate_json(data):
    """ To validate datas with the jsonschema """
    """REF: https://json-schema.org/ """
    try:
        validate(instance=data, schema=json_schema_tree)
    except jsonschema.exceptions.ValidationError as err:
        print(err)
        err = "Given data is InValid"
        return False, err

    message = "Given data is Valid"
    return True, message

# validate it
is_valid, msg = validate_json(CONTAINER_TEST)
print(msg)


if __name__ == "__main__":
    print("hello")

