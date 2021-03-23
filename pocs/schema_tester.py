import wacryptolib
from wacryptolib.container import (LOCAL_ESCROW_MARKER, SHARED_SECRET_MARKER,)
from wacryptolib.encryption import (SUPPORTED_ENCRYPTION_ALGOS)
from wacryptolib.signature import (SUPPORTED_SIGNATURE_ALGOS)
from wacryptolib.utilities import (SUPPORTED_HASH_ALGOS)
from wacryptolib.key_generation import (ASYMMETRIC_KEY_TYPES_REGISTRY)
import schema as pythonschema
from schema import Schema, Optional, Or, And, SchemaError, Const, Regex
from uuid import UUID
import json
import math
import jsonschema
from jsonschema import validate
import pytest
import copy


def  create_schema(for_container) :
    #global SCHEMA_CONTAINERS

    micro_schema_uid = And(str, Or(Regex('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$'), Regex('[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}')))
    micro_schema_binary_uid = {
        "$binary": [{
            "base64": micro_schema_uid,
            "subType": "03"}]}
    micro_schema_binary = {
        "$binary": [{
            "base64": And(str, Regex('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$')),
            "subType": "00"}]}
    micro_schema_number_int = {
        "$numberInt": And(str, Regex('^(-?\d{1,9}|-?1\d{9}|-?20\d{8}|-?21[0-3]\d{7}|-?214[0-6]\d{6}|-?2147[0-3]\d{5}|-?21474[0-7]\d{4}|-?214748[012]\d{4}|-?2147483[0-5]\d{3}|-?21474836[0-3]\d{2}|214748364[0-7]|-214748364[0-8])$'))}
    micro_schema_number_long = {
        "$numberLong": And(str, Regex('^([+-]?[0-9]\d*|0)$'))}

    if for_container:
        extra_container = {
            "container_format": "WA_0.1a",
            "container_uid": [{
                **micro_schema_binary_uid}],
            "data_ciphertext": [{
                **micro_schema_binary}]}
        extra_key_cyphertext = {
            "key_ciphertext": [{**micro_schema_binary}]}
        extra_signature = {
            "signature_value": [{
                "digest": [{**micro_schema_binary}],
            "timestamp_utc": Or([micro_schema_number_int, micro_schema_number_long], int)}]}
        extra_keychain = {
            "keychain_uid" : [{**micro_schema_binary_uid}]}
    else :
        extra_container={}
        extra_key_cyphertext={}
        extra_signature={}
        extra_keychain={}
	
    SIMPLE_CONTAINER_PIECE = {
        "key_encryption_algo" : Or(*ASYMMETRIC_KEY_TYPES_REGISTRY), 
        "key_escrow": Const(LOCAL_ESCROW_MARKER),
        Optional("keychain_uid"): micro_schema_uid}
	
    RECURSIVE_SHAMIR=[]
    SHAMIR_CONTAINER_PIECE = Schema({
        "key_encryption_algo": SHARED_SECRET_MARKER,
        "key_shared_secret_threshold": Or(And(int, lambda n: 0 < n < math.inf),micro_schema_number_int),
        "key_shared_secret_escrows": [{ 
                    "key_encryption_strata": Or([{
                        "key_encryption_algo": Or(*ASYMMETRIC_KEY_TYPES_REGISTRY),
                        "key_escrow": Const(LOCAL_ESCROW_MARKER),
                        Optional("keychain_uid"): micro_schema_uid}], RECURSIVE_SHAMIR)}]}, name= "Recursive_shamir", as_reference=True)
    RECURSIVE_SHAMIR.append(SHAMIR_CONTAINER_PIECE)

    SCHEMA_CONTAINERS = Schema({**extra_container,
		"data_encryption_strata" : [{
			"data_encryption_algo": Or(*SUPPORTED_ENCRYPTION_ALGOS),
			"key_encryption_strata": [SHAMIR_CONTAINER_PIECE, SIMPLE_CONTAINER_PIECE],
			**extra_key_cyphertext,
			Optional("data_signatures"): [{
				"message_digest_algo": Or(*SUPPORTED_HASH_ALGOS),
				"signature_algo": Or(*SUPPORTED_SIGNATURE_ALGOS), 
				"signature_escrow": Const(LOCAL_ESCROW_MARKER),
				**extra_signature,
				Optional("keychain_uid"): micro_schema_uid}]
			}],
			**extra_keychain,
			Optional("metadata"): str})
	
    return SCHEMA_CONTAINERS


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
Here is just for testing the container's configuration
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
# container_json_schema_tree = SCHEMA_CONTAINERS.json_schema("Schema_container")
# #print(json_schema_tree)
# container_json_tree= json.dumps(container_json_schema_tree, indent=4)


# def validate_json(data):
#     """ To validate datas with the jsonschema """
#     """REF: https://json-schema.org/ """
#     try:
#         validate(instance=data, schema=container_json_schema_tree)
#     except jsonschema.exceptions.ValidationError as err:
#         print(err)
#         err = "Given data is InValid"
#         return False, err

#     message = "Given data is Valid"
#     return True, message

# # validate it
# is_valid, msg = validate_json(CONTAINER_TEST)
# print(msg)


CONF_SCHEMA=create_schema(for_container=False)
DATA_CONTAINER_SCHEMA=create_schema(for_container=True)

@pytest.mark.parametrize(
    "container,schemaTest",
    [
        (COMPLEX_CONTAINER_CONF, CONF_SCHEMA),
        (COMPLEX_SHAMIR_CONTAINER_CONF, CONF_SCHEMA),
        (COMPLEX_STRATAS_SHAMIR_CONTAINER_CONF, CONF_SCHEMA),
        (CONTAINER_TEST, DATA_CONTAINER_SCHEMA)
    ])
def test_container_schema(container, schemaTest): #TODO test end-to-end creation of container and validation !

    #Validation of Python Data with Schema Python
    schemaTest.validate(container)

    #Exporting schema in jsonschema format
    container_json_schema_tree = schemaTest.json_schema("my_schema_test")

    #Exporting container in pymongo extended json format
    json_std_lib = wacryptolib.utilities.dump_to_json_str(container)
    #Parsing Json from string
    json_str_lib = json.loads(json_std_lib)

    #Validation of Json Data with JsonSchema
    validate(instance=json_str_lib, schema=container_json_schema_tree)

@pytest.mark.parametrize(
    "container,schemaTest",
    [
        (COMPLEX_SHAMIR_CONTAINER_CONF, CONF_SCHEMA),
        (CONTAINER_TEST, DATA_CONTAINER_SCHEMA)
    ])
def test_corrupted_container(container,schemaTest):
    #Using copy to create a deepcopy of a container configuration
    new_cont = copy.deepcopy(container)
    #Add a false information to the new container configuration
    new_cont["data_encryption_strata"][0]["keychain_uid"]="65dbbe4f-0bd5-4083-a274-3c76efeebbbb"

    #Exporting schema in jsonschema format
    container_json_schema_tree = schemaTest.json_schema("my_schema_test")

    #Exporting container in pymongo extended json format
    json_std_lib = wacryptolib.utilities.dump_to_json_str(new_cont)
    #Parsing Json from string
    json_str_lib = json.loads(json_std_lib)

    #Validation of Python Data with Python Schema
    with pytest.raises(pythonschema.SchemaError, match="Wrong key 'keychain_uid'"):
        schemaTest.validate(new_cont)

    #Validation of Json Data with JsonSchema
    with pytest.raises(jsonschema.ValidationError, match="'keychain_uid' was unexpected"):
        validate(instance=json_str_lib, schema=container_json_schema_tree)



if __name__ == "__main__":
    print("hello")

