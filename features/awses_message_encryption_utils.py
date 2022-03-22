# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# Only Python 3.6+ compatibility is guaranteed.

import itertools
import functools
import re
import uuid

# AWS Encryption SDK supported algorithm suites
# https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
ALGORITHM_SUITES = (
    "0014",
    "0046",
    "0078",
    "0114",
    "0146",
    "0178",
    "0214",
    "0346",
    "0378",
    "0478",
    "0578"
)

PLAINTEXTS = {"zero": 0, "tiny": 10, "small": 10 * 1024}

FRAME_SIZES = (
    0,  # Unframed
    512,  # >10 frames
    4096,  # frame size smaller than plaintext size
    10240,  # frame size equal to plaintext size
    20480,  # frame size larger than plaintext size
)

EMPTY_ENCRYPTION_CONTEXT = {}
NON_UNICODE_ENCRYPTION_CONTEXT = {"key1": "val1", "key2": "val2"}
UNICODE_ENCRYPTION_CONTEXT = {
    "key1": "val1",
    u"unicode_key_ловие": u"unicode_value_Предисл",
}
UNPRINTABLE_UNICODE_ENCRYPTION_CONTEXT = {
    "key1": "val1",
    b"\x01\x02\x03".decode("utf-8"): b"\x20\x22\x44".decode("utf-8"),
}
ENCRYPTION_CONTEXTS = (
    EMPTY_ENCRYPTION_CONTEXT,
    NON_UNICODE_ENCRYPTION_CONTEXT,
    UNICODE_ENCRYPTION_CONTEXT,
    UNPRINTABLE_UNICODE_ENCRYPTION_CONTEXT,
)

# Padding algorithms to test with each RSA Raw Master Key
RAW_RSA_PADDING_ALGORITHMS = (
    {"padding-algorithm": "pkcs1"},
    {"padding-algorithm": "oaep-mgf1", "padding-hash": "sha1"},
    {"padding-algorithm": "oaep-mgf1", "padding-hash": "sha256"},
    {"padding-algorithm": "oaep-mgf1", "padding-hash": "sha384"},
    {"padding-algorithm": "oaep-mgf1", "padding-hash": "sha512"},
)
# Padding algorithm to use with any RSA Raw Master Keys that cannot decrypt
RAW_RSA_BLACKHOLE_ARGUMENTS_OVERRIDE = {
    "padding-algorithm": "oaep-mgf1",
    "padding-hash": "sha256",
}

def _keys_for_algorithm(algorithm_name, keys):
    """Filter keys manifest keys by type.

    :param str algorithm_name: Key algorithm name for which to filter
    :param dict keys: Parsed keys manifest
    """
    for name, key in keys["keys"].items():
        if key.get("algorithm", None) == algorithm_name:
            yield name, key


def _keys_for_type(type_name, keys):
    """Filter keys manifest keys by type.

    :param str type_name: Key type name for which to filter
    :param dict keys: Parsed keys manifest
    """
    for name, key in keys["keys"].items():
        if key["type"] == type_name:
            yield name, key

def _keys_for_encryptval(encrypt_value, keys):
    """Filter keys manifest keys by type.

    :param boolean encrypt_value: True/False value for which to filter encrypt
    :param dict keys: Parsed keys manifest
    """
    for name, key in keys["keys"].items():
        if key["encrypt"] == encrypt_value:
            yield name, key

def _keys_for_decryptval(decrypt_value, keys):
    """Filter keys manifest keys by type.

    :param boolean encrypt_value: True/False value for which to filter decrypt
    :param dict keys: Parsed keys manifest
    """
    for name, key in keys["keys"].items():
        if key["decrypt"] == decrypt_value:
            yield name, key

def _split_on_decryptable(keys, filter_function, key_builder):
    """Filter keys manifest keys of specified type into two groups: those that can both encrypt
    and decrypt and those that can only encrypt.

    :param dict keys: Parsed keys manifest
    :param callable filter_function: Callable that will filter keys
    :param key_builder: Function that returns a properly formed master key configuration given
        a key name and configuration from the keys manifest
    :returns: list of cyclable master key configurations and list of encrypt only master key configurations
    """
    encrypt_only = []
    cyclable = []
    for name, key in filter_function(keys):
        if key["encrypt"]:
            if key["decrypt"]:
                cyclable.append(key_builder(name, key))
            else:
                encrypt_only.append(key_builder(name, key))
    return cyclable, encrypt_only


def _aws_kms_providers(keys):
    """Build all AWS KMS Master Key configurations to test.

    :param dict keys: Parsed keys manifest
    """

    def _key_builder(name, key):
        return {"type": "aws-kms", "key": name}

    cyclable, encrypt_only = _split_on_decryptable(
        keys, functools.partial(_keys_for_type, "aws-kms"), _key_builder
    )

    # Single KMS MasterKey which can be decrypted by all consumers
    for key in cyclable:
        yield (key,)

        # Multiple KMS MasterKeys, of which only one can be decrypted by all consumers
        for blackhole in encrypt_only:
            yield (key, blackhole)


def parse_arn(arn):
    return re.split("[:/]", arn)


def build_arn(arn_pieces):
    arn = ":".join(arn_pieces[0:6])
    if len(arn_pieces) > 6:
        arn += "/" + "/".join(arn_pieces[6:])
    return arn


def kms_mkr_arn_mismatches(arn):
    # Example:
    # arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7

    arn_pieces = re.split("[:/]", arn)
    for index, arn_piece in enumerate(arn_pieces):
        # With the value removed
        yield build_arn(arn_pieces[0:index] + arn_pieces[index + 1:])

        # With the value replaced by an empty string
        yield build_arn(arn_pieces[0:index] + [""] + arn_pieces[index + 1:])

        # With the value modified to an incorrect value,
        # EXCEPT for the region (which is the one piece that can change between
        # related multi-region keys)
        # NOTE: the `not` is appended and not prepended
        # in order to alow for an `mrk-` match.
        if index != 3:
            yield build_arn(arn_pieces[0:index] + [arn_piece + "-not"] + arn_pieces[index + 1:])
    
    # An alias could be confused with an MRK arn
    # so this takes a good MRK arn
    # and replaces `key` with `alias`
    yield build_arn(arn_pieces[0:5] + ["alias"] + arn_pieces[6:])

    # A raw key id is valid for encrypt, but MUST not work for decrypt.
    yield arn_pieces[-1]


AWS_KMS_MRK_WEST_ARN = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
AWS_KMS_MRK_EAST_ARN = "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"

AWS_KMS_MRK_WEST_ARN_MISMATCHES = list(kms_mkr_arn_mismatches(AWS_KMS_MRK_WEST_ARN))


def _raw_aes_providers(keys):
    """Build all AES Raw Master Key configurations to test.

    :param dict keys: Parsed keys manifest
    """
    for name, key in _keys_for_algorithm("aes", keys):
        # Single AES Symmetric Static Raw MasterKey, which can be decrypted
        yield (
            {
                "type": "raw",
                "key": name,
                "provider-id": "aws-raw-vectors-persistent-aes",
                "encryption-algorithm": "aes",
            },
        )


def _raw_rsa_providers(keys):
    """Build all RSA Raw Master Key configurations to test.

    :param dict keys: Parsed keys manifest
    """

    def _key_builder(name, key):
        return {
            "type": "raw",
            "key": name,
            "provider-id": "aws-raw-vectors-persistent-rsa",
            "encryption-algorithm": "rsa",
        }

    cyclable, encrypt_only = _split_on_decryptable(
        keys, functools.partial(_keys_for_algorithm, "rsa"), _key_builder
    )

    for key in cyclable:
        for padding_config in RAW_RSA_PADDING_ALGORITHMS:
            # Single RSA Asymmetric Static Raw MasterKey, which can be decrypted
            _key = key.copy()
            _key.update(padding_config)
            yield (_key,)

            # Multiple Asymmetric Raw MasterKeys, only one of which can be decrypted
            for blackhole in encrypt_only:
                _blackhole_key = blackhole.copy()
                _blackhole_key.update(RAW_RSA_BLACKHOLE_ARGUMENTS_OVERRIDE)
                yield (_key, _blackhole_key)



def _raw_asymmetric_pair_providers(keys):
    """Build all RSA Raw Master Key configurations to test.

    :param dict keys: Parsed keys manifest
    """

    def _key_builder(name, key):
        return {
            "type": "raw",
            "key": name,
            "provider-id": "aws-raw-vectors-persistent-rsa",
            "encryption-algorithm": key["algorithm"],
        }

    # The only asynchronous keys are RSA
    for publicName, public in _keys_for_type("public", keys):
        for privateName, private in  _keys_for_type("private", keys):
            if private["key-id"] == public["key-id"]:
                yield(_key_builder(publicName, public), _key_builder(privateName, private))

def _raw_symmetric_pair_providers(keys):
    """Build all master key provider configurations to test.

    :param dict keys: Parsed keys manifest
    """
    return itertools.chain(
        _aws_kms_providers(keys), _raw_aes_providers(keys)
    )

def _providers(keys):
    """Build all master key provider configurations to test.

    :param dict keys: Parsed keys manifest
    """
    return itertools.chain(
        _aws_kms_providers(keys), _raw_aes_providers(keys), _raw_rsa_providers(keys)
    )


def build_tests(keys):
    """Build all tests to define in manifest, building from current rules and provided keys manifest.

    :param dict keys: Parsed keys manifest
    """
    for algorithm in ALGORITHM_SUITES:
        for frame_size in FRAME_SIZES:
            for ec in ENCRYPTION_CONTEXTS:
                for provider_set in _providers(keys):
                    yield (
                        str(uuid.uuid4()),
                        {
                            "plaintext": "small",
                            "algorithm": algorithm,
                            "frame-size": frame_size,
                            "encryption-context": ec,
                            "master-keys": provider_set,
                        },
                    )
