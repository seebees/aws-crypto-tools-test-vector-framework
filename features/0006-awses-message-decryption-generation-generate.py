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

import argparse
import uuid
import json
import re
import os
import sys
from urllib.parse import urlunparse
from awses_message_encryption_utils import (
    PLAINTEXTS,
    RAW_RSA_PADDING_ALGORITHMS,
    ALGORITHM_SUITES,
    FRAME_SIZES,
    ENCRYPTION_CONTEXTS,
    UNPRINTABLE_UNICODE_ENCRYPTION_CONTEXT,
    _providers,
    _raw_aes_providers
)

MANIFEST_VERSION = 2

TAMPERINGS = (
    "truncate",
    "mutate",
    "half-sign",
)

def _build_tests(keys):
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
                            "encryption-scenario": {
                                "plaintext": "small",
                                "algorithm": algorithm,
                                "frame-size": frame_size,
                                "encryption-context": ec,
                                "master-keys": provider_set,
                            }
                        },
                    )

    for algorithm in ALGORITHM_SUITES:
        for frame_size in FRAME_SIZES:
            for ec in ENCRYPTION_CONTEXTS:
                for provider_set in _providers(keys):
                    yield (
                        str(uuid.uuid4()),
                        {
                            "encryption-scenario": {
                                "plaintext": "zero",
                                "algorithm": algorithm,
                                "frame-size": frame_size,
                                "encryption-context": ec,
                                "master-keys": provider_set,
                            }
                        },
                    )

    yield (
        str(uuid.uuid4()),
        {
            "encryption-scenario": {
                "plaintext": "tiny",
                "algorithm": "0178",
                "frame-size": 512,
                "encryption-context": UNPRINTABLE_UNICODE_ENCRYPTION_CONTEXT,
                "master-keys": next(_raw_aes_providers(keys)),
            },
            "decryption-method": "streaming-unsigned-only"
        },
    )

    yield (
        str(uuid.uuid4()),
        {
            "encryption-scenario": {
                "plaintext": "tiny",
                "algorithm": "0378",
                "frame-size": 512,
                "encryption-context": UNPRINTABLE_UNICODE_ENCRYPTION_CONTEXT,
                "master-keys": next(_raw_aes_providers(keys)),
            },
            "decryption-method": "streaming-unsigned-only",
            "result": {
                "error": {
                    "error-description": "Signed message input to streaming unsigned-only decryption method"
                }
            }
        }
    )

    for tampering in TAMPERINGS:
        yield (
            str(uuid.uuid4()),
            {
                "encryption-scenario": {
                    "plaintext": "tiny",
                    "algorithm": "0478" if tampering == "half-sign" else "0578",
                    "frame-size": 512,
                    "encryption-context": UNPRINTABLE_UNICODE_ENCRYPTION_CONTEXT,
                    "master-keys": next(_raw_aes_providers(keys)),
                },
                "tampering": tampering
            }
        )

    yield (
        str(uuid.uuid4()),
        {
            "encryption-scenario": {
                "plaintext": "tiny",
                "algorithm": "0578",
                "frame-size": 512,
                "encryption-context": UNPRINTABLE_UNICODE_ENCRYPTION_CONTEXT,
                "master-keys": next(_raw_aes_providers(keys)),
            },
            "tampering": {
                "change-edk-provider-info": [
                    "arn:aws:kms:us-west-2:658956600833:alias/EncryptOnly"
                ]
            },
            "decryption-master-keys": [
                {
                    "type": "aws-kms",
                    "key": "us-west-2-encrypt-only"
                }
            ]
        },
    )


def parse_arn(arn):
    return re.split("[:/]", arn)


def build_arn(arn_pieces):
    ":".join(arn_pieces[0:6]) + "/" + arn_pieces[6]


def kms_mkr_arn_mismatches(arn):
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


def build_manifest(keys_filename):
    """Build the test-case manifest which directs the behavior of cross-compatibility clients.

    :param str keys_file: Name of file containing the keys manifest
    """
    with open(keys_filename, "r") as keys_file:
        keys = json.load(keys_file)

    keys_path = "/".join(keys_filename.split(os.path.sep))
    keys_uri = urlunparse(("file", keys_path, "", "", "", ""))

    return {
        "manifest": {"type": "awses-decrypt-generate", "version": MANIFEST_VERSION},
        "keys": keys_uri,
        "plaintexts": PLAINTEXTS,
        "tests": dict(_build_tests(keys)),
    }


def main(args=None):
    """Entry point for CLI"""
    parser = argparse.ArgumentParser(
        description="Build an AWS Encryption SDK decrypt message generation manifest."
    )
    parser.add_argument(
        "--human", action="store_true", help="Print human-readable JSON"
    )
    parser.add_argument("--keys", required=True, help="Keys manifest to use")

    parsed = parser.parse_args(args)

    manifest = build_manifest(parsed.keys)

    kwargs = {}
    if parsed.human:
        kwargs["indent"] = 4

    return json.dumps(manifest, **kwargs)


if __name__ == "__main__":
    sys.exit(main())
