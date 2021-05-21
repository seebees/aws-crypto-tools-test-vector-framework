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
 
from awses_message_encryption_utils import kms_mkr_arn_mismatches

def test_kms_mkr_arn_mismatches():
    mrk_arn = "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    actual = list(kms_mkr_arn_mismatches(mrk_arn))

    expected = [
        # Wrong "arn"
        "aws:kms:us-east-1:658956600833:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        ":aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn-not:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",

        # Wrong partition
        "arn:kms:us-east-1:658956600833:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn::kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws-not:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",

        # Wrong service
        "arn:aws:us-east-1:658956600833:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws::us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws:kms-not:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        
        # Missing/blank region (wrong is not a mismatch)
        "arn:aws:kms:658956600833:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws:kms::658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        
        # Wrong account
        "arn:aws:kms:us-east-1:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws:kms:us-east-1::key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws:kms:us-east-1:658956600833-not:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        
        # Wrong resource type
        "arn:aws:kms:us-east-1:658956600833:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws:kms:us-east-1:658956600833:/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        "arn:aws:kms:us-east-1:658956600833:key-not/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        
        # Wrong resource
        "arn:aws:kms:us-east-1:658956600833:key",
        "arn:aws:kms:us-east-1:658956600833:key/",
        "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7-not",
        
        # Alias
        "arn:aws:kms:us-east-1:658956600833:alias/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
        
        # Raw key ID
        "mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    ]
    assert actual == expected
    
