#!/bin/bash

# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

./aws-encryption-sdk-specification/util/test_conditions \
  -s '-r src/main/ --include *.java' \
  -t '-r src/test/ --include *.java' \
  -s 'compliance_exceptions/*.java'
