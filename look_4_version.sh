## Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: Apache-2.0

#!bin/bash

VERSION=$1
COUNTER=0
STATUS=1

echo "Looking for version $VERSION"

while [  $STATUS -ne 0 ]; do
    mvn org.apache.maven.plugins:maven-dependency-plugin:3.0.1:get \
        -Dartifact=com.amazonaws:aws-encryption-sdk-java:$VERSION:jar -U

    STATUS=$?
    if [ $STATUS -eq 0 ]; then
        echo "Found version $VERSION in Maven Central :)"
        break
    fi

    if [  $((COUNTER+=1)) -eq 15 ]; then
        echo "It has been an awfully long time, you should check Maven Central for issues"
        exit 1
    fi

    echo "Could not find version $VERSION. Trying again."
    sleep 60
done
