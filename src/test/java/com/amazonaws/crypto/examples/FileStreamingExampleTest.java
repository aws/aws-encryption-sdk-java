/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.crypto.examples;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

class FileStreamingExampleTest {

    @Test
    void testEncryptAndDecrypt() throws IOException {
        final File tempFile = File.createTempFile("FileStreamingExampleTest-TempTestData", ".tmp");
        tempFile.deleteOnExit();

        try(BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath())) {
            for(int i = 0; i < 1000 ; i++) {
                writer.write(RandomStringUtils.randomAlphanumeric(100));
                writer.newLine();
            }
        }

        FileStreamingExample.encryptAndDecrypt(tempFile.getPath());
    }
}
