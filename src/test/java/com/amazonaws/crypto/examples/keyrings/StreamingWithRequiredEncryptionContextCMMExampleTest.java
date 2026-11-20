// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import org.junit.Test;

public class StreamingWithRequiredEncryptionContextCMMExampleTest {

  @Test
  public void testEncryptAndDecrypt() throws IOException {
    // Create a temporary file for testing the example
    final String srcFile = "RandomFile.txt";
    final File file = new File(srcFile);
    file.createNewFile();
    String randomMessage = generateRandomMessage(1024);

    writeToFile(srcFile, randomMessage);

    StreamingWithRequiredEncryptionContextCMMExample.encryptAndDecryptWithKeyring(
        srcFile, KMSTestFixtures.US_WEST_2_KEY_ID);
  }

  private static String generateRandomMessage(int length) {
    String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    StringBuilder randomMessage = new StringBuilder();

    SecureRandom random = new SecureRandom();
    for (int i = 0; i < length; i++) {
      int randomIndex = random.nextInt(characters.length());
      randomMessage.append(characters.charAt(randomIndex));
    }

    return randomMessage.toString();
  }

  private static void writeToFile(String srcFile, String content) throws IOException {
    Files.write(Paths.get(srcFile), content.getBytes(StandardCharsets.UTF_8));
  }
}
