// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static org.junit.Assert.assertArrayEquals;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class XCompatKmsDecryptTest {
  private final String plaintextFileName;
  private final String ciphertextFileName;
  private final String kmsKeyId;

  public XCompatKmsDecryptTest(
      String plaintextFileName, String ciphertextFileName, String kmsKeyId) {
    this.plaintextFileName = plaintextFileName;
    this.ciphertextFileName = ciphertextFileName;
    this.kmsKeyId = kmsKeyId;
  }

  @Parameters(name = "{index}: testDecryptFromFile({0}, {1}, {2})")
  public static Collection<Object[]> data() throws Exception {
    String baseDirName;
    baseDirName = System.getProperty("staticCompatibilityResourcesDir");
    if (baseDirName == null) {
      baseDirName =
          XCompatKmsDecryptTest.class.getProtectionDomain().getCodeSource().getLocation().getPath()
              + "aws_encryption_sdk_resources";
    }

    List<Object[]> testCases_ = new ArrayList<>();

    String ciphertextManifestName =
        StringUtils.join(
            new String[] {baseDirName, "manifests", "ciphertext.manifest"}, File.separator);
    File ciphertextManifestFile = new File(ciphertextManifestName);

    if (!ciphertextManifestFile.exists()) {
      return Collections.emptyList();
    }

    ObjectMapper ciphertextManifestMapper = new ObjectMapper();
    Map<String, Object> ciphertextManifest =
        ciphertextManifestMapper.readValue(
            ciphertextManifestFile, new TypeReference<Map<String, Object>>() {});

    List<Map<String, Object>> testCases =
        (List<Map<String, Object>>) ciphertextManifest.get("test_cases");
    for (Map<String, Object> testCase : testCases) {
      Map<String, String> plaintext = (Map<String, String>) testCase.get("plaintext");
      Map<String, String> ciphertext = (Map<String, String>) testCase.get("ciphertext");

      List<Map<String, Object>> masterKeys =
          (List<Map<String, Object>>) testCase.get("master_keys");
      for (Map<String, Object> masterKey : masterKeys) {
        String providerId = (String) masterKey.get("provider_id");
        if (providerId.equals("aws-kms") && (boolean) masterKey.get("decryptable")) {
          testCases_.add(
              new Object[] {
                baseDirName + File.separator + plaintext.get("filename"),
                baseDirName + File.separator + ciphertext.get("filename"),
                (String) masterKey.get("key_id")
              });
          break;
        }
      }
    }
    return testCases_;
  }

  @Test
  public void testDecryptFromFile() throws Exception {
    AwsCrypto crypto = AwsCrypto.standard();
    final KmsMasterKeyProvider masterKeyProvider =
        KmsMasterKeyProvider.builder().buildStrict(kmsKeyId);
    byte[] ciphertextBytes = Files.readAllBytes(Paths.get(ciphertextFileName));
    byte[] plaintextBytes = Files.readAllBytes(Paths.get(plaintextFileName));
    final CryptoResult<byte[], KmsMasterKey> decryptResult =
        crypto.decryptData(masterKeyProvider, ciphertextBytes);
    assertArrayEquals(plaintextBytes, decryptResult.getResult());
  }
}
