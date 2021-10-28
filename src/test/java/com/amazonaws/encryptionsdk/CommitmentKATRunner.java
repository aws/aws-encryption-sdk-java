// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class CommitmentKATRunner {
  private String comment;
  private String keyringType;
  private byte[] ciphertext;
  private byte[] commitment;
  private byte[] plaintext;
  private byte[] decryptedDEK;
  private byte[] messageId;
  private byte[] header;
  private Map<String, String> encryptionContext;
  private boolean status;

  private static final String TEST_VECTOR_RESOURCE_PATH = "/commitment-test-vectors.json";

  public CommitmentKATRunner(
      String comment,
      String keyringType,
      byte[] ciphertext,
      byte[] commitment,
      byte[] plaintext,
      byte[] decryptedDEK,
      byte[] messageId,
      byte[] header,
      Map<String, String> encryptionContext,
      boolean status)
      throws Exception {
    this.comment = comment;
    this.keyringType = keyringType;
    this.ciphertext = ciphertext;
    this.commitment = commitment;
    this.plaintext = plaintext;
    this.decryptedDEK = decryptedDEK;
    this.messageId = messageId;
    this.header = header;
    this.encryptionContext = encryptionContext;
    this.status = status;
  }

  @Parameters(
      name = "{index}: testDecryptCommitment({0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9})")
  public static Collection<Object[]> data() throws Exception {
    final String testVectorsName =
        CommitmentKATRunner.class.getResource(TEST_VECTOR_RESOURCE_PATH).getPath();
    final File ciphertextManifestFile = new File(testVectorsName);

    final List<Object[]> testCases_ = new ArrayList<Object[]>();

    if (!ciphertextManifestFile.exists()) {
      throw new IllegalStateException(
          "Missing commitment test vectors file from src/test/resources.");
    }

    final ObjectMapper ciphertextManifestMapper = new ObjectMapper();
    final Map<String, Object> ciphertextManifest =
        ciphertextManifestMapper.readValue(
            ciphertextManifestFile, new TypeReference<Map<String, Object>>() {});

    final List<Map<String, Object>> testCases =
        (List<Map<String, Object>>) ciphertextManifest.get("tests");
    for (Map<String, Object> test : testCases) {
      final String keyringType = (String) test.get("keyring-type");
      final byte[] decryptedDEK = Utils.decodeBase64String((String) test.get("decrypted-dek"));
      final byte[] ciphertext = Utils.decodeBase64String((String) test.get("ciphertext"));
      final byte[] commitment = Utils.decodeBase64String((String) test.get("commitment"));
      final byte[] messageId = Utils.decodeBase64String((String) test.get("message-id"));
      final byte[] header = Utils.decodeBase64String((String) test.get("header"));
      final boolean status = (boolean) test.get("status");
      final String comment = (String) test.get("comment");
      final Map<String, String> encryptionContext =
          (Map<String, String>) test.get("encryption-context");

      // plaintext is available for cases which succeed decryption
      byte[] plaintext = null;
      if (status) {
        final List<String> plaintextFrames = (List<String>) test.get("plaintext-frames");
        plaintext = String.join("", plaintextFrames).getBytes(StandardCharsets.UTF_8);
      }

      testCases_.add(
          new Object[] {
            comment,
            keyringType,
            ciphertext,
            commitment,
            plaintext,
            decryptedDEK,
            messageId,
            header,
            encryptionContext,
            status
          });
    }
    return testCases_;
  }

  @Test
  public void testDecryptCommitment() throws Exception {
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();

    // Determine what MKP to test with based on whether the test case was create using kms or not.
    // If it was, we can test decryption of the message completely end to end by using a
    // Discovery KMS MKP.
    // Otherwise, we must mock out a provider that just returns the data encryption key associated
    // with the test case.
    final MasterKeyProvider mkp;
    switch (keyringType) {
      case "aws-kms":
        mkp = KmsMasterKeyProvider.builder().buildDiscovery();
        break;
      case "static":
      default:
        mkp = mock(MasterKeyProvider.class);
        DataKey dataKey =
            new DataKey(
                // All committing algorithms use HkdfSHA512 for
                // the kdf. If this changes, the test vectors
                // will need to indicate what algorithm suite
                // was used in order for this test to
                // appropriately set the secret key spec's algorithm
                new SecretKeySpec(decryptedDEK, "HkdfSHA512"), new byte[0], new byte[0], null);
        when(mkp.decryptDataKey(any(), any(), any())).thenReturn(dataKey);
        break;
    }

    // Ensure tests that are expected to fail do so with the right exception and error message
    if (!status) {
      assertThrows(
          BadCiphertextException.class,
          "Key commitment validation failed. Key identity does not "
              + "match the identity asserted in the message. Halting processing of this message.",
          () -> crypto.decryptData(mkp, ciphertext));
      return;
    }

    // Otherwise ensure our result matches the expected commitment data
    final CryptoResult decryptResult = crypto.decryptData(mkp, ciphertext);
    assertArrayEquals(decryptResult.getHeaders().getSuiteData(), commitment);
    assertArrayEquals(decryptResult.getHeaders().getMessageId(), messageId);
    assertArrayEquals(decryptResult.getHeaders().toByteArray(), header);
    assertTrue(decryptResult.getEncryptionContext().equals(encryptionContext));
    assertArrayEquals((byte[]) decryptResult.getResult(), plaintext);
  }
}
