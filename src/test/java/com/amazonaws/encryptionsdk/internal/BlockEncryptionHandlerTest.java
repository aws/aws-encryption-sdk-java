/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.internal;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoInputStream;
import com.amazonaws.encryptionsdk.CryptoOutputStream;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.model.CipherBlockHeaders;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

public class BlockEncryptionHandlerTest {
  private final CryptoAlgorithm cryptoAlgorithm_ = TestUtils.DEFAULT_TEST_CRYPTO_ALG;
  private final byte[] messageId_ =
      RandomBytesGenerator.generate(cryptoAlgorithm_.getMessageIdLength());
  private final byte nonceLen_ = cryptoAlgorithm_.getNonceLen();
  private final byte[] dataKeyBytes_ =
      RandomBytesGenerator.generate(cryptoAlgorithm_.getKeyLength());
  private final SecretKey encryptionKey_ = new SecretKeySpec(dataKeyBytes_, "AES");

  private BlockEncryptionHandler blockEncryptionHandler_;

  @Before
  public void setUp() throws Exception {
    blockEncryptionHandler_ =
        new BlockEncryptionHandler(encryptionKey_, nonceLen_, cryptoAlgorithm_, messageId_);
  }

  @Test
  public void emptyOutBytes() {
    final int outLen = 0;
    final byte[] out = new byte[outLen];
    final int processedLen = blockEncryptionHandler_.doFinal(out, 0);
    assertEquals(outLen, processedLen);
  }

  @Test
  public void correctIVGenerated() throws Exception {
    final byte[] out = new byte[1024];
    int outOff = blockEncryptionHandler_.processBytes(new byte[1], 0, 1, out, 0).getBytesWritten();
    final int processedLen = blockEncryptionHandler_.doFinal(out, outOff);

    CipherBlockHeaders headers = new CipherBlockHeaders();
    headers.setNonceLength(cryptoAlgorithm_.getNonceLen());
    headers.deserialize(out, 0);

    assertArrayEquals(
        new byte[] {
          0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, 1
        },
        headers.getNonce());
  }

  /**
   * This isn't a unit test, but it reproduces a bug found in the FrameEncryptionHandler where the
   * stream would be truncated when the offset is >0. For the sake of robustness, the same test is
   * included against the BlockEncryptionHandler.
   *
   * @throws Exception
   */
  @Test
  public void testStreamTruncation() throws Exception {
    // Initialize AES key and keyring
    SecureRandom rnd = new SecureRandom();
    byte[] rawKey = new byte[16];
    rnd.nextBytes(rawKey);
    SecretKeySpec cryptoKey = new SecretKeySpec(rawKey, "AES");
    MaterialProviders materialProviders =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    CreateRawAesKeyringInput keyringInput =
        CreateRawAesKeyringInput.builder()
            .wrappingKey(ByteBuffer.wrap(cryptoKey.getEncoded()))
            .keyNamespace("Example")
            .keyName("RandomKey")
            .wrappingAlg(AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16)
            .build();
    IKeyring keyring = materialProviders.CreateRawAesKeyring(keyringInput);
    // Use unframed (block) encryption
    AwsCrypto crypto = AwsCrypto.builder().withEncryptionFrameSize(0).build();

    String testDataString = StringUtils.repeat("Hello, World! ", 5_000);

    int startOffset = 100; // The data will start from this offset
    byte[] inputDataWithOffset = new byte[10_000];
    // the length of the actual data
    int dataLength = inputDataWithOffset.length - startOffset;
    // copy some data, starting at the startOffset
    // so the first |startOffset| bytes are 0s
    System.arraycopy(
        testDataString.getBytes(StandardCharsets.UTF_8),
        0,
        inputDataWithOffset,
        startOffset,
        dataLength);
    // decryptData (non-streaming) doesn't know about the offset
    // it will strip out the original 0s
    byte[] expectedOutput = new byte[10_000 - startOffset];
    System.arraycopy(
        testDataString.getBytes(StandardCharsets.UTF_8), 0, expectedOutput, 0, dataLength);

    // Encrypt the data
    byte[] encryptedData;
    try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
      try (CryptoOutputStream cryptoOutput =
          crypto.createEncryptingStream(keyring, os, Collections.emptyMap())) {
        cryptoOutput.write(inputDataWithOffset, startOffset, dataLength);
      }
      encryptedData = os.toByteArray();
    }

    // Check non-streaming decrypt
    CryptoResult<byte[], ?> nonStreamDecrypt = crypto.decryptData(keyring, encryptedData);
    assertEquals(dataLength, nonStreamDecrypt.getResult().length);
    assertArrayEquals(expectedOutput, nonStreamDecrypt.getResult());

    // Check streaming decrypt
    int decryptedLength = 0;
    byte[] decryptedData = new byte[inputDataWithOffset.length];
    try (ByteArrayInputStream is = new ByteArrayInputStream(encryptedData);
        CryptoInputStream cryptoInput = crypto.createDecryptingStream(keyring, is)) {
      int offset = startOffset;
      do {
        int bytesRead = cryptoInput.read(decryptedData, offset, decryptedData.length - offset);
        if (bytesRead <= 0) {
          break; // End of stream
        }
        offset += bytesRead;
        decryptedLength += bytesRead;
      } while (true);
    }
    assertEquals(dataLength, decryptedLength);
    // These arrays will be offset, i.e. the first |startOffset| bytes are 0s
    assertArrayEquals(inputDataWithOffset, decryptedData);
  }
}
