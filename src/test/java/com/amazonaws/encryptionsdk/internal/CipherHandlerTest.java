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

import static org.junit.Assert.assertTrue;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import java.util.Arrays;
import java.util.EnumSet;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public class CipherHandlerTest {
  private final int contentLen_ = 1024; // 1KB
  private final byte[] contentAad_ = "Test string AAD".getBytes();

  @Test
  public void encryptDecryptWithAllAlgos() {
    for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
      assertTrue(encryptDecryptContent(cryptoAlg));
      assertTrue(encryptDecryptEmptyContent(cryptoAlg));
    }
  }

  @Test(expected = BadCiphertextException.class)
  public void tamperCiphertext() {
    final CryptoAlgorithm cryptoAlgorithm = TestUtils.DEFAULT_TEST_CRYPTO_ALG;
    final byte[] content = RandomBytesGenerator.generate(contentLen_);
    final byte[] keyBytes = RandomBytesGenerator.generate(cryptoAlgorithm.getKeyLength());
    final byte[] nonce = RandomBytesGenerator.generate(cryptoAlgorithm.getNonceLen());

    final SecretKey key = new SecretKeySpec(keyBytes, cryptoAlgorithm.getKeyAlgo());
    CipherHandler cipherHandler = createCipherHandler(key, cryptoAlgorithm, Cipher.ENCRYPT_MODE);
    final byte[] encryptedBytes =
        cipherHandler.cipherData(nonce, contentAad_, content, 0, content.length);

    encryptedBytes[0] += 1; // tamper the first byte in ciphertext

    cipherHandler = createCipherHandler(key, cryptoAlgorithm, Cipher.DECRYPT_MODE);
    cipherHandler.cipherData(nonce, contentAad_, encryptedBytes, 0, encryptedBytes.length);
  }

  private boolean encryptDecryptContent(final CryptoAlgorithm cryptoAlgorithm) {
    final byte[] content = RandomBytesGenerator.generate(contentLen_);
    final byte[] result = encryptDecrypt(content, cryptoAlgorithm);
    return Arrays.equals(content, result) ? true : false;
  }

  private boolean encryptDecryptEmptyContent(final CryptoAlgorithm cryptoAlgorithm) {
    final byte[] result = encryptDecrypt(new byte[0], cryptoAlgorithm);
    return (result.length == 0) ? true : false;
  }

  private byte[] encryptDecrypt(final byte[] content, final CryptoAlgorithm cryptoAlgorithm) {
    final byte[] keyBytes = RandomBytesGenerator.generate(cryptoAlgorithm.getKeyLength());
    final byte[] nonce = RandomBytesGenerator.generate(cryptoAlgorithm.getNonceLen());

    final SecretKey key = new SecretKeySpec(keyBytes, cryptoAlgorithm.getKeyAlgo());
    CipherHandler cipherHandler = createCipherHandler(key, cryptoAlgorithm, Cipher.ENCRYPT_MODE);
    final byte[] encryptedBytes =
        cipherHandler.cipherData(nonce, contentAad_, content, 0, content.length);

    cipherHandler = createCipherHandler(key, cryptoAlgorithm, Cipher.DECRYPT_MODE);
    final byte[] decryptedBytes =
        cipherHandler.cipherData(nonce, contentAad_, encryptedBytes, 0, encryptedBytes.length);

    return decryptedBytes;
  }

  private CipherHandler createCipherHandler(
      final SecretKey key, final CryptoAlgorithm cryptoAlgorithm, final int mode) {
    return new CipherHandler(key, mode, cryptoAlgorithm);
  }
}
