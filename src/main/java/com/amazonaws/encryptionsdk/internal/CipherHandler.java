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

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ArrayBlockingQueue;
import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * This class provides a cryptographic cipher handler powered by an underlying block cipher. The
 * block cipher performs authenticated encryption of the provided bytes using Additional
 * Authenticated Data (AAD).
 *
 * <p>This class implements a method called cipherData() that encrypts or decrypts a byte array by
 * calling methods on the underlying block cipher.
 */
@NotThreadSafe
class CipherHandler {
  //TODO how to sze this, or allow it to be configured externally
  private static final CipherPool CIPHER_POOL = new CipherPool(32);

  private final int cipherMode_;
  private final SecretKey key_;
  private final CryptoAlgorithm cryptoAlgorithm_;

  /**
   * Process data through the cipher.
   *
   * <p>This method calls the <code>update</code> and <code>doFinal</code> methods on the underlying
   * cipher to complete processing of the data.
   *
   * @param nonce the nonce to be used by the underlying cipher
   * @param contentAad the optional additional authentication data to be used by the underlying
   *     cipher
   * @param content the content to be processed by the underlying cipher
   * @param off the offset into content array to be processed
   * @param len the number of bytes to process
   * @return the bytes processed by the underlying cipher
   * @throws AwsCryptoException if cipher initialization fails
   * @throws BadCiphertextException if processing the data through the cipher fails
   */
  public byte[] cipherData(
      byte[] nonce, byte[] contentAad, final byte[] content, final int off, final int len) {
    if (nonce.length != cryptoAlgorithm_.getNonceLen()) {
      throw new IllegalArgumentException("Invalid nonce length: " + nonce.length);
    }
    final AlgorithmParameterSpec spec =
        new GCMParameterSpec(cryptoAlgorithm_.getTagLen() * 8, nonce, 0, nonce.length);

    final Cipher cipher = CIPHER_POOL.borrowCipher();
    try {
      cipher.init(cipherMode_, key_, spec);
      if (contentAad != null) {
        cipher.updateAAD(contentAad);
      }
    } catch (final GeneralSecurityException gsx) {
      throw new AwsCryptoException(gsx);
    }
    try {
      byte[] bytes = cipher.doFinal(content, off, len);
      CIPHER_POOL.returnCipher(cipher);
      return bytes;
    } catch (final GeneralSecurityException gsx) {
      throw new BadCiphertextException(gsx);
    }
  }

  /**
   * Create a cipher handler for processing bytes using an underlying block cipher.
   *
   * @param key the key to use in encrypting or decrypting bytes
   * @param cipherMode the mode for processing the bytes as defined in {@link Cipher#init(int,
   *     java.security.Key)}
   * @param cryptoAlgorithm the cryptography algorithm to be used by the underlying block cipher.
   * @throws GeneralSecurityException
   */
  CipherHandler(final SecretKey key, final int cipherMode, final CryptoAlgorithm cryptoAlgorithm) {
    this.cipherMode_ = cipherMode;
    this.key_ = key;
    this.cryptoAlgorithm_ = cryptoAlgorithm;
  }

  private static class CipherPool {
    private final ArrayBlockingQueue<Cipher> pool;

    CipherPool(int size) {
      this.pool = new ArrayBlockingQueue<>(size);
    }

    Cipher borrowCipher() {
      Cipher cipher = pool.poll();
      if (cipher == null) {
        try {
          // Right now, just GCM is supported
          cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (final GeneralSecurityException ex) {
          throw new IllegalStateException("Java does not support the requested algorithm", ex);
        }
      }
      return cipher;
    }

    void returnCipher(Cipher cipher) {
      pool.offer(cipher);
    }
  }
}
