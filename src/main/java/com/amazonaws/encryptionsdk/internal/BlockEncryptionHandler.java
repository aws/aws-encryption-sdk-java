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
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.model.CipherBlockHeaders;
import java.io.ByteArrayOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * The block encryption handler is an implementation of {@link MessageCryptoHandler} that provides
 * methods to encrypt content and store it in a single block.
 *
 * <p>In this SDK, content encrypted by this class is decrypted by the {@link
 * BlockDecryptionHandler}.
 */
class BlockEncryptionHandler implements CryptoHandler {
  private final SecretKey encryptionKey_;
  private final CryptoAlgorithm cryptoAlgo_;
  private final int nonceLen_;
  private final byte[] messageId_;
  private final int tagLenBytes_;

  private final ByteArrayOutputStream bytesToEncryptStream_ = new ByteArrayOutputStream(1024);

  private boolean complete_ = false;

  /**
   * Construct an encryption handler for encrypting bytes and storing them in a single block.
   *
   * @param encryptionKey the key to use for encrypting the plaintext
   * @param nonceLen the length of the nonce to use when encrypting the plaintext
   * @param cryptoAlgo the crypto algorithm to use for encrypting the plaintext
   * @param messageId the byte array containing the message identifier that is used in binding the
   *     encrypted content to the headers in the ciphertext.
   */
  public BlockEncryptionHandler(
      final SecretKey encryptionKey,
      final int nonceLen,
      final CryptoAlgorithm cryptoAlgo,
      final byte[] messageId) {
    encryptionKey_ = encryptionKey;
    cryptoAlgo_ = cryptoAlgo;
    nonceLen_ = nonceLen;
    messageId_ = messageId.clone();
    tagLenBytes_ = cryptoAlgo_.getTagLen();
  }

  /**
   * Encrypt the block of bytes provide in {@code in} and copy the resulting ciphertext bytes into
   * {@code out}.
   *
   * @param in the input byte array containing plaintext bytes.
   * @param off the offset into {@code in} where the data to be encrypted starts.
   * @param len the number of bytes to be encrypted.
   * @param out the output buffer the encrypted bytes are copied into.
   * @param outOff the offset into the output byte array the encrypted data starts at.
   * @return the number of bytes written to {@code out} and the number of bytes processed
   */
  @Override
  public ProcessingSummary processBytes(
      final byte[] in, final int off, final int len, final byte[] out, final int outOff) {
    bytesToEncryptStream_.write(in, off, len);
    return new ProcessingSummary(0, len);
  }

  /**
   * Finish encryption of the plaintext bytes.
   *
   * @param out space for any resulting output data.
   * @param outOff offset into {@code out} to start copying the data at.
   * @return number of bytes written into {@code out}.
   * @throws BadCiphertextException thrown by the underlying cipher handler.
   */
  @Override
  public int doFinal(final byte[] out, final int outOff) throws BadCiphertextException {
    complete_ = true;
    return writeEncryptedBlock(
        bytesToEncryptStream_.toByteArray(), 0, bytesToEncryptStream_.size(), out, outOff);
  }

  /**
   * Return the size of the output buffer required for a processBytes plus a doFinal with an input
   * size of {@code inLen} bytes.
   *
   * @param inLen the length of the input.
   * @return the space required to accommodate a call to processBytes and doFinal with {@code inLen}
   *     bytes of input.
   */
  @Override
  public int estimateOutputSize(final int inLen) {
    int outSize = 0;

    outSize += nonceLen_ + tagLenBytes_;
    // include long for storing size of content
    outSize += Long.SIZE / Byte.SIZE;

    // include any buffered bytes
    outSize += bytesToEncryptStream_.size();

    if (inLen > 0) {
      outSize += inLen;
    }

    return outSize;
  }

  @Override
  public int estimatePartialOutputSize(int inLen) {
    return 0;
  }

  @Override
  public int estimateFinalOutputSize() {
    return estimateOutputSize(0);
  }

  /**
   * This method encrypts the provided bytes, creates the headers for the block, and assembles the
   * block containing the headers and the encrypted bytes.
   *
   * @param in the input byte array.
   * @param inOff the offset into {@code in} array where the data to be encrypted starts.
   * @param inLen the number of bytes to be encrypted.
   * @param out the output buffer the encrypted bytes is copied into.
   * @param outOff the offset into the output byte array the encrypted data starts at.
   * @return the number of bytes written to {@code out}.
   * @throws BadCiphertextException thrown by the underlying cipher handler.
   */
  private int writeEncryptedBlock(
      final byte[] input, final int off, final int len, final byte[] out, final int outOff)
      throws BadCiphertextException {
    if (out.length == 0) {
      return 0;
    }

    int outLen = 0;
    final int seqNum = 1; // always 1 for single block case

    final byte[] contentAad =
        Utils.generateContentAad(messageId_, Constants.SINGLE_BLOCK_STRING_ID, seqNum, len);

    final byte[] nonce = getNonce();

    final byte[] encryptedBytes =
        new CipherHandler(encryptionKey_, Cipher.ENCRYPT_MODE, cryptoAlgo_)
            .cipherData(nonce, contentAad, input, off, len);

    // create the cipherblock headers now for the encrypted data
    final int encryptedContentLen = encryptedBytes.length - tagLenBytes_;
    final CipherBlockHeaders cipherBlockHeaders =
        new CipherBlockHeaders(nonce, encryptedContentLen);
    final byte[] cipherBlockHeaderBytes = cipherBlockHeaders.toByteArray();

    // assemble the headers and the encrypted bytes into a single block
    System.arraycopy(
        cipherBlockHeaderBytes, 0, out, outOff + outLen, cipherBlockHeaderBytes.length);
    outLen += cipherBlockHeaderBytes.length;
    System.arraycopy(encryptedBytes, 0, out, outOff + outLen, encryptedBytes.length);
    outLen += encryptedBytes.length;

    return outLen;
  }

  private byte[] getNonce() {
    final byte[] nonce = new byte[nonceLen_];

    // The IV for the non-framed encryption case is generated as if we were encrypting a message
    // with a single
    // frame.
    nonce[nonce.length - 1] = 1;

    return nonce;
  }

  @Override
  public boolean isComplete() {
    return complete_;
  }
}
