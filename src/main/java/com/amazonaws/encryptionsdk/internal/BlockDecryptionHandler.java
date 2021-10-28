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
import com.amazonaws.encryptionsdk.model.CipherBlockHeaders;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * The block decryption handler is an implementation of CryptoHandler that provides methods to
 * decrypt content encrypted and stored in a single block.
 *
 * <p>In this SDK, this class decrypts content that is encrypted by {@link BlockEncryptionHandler}.
 */
class BlockDecryptionHandler implements CryptoHandler {
  private final SecretKey decryptionKey_;
  private final short nonceLen_;
  private final CryptoAlgorithm cryptoAlgo_;
  private final byte[] messageId_;
  private final CipherBlockHeaders blockHeaders_;

  private final byte[] bytesToDecrypt_ = new byte[0];
  private byte[] unparsedBytes_ = new byte[0];
  private boolean complete_ = false;

  /**
   * Construct a decryption handler for decrypting bytes stored in a single block.
   *
   * @param decryptionKey the key to use for decrypting the ciphertext
   * @param nonceLen the length to use when parsing the nonce in the block headers.
   * @param cryptoAlgo the crypto algorithm to use for decrypting the ciphertext
   * @param messageId the byte array containing the message identifier that is used in binding the
   *     encrypted content to the headers in the ciphertext.
   */
  public BlockDecryptionHandler(
      final SecretKey decryptionKey,
      final short nonceLen,
      final CryptoAlgorithm cryptoAlgo,
      final byte[] messageId) {
    decryptionKey_ = decryptionKey;
    nonceLen_ = nonceLen;
    cryptoAlgo_ = cryptoAlgo;
    messageId_ = messageId;
    blockHeaders_ = new CipherBlockHeaders();
  }

  /**
   * Decrypt the ciphertext bytes provided in {@code in} containing the encrypted bytes of the
   * plaintext stored in a single block. The decrypted bytes are copied into {@code out} starting at
   * {@code outOff}.
   *
   * <p>This method performs two operations: parses the headers of the single block structure in the
   * ciphertext and processes the encrypted content following the headers and decrypts it.
   *
   * @param in the input byte array.
   * @param off the offset into the in array where the data to be decrypted starts.
   * @param len the number of bytes to be decrypted.
   * @param out the output buffer the decrypted plaintext bytes go into.
   * @param outOff the offset into the output byte array the decrypted data starts at.
   * @return the number of bytes written to out.
   * @throws AwsCryptoException if the content type found in the headers is not of single-block
   *     type.
   */
  @Override
  public synchronized ProcessingSummary processBytes(
      final byte[] in, final int off, final int len, final byte[] out, final int outOff)
      throws AwsCryptoException {

    if (complete_) {
      throw new AwsCryptoException("Ciphertext has already been processed.");
    }

    final byte[] bytesToParse = new byte[unparsedBytes_.length + len];
    // If there were previously unparsed bytes, add them as the first
    // set of bytes to be parsed in this call.
    System.arraycopy(unparsedBytes_, 0, bytesToParse, 0, unparsedBytes_.length);
    System.arraycopy(in, off, bytesToParse, unparsedBytes_.length, len);

    long parsedBytes = 0;

    // Parse available bytes. Stop parsing when there aren't enough
    // bytes to complete parsing of the :
    // - the blockcipher headers
    // - encrypted content
    while (!complete_ && parsedBytes < bytesToParse.length) {
      blockHeaders_.setNonceLength(nonceLen_);

      parsedBytes += blockHeaders_.deserialize(bytesToParse, (int) parsedBytes);
      if (parsedBytes > Integer.MAX_VALUE) {
        throw new AwsCryptoException(
            "Integer overflow of the total bytes to parse and decrypt occured.");
      }

      // if we have all header fields, process the encrypted content.
      if (blockHeaders_.isComplete() == true) {
        if (blockHeaders_.getContentLength() > Integer.MAX_VALUE) {
          throw new AwsCryptoException("Content length exceeds the maximum allowed value.");
        }
        int protectedContentLen = (int) blockHeaders_.getContentLength();

        // include the tag which is added by the underlying cipher.
        protectedContentLen += cryptoAlgo_.getTagLen();

        if ((bytesToParse.length - parsedBytes) < protectedContentLen) {
          // if we don't have all of the encrypted bytes, break
          // until they become available.
          break;
        }
        byte[] plaintext = decryptContent(bytesToParse, (int) parsedBytes, protectedContentLen);
        System.arraycopy(plaintext, 0, out, outOff, plaintext.length);

        complete_ = true;
        return new ProcessingSummary(
            plaintext.length, (int) (parsedBytes + protectedContentLen) - unparsedBytes_.length);
      } else {
        // if there aren't enough bytes to parse the block headers,
        // we can't continue parsing.
        break;
      }
    }

    // buffer remaining bytes for parsing in the next round.
    unparsedBytes_ = Arrays.copyOfRange(bytesToParse, (int) parsedBytes, bytesToParse.length);

    return new ProcessingSummary(0, len);
  }

  /**
   * Finish processing of the bytes by decrypting the ciphertext.
   *
   * @param out space for any resulting output data.
   * @param outOff offset into {@code out} to start copying the data at.
   * @return number of bytes written into {@code out}.
   * @throws BadCiphertextException if the bytes do not decrypt correctly.
   */
  @Override
  public synchronized int doFinal(final byte[] out, final int outOff)
      throws BadCiphertextException {
    if (!complete_) {
      throw new BadCiphertextException("Unable to process entire ciphertext.");
    }
    return 0;
  }

  /**
   * Return the size of the output buffer required for a processBytes plus a doFinal with an input
   * of inLen bytes.
   *
   * @param inLen the length of the input.
   * @return the space required to accommodate a call to processBytes and doFinal with len bytes of
   *     input.
   */
  @Override
  public synchronized int estimateOutputSize(final int inLen) {
    // include any buffered bytes
    int outSize = bytesToDecrypt_.length + unparsedBytes_.length;

    if (inLen > 0) {
      outSize += inLen;
    }

    return outSize;
  }

  @Override
  public int estimatePartialOutputSize(int inLen) {
    return estimateOutputSize(inLen);
  }

  @Override
  public int estimateFinalOutputSize() {
    return estimateOutputSize(0);
  }

  /**
   * Returns the plaintext bytes of the encrypted content.
   *
   * @param input the input bytes containing the content
   * @param off the offset into the input array where the data to be decrypted starts.
   * @param len the number of bytes to be decrypted.
   * @return the plaintext bytes of the encrypted content.
   * @throws BadCiphertextException if the MAC tag verification fails or an invalid header value is
   *     found.
   */
  private byte[] decryptContent(final byte[] input, final int off, final int len)
      throws BadCiphertextException {
    if (blockHeaders_.isComplete() == false) {
      return new byte[0];
    }

    final byte[] nonce = blockHeaders_.getNonce();
    final int seqNum = 1; // always 1 for single block case.

    final byte[] contentAad =
        Utils.generateContentAad(
            messageId_, Constants.SINGLE_BLOCK_STRING_ID, seqNum, blockHeaders_.getContentLength());

    final CipherHandler cipherHandler =
        new CipherHandler(decryptionKey_, Cipher.DECRYPT_MODE, cryptoAlgo_);
    return cipherHandler.cipherData(nonce, contentAad, input, off, len);
  }

  @Override
  public boolean isComplete() {
    return complete_;
  }
}
