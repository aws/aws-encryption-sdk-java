// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.model.CiphertextFooters;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import com.amazonaws.encryptionsdk.model.CiphertextType;
import com.amazonaws.encryptionsdk.model.ContentType;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsHandler;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * This class implements the CryptoHandler interface by providing methods for the encryption of
 * plaintext data.
 *
 * <p>This class creates the ciphertext headers and delegates the encryption of the plaintext to the
 * {@link BlockEncryptionHandler} or {@link FrameEncryptionHandler} based on the content type.
 */
public class EncryptionHandler implements MessageCryptoHandler {
  private static final CiphertextType CIPHERTEXT_TYPE =
      CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA;

  private final EncryptionMaterialsHandler encryptionMaterials_;
  private final Map<String, String> storedEncryptionContext_;
  private final Map<String, String> reqEncryptionContext_;
  private final CryptoAlgorithm cryptoAlgo_;
  private final List<MasterKey> masterKeys_;
  private final List<KeyBlob> keyBlobs_;
  private final SecretKey encryptionKey_;
  private final byte version_;
  private final CiphertextType type_;
  private final byte nonceLen_;
  private final PrivateKey trailingSignaturePrivateKey_;
  private final MessageDigest trailingDigest_;
  private final Signature trailingSig_;

  private final CiphertextHeaders ciphertextHeaders_;
  private final byte[] ciphertextHeaderBytes_;
  private final CryptoHandler contentCryptoHandler_;

  private boolean firstOperation_ = true;
  private boolean complete_ = false;

  private long plaintextBytes_ = 0;
  private long plaintextByteLimit_ = -1;

  /**
   * Create an encryption handler using the provided master key and encryption context.
   *
   * @param frameSize The encryption frame size, or zero for a one-shot encryption task
   * @param result The EncryptionMaterials with the crypto materials for this encryption job
   * @throws AwsCryptoException if the encryption context or master key is null.
   */
  public EncryptionHandler(
      int frameSize, EncryptionMaterialsHandler result, CommitmentPolicy commitmentPolicy)
      throws AwsCryptoException {
    Utils.assertNonNull(result, "result");
    Utils.assertNonNull(commitmentPolicy, "commitmentPolicy");

    this.encryptionMaterials_ = result;

    Map<String, String> encryptionContext = result.getEncryptionContext();
    List<String> reqKeys = result.getRequiredEncryptionContextKeys();
    Map<Boolean, Map<String, String>> partitionedEncryptionContext =
        encryptionContext.entrySet().stream()
            .collect(
                Collectors.partitioningBy(
                    entry -> reqKeys.contains(entry.getKey()),
                    Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));

    storedEncryptionContext_ = partitionedEncryptionContext.get(false);
    reqEncryptionContext_ = partitionedEncryptionContext.get(true);

    if (!commitmentPolicy.algorithmAllowedForEncrypt(result.getAlgorithm())) {
      if (commitmentPolicy == CommitmentPolicy.ForbidEncryptAllowDecrypt) {
        throw new AwsCryptoException(
            "Configuration conflict. Cannot encrypt due to CommitmentPolicy "
                + commitmentPolicy
                + " requiring only non-committed messages. Algorithm ID was "
                + result.getAlgorithm()
                + ". See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html");
      } else {
        throw new AwsCryptoException(
            "Configuration conflict. Cannot encrypt due to CommitmentPolicy "
                + commitmentPolicy
                + " requiring only committed messages. Algorithm ID was "
                + result.getAlgorithm()
                + ". See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html");
      }
    }
    this.cryptoAlgo_ = result.getAlgorithm();
    this.masterKeys_ = result.getMasterKeys();
    this.keyBlobs_ = result.getEncryptedDataKeys();
    this.trailingSignaturePrivateKey_ = result.getTrailingSignatureKey();

    if (keyBlobs_.isEmpty()) {
      throw new IllegalArgumentException("No encrypted data keys in materials result");
    }

    if (trailingSignaturePrivateKey_ != null) {
      try {
        TrailingSignatureAlgorithm algorithm =
            TrailingSignatureAlgorithm.forCryptoAlgorithm(cryptoAlgo_);
        trailingDigest_ = MessageDigest.getInstance(algorithm.getMessageDigestAlgorithm());
        trailingSig_ = Signature.getInstance(algorithm.getRawSignatureAlgorithm());

        trailingSig_.initSign(trailingSignaturePrivateKey_, Utils.getSecureRandom());
      } catch (final GeneralSecurityException ex) {
        throw new AwsCryptoException(ex);
      }
    } else {
      trailingDigest_ = null;
      trailingSig_ = null;
    }

    // set default values
    version_ = cryptoAlgo_.getMessageFormatVersion();
    type_ = CIPHERTEXT_TYPE;
    nonceLen_ = cryptoAlgo_.getNonceLen();

    ContentType contentType;
    if (frameSize > 0) {
      contentType = ContentType.FRAME;
    } else if (frameSize == 0) {
      contentType = ContentType.SINGLEBLOCK;
    } else {
      throw Utils.cannotBeNegative("Frame size");
    }

    // Construct the headers
    // Included here rather than as a sub-routine so we can set final variables.
    // This way we can avoid calculating the keys more times than we need.
    //
    // AAD: MUST be the serialization of the encryption context in the encryption materials, and
    // this serialization MUST NOT contain any key value pairs listed in the encryption material's
    // required encryption context keys.
    final byte[] storedEncryptionContextBytes =
        EncryptionContextSerializer.serialize(storedEncryptionContext_);
    final CiphertextHeaders unsignedHeaders =
        new CiphertextHeaders(
            type_, cryptoAlgo_, storedEncryptionContextBytes, keyBlobs_, contentType, frameSize);
    // We use a deterministic IV of zero for the header authentication.
    unsignedHeaders.setHeaderNonce(new byte[nonceLen_]);

    // If using a committing crypto algorithm, we also need to calculate the commitment value along
    // with the key derivation
    if (cryptoAlgo_.isCommitting()) {
      final CommittedKey committedKey =
          CommittedKey.generate(
              cryptoAlgo_, result.getCleartextDataKey(), unsignedHeaders.getMessageId());
      unsignedHeaders.setSuiteData(committedKey.getCommitment());
      encryptionKey_ = committedKey.getKey();
    } else {
      try {
        encryptionKey_ =
            cryptoAlgo_.getEncryptionKeyFromDataKey(result.getCleartextDataKey(), unsignedHeaders);
      } catch (final InvalidKeyException ex) {
        throw new AwsCryptoException(ex);
      }
    }

    // The authenticated only encryption context is all encryption context key-value pairs where the
    // key exists in Required Encryption Context Keys. It is then serialized according to the
    // message header Key Value Pairs.
    final byte[] reqEncryptionContextBytes =
        EncryptionContextSerializer.serialize(reqEncryptionContext_);
    ciphertextHeaders_ = signCiphertextHeaders(unsignedHeaders, reqEncryptionContextBytes);
    ciphertextHeaderBytes_ = ciphertextHeaders_.toByteArray();
    byte[] messageId_ = ciphertextHeaders_.getMessageId();

    switch (contentType) {
      case FRAME:
        contentCryptoHandler_ =
            new FrameEncryptionHandler(
                encryptionKey_, nonceLen_, cryptoAlgo_, messageId_, frameSize);
        break;
      case SINGLEBLOCK:
        contentCryptoHandler_ =
            new BlockEncryptionHandler(encryptionKey_, nonceLen_, cryptoAlgo_, messageId_);
        break;
      default:
        // should never get here because a valid content type is always
        // set above based on the frame size.
        throw new AwsCryptoException("Unknown content type.");
    }
  }

  /**
   * Encrypt a block of bytes from {@code in} putting the plaintext result into {@code out}.
   *
   * <p>It encrypts by performing the following operations:
   *
   * <ol>
   *   <li>if this is the first call to encrypt, write the ciphertext headers to the output being
   *       returned.
   *   <li>else, pass off the input data to underlying content cryptohandler.
   * </ol>
   *
   * @param in the input byte array.
   * @param off the offset into the in array where the data to be encrypted starts.
   * @param len the number of bytes to be encrypted.
   * @param out the output buffer the encrypted bytes go into.
   * @param outOff the offset into the output byte array the encrypted data starts at.
   * @return the number of bytes written to out and processed
   * @throws AwsCryptoException if len or offset values are negative.
   * @throws BadCiphertextException thrown by the underlying cipher handler.
   */
  @Override
  public ProcessingSummary processBytes(
      final byte[] in, final int off, final int len, final byte[] out, final int outOff)
      throws AwsCryptoException, BadCiphertextException {
    if (len < 0 || off < 0) {
      throw new AwsCryptoException(
          String.format("Invalid values for input offset: %d and length: %d", off, len));
    }

    checkPlaintextSizeLimit(len);

    int actualOutLen = 0;

    if (firstOperation_ == true) {
      System.arraycopy(ciphertextHeaderBytes_, 0, out, outOff, ciphertextHeaderBytes_.length);
      actualOutLen += ciphertextHeaderBytes_.length;

      firstOperation_ = false;
    }

    ProcessingSummary contentOut =
        contentCryptoHandler_.processBytes(in, off, len, out, outOff + actualOutLen);
    actualOutLen += contentOut.getBytesWritten();
    updateTrailingSignature(out, outOff, actualOutLen);
    plaintextBytes_ += contentOut.getBytesProcessed();
    return new ProcessingSummary(actualOutLen, contentOut.getBytesProcessed());
  }

  /**
   * Finish encryption of the plaintext bytes.
   *
   * @param out space for any resulting output data.
   * @param outOff offset into out to start copying the data at.
   * @return number of bytes written into out.
   * @throws BadCiphertextException thrown by the underlying cipher handler.
   */
  @Override
  public int doFinal(final byte[] out, final int outOff) throws BadCiphertextException {
    if (complete_) {
      throw new IllegalStateException("Attempted to call doFinal twice");
    }

    complete_ = true;

    checkPlaintextSizeLimit(0);

    int written = contentCryptoHandler_.doFinal(out, outOff);
    updateTrailingSignature(out, outOff, written);
    if (cryptoAlgo_.getTrailingSignatureLength() > 0) {
      try {
        CiphertextFooters footer = new CiphertextFooters(signContent());
        byte[] fBytes = footer.toByteArray();
        System.arraycopy(fBytes, 0, out, outOff + written, fBytes.length);
        return written + fBytes.length;
      } catch (final SignatureException ex) {
        throw new AwsCryptoException(ex);
      }
    } else {
      return written;
    }
  }

  private byte[] signContent() throws SignatureException {
    if (trailingDigest_ != null) {
      if (!trailingSig_.getAlgorithm().contains("ECDSA")) {
        throw new UnsupportedOperationException(
            "Signatures calculated in pieces is only supported for ECDSA.");
      }
      final byte[] digest = trailingDigest_.digest();
      return generateEcdsaFixedLengthSignature(digest);
    }
    return trailingSig_.sign();
  }

  private byte[] generateEcdsaFixedLengthSignature(final byte[] digest) throws SignatureException {
    byte[] signature;
    // Unfortunately, we need deterministic lengths some signatures are non-deterministic in length.
    // So, retry until we get the right length :-(
    do {
      trailingSig_.update(digest);
      signature = trailingSig_.sign();
      if (signature.length != cryptoAlgo_.getTrailingSignatureLength()) {
        // Most of the time, a signature of the wrong length can be fixed
        // be negating s in the signature relative to the group order.
        ASN1Sequence seq = ASN1Sequence.getInstance(signature);
        ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
        ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);
        ECPrivateKey ecKey = (ECPrivateKey) trailingSignaturePrivateKey_;
        s = new ASN1Integer(ecKey.getParams().getOrder().subtract(s.getPositiveValue()));
        seq = new DERSequence(new ASN1Encodable[] {r, s});
        try {
          signature = seq.getEncoded();
        } catch (IOException ex) {
          throw new SignatureException(ex);
        }
      }
    } while (signature.length != cryptoAlgo_.getTrailingSignatureLength());
    return signature;
  }

  /**
   * Return the size of the output buffer required for a {@code processBytes} plus a {@code doFinal}
   * with an input of inLen bytes.
   *
   * @param inLen the length of the input.
   * @return the space required to accommodate a call to processBytes and doFinal with len bytes of
   *     input.
   */
  @Override
  public int estimateOutputSize(final int inLen) {
    int outSize = 0;
    if (firstOperation_ == true) {
      outSize += ciphertextHeaderBytes_.length;
    }
    outSize += contentCryptoHandler_.estimateOutputSize(inLen);

    if (cryptoAlgo_.getTrailingSignatureLength() > 0) {
      outSize += 2; // Length field in footer
      outSize += cryptoAlgo_.getTrailingSignatureLength();
    }
    return outSize;
  }

  @Override
  public int estimatePartialOutputSize(int inLen) {
    int outSize = 0;
    if (firstOperation_ == true) {
      outSize += ciphertextHeaderBytes_.length;
    }
    outSize += contentCryptoHandler_.estimatePartialOutputSize(inLen);

    return outSize;
  }

  @Override
  public int estimateFinalOutputSize() {
    return estimateOutputSize(0);
  }

  /**
   * Return the encryption context.
   *
   * @return the key-value map containing encryption context.
   */
  @Override
  public Map<String, String> getEncryptionContext() {
    return storedEncryptionContext_;
  }

  @Override
  public CiphertextHeaders getHeaders() {
    return ciphertextHeaders_;
  }

  @Override
  public void setMaxInputLength(long size) {
    if (size < 0) {
      throw Utils.cannotBeNegative("Max input length");
    }

    if (plaintextByteLimit_ == -1 || plaintextByteLimit_ > size) {
      plaintextByteLimit_ = size;
    }

    // check that we haven't already exceeded the limit
    checkPlaintextSizeLimit(0);
  }

  private void checkPlaintextSizeLimit(long additionalBytes) {
    if (plaintextByteLimit_ != -1 && plaintextBytes_ + additionalBytes > plaintextByteLimit_) {
      throw new IllegalStateException("Plaintext size exceeds max input size limit");
    }
  }

  long getMaxInputLength() {
    return plaintextByteLimit_;
  }

  /**
   * Compute the MAC tag of the header bytes using the provided key, nonce, AAD, and crypto
   * algorithm identifier.
   *
   * @param nonce the nonce to use in computing the MAC tag.
   * @param aad the AAD to use in computing the MAC tag.
   * @return the bytes containing the computed MAC tag.
   */
  private byte[] computeHeaderTag(final byte[] nonce, final byte[] aad) {
    final CipherHandler cipherHandler =
        new CipherHandler(encryptionKey_, Cipher.ENCRYPT_MODE, cryptoAlgo_);

    return cipherHandler.cipherData(nonce, aad, new byte[0], 0, 0);
  }

  private CiphertextHeaders signCiphertextHeaders(
      final CiphertextHeaders unsignedHeaders, byte[] reqEncryptionContextBytes) {
    final byte[] headerFields = unsignedHeaders.serializeAuthenticatedFields();
    // The AAD MUST be the concatenation of the serialized message header body and the serialization
    // of encryption context to only authenticate. The encryption context to only authenticate MUST
    // be the encryption context in the encryption materials filtered to only contain key value
    // pairs listed in the encryption material's required encryption context keys serialized
    // according to the encryption context serialization specification.
    final byte[] headerTag =
        computeHeaderTag(
            unsignedHeaders.getHeaderNonce(),
            Arrays.concatenate(headerFields, reqEncryptionContextBytes));

    unsignedHeaders.setHeaderTag(headerTag);

    return unsignedHeaders;
  }

  @Override
  public List<? extends MasterKey<?>> getMasterKeys() {
    //noinspection unchecked
    return (List) masterKeys_; // This is unmodifiable
  }

  private void updateTrailingSignature(byte[] input, int offset, int len) {
    if (trailingDigest_ != null) {
      trailingDigest_.update(input, offset, len);
    } else if (trailingSig_ != null) {
      try {
        trailingSig_.update(input, offset, len);
      } catch (final SignatureException ex) {
        throw new AwsCryptoException(ex);
      }
    }
  }

  @Override
  public boolean isComplete() {
    return complete_;
  }
}
