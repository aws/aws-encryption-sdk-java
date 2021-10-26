// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.exception.ParseException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.EncryptionContextSerializer;
import com.amazonaws.encryptionsdk.internal.PrimitivesParser;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * This class implements the headers for the message (ciphertext) produced by this library. These
 * headers are parsed and used when the ciphertext is decrypted.
 *
 * <p>See https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html for
 * a detailed description of the fields that make up the encrypted message header.
 *
 * <p>It is important to note that all but the last two header fields are checked for their
 * integrity during decryption using AES-GCM with the nonce and MAC tag values supplied in the last
 * two fields of the header.
 */
public class CiphertextHeaders {
  /**
   * When passed as maxEncryptedDataKeys, indicates that no maximum should be enforced (i.e., any
   * number of EDKs are allowed).
   */
  public static final int NO_MAX_ENCRYPTED_DATA_KEYS = 0;

  private static final SecureRandom RND = new SecureRandom();
  private byte version_ = -1;
  private byte typeVal_; // don't set this to -1 since Java byte is signed
  // while this value is unsigned and can go up to 128.
  private short cryptoAlgoVal_ = -1;
  private byte[] messageId_;
  private int encryptionContextLen_ = -1;
  private byte[] encryptionContext_ = new byte[0];
  private int cipherKeyCount_ = -1;
  private List<KeyBlob> cipherKeyBlobs_;
  private byte contentTypeVal_ = -1;
  private int reservedField_ = -1;
  private short nonceLen_ = -1;
  private int frameLength_ = -1;

  private byte[] headerNonce_;
  private byte[] headerTag_;

  private int suiteDataLen_ = -1;
  private byte[] suiteData_;

  // internal variables
  private int currKeyBlobIndex_ = 0;
  private boolean isComplete_;
  private int maxEncryptedDataKeys_ = NO_MAX_ENCRYPTED_DATA_KEYS;

  /** Default constructor. */
  public CiphertextHeaders() {}

  /**
   * Construct the ciphertext headers using the provided values.
   *
   * @param version the version to set in the header.
   * @param type the type to set in the header.
   * @param cryptoAlgo the CryptoAlgorithm enum to encode in the header.
   * @param encryptionContext the bytes containing the encryption context to set in the header.
   * @param keyBlobs list of keyBlobs containing the key provider id, key provider info, and
   *     encrypted data key to encode in the header.
   * @param contentType the content type to set in the header.
   * @param frameSize the frame payload size to set in the header.
   * @deprecated {@link #CiphertextHeaders(CiphertextType, CryptoAlgorithm, byte[], List,
   *     ContentType, int)}
   */
  @Deprecated
  public CiphertextHeaders(
      final byte version,
      final CiphertextType type,
      final CryptoAlgorithm cryptoAlgo,
      final byte[] encryptionContext,
      final List<KeyBlob> keyBlobs,
      final ContentType contentType,
      final int frameSize) {
    this(
        type,
        assertVersionCompatibility(version, cryptoAlgo),
        encryptionContext,
        keyBlobs,
        contentType,
        frameSize);
  }

  // Utility method since there isn't another good way to check the argument prior to calling a
  // second constructor
  private static CryptoAlgorithm assertVersionCompatibility(
      final byte version, final CryptoAlgorithm cryptoAlgo) {
    if (version != cryptoAlgo.getMessageFormatVersion()) {
      throw new IllegalArgumentException(
          "Version must match the message format version from the type");
    }
    return cryptoAlgo;
  }

  /**
   * Construct the ciphertext headers using the provided values.
   *
   * @param type the type to set in the header.
   * @param cryptoAlgo the CryptoAlgorithm enum to encode in the header.
   * @param encryptionContext the bytes containing the encryption context to set in the header.
   * @param keyBlobs list of keyBlobs containing the key provider id, key provider info, and
   *     encrypted data key to encode in the header.
   * @param contentType the content type to set in the header.
   * @param frameSize the frame payload size to set in the header.
   */
  public CiphertextHeaders(
      final CiphertextType type,
      final CryptoAlgorithm cryptoAlgo,
      final byte[] encryptionContext,
      final List<KeyBlob> keyBlobs,
      final ContentType contentType,
      final int frameSize) {

    version_ = cryptoAlgo.getMessageFormatVersion();
    typeVal_ = type.getValue();

    cryptoAlgoVal_ = cryptoAlgo.getValue();

    encryptionContext_ = encryptionContext.clone();
    if (encryptionContext_.length > Constants.UNSIGNED_SHORT_MAX_VAL) {
      throw new AwsCryptoException(
          "Size of encryption context exceeds the allowed maximum "
              + Constants.UNSIGNED_SHORT_MAX_VAL);
    }
    encryptionContextLen_ = encryptionContext.length;

    // we only support the encoding of 1 data key in the cipher blob.
    cipherKeyCount_ = keyBlobs.size();
    cipherKeyBlobs_ = new ArrayList<>(keyBlobs);

    contentTypeVal_ = contentType.getValue();
    reservedField_ = 0;
    nonceLen_ = cryptoAlgo.getNonceLen();

    // generate random bytes and assign them as the unique identifier of the
    // message wrapped by this header.
    messageId_ = new byte[cryptoAlgo.getMessageIdLength()];
    RND.nextBytes(messageId_);

    frameLength_ = frameSize;

    // Completed by construction
    isComplete_ = true;
  }

  /**
   * Check if this object has all the header fields populated and available for reading.
   *
   * @return true if this object containing the single block header fields is complete; false
   *     otherwise.
   */
  public Boolean isComplete() {
    return isComplete_;
  }

  /**
   * Parse the version in the provided bytes. It looks for a single byte in the provided bytes
   * starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseVersion(final byte[] b, final int off) throws ParseException {
    if (version_ >= 0) {
      return 0;
    }
    version_ = PrimitivesParser.parseByte(b, off);
    return 1;
  }

  /** Sets appropriate constants and parameters for v1 parsing */
  private int configV1(final byte[] b, final int off) {
    suiteDataLen_ = -1;
    return 0;
  }

  /** Sets appropriate constants and parameters for v2 parsing */
  private int configV2(final byte[] b, final int off) {
    suiteDataLen_ = getCryptoAlgoId().getSuiteDataLength();
    typeVal_ = CiphertextType.CUSTOMER_AUTHENTICATED_ENCRYPTED_DATA.getValue();
    headerNonce_ = getCryptoAlgoId().getHeaderNonce();
    if (headerNonce_ == null) {
      throw new IllegalStateException(
          "Message format v2 requires the algorithm to specify a header nonce.");
    }
    if (headerNonce_.length > Short.MAX_VALUE) {
      throw new IllegalStateException(
          "Message format v2 requires the algorithm to specify a header nonce with "
              + "length less than 2^15.");
    }
    nonceLen_ = (short) headerNonce_.length;
    return 0;
  }

  /**
   * Parse the type in the provided bytes. It looks for a single byte in the provided bytes starting
   * at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseType(final byte[] b, final int off) throws ParseException {
    if (typeVal_ != 0) {
      return 0;
    }
    typeVal_ = PrimitivesParser.parseByte(b, off);
    if (CiphertextType.deserialize(typeVal_) == null) {
      throw new BadCiphertextException("Invalid ciphertext type.");
    }
    return 1;
  }

  /**
   * Parse the algorithm identifier in the provided bytes. It looks for 2 bytes representing a short
   * primitive type in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseAlgoId(final byte[] b, final int off) throws ParseException {
    if (cryptoAlgoVal_ >= 0) {
      return 0;
    }
    cryptoAlgoVal_ = PrimitivesParser.parseShort(b, off);
    if (CryptoAlgorithm.deserialize(version_, cryptoAlgoVal_) == null) {
      throw new BadCiphertextException("Invalid algorithm identifier in ciphertext");
    }
    return Short.SIZE / Byte.SIZE;
  }

  /**
   * Parse the message ID in the provided bytes. It looks for bytes of the size defined by the
   * message identifier length in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseMessageId(final byte[] b, final int off) throws ParseException {
    if (messageId_ != null) {
      return 0;
    }
    final int len = b.length - off;
    final int messageIdLen = getCryptoAlgoId().getMessageIdLength();
    if (len >= messageIdLen) {
      messageId_ = Arrays.copyOfRange(b, off, off + messageIdLen);
      return messageIdLen;
    } else {
      throw new ParseException("Not enough bytes to parse serial number");
    }
  }

  /**
   * Parses suite specific data
   *
   * @see {@link ParsingStep}
   */
  private int parseSuiteData(final byte[] b, final int off) throws ParseException {
    if (suiteData_ != null) {
      return 0;
    }
    final int len = b.length - off;
    if (len >= suiteDataLen_) {
      suiteData_ = Arrays.copyOfRange(b, off, off + suiteDataLen_);
      return suiteDataLen_;
    } else {
      throw new ParseException("Not enough bytes to parse suite specific data");
    }
  }

  /**
   * Parse the length of the encryption context in the provided bytes. It looks for 2 bytes
   * representing a short primitive type in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseEncryptionContextLen(final byte[] b, final int off) throws ParseException {
    if (encryptionContextLen_ >= 0) {
      return 0;
    }
    encryptionContextLen_ = PrimitivesParser.parseUnsignedShort(b, off);
    if (encryptionContextLen_ < 0) {
      throw new BadCiphertextException("Invalid encryption context length in ciphertext");
    }
    return Short.SIZE / Byte.SIZE;
  }

  /**
   * Parse the encryption context in the provided bytes. It looks for bytes of size defined by the
   * encryption context length in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseEncryptionContext(final byte[] b, final int off) throws ParseException {
    if (encryptionContextLen_ < encryptionContext_.length) {
      throw new IllegalStateException(
          "Parsed encryption context is in an invalid state. Size exceeds parsed "
              + "encryption context length.");
    }
    if (encryptionContextLen_ == encryptionContext_.length) {
      return 0;
    }
    final int len = b.length - off;
    if (len >= encryptionContextLen_) {
      encryptionContext_ = Arrays.copyOfRange(b, off, off + encryptionContextLen_);
      return encryptionContextLen_;
    } else {
      throw new ParseException("Not enough bytes to parse encryption context");
    }
  }

  /**
   * Parse the data key count in the provided bytes. It looks for 2 bytes representing a short
   * primitive type in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseEncryptedDataKeyCount(final byte[] b, final int off) throws ParseException {
    if (cipherKeyCount_ >= 0) {
      return 0;
    }
    cipherKeyCount_ = PrimitivesParser.parseUnsignedShort(b, off);
    if (cipherKeyCount_ < 0) {
      throw new BadCiphertextException("Invalid cipher key count in ciphertext");
    }
    if (maxEncryptedDataKeys_ > 0 && cipherKeyCount_ > maxEncryptedDataKeys_) {
      throw new AwsCryptoException("Ciphertext encrypted data keys exceed maxEncryptedDataKeys");
    }
    cipherKeyBlobs_ = Arrays.asList(new KeyBlob[cipherKeyCount_]);
    return Short.SIZE / Byte.SIZE;
  }

  /**
   * Parses the list of encrypted key blobs. Unlike many of the other parsing methods, this one can
   * make partial progress. To indicate this partial progress it throws a {@link
   * PartialParseException} containing the number of parsed bytes.
   *
   * @see {@link ParsingStep}
   */
  private int parseEncryptedKeyBlobList(final byte[] b, final int off)
      throws PartialParseException {
    int parsedBytes = 0;
    try {
      if (cipherKeyCount_ > 0) {
        while (currKeyBlobIndex_ < cipherKeyCount_) {
          if (cipherKeyBlobs_.get(currKeyBlobIndex_) == null) {
            cipherKeyBlobs_.set(currKeyBlobIndex_, new KeyBlob());
          }
          if (cipherKeyBlobs_.get(currKeyBlobIndex_).isComplete() == false) {
            parsedBytes += parseEncryptedKeyBlob(b, off + parsedBytes);
            // check if we had enough bytes to parse the key blob
            if (cipherKeyBlobs_.get(currKeyBlobIndex_).isComplete() == false) {
              throw new ParseException("Not enough bytes to parse key blob");
            }
          }
          currKeyBlobIndex_++;
        }
      }
    } catch (final ParseException ex) {
      throw new PartialParseException(ex, parsedBytes);
    }
    return parsedBytes;
  }

  /**
   * Parse the encrypted key blob. It delegates the parsing to the methods in the key blob class.
   *
   * @see {@link ParsingStep}
   */
  private int parseEncryptedKeyBlob(final byte[] b, final int off) throws ParseException {
    return cipherKeyBlobs_.get(currKeyBlobIndex_).deserialize(b, off);
  }

  /**
   * Parse the content type in the provided bytes. It looks for a single byte in the provided bytes
   * starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseContentType(final byte[] b, final int off) throws ParseException {
    if (contentTypeVal_ >= 0) {
      return 0;
    }
    contentTypeVal_ = PrimitivesParser.parseByte(b, off);
    if (ContentType.deserialize(contentTypeVal_) == null) {
      throw new BadCiphertextException("Invalid content type in ciphertext.");
    }
    return 1;
  }

  /**
   * Parse reserved field in the provided bytes. It looks for 4 bytes representing an integer
   * primitive type in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseReservedField(final byte[] b, final int off) throws ParseException {
    if (reservedField_ >= 0) {
      return 0;
    }
    reservedField_ = PrimitivesParser.parseInt(b, off);
    if (reservedField_ != 0) {
      throw new BadCiphertextException("Invalid value for reserved field in ciphertext");
    }
    return Integer.SIZE / Byte.SIZE;
  }

  /**
   * Parse the length of the nonce in the provided bytes. It looks for a single byte in the provided
   * bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseNonceLen(final byte[] b, final int off) throws ParseException {
    if (nonceLen_ >= 0) {
      return 0;
    }
    nonceLen_ = PrimitivesParser.parseByte(b, off);
    if (nonceLen_ < 0) {
      throw new BadCiphertextException("Invalid nonce length in ciphertext");
    }
    return 1;
  }

  /**
   * Parse the frame payload length in the provided bytes. It looks for 4 bytes representing an
   * integer primitive type in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseFramePayloadLength(final byte[] b, final int off) throws ParseException {
    if (frameLength_ >= 0) {
      return 0;
    }
    frameLength_ = PrimitivesParser.parseInt(b, off);
    if (frameLength_ < 0) {
      throw new BadCiphertextException("Invalid frame length in ciphertext");
    }
    return Integer.SIZE / Byte.SIZE;
  }

  /**
   * Parse the header nonce in the provided bytes. It looks for bytes of the size defined by the
   * nonce length in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseHeaderNonce(final byte[] b, final int off) throws ParseException {
    if (nonceLen_ == 0 || headerNonce_ != null) {
      return 0;
    }
    final int len = b.length - off;
    if (len >= nonceLen_) {
      headerNonce_ = Arrays.copyOfRange(b, off, off + nonceLen_);
      return nonceLen_;
    } else {
      throw new ParseException("Not enough bytes to parse header nonce");
    }
  }

  /**
   * Parse the header tag in the provided bytes. It uses the crypto algorithm identifier to
   * determine the length of the tag to parse. It looks for bytes of size defined by the tag length
   * in the provided bytes starting at the specified off.
   *
   * @see {@link ParsingStep}
   */
  private int parseHeaderTag(final byte[] b, final int off) throws ParseException {
    if (headerTag_ != null) {
      return 0;
    }
    final int len = b.length - off;
    final CryptoAlgorithm cryptoAlgo = CryptoAlgorithm.deserialize(version_, cryptoAlgoVal_);
    final int tagLen = cryptoAlgo.getTagLen();
    if (len >= tagLen) {
      headerTag_ = Arrays.copyOfRange(b, off, off + tagLen);
      return tagLen;
    } else {
      throw new ParseException("Not enough bytes to parse header tag");
    }
  }

  /**
   * Marks a deserialization operation as complete. This method always succeeds while consuming zero
   * bytes. It sets {@link #isComplete_} to {@code true}.
   *
   * @see {@link ParsingStep}
   */
  private int parseComplete(final byte[] b, final int off) throws ParseException {
    isComplete_ = true;
    return 0;
  }

  /**
   * Deserialize the provided bytes starting at the specified offset to construct an instance of
   * this class. Uses the default value for maxEncryptedDataKeys, which results in no limit.
   *
   * <p>This method parses the provided bytes for the individual fields in this class. This method
   * also supports partial parsing where not all the bytes required for parsing the fields
   * successfully are available.
   *
   * @param b the byte array to deserialize.
   * @param off the offset in the byte array to use for deserialization.
   * @return the number of bytes consumed in deserialization.
   */
  public int deserialize(final byte[] b, final int off) throws ParseException {
    return deserialize(b, off, NO_MAX_ENCRYPTED_DATA_KEYS);
  }

  /**
   * Deserialize the provided bytes starting at the specified offset to construct an instance of
   * this class.
   *
   * <p>This method parses the provided bytes for the individual fields in this class. This method
   * also supports partial parsing where not all the bytes required for parsing the fields
   * successfully are available.
   *
   * @param b the byte array to deserialize.
   * @param off the offset in the byte array to use for deserialization.
   * @param maxEncryptedDataKeys the maximum number of EDKs to deserialize; zero indicates no
   *     maximum
   * @return the number of bytes consumed in deserialization.
   */
  public int deserialize(final byte[] b, final int off, int maxEncryptedDataKeys)
      throws ParseException {
    if (b == null) {
      return 0;
    }

    maxEncryptedDataKeys_ = maxEncryptedDataKeys;

    int parsedBytes = 0;
    try {
      parsedBytes += parseVersion(b, off + parsedBytes);

      final ParsingStep[] steps;
      switch (version_) {
        case 1: // Initial version
          steps =
              new ParsingStep[] {
                this::configV1,
                this::parseType,
                this::parseAlgoId,
                this::parseMessageId,
                this::parseEncryptionContextLen,
                this::parseEncryptionContext,
                this::parseEncryptedDataKeyCount,
                this::parseEncryptedKeyBlobList,
                this::parseContentType,
                this::parseReservedField,
                this::parseNonceLen,
                this::parseFramePayloadLength,
                this::parseHeaderNonce,
                this::parseHeaderTag,
                this::parseComplete
              };
          break;
        case 2:
          steps =
              new ParsingStep[] {
                this::parseAlgoId,
                this::configV2, // Must come after we've parsed the algorithm
                this::parseMessageId,
                this::parseEncryptionContextLen,
                this::parseEncryptionContext,
                this::parseEncryptedDataKeyCount,
                this::parseEncryptedKeyBlobList,
                this::parseContentType,
                this::parseFramePayloadLength,
                this::parseSuiteData,
                this::parseHeaderTag,
                this::parseComplete
              };
          break;
        default:
          throw new BadCiphertextException("Invalid version");
      }

      for (final ParsingStep step : steps) {
        parsedBytes += step.parse(b, off + parsedBytes);
      }

    } catch (final PartialParseException e) {
      // this results when we do partial parsing and there aren't enough
      // bytes to parse; ignore it and return the bytes parsed thus far.
      parsedBytes += e.bytesParsed_;
    } catch (final ParseException e) {
      // this results when we do partial parsing and there aren't enough
      // bytes to parse; ignore it and return the bytes parsed thus far.
    }

    return parsedBytes;
  }

  /**
   * Serialize the header fields into a byte array. Note this method does not serialize the header
   * nonce and tag.
   *
   * @return the serialized bytes of the header fields not including the header nonce and tag.
   */
  public byte[] serializeAuthenticatedFields() {
    try {
      ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
      DataOutputStream dataStream = new DataOutputStream(outBytes);

      dataStream.writeByte(version_);

      if (version_ == 1) {
        dataStream.writeByte(typeVal_);
        dataStream.writeShort(cryptoAlgoVal_);
        dataStream.write(messageId_);
        PrimitivesParser.writeUnsignedShort(dataStream, encryptionContextLen_);
        if (encryptionContextLen_ > 0) {
          dataStream.write(encryptionContext_);
        }

        dataStream.writeShort(cipherKeyCount_);
        for (int i = 0; i < cipherKeyCount_; i++) {
          final byte[] cipherKeyBlobBytes = cipherKeyBlobs_.get(i).toByteArray();
          dataStream.write(cipherKeyBlobBytes);
        }

        dataStream.writeByte(contentTypeVal_);
        dataStream.writeInt(reservedField_);

        dataStream.writeByte(nonceLen_);
        dataStream.writeInt(frameLength_);
      } else if (version_ == 2) {
        dataStream.writeShort(cryptoAlgoVal_);
        dataStream.write(messageId_);
        PrimitivesParser.writeUnsignedShort(dataStream, encryptionContextLen_);
        if (encryptionContextLen_ > 0) {
          dataStream.write(encryptionContext_);
        }

        dataStream.writeShort(cipherKeyCount_);
        for (int i = 0; i < cipherKeyCount_; i++) {
          final byte[] cipherKeyBlobBytes = cipherKeyBlobs_.get(i).toByteArray();
          dataStream.write(cipherKeyBlobBytes);
        }

        dataStream.writeByte(contentTypeVal_);
        dataStream.writeInt(frameLength_);
        dataStream.write(suiteData_);
      } else {
        throw new IllegalArgumentException("Unsupported version: " + version_);
      }
      dataStream.close();
      return outBytes.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException("Failed to serialize cipher text headers", e);
    }
  }

  /**
   * Serialize the header fields into a byte array. This method serializes all the header fields
   * including the header nonce and tag.
   *
   * @return the serialized bytes of the entire header.
   */
  public byte[] toByteArray() {
    if (headerNonce_ == null || headerTag_ == null) {
      throw new AwsCryptoException("Header nonce and tag cannot be null.");
    }
    if (version_ == 2 && suiteData_ == null) {
      throw new AwsCryptoException("Suite Data cannot be null in the v2 message format.");
    }

    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      baos.write(serializeAuthenticatedFields());
      // The v1 header format includes the header nonce.
      // In v2 this is specified by the crypto algorithm.
      if (version_ == 1) {
        baos.write(headerNonce_);
      }
      baos.write(headerTag_);

      return baos.toByteArray();
    } catch (IOException ex) {
      throw new AwsCryptoException(ex);
    }
  }

  /**
   * Return the version set in the header.
   *
   * @return the byte value representing the version.
   */
  public byte getVersion() {
    return version_;
  }

  /**
   * Return the type set in the header.
   *
   * @return the CiphertextType enum value representing the type set in the header.
   */
  public CiphertextType getType() {
    return CiphertextType.deserialize(typeVal_);
  }

  /**
   * Return the crypto algorithm identifier set in the header.
   *
   * @return the CryptoAlgorithm enum value representing the identifier set in the header.
   */
  public CryptoAlgorithm getCryptoAlgoId() {
    return CryptoAlgorithm.deserialize(version_, cryptoAlgoVal_);
  }

  /**
   * Return the length of the encryption context set in the header.
   *
   * @return the length of the encryption context set in the header.
   */
  public int getEncryptionContextLen() {
    return encryptionContextLen_;
  }

  /**
   * Return the encryption context set in the header.
   *
   * @return the bytes containing encryption context set in the header.
   */
  public byte[] getEncryptionContext() {
    return encryptionContext_.clone();
  }

  public Map<String, String> getEncryptionContextMap() {
    return EncryptionContextSerializer.deserialize(encryptionContext_);
  }

  /**
   * Return the count of the encrypted key blobs set in the header.
   *
   * @return the count of the encrypted key blobs set in the header.
   */
  public int getEncryptedKeyBlobCount() {
    return cipherKeyCount_;
  }

  /**
   * Return the encrypted key blobs set in the header.
   *
   * @return the KeyBlob objects representing the key blobs set in the header.
   */
  public List<KeyBlob> getEncryptedKeyBlobs() {
    return new ArrayList<>(cipherKeyBlobs_);
  }

  /**
   * Return the content type set in the header.
   *
   * @return the ContentType enum value representing the content type set in the header.
   */
  public ContentType getContentType() {
    return ContentType.deserialize(contentTypeVal_);
  }

  /**
   * Return the message identifier set in the header.
   *
   * @return the bytes containing the message identifier set in the header.
   */
  public byte[] getMessageId() {
    return messageId_ != null ? messageId_.clone() : null;
  }

  /**
   * Return the length of the nonce set in the header.
   *
   * @return the length of the nonce set in the header.
   */
  public short getNonceLength() {
    return nonceLen_;
  }

  /**
   * Return the length of the frame set in the header.
   *
   * @return the length of the frame set in the header.
   */
  public int getFrameLength() {
    return frameLength_;
  }

  /**
   * Return the header nonce set in the header.
   *
   * @return the bytes containing the header nonce set in the header.
   */
  public byte[] getHeaderNonce() {
    return headerNonce_ != null ? headerNonce_.clone() : null;
  }

  /**
   * Return the header tag set in the header.
   *
   * @return the header tag set in the header.
   */
  public byte[] getHeaderTag() {
    return headerTag_ != null ? headerTag_.clone() : null;
  }

  /**
   * Set the header nonce to use for authenticating the header data.
   *
   * @param headerNonce the header nonce to use.
   */
  public void setHeaderNonce(final byte[] headerNonce) {
    headerNonce_ = headerNonce.clone();
  }

  /**
   * Set the header tag to use for authenticating the header data.
   *
   * @param headerTag the header tag to use.
   */
  public void setHeaderTag(final byte[] headerTag) {
    headerTag_ = headerTag.clone();
  }

  /**
   * Return suite specific data.
   *
   * @return suiteData
   */
  public byte[] getSuiteData() {
    return suiteData_ != null ? suiteData_.clone() : null;
  }

  /**
   * Sets suite specific data
   *
   * @param suiteData
   */
  public void setSuiteData(byte[] suiteData) {
    suiteData_ = suiteData.clone();
  }

  /**
   * Return max encrypted data keys. Package scope for unit testing.
   *
   * @return int
   */
  int getMaxEncryptedDataKeys() {
    return maxEncryptedDataKeys_;
  }

  private static class PartialParseException extends Exception {
    private static final long serialVersionUID = 1L;
    final int bytesParsed_;

    private PartialParseException(Throwable ex, int bytesParsed) {
      super(ex);
      bytesParsed_ = bytesParsed;
    }
  }

  /**
   * Represents a single step in parsing a header.
   *
   * <p>The following requirements apply:
   *
   * <ul>
   *   <li>It must be safe to call multiple times. This means that it knows if it has already parsed
   *       something and should be a NOP
   *   <li>It returns how many bytes have been consumed. This will be 0 in the case of a NOP.
   *   <li>If there are insufficient bytes and no bytes are consumed, it may throw either a {@link
   *       ParseException} or a {@link PartialParseException}.
   *   <li>If there are insufficient bytes and some bytes are parsed then it must throw a {@link
   *       PartialParseException} indicating the number of bytes parsed.
   * </ul>
   */
  @FunctionalInterface
  private interface ParsingStep {
    int parse(byte[] b, int off) throws ParseException, PartialParseException;
  }
}
