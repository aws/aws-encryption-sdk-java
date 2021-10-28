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

package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.ParseException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.PrimitivesParser;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * This class implements the format of the key blob. The format contains the following fields in
 * order:
 *
 * <ol>
 *   <li>length of key provider
 *   <li>key provider
 *   <li>length of key provider info
 *   <li>key provider info
 *   <li>length of encrypted key
 *   <li>encrypted key
 * </ol>
 */
// @ nullable_by_default
public final class KeyBlob implements EncryptedDataKey {
  private int keyProviderIdLen_ = -1; // @ in providerId;
  private byte[] keyProviderId_; // @ in providerId;
  private int keyProviderInfoLen_ = -1; // @ in providerInformation;
  private byte[] keyProviderInfo_; // @ in providerInformation;
  private int encryptedKeyLen_ = -1; // @ in encryptedDataKey;
  private byte[] encryptedKey_; // @ in encryptedDataKey;

  // @ private invariant keyProviderIdLen_ <= Constants.UNSIGNED_SHORT_MAX_VAL;
  // @ private invariant keyProviderInfoLen_ <= Constants.UNSIGNED_SHORT_MAX_VAL;
  // @ private invariant encryptedKeyLen_ <= Constants.UNSIGNED_SHORT_MAX_VAL;

  // @// KeyBlob implements EncryptedDataKey, which defines three model fields.
  // @// For a KeyBlob, these model fields correspond directly to some underlying
  // @// Java fields, as expressed by the following "represents" declarations:
  // @ private represents providerId = keyProviderId_;
  // @ private represents providerInformation = keyProviderInfo_;
  // @ private represents encryptedDataKey = encryptedKey_;

  // @// As mentioned in EncryptedDataKey, deserialization goes through some
  // @// incomplete intermediate states. The ghost field "deserializing" keeps
  // @// track of these states:
  // @ private ghost int deserializing;
  // @ private invariant 0 <= deserializing && deserializing < 4;
  // @// The abstract "isDeserializing", defined in EncryptedDataKey, is represented
  // @// as "true" whenever "deserializing" is non-0.
  // @ private represents isDeserializing = deserializing != 0;

  // @// The fields of KeyBlob come in pairs, for example, "keyProviderId_" and
  // @// "keyProviderIdLen_". Generally, the latter stores the length of the former.
  // @// But this is not always so. For one, if the former is "null", then the latter
  // @// is -1. Also, this relationship the two fields does not hold in one of the
  // @// incomplete intermediate deserialization states. Therefore, the invariants
  // @// about these fields are as follows:

  // @ private invariant deserializing == 1 || keyProviderIdLen_ == (keyProviderId_ == null ? -1 :
  // keyProviderId_.length);
  // @ private invariant deserializing == 2 || keyProviderInfoLen_ == (keyProviderInfo_ == null ? -1
  // : keyProviderInfo_.length);
  // @ private invariant deserializing == 3 || encryptedKeyLen_ == (encryptedKey_ == null ? -1 :
  // encryptedKey_.length);

  // @// In the incomplete intermediate states, other specific properties hold about the
  // @// fields, as expressed in the following invariants:

  // @ private invariant deserializing == 1 ==> 0 <= keyProviderIdLen_ && keyProviderId_ == null;
  // @ private invariant deserializing == 2 ==> 0 <= keyProviderIdLen_ && 0 <= keyProviderInfoLen_
  // && keyProviderInfo_ == null;
  // @ private invariant deserializing == 3 ==> 0 <= keyProviderIdLen_ && 0 <= keyProviderInfoLen_
  // && 0 <= encryptedKeyLen_ && encryptedKey_ == null;

  // @// It is by querying the "isComplete()" method that a caller finds out if the
  // @// deserialization is only partially done or is complete. The "isComplete()"
  // @// method is defined later on and returns the value of the field "isComplete_".
  // @// If postcondition of "deserialize()" and the following public invariant about
  // @// "isComplete_" tell a client that the 3 abstract properties of the class have
  // @// been initialized. Note that this invariant (and, indeed, the "isComplete()"
  // @// method) does not tell a client anything useful unless "deserialize()" has been
  // @// called. For example, if the 3 abstract properties of a KeyBlob have been
  // @// initialized using the "set..." methods, then the result value of "isComplete()"
  // @// is meaningless.
  // @ spec_public
  private boolean isComplete_ = false;
  // @ public invariant isComplete_ && !isDeserializing ==> providerId != null &&
  // providerInformation != null && encryptedDataKey != null;

  /** Default constructor. */
  // @ public normal_behavior
  // @   ensures providerId == null && providerInformation == null && encryptedDataKey == null;
  // @   ensures !isDeserializing;
  // @ pure
  public KeyBlob() {}

  /**
   * Construct a key blob using the provided key, key provider identifier, and key provider
   * information.
   *
   * @param keyProviderId the key provider identifier string.
   * @param keyProviderInfo the bytes containing the key provider info.
   * @param encryptedDataKey the encrypted bytes of the data key.
   */
  // @ public normal_behavior
  // @   requires keyProviderId != null && EncryptedDataKey.s2ba(keyProviderId).length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   requires keyProviderInfo != null && keyProviderInfo.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   requires encryptedDataKey != null && encryptedDataKey.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   ensures \fresh(providerId);
  // @   ensures Arrays.equalArrays(providerId, EncryptedDataKey.s2ba(keyProviderId));
  // @   ensures \fresh(providerInformation);
  // @   ensures Arrays.equalArrays(providerInformation, keyProviderInfo);
  // @   ensures \fresh(this.encryptedDataKey);
  // @   ensures Arrays.equalArrays(this.encryptedDataKey, encryptedDataKey);
  // @   ensures !isDeserializing;
  // @ also
  // @ public exceptional_behavior
  // @   requires keyProviderId != null && keyProviderInfo != null && encryptedDataKey != null;
  // @   requires Constants.UNSIGNED_SHORT_MAX_VAL < EncryptedDataKey.s2ba(keyProviderId).length ||
  // Constants.UNSIGNED_SHORT_MAX_VAL < keyProviderInfo.length || Constants.UNSIGNED_SHORT_MAX_VAL <
  // encryptedDataKey.length;
  // @   signals_only AwsCryptoException;
  // @ pure
  public KeyBlob(
      final String keyProviderId, final byte[] keyProviderInfo, final byte[] encryptedDataKey) {
    setEncryptedDataKey(encryptedDataKey);
    setKeyProviderId(keyProviderId);
    setKeyProviderInfo(keyProviderInfo);
  }

  // @ public normal_behavior
  // @   requires edk != null && !edk.isDeserializing;
  // @   requires edk.providerId != null && EncryptedDataKey.ba2s2ba(edk.providerId).length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   requires edk.providerInformation != null && edk.providerInformation.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   requires edk.encryptedDataKey != null && edk.encryptedDataKey.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   ensures \fresh(providerId);
  // @   ensures Arrays.equalArrays(providerId, EncryptedDataKey.ba2s2ba(edk.providerId));
  // @   ensures \fresh(providerInformation);
  // @   ensures Arrays.equalArrays(providerInformation, edk.providerInformation);
  // @   ensures \fresh(encryptedDataKey);
  // @   ensures Arrays.equalArrays(encryptedDataKey, edk.encryptedDataKey);
  // @   ensures !isDeserializing;
  // @ also
  // @ public exceptional_behavior
  // @   requires edk != null && !edk.isDeserializing;
  // @   requires edk.providerId != null && edk.providerInformation != null && edk.encryptedDataKey
  // != null;
  // @   requires Constants.UNSIGNED_SHORT_MAX_VAL < EncryptedDataKey.ba2s2ba(edk.providerId).length
  // || Constants.UNSIGNED_SHORT_MAX_VAL < edk.providerInformation.length ||
  // Constants.UNSIGNED_SHORT_MAX_VAL < edk.encryptedDataKey.length;
  // @   signals_only AwsCryptoException;
  // @ pure
  public KeyBlob(final EncryptedDataKey edk) {
    setEncryptedDataKey(edk.getEncryptedDataKey());
    String s = edk.getProviderId();
    // @ set EncryptedDataKey.lemma_s2ba_depends_only_string_contents_only(s,
    // EncryptedDataKey.ba2s(edk.providerId));
    setKeyProviderId(s);
    setKeyProviderInfo(edk.getProviderInformation());
  }

  /**
   * Parse the key provider identifier length in the provided bytes. It looks for 2 bytes
   * representing a short primitive type in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the size of the short
   * primitive type. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the size of the short primitive.
   * @throws ParseException if there are not sufficient bytes to parse the identifier length.
   */
  // @ private normal_behavior
  // @   requires deserializing == 0 && keyProviderId_ == null;
  // @   requires b != null && 0 <= off && off <= b.length - Short.BYTES;
  // @   assignable keyProviderIdLen_, deserializing, isDeserializing;
  // @   ensures \result == Short.BYTES && deserializing == 1;
  // @ also
  // @ private exceptional_behavior
  // @   requires keyProviderId_ == null;
  // @   requires b != null && 0 <= off && b.length - Short.BYTES < off;
  // @   assignable \nothing;
  // @   signals_only ParseException;
  private int parseKeyProviderIdLen(final byte[] b, final int off) throws ParseException {
    keyProviderIdLen_ = PrimitivesParser.parseUnsignedShort(b, off);
    // @ set deserializing = 1;
    return Short.SIZE / Byte.SIZE;
  }

  /**
   * Parse the key provider identifier in the provided bytes. It looks for bytes of size defined by
   * the key provider identifier length in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the key provider identifier
   * length. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the key provider identifier length.
   * @throws ParseException if there are not sufficient bytes to parse the identifier.
   */
  // @ private normal_behavior
  // @   requires deserializing == 1 && b != null && 0 <= off && off <= b.length;
  // @   requires keyProviderIdLen_ <= b.length - off;
  // @   assignable keyProviderId_, deserializing, isDeserializing;
  // @   ensures \result == keyProviderIdLen_ && deserializing == 0;
  // @   ensures keyProviderId_ != null && keyProviderId_.length == keyProviderIdLen_;
  // @ also
  // @ private exceptional_behavior
  // @   requires deserializing == 1 && b != null && 0 <= off && off <= b.length;
  // @   requires b.length - off < keyProviderIdLen_;
  // @   assignable \nothing;
  // @   signals_only ParseException;
  private int parseKeyProviderId(final byte[] b, final int off) throws ParseException {
    final int bytesToParseLen = b.length - off;
    if (bytesToParseLen >= keyProviderIdLen_) {
      keyProviderId_ = Arrays.copyOfRange(b, off, off + keyProviderIdLen_);
      // @ set deserializing = 0;
      return keyProviderIdLen_;
    } else {
      throw new ParseException("Not enough bytes to parse key provider id");
    }
  }

  /**
   * Parse the key provider info length in the provided bytes. It looks for 2 bytes representing a
   * short primitive type in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the size of the short
   * primitive type. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the size of the short primitive type.
   * @throws ParseException if there are not sufficient bytes to parse the provider info length.
   */
  // @ private normal_behavior
  // @   requires deserializing == 0 && 0 <= keyProviderIdLen_ && keyProviderInfo_ == null;
  // @   requires b != null && 0 <= off && off <= b.length - Short.BYTES;
  // @   assignable keyProviderInfoLen_, deserializing, isDeserializing;
  // @   ensures \result == Short.BYTES && deserializing == 2;
  // @ also
  // @ private exceptional_behavior
  // @   requires deserializing == 0 && 0 <= keyProviderIdLen_ && keyProviderInfo_ == null;
  // @   requires b != null && 0 <= off && b.length - Short.BYTES < off;
  // @   assignable \nothing;
  // @   signals_only ParseException;
  private int parseKeyProviderInfoLen(final byte[] b, final int off) throws ParseException {
    keyProviderInfoLen_ = PrimitivesParser.parseUnsignedShort(b, off);
    // @ set deserializing = 2;
    return Short.SIZE / Byte.SIZE;
  }

  /**
   * Parse the key provider info in the provided bytes. It looks for bytes of size defined by the
   * key provider info length in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the key provider info
   * length. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the key provider info length.
   * @throws ParseException if there are not sufficient bytes to parse the provider info.
   */
  // @ private normal_behavior
  // @   requires deserializing == 2 && b != null && 0 <= off && off <= b.length;
  // @   requires keyProviderInfoLen_ <= b.length - off;
  // @   assignable keyProviderInfo_, deserializing, isDeserializing;
  // @   ensures \result == keyProviderInfoLen_ && deserializing == 0;
  // @   ensures keyProviderInfo_ != null && keyProviderInfo_.length == keyProviderInfoLen_;
  // @ also
  // @ private exceptional_behavior
  // @   requires deserializing == 2 && b != null && 0 <= off && off <= b.length;
  // @   requires b.length - off < keyProviderInfoLen_;
  // @   assignable \nothing;
  // @   signals_only ParseException;
  private int parseKeyProviderInfo(final byte[] b, final int off) throws ParseException {
    final int bytesToParseLen = b.length - off;
    if (bytesToParseLen >= keyProviderInfoLen_) {
      keyProviderInfo_ = Arrays.copyOfRange(b, off, off + keyProviderInfoLen_);
      // @ set deserializing = 0;
      return keyProviderInfoLen_;
    } else {
      throw new ParseException("Not enough bytes to parse key provider info");
    }
  }

  /**
   * Parse the key length in the provided bytes. It looks for 2 bytes representing a short primitive
   * type in the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the size of the short
   * primitive type. On failure, it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the size of the short primitive type.
   * @throws ParseException if there are not sufficient bytes to parse the key length.
   */
  // @ private normal_behavior
  // @   requires deserializing == 0 && 0 <= keyProviderIdLen_ && 0 <= keyProviderInfoLen_ &&
  // encryptedKey_ == null;
  // @   requires b != null && 0 <= off && off <= b.length - Short.BYTES;
  // @   assignable encryptedKeyLen_, deserializing, isDeserializing;
  // @   ensures \result == Short.BYTES && deserializing == 3;
  // @ also
  // @ private exceptional_behavior
  // @   requires deserializing == 0 && 0 <= keyProviderIdLen_ && 0 <= keyProviderInfoLen_ &&
  // encryptedKey_ == null;
  // @   requires b != null && 0 <= off && b.length - Short.BYTES < off;
  // @   assignable \nothing;
  // @   signals_only ParseException;
  private int parseKeyLen(final byte[] b, final int off) throws ParseException {
    encryptedKeyLen_ = PrimitivesParser.parseUnsignedShort(b, off);
    // @ set deserializing = 3;
    return Short.SIZE / Byte.SIZE;
  }

  /**
   * Parse the key in the provided bytes. It looks for bytes of size defined by the key length in
   * the provided bytes starting at the specified off.
   *
   * <p>If successful, it returns the size of the parsed bytes which is the key length. On failure,
   * it throws a parse exception.
   *
   * @param b the byte array to parse.
   * @param off the offset in the byte array to use when parsing.
   * @return the size of the parsed bytes which is the key length.
   * @throws ParseException if there are not sufficient bytes to parse the key.
   */
  // @ private normal_behavior
  // @   requires deserializing == 3 && b != null && 0 <= off && off <= b.length;
  // @   requires encryptedKeyLen_ <= b.length - off;
  // @   assignable encryptedKey_, deserializing, isDeserializing;
  // @   ensures \result == encryptedKeyLen_ && deserializing == 0;
  // @   ensures encryptedKey_ != null && encryptedKey_.length == encryptedKeyLen_;
  // @ also
  // @ private exceptional_behavior
  // @   requires deserializing == 3 && b != null && 0 <= off && off <= b.length;
  // @   requires b.length - off < encryptedKeyLen_;
  // @   assignable \nothing;
  // @   signals_only ParseException;
  private int parseKey(final byte[] b, final int off) throws ParseException {
    final int bytesToParseLen = b.length - off;
    if (bytesToParseLen >= encryptedKeyLen_) {
      encryptedKey_ = Arrays.copyOfRange(b, off, off + encryptedKeyLen_);
      // @ set deserializing = 0;
      return encryptedKeyLen_;
    } else {
      throw new ParseException("Not enough bytes to parse key");
    }
  }

  /**
   * Deserialize the provided bytes starting at the specified offset to construct an instance of
   * this class.
   *
   * <p>This method parses the provided bytes for the individual fields in this class. This methods
   * also supports partial parsing where not all the bytes required for parsing the fields
   * successfully are available.
   *
   * @param b the byte array to deserialize.
   * @param off the offset in the byte array to use for deserialization.
   * @return the number of bytes consumed in deserialization.
   */
  // @ public normal_behavior
  // @   requires b == null;
  // @   assignable \nothing;
  // @   ensures \result == 0;
  // @ also
  // @ public normal_behavior
  // @   requires !isComplete_;
  // @   requires b != null && 0 <= off && off <= b.length;
  // @   assignable this.*;
  // @   ensures 0 <= \result && \result <= b.length - off;
  // @   ensures isComplete_ ==> !isDeserializing;
  public int deserialize(final byte[] b, final int off) {
    if (b == null) {
      return 0;
    }

    int parsedBytes = 0;
    try {
      if (keyProviderIdLen_ < 0) {
        parsedBytes += parseKeyProviderIdLen(b, off + parsedBytes);
      }

      if (keyProviderId_ == null) {
        parsedBytes += parseKeyProviderId(b, off + parsedBytes);
      }

      if (keyProviderInfoLen_ < 0) {
        parsedBytes += parseKeyProviderInfoLen(b, off + parsedBytes);
      }

      if (keyProviderInfo_ == null) {
        parsedBytes += parseKeyProviderInfo(b, off + parsedBytes);
      }

      if (encryptedKeyLen_ < 0) {
        parsedBytes += parseKeyLen(b, off + parsedBytes);
      }

      if (encryptedKey_ == null) {
        parsedBytes += parseKey(b, off + parsedBytes);
      }

      isComplete_ = true;
    } catch (ParseException e) {
      // this results when we do partial parsing and there aren't enough
      // bytes to parse; ignore it and return the bytes parsed thus far.
    }
    return parsedBytes;
  }

  /**
   * Serialize an instance of this class to a byte array.
   *
   * @return the serialized bytes of the instance.
   */
  // @ public normal_behavior
  // @   requires !isDeserializing;
  // @   requires providerId != null;
  // @   requires providerInformation != null;
  // @   requires encryptedDataKey != null;
  // @   assignable \nothing;
  // @   ensures \fresh(\result);
  // @   ensures \result.length == 3 * Short.BYTES + providerId.length + providerInformation.length
  // + encryptedDataKey.length;
  // @ code_java_math // necessary, or else casts to short are warnings
  public byte[] toByteArray() {
    final int outLen =
        3 * (Short.SIZE / Byte.SIZE) + keyProviderIdLen_ + keyProviderInfoLen_ + encryptedKeyLen_;
    final ByteBuffer out = ByteBuffer.allocate(outLen);

    out.putShort((short) keyProviderIdLen_);
    out.put(keyProviderId_, 0, keyProviderIdLen_);

    out.putShort((short) keyProviderInfoLen_);
    out.put(keyProviderInfo_, 0, keyProviderInfoLen_);

    out.putShort((short) encryptedKeyLen_);
    out.put(encryptedKey_, 0, encryptedKeyLen_);

    return out.array();
  }

  /**
   * Check if this object has all the header fields populated and available for reading.
   *
   * @return true if this object containing the single block header fields is complete; false
   *     otherwise.
   */
  // @ public normal_behavior
  // @   ensures \result == isComplete_;
  // @ pure
  public boolean isComplete() {
    return isComplete_;
  }

  /**
   * Return the length of the key provider identifier set in the header.
   *
   * @return the length of the key provider identifier.
   */
  // @ public normal_behavior
  // @   requires !isDeserializing;
  // @   ensures providerId == null ==> \result < 0;
  // @   ensures providerId != null ==> \result == providerId.length;
  // @ pure
  public int getKeyProviderIdLen() {
    return keyProviderIdLen_;
  }

  /**
   * Return the key provider identifier set in the header.
   *
   * @return the string containing the key provider identifier.
   */
  @Override
  public String getProviderId() {
    String s = new String(keyProviderId_, StandardCharsets.UTF_8);
    // The following assume statement essentially says that different
    // calls to the String constructor above, with the same parameters,
    // result in strings with the same contents. The assumption is
    // needed, because JML does not give a way to prove it.
    // @ assume String.equals(s, EncryptedDataKey.ba2s(keyProviderId_));
    return s;
  }

  /**
   * Return the length of the key provider info set in the header.
   *
   * @return the length of the key provider info.
   */
  // @ public normal_behavior
  // @   requires !isDeserializing;
  // @   ensures providerInformation == null ==> \result < 0;
  // @   ensures providerInformation != null ==> \result == providerInformation.length;
  // @ pure
  public int getKeyProviderInfoLen() {
    return keyProviderInfoLen_;
  }

  /**
   * Return the information on the key provider set in the header.
   *
   * @return the bytes containing information on the key provider.
   */
  @Override
  public byte[] getProviderInformation() {
    return keyProviderInfo_.clone();
  }

  /**
   * Return the length of the encrypted data key set in the header.
   *
   * @return the length of the encrypted data key.
   */
  // @ public normal_behavior
  // @   requires !isDeserializing;
  // @   ensures encryptedDataKey == null ==> \result < 0;
  // @   ensures encryptedDataKey != null ==> \result == encryptedDataKey.length;
  // @ pure
  public int getEncryptedDataKeyLen() {
    return encryptedKeyLen_;
  }

  /**
   * Return the encrypted data key set in the header.
   *
   * @return the bytes containing the encrypted data key.
   */
  @Override
  public byte[] getEncryptedDataKey() {
    return encryptedKey_.clone();
  }

  /**
   * Set the key provider identifier.
   *
   * @param keyProviderId the key provider identifier.
   */
  // @ public normal_behavior
  // @   requires !isDeserializing;
  // @   requires keyProviderId != null && EncryptedDataKey.s2ba(keyProviderId).length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable providerId;
  // @   ensures \fresh(providerId);
  // @   ensures Arrays.equalArrays(providerId, EncryptedDataKey.s2ba(keyProviderId));
  // @ also
  // @ private normal_behavior  // TODO: this behavior is a temporary workaround
  // @   requires !isDeserializing;
  // @   requires keyProviderId != null && EncryptedDataKey.s2ba(keyProviderId).length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable keyProviderId_, keyProviderIdLen_;
  // @ also
  // @ public exceptional_behavior
  // @   requires !isDeserializing;
  // @   requires keyProviderId != null && Constants.UNSIGNED_SHORT_MAX_VAL <
  // EncryptedDataKey.s2ba(keyProviderId).length;
  // @   assignable \nothing;
  // @   signals_only AwsCryptoException;
  public void setKeyProviderId(final String keyProviderId) {
    final byte[] keyProviderIdBytes = keyProviderId.getBytes(StandardCharsets.UTF_8);
    // @ assume Arrays.equalArrays(keyProviderIdBytes, EncryptedDataKey.s2ba(keyProviderId));
    if (keyProviderIdBytes.length > Constants.UNSIGNED_SHORT_MAX_VAL) {
      throw new AwsCryptoException(
          "Key provider identifier length exceeds the max value of an unsigned short primitive.");
    }
    keyProviderId_ = keyProviderIdBytes;
    keyProviderIdLen_ = keyProviderId_.length;
  }

  /**
   * Set the information on the key provider identifier.
   *
   * @param keyProviderInfo the bytes containing information on the key provider identifier.
   */
  // @ public normal_behavior
  // @   requires !isDeserializing;
  // @   requires keyProviderInfo != null && keyProviderInfo.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable providerInformation;
  // @   ensures \fresh(providerInformation);
  // @   ensures Arrays.equalArrays(providerInformation, keyProviderInfo);
  // @ also
  // @ private normal_behavior  // TODO: this behavior is a temporary workaround
  // @   requires !isDeserializing;
  // @   requires keyProviderInfo != null && keyProviderInfo.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable keyProviderInfo_, keyProviderInfoLen_;
  // @ also private exceptional_behavior
  // @   requires !isDeserializing;
  // @   requires keyProviderInfo != null;
  // @   requires keyProviderInfo.length > Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable \nothing;
  // @   signals_only AwsCryptoException;
  public void setKeyProviderInfo(final byte[] keyProviderInfo) {
    if (keyProviderInfo.length > Constants.UNSIGNED_SHORT_MAX_VAL) {
      throw new AwsCryptoException(
          "Key provider identifier information length exceeds the max value of an unsigned short primitive.");
    }
    keyProviderInfo_ = keyProviderInfo.clone();
    keyProviderInfoLen_ = keyProviderInfo.length;
  }

  /**
   * Set the encrypted data key.
   *
   * @param encryptedDataKey the bytes containing the encrypted data key.
   */
  // @ public normal_behavior
  // @   requires !isDeserializing;
  // @   requires encryptedDataKey != null && encryptedDataKey.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable this.encryptedDataKey;
  // @   ensures \fresh(this.encryptedDataKey);
  // @   ensures Arrays.equalArrays(this.encryptedDataKey, encryptedDataKey);
  // @ also
  // @ private normal_behavior  // TODO: this behavior is a temporary workaround
  // @   requires !isDeserializing;
  // @   requires encryptedDataKey != null && encryptedDataKey.length <=
  // Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable encryptedKey_, encryptedKeyLen_;
  // @ also
  // @ public exceptional_behavior
  // @   requires !isDeserializing;
  // @   requires encryptedDataKey != null;
  // @   requires encryptedDataKey.length > Constants.UNSIGNED_SHORT_MAX_VAL;
  // @   assignable \nothing;
  // @   signals_only AwsCryptoException;
  public void setEncryptedDataKey(final byte[] encryptedDataKey) {
    if (encryptedDataKey.length > Constants.UNSIGNED_SHORT_MAX_VAL) {
      throw new AwsCryptoException(
          "Key length exceeds the max value of an unsigned short primitive.");
    }
    encryptedKey_ = encryptedDataKey.clone();
    encryptedKeyLen_ = encryptedKey_.length;
  }
}
