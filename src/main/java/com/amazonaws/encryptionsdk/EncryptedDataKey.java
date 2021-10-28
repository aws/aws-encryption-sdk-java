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

package com.amazonaws.encryptionsdk;

// @ model import java.util.Arrays;
// @ model import java.nio.charset.StandardCharsets;

// @ nullable_by_default
public interface EncryptedDataKey {

  // @// An EncryptedDataKey object abstractly contains 3 pieces of data.
  // @// These are represented by 3 byte arrays:

  // @ model public instance byte[] providerId;
  // @ model public instance byte[] providerInformation;
  // @ model public instance byte[] encryptedDataKey;

  // @// The fields of an EncryptedDataKey may be populated via deserialization. The
  // @// Encryption SDK design allows the deserialization routine to be called repeatedly,
  // @// each call trying to fill in information that for some reason was not possible
  // @// with the previous call. In some such "intermediate" states, the deserialization
  // @// is incomplete in a way that other methods don't expect. Therefore, those methods
  // @// should not be called in these incomplete intermediate states. The model field
  // @// isDeserializing is true in those incomplete intermediate states, and it is used
  // @// in method specifications.
  // @ public model instance boolean isDeserializing;

  // @// There are some complications surrounding the representations of strings versus
  // @// byte arrays. The serialized form in message headers is always a sequence of
  // @// bytes, but the EncryptedDataKey interface (and some other methods)
  // @// expose the provider ID as if it were a string. Conversions (using UTF-8)
  // @// between byte arrays and strings (which in Java use UTF-16) are not bijections.
  // @// For example, both "\u003f".getBytes() and "\ud800".getBytes() yield a 1-byte
  // @// array containing [0x3f], and calling `new String(..., StandardCharsets.UTF_8)`
  // @// with either the 1-byte array [0x80] or the 3-byte array [0xef,0xbf,0xbd] yields
  // @// the string "\ufffd". Therefore, all we can say about these conversions
  // @// is that a given byte[]-String pair satisfies a conversion relation.
  // @//
  // @// The model functions "ba2s" and "s2ba" are used to specify the conversions
  // @// between byte arrays and strings:
  /*@ public normal_behavior
  @   requires s != null;
  @   ensures \result != null;
  @ function
  @ public model static byte[] s2ba(String s) {
  @   return s.getBytes(StandardCharsets.UTF_8);
  @ }
  @*/
  /*@ public normal_behavior
  @   requires ba != null;
  @   ensures \result != null;
  @ function
  @ public model static String ba2s(byte[] ba) {
  @   return new String(ba, StandardCharsets.UTF_8);
  @ }
  @*/
  // @// The "ba2s" and "s2ba" are given function bodies above, but the verification
  // @// does not rely on these function bodies directly. Instead, the code (in KeyBlob)
  // @// uses "assume" statements when it necessary to connect these functions with
  // @// copies of their bodies that appear in the code. This is a limitation of JML.
  // @//
  // @// One of the properties that holds of "s2ba(s)" is that its result depends not
  // @// on the particular String reference "s" being passed in, but only the contents
  // @// of the string referenced by "s". This property is captured in the following
  // @// lemma:
  /*@ public normal_behavior
  @   requires s != null && t != null && String.equals(s, t);
  @   ensures Arrays.equalArrays(s2ba(s), s2ba(t));
  @ pure
  @ public model static void lemma_s2ba_depends_only_string_contents_only(String s, String t);
  @*/
  // @//
  // @// As a specification convenience, the model function "ba2s2ba" uses the two
  // @// model functions above to convert from a byte array to a String and then back
  // @// to a byte array. As mentioned above, this does not always result in a byte
  // @// array with the original contents. The "assume" statements about the conversion
  // @// functions need to be careful not to assume too much.
  /*@ public normal_behavior
  @   requires ba != null;
  @   ensures \result == s2ba(ba2s(ba));
  @ function
  @ public model static byte[] ba2s2ba(byte[] ba) {
  @   return s2ba(ba2s(ba));
  @ }
  @*/

  // @// Here follows 3 methods that access the abstract values of interface properties.
  // @// Something to note about these methods is that each one requires the property
  // @// requested to be known to be non-null. For example, "getProviderId" is only allowed
  // @// to be called when "providerId" is known to be non-null.

  // @ public normal_behavior
  // @   requires providerId != null;
  // @   ensures \result != null;
  // @   ensures String.equals(\result, ba2s(providerId));
  // @ pure
  public String getProviderId();

  // @ public normal_behavior
  // @   requires providerInformation != null;
  // @   ensures \fresh(\result);
  // @   ensures Arrays.equalArrays(providerInformation, \result);
  // @ pure
  public byte[] getProviderInformation();

  // @ public normal_behavior
  // @   requires encryptedDataKey != null;
  // @   ensures \fresh(\result);
  // @   ensures Arrays.equalArrays(encryptedDataKey, \result);
  // @ pure
  public byte[] getEncryptedDataKey();
}
