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

import com.amazonaws.encryptionsdk.internal.Utils;

public class ByteFormatCheckValues {
  private static final String base64MessageId_ = "NQ/NXvg4mMN5zm5JFZHUWw==";
  private static final String base64PlaintextKey_ = "N9vW5Ox5xh4BrUgeaL2gXg==";
  private static final String base64EncryptedKey_ = "Zg5VUzPfgD0/H92Fx7h0ew==";

  private static final String base64Nonce_ = "3rktZhNbwrZBSaqt";
  private static final String base64Tag_ = "cBPLjSEz0fsWDToxTqMvfQ==";

  private static final String base64CiphertextHeaderHash_ =
      "bCScP4wa25l9TLQZ4KLv7xqVCg9AN58lB1FHrl2yVes=";
  private static final String base64BlockHeaderHash_ =
      "7q8fULz95XaJqrksEuzDoVpSYih54QbPC1+v833s/5Y=";
  private static final String base64FrameHeaderHash_ =
      "tB/UmW+/hLJU5i2D9Or8guXrn8lP0uCiUaP1KkdyKGs=";
  private static final String base64FinalFrameHeaderHash_ =
      "/b2fVFOxvnaM5vXDMGyyFPNTWMjuU/c/48qeH3uTHj0=";

  public static byte[] getMessageId() {
    return Utils.decodeBase64String(base64MessageId_);
  }

  public static byte[] getEncryptedKey() {
    return Utils.decodeBase64String(base64EncryptedKey_);
  }

  public static byte[] getPlaintextKey() {
    return Utils.decodeBase64String(base64PlaintextKey_);
  }

  public static byte[] getCiphertextHeaderHash() {
    return Utils.decodeBase64String(base64CiphertextHeaderHash_);
  }

  public static byte[] getCipherBlockHeaderHash() {
    return Utils.decodeBase64String(base64BlockHeaderHash_);
  }

  public static byte[] getCipherFrameHeaderHash() {
    return Utils.decodeBase64String(base64FrameHeaderHash_);
  }

  public static byte[] getCipherFinalFrameHeaderHash() {
    return Utils.decodeBase64String(base64FinalFrameHeaderHash_);
  }

  public static byte[] getNonce() {
    return Utils.decodeBase64String(base64Nonce_);
  }

  public static byte[] getTag() {
    return Utils.decodeBase64String(base64Tag_);
  }
}
