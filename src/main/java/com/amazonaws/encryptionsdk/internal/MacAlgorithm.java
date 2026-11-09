// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.internal;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.crypto.Mac;

/** HMAC algorithms used for key derivation. */
public enum MacAlgorithm {
  HmacSHA1("HmacSHA1"),
  HmacSHA256("HmacSHA256"),
  HmacSHA384("HmacSHA384"),
  HmacSHA512("HmacSHA512");

  private final String algorithm;
  // Looked up once, because Mac.getInstance without a provider is slow.
  // Providers registered after the first lookup are not picked up.
  private volatile Provider provider;

  MacAlgorithm(final String algorithm) {
    this.algorithm = algorithm;
  }

  String getAlgorithm() {
    return algorithm;
  }

  Provider getProvider() throws NoSuchAlgorithmException {
    Provider result = provider;
    if (result == null) {
      result = Mac.getInstance(algorithm).getProvider();
      provider = result;
    }
    return result;
  }
}
