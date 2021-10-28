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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains information which {@link MasterKeyProvider}s can use to select which {@link MasterKey}s
 * to use to protect a given plaintext. This class is immutable.
 */
public final class MasterKeyRequest {
  private final Map<String, String> encryptionContext_;
  private final boolean isStreaming_;
  private final byte[] plaintext_;
  private final long size_;

  private MasterKeyRequest(
      final Map<String, String> encryptionContext,
      final boolean isStreaming,
      final byte[] plaintext,
      final long size) {
    encryptionContext_ = encryptionContext;
    isStreaming_ = isStreaming;
    plaintext_ = plaintext;
    size_ = size;
  }

  public Map<String, String> getEncryptionContext() {
    return encryptionContext_;
  }

  public boolean isStreaming() {
    return isStreaming_;
  }

  /** The plaintext, if available, to be protected by this request. Otherwise, {@code null}. */
  public byte[] getPlaintext() {
    return plaintext_ != null ? plaintext_.clone() : null;
  }

  /** The size of the plaintext, if available. Otherwise {@code -1}. */
  public long getSize() {
    return size_;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static final class Builder {
    private Map<String, String> encryptionContext_ = new HashMap<>();
    private boolean isStreaming_ = false;
    private byte[] plaintext_ = null;
    private long size_ = -1;

    public Map<String, String> getEncryptionContext() {
      return encryptionContext_;
    }

    public Builder setEncryptionContext(final Map<String, String> encryptionContext) {
      encryptionContext_ = encryptionContext;
      return this;
    }

    public boolean isStreaming() {
      return isStreaming_;
    }

    public Builder setStreaming(final boolean isStreaming) {
      isStreaming_ = isStreaming;
      return this;
    }

    /**
     * Please note that this does not make a defensive copy of the plaintext and so any
     * modifications made to the backing array will be reflected in this Builder.
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getPlaintext() {
      return plaintext_;
    }

    /**
     * Please note that this does not make a defensive copy of the plaintext and so any
     * modifications made to the backing array will be reflected in this Builder.
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public Builder setPlaintext(final byte[] plaintext) {
      if (size_ != -1) {
        throw new IllegalStateException(
            "The plaintext may only be set if the size has not been explicitly set");
      }
      plaintext_ = plaintext;
      return this;
    }

    public Builder setSize(final long size) {
      if (plaintext_ != null) {
        throw new IllegalStateException(
            "Size may only explicitly set when the plaintext is not set");
      }
      size_ = size;
      return this;
    }

    public long getSize() {
      return size_;
    }

    public MasterKeyRequest build() {
      return new MasterKeyRequest(
          Collections.unmodifiableMap(new HashMap<>(encryptionContext_)),
          isStreaming_,
          plaintext_,
          plaintext_ != null ? plaintext_.length : size_);
    }
  }
}
