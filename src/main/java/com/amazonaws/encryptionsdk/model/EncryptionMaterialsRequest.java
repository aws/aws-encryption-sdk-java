// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Contains the contextual information needed to prepare an encryption operation.
 *
 * @see
 *     com.amazonaws.encryptionsdk.CryptoMaterialsManager#getMaterialsForEncrypt(EncryptionMaterialsRequest)
 */
public final class EncryptionMaterialsRequest {
  private final Map<String, String> context;
  private final CryptoAlgorithm requestedAlgorithm;
  private final long plaintextSize;
  private final byte[] plaintext;
  private final CommitmentPolicy commitmentPolicy;

  private EncryptionMaterialsRequest(Builder builder) {
    this.context = builder.context;
    this.requestedAlgorithm = builder.requestedAlgorithm;
    this.plaintextSize = builder.plaintextSize;
    this.plaintext = builder.plaintext;

    // Requests MAY include a commitmentPolicy.
    // This will become a required field in 2.0
    this.commitmentPolicy = builder.commitmentPolicy;
  }

  /** @return the encryption context (possibly an empty map) */
  public Map<String, String> getContext() {
    return context;
  }

  /**
   * @return If a specific encryption algorithm was requested by calling {@link
   *     com.amazonaws.encryptionsdk.AwsCrypto#setEncryptionAlgorithm(CryptoAlgorithm)}, the
   *     algorithm requested. Otherwise, returns null.
   */
  public CryptoAlgorithm getRequestedAlgorithm() {
    return requestedAlgorithm;
  }

  /** @return The size of the plaintext if known, or -1 otherwise */
  public long getPlaintextSize() {
    return plaintextSize;
  }

  /**
   * @return The entire input plaintext, if available (and not streaming). Note that for performance
   *     reason this is <i>not</i> a copy of the plaintext; you should never modify this buffer,
   *     lest the actual data being encrypted be modified. If the input plaintext is unavailable,
   *     this will be null.
   */
  @SuppressFBWarnings("EI_EXPOSE_REP")
  public byte[] getPlaintext() {
    return plaintext;
  }

  public CommitmentPolicy getCommitmentPolicy() {
    return commitmentPolicy;
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    EncryptionMaterialsRequest request = (EncryptionMaterialsRequest) o;
    return plaintextSize == request.plaintextSize
        && Objects.equals(context, request.context)
        && requestedAlgorithm == request.requestedAlgorithm
        && Arrays.equals(plaintext, request.plaintext);
  }

  @Override
  public int hashCode() {
    return Objects.hash(context, requestedAlgorithm, plaintextSize, plaintext);
  }

  public static class Builder {
    private Map<String, String> context = Collections.emptyMap();
    private CryptoAlgorithm requestedAlgorithm = null;
    private long plaintextSize = -1;
    private byte[] plaintext = null;
    private CommitmentPolicy commitmentPolicy = null;

    private Builder() {}

    private Builder(EncryptionMaterialsRequest request) {
      this.context = request.getContext();
      this.requestedAlgorithm = request.getRequestedAlgorithm();
      this.plaintextSize = request.getPlaintextSize();
      this.plaintext = request.getPlaintext();
      this.commitmentPolicy = request.getCommitmentPolicy();
    }

    public EncryptionMaterialsRequest build() {
      return new EncryptionMaterialsRequest(this);
    }

    public Map<String, String> getContext() {
      return context;
    }

    public Builder setContext(Map<String, String> context) {
      this.context = Collections.unmodifiableMap(new HashMap<>(context));
      return this;
    }

    public CryptoAlgorithm getRequestedAlgorithm() {
      return requestedAlgorithm;
    }

    public Builder setRequestedAlgorithm(CryptoAlgorithm requestedAlgorithm) {
      this.requestedAlgorithm = requestedAlgorithm;
      return this;
    }

    public long getPlaintextSize() {
      return plaintextSize;
    }

    public Builder setPlaintextSize(long plaintextSize) {
      if (plaintextSize < -1) {
        throw new IllegalArgumentException("Bad plaintext size");
      }

      this.plaintextSize = plaintextSize;
      return this;
    }

    /**
     * Please note that this does not make a defensive copy of the plaintext and so any
     * modifications made to the backing array will be reflected in this Builder.
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public byte[] getPlaintext() {
      return plaintext;
    }

    /**
     * Sets the plaintext field of the request.
     *
     * <p>Please note that this does not make a defensive copy of the plaintext and so any
     * modifications made to the backing array will be reflected in this Builder.
     *
     * <p>This method implicitly sets plaintext size as well.
     */
    @SuppressFBWarnings("EI_EXPOSE_REP")
    public Builder setPlaintext(byte[] plaintext) {
      this.plaintext = plaintext;

      if (plaintext != null) {
        return setPlaintextSize(plaintext.length);
      } else {
        return setPlaintextSize(-1);
      }
    }

    public CommitmentPolicy getCommitmentPolicy() {
      return commitmentPolicy;
    }

    public Builder setCommitmentPolicy(CommitmentPolicy commitmentPolicy) {
      this.commitmentPolicy = commitmentPolicy;
      return this;
    }
  }
}
