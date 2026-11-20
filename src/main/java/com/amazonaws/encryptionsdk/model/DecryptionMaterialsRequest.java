package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DecryptionMaterialsRequest {
  private final CryptoAlgorithm algorithm;
  private final Map<String, String> encryptionContext;
  private final Map<String, String> reproducedEncryptionContext;
  private final List<KeyBlob> encryptedDataKeys;

  private DecryptionMaterialsRequest(Builder b) {
    this.algorithm = b.getAlgorithm();
    this.encryptionContext = b.getEncryptionContext();
    this.reproducedEncryptionContext = b.getReproducedEncryptionContext();
    this.encryptedDataKeys = b.getEncryptedDataKeys();
  }

  public CryptoAlgorithm getAlgorithm() {
    return algorithm;
  }

  public Map<String, String> getEncryptionContext() {
    return encryptionContext;
  }

  public Map<String, String> getReproducedEncryptionContext() {
    return reproducedEncryptionContext;
  }

  public List<KeyBlob> getEncryptedDataKeys() {
    return encryptedDataKeys;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static DecryptionMaterialsRequest fromCiphertextHeaders(CiphertextHeaders headers) {
    return newBuilder()
        .setAlgorithm(headers.getCryptoAlgoId())
        .setEncryptionContext(headers.getEncryptionContextMap())
        .setEncryptedDataKeys(headers.getEncryptedKeyBlobs())
        .build();
  }

  public static final class Builder {
    private CryptoAlgorithm algorithm;
    private Map<String, String> encryptionContext;
    private Map<String, String> reproducedEncryptionContext;
    private List<KeyBlob> encryptedDataKeys;

    private Builder(DecryptionMaterialsRequest request) {
      this.algorithm = request.getAlgorithm();
      this.encryptionContext = request.getEncryptionContext();
      this.reproducedEncryptionContext = request.getReproducedEncryptionContext();
      this.encryptedDataKeys = request.getEncryptedDataKeys();
    }

    private Builder() {}

    public DecryptionMaterialsRequest build() {
      return new DecryptionMaterialsRequest(this);
    }

    public CryptoAlgorithm getAlgorithm() {
      return algorithm;
    }

    public Builder setAlgorithm(CryptoAlgorithm algorithm) {
      this.algorithm = algorithm;
      return this;
    }

    public Map<String, String> getEncryptionContext() {
      return encryptionContext;
    }

    public Builder setEncryptionContext(Map<String, String> encryptionContext) {
      this.encryptionContext = Collections.unmodifiableMap(new HashMap<>(encryptionContext));
      return this;
    }

    public Map<String, String> getReproducedEncryptionContext() {
      return reproducedEncryptionContext;
    }

    public Builder setReproducedEncryptionContext(Map<String, String> reproducedEncryptionContext) {
      this.reproducedEncryptionContext =
          Collections.unmodifiableMap(new HashMap<>(reproducedEncryptionContext));
      return this;
    }

    public List<KeyBlob> getEncryptedDataKeys() {
      return encryptedDataKeys;
    }

    public Builder setEncryptedDataKeys(List<KeyBlob> encryptedDataKeys) {
      this.encryptedDataKeys = Collections.unmodifiableList(new ArrayList<>(encryptedDataKeys));
      return this;
    }
  }
}
