package com.amazonaws.encryptionsdk.model;

import com.amazonaws.encryptionsdk.DataKey;
import java.security.PublicKey;

public final class DecryptionMaterials {
  private final DataKey<?> dataKey;
  private final PublicKey trailingSignatureKey;

  private DecryptionMaterials(Builder b) {
    dataKey = b.getDataKey();
    trailingSignatureKey = b.getTrailingSignatureKey();
  }

  public DataKey<?> getDataKey() {
    return dataKey;
  }

  public PublicKey getTrailingSignatureKey() {
    return trailingSignatureKey;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static final class Builder {
    private DataKey<?> dataKey;
    private PublicKey trailingSignatureKey;

    private Builder(DecryptionMaterials result) {
      this.dataKey = result.getDataKey();
      this.trailingSignatureKey = result.getTrailingSignatureKey();
    }

    private Builder() {}

    public DataKey<?> getDataKey() {
      return dataKey;
    }

    public Builder setDataKey(DataKey<?> dataKey) {
      this.dataKey = dataKey;
      return this;
    }

    public PublicKey getTrailingSignatureKey() {
      return trailingSignatureKey;
    }

    public Builder setTrailingSignatureKey(PublicKey trailingSignatureKey) {
      this.trailingSignatureKey = trailingSignatureKey;
      return this;
    }

    public DecryptionMaterials build() {
      return new DecryptionMaterials(this);
    }
  }
}
