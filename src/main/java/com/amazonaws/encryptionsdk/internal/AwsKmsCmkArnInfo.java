package com.amazonaws.encryptionsdk.internal;

public final class AwsKmsCmkArnInfo {
  private final String partition_;
  private final String accountId_;
  private final String region_;

  public AwsKmsCmkArnInfo(String partition, String region, String accountId) {
    partition_ = partition;
    region_ = region;
    accountId_ = accountId;
  }

  public String getPartition() {
    return partition_;
  }

  public String getAccountId() {
    return accountId_;
  }

  public String getRegion() {
    return region_;
  }
}
