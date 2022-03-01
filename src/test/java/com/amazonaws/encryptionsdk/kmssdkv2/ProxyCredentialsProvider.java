package com.amazonaws.encryptionsdk.kmssdkv2;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

class ProxyCredentialsProvider implements AwsCredentialsProvider {
  private final AwsCredentialsProvider proxiedProvider_;

  ProxyCredentialsProvider(AwsCredentialsProvider credentialsProvider) {
    proxiedProvider_ = credentialsProvider;
  }

  @Override
  public AwsCredentials resolveCredentials() {
    return proxiedProvider_.resolveCredentials();
  }
}
