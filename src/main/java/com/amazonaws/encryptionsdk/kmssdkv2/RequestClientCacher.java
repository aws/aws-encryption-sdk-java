package com.amazonaws.encryptionsdk.kmssdkv2;

import java.util.concurrent.ConcurrentHashMap;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

class RequestClientCacher implements ExecutionInterceptor {
  private final ConcurrentHashMap<Region, KmsClient> cache_;
  private final Region region_;
  private KmsClient client_;

  volatile boolean ranBefore_ = false;

  RequestClientCacher(final ConcurrentHashMap<Region, KmsClient> cache, final Region region) {
    this.region_ = region;
    this.cache_ = cache;
  }

  public KmsClient setClient(final KmsClient client) {
    client_ = client;
    return client;
  }

  @Override
  public void afterExecution(
      Context.AfterExecution context, ExecutionAttributes executionAttributes) {
    if (ranBefore_) {
      return;
    }
    ranBefore_ = true;

    cache_.putIfAbsent(region_, client_);
  }

  @Override
  public void onExecutionFailure(
      Context.FailedExecution context, ExecutionAttributes executionAttributes) {
    if (ranBefore_) {
      return;
    }

    if (!(context.exception() instanceof AwsServiceException)) {
      return;
    }

    ranBefore_ = true;
    cache_.putIfAbsent(region_, client_);
  }
}
