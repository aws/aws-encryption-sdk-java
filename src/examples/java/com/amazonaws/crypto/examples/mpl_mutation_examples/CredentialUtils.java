// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazonaws.crypto.examples.mpl_mutation_examples;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import javax.annotation.Nonnull;

public class CredentialUtils {

  public static StsAssumeRoleCredentialsProvider credsForRole(
    @Nonnull String roleArn,
    @Nonnull String roleSessionName,
    @Nonnull Region region,
    @Nonnull SdkHttpClient httpClient,
    @Nonnull AwsCredentialsProvider creds
  ) {
    StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider
      .builder()
      .stsClient(
        StsClient
          .builder()
          .httpClient(httpClient)
          .region(region)
          .credentialsProvider(creds)
          .build()
      )
      .refreshRequest(
        AssumeRoleRequest
          .builder()
          .roleArn(roleArn)
          .roleSessionName(roleSessionName)
          .durationSeconds(900) // 15 minutes by 60 seconds
          .build()
      )
      .build();
    // Force credential resolution.
    // If the host does not have permission to use these credentials,
    // we want to fail early.
    // This may not be appropriate in a production environment,
    // as it is "greedy initialization".
    provider.resolveCredentials();
    return provider;
  }
}
