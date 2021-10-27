// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

/**
 * This class stores the configuration for filtering AWS KMS CMK ARNs by AWS account ID and
 * partition.
 *
 * <p>The filter allows a KMS CMK if its partition matches {@code partition} and its accountId is
 * included in {@code accountIds}.
 */
public final class DiscoveryFilter {
  private final String partition_;
  private final Collection<String> accountIds_;

  public DiscoveryFilter(String partition, String... accountIds) {
    this(partition, Arrays.asList(accountIds));
  }

  public DiscoveryFilter(String partition, Collection<String> accountIds) {
    if (partition == null || partition.isEmpty()) {
      throw new IllegalArgumentException(
          "Discovery filter cannot be configured without " + "a partition.");
    } else if (accountIds == null || accountIds.isEmpty()) {
      throw new IllegalArgumentException(
          "Discovery filter cannot be configured without " + "account IDs.");
    } else if (accountIds.contains(null) || accountIds.contains("")) {
      throw new IllegalArgumentException(
          "Discovery filter cannot be configured with " + "null or empty account IDs.");
    }

    partition_ = partition;
    accountIds_ = new HashSet<String>(accountIds);
  }

  public String getPartition() {
    return partition_;
  }

  public Collection<String> getAccountIds() {
    return Collections.unmodifiableSet(new HashSet<>(accountIds_));
  }

  public boolean allowsPartitionAndAccount(String partition, String accountId) {
    return (partition_.equals(partition) && accountIds_.contains(accountId));
  }
}
