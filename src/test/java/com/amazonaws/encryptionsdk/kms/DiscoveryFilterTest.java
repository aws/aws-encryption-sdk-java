// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class DiscoveryFilterTest {
  @Test
  public void testValidConstruct() throws Exception {
    DiscoveryFilter filter = new DiscoveryFilter("partition", Arrays.asList("accountId"));
    assertNotNull(filter);

    DiscoveryFilter filter2 = new DiscoveryFilter("partition", "accountId1", "accountId2");
    assertNotNull(filter2);
  }

  @Test
  public void testConstructWithEmptyPartition() throws Exception {
    assertThrows(
        IllegalArgumentException.class, () -> new DiscoveryFilter("", Arrays.asList("accountId")));
    assertThrows(IllegalArgumentException.class, () -> new DiscoveryFilter("", "accountId"));
  }

  @Test
  public void testConstructWithNullPartition() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new DiscoveryFilter(null, Arrays.asList("accountId")));
    assertThrows(IllegalArgumentException.class, () -> new DiscoveryFilter(null, "accountId"));
  }

  @Test
  public void testConstructWithEmptyIds() throws Exception {
    assertThrows(
        IllegalArgumentException.class, () -> new DiscoveryFilter("aws", Collections.emptyList()));
  }

  @Test
  public void testConstructWithNullIds() throws Exception {
    assertThrows(
        IllegalArgumentException.class, () -> new DiscoveryFilter("aws", (List<String>) null));
  }

  @Test
  public void testConstructWithIdsContainingEmptyId() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new DiscoveryFilter("aws", Arrays.asList("accountId", "")));
    assertThrows(IllegalArgumentException.class, () -> new DiscoveryFilter("aws", "accountId", ""));
  }

  @Test
  public void testConstructWithIdsContainingNullId() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new DiscoveryFilter("aws", Arrays.asList("accountId", null)));
    assertThrows(
        IllegalArgumentException.class, () -> new DiscoveryFilter("aws", "accountId", null));
  }
}
