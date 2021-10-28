// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.amazonaws.encryptionsdk.CommitmentPolicy;
import org.junit.Test;

public class EncryptionMaterialsRequestTest {
  @Test
  public void testConstructWithoutCommitmentPolicy() {
    EncryptionMaterialsRequest req = EncryptionMaterialsRequest.newBuilder().build();
    assertNotNull(req);
  }

  @Test
  public void testConstructWithCommitmentPolicy() {
    EncryptionMaterialsRequest req =
        EncryptionMaterialsRequest.newBuilder()
            .setCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    assertNotNull(req);
    assertEquals(CommitmentPolicy.ForbidEncryptAllowDecrypt, req.getCommitmentPolicy());
  }
}
