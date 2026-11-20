// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings.hierarchical;

import software.amazon.cryptography.materialproviders.IBranchKeyIdSupplier;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdInput;
import software.amazon.cryptography.materialproviders.model.GetBranchKeyIdOutput;

import java.util.Map;

// Use the encryption contexts to define friendly names for each branch key
public class ExampleBranchKeyIdSupplier implements IBranchKeyIdSupplier {
  private static String branchKeyIdForTenantA;
  private static String branchKeyIdForTenantB;

  public ExampleBranchKeyIdSupplier(String tenant1Id, String tenant2Id) {
    this.branchKeyIdForTenantA = tenant1Id;
    this.branchKeyIdForTenantB = tenant2Id;
  }

  @Override
  public GetBranchKeyIdOutput GetBranchKeyId(GetBranchKeyIdInput input) {

    Map<String, String> encryptionContext = input.encryptionContext();

    if (!encryptionContext.containsKey("tenant")) {
      throw new IllegalArgumentException(
          "EncryptionContext invalid, does not contain expected tenant key value pair.");
    }

    String tenantKeyId = encryptionContext.get("tenant");
    String branchKeyId;

    if (tenantKeyId.equals("TenantA")) {
      branchKeyId = branchKeyIdForTenantA;
    } else if (tenantKeyId.equals("TenantB")) {
      branchKeyId = branchKeyIdForTenantB;
    } else {
      throw new IllegalArgumentException("Item does not contain valid tenant ID");
    }
    return GetBranchKeyIdOutput.builder().branchKeyId(branchKeyId).build();
  }
}
