// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validate;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;

/**
 * Smoke test that the published ESDK artifact is resolvable
 * and that key public API classes are importable and usable.
 */
public class EsdkSmokeTest {
    public static void main(String[] args) {
        AwsCrypto crypto = AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();
        System.out.println("ESDK artifact resolved and AwsCrypto instantiated successfully.");
        System.out.println("AwsCrypto version info: " + crypto.toString());
    }
}
