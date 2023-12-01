// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Demonstrate an encrypt/decrypt cycle using a Required Encryption Context CMM.
 * A required encryption context CMM asks for required keys in the encryption context field
 * on encrypt such that they will not be stored on the message, but WILL be included in the header signature.
 * On decrypt the client MUST supply the key/value pair(s) that were not stored to successfully decrypt the message.
 */
public class RequiredEncryptionContextCMMExample {
  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyArn = args[0];

    encryptAndDecryptWithKeyring(keyArn);
  }

  public static void encryptAndDecryptWithKeyring(final String keyArn) {
    // 1. Instantiate the SDK
    // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
    // which enforces that this client only encrypts using committing algorithm suites and enforces
    // that this client will only decrypt encrypted messages that were created with a committing
    // algorithm suite.
    // This is the default commitment policy if you build the client with
    // `AwsCrypto.builder().build()`
    // or `AwsCrypto.standard()`.
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    // 2. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("key1", "value1");
    encryptionContext.put("key2", "value2");
    encryptionContext.put("requiredKey1", "requiredValue1");
    encryptionContext.put("requiredKey2", "requiredValue2");

    // 3. Create list of required encryption context keys.
    // This is a list of keys that must be present in the encryption context.
    final List<String> requiredEncryptionContextKeys =
        Arrays.asList("requiredKey1", "requiredKey2");

    // 4. Create the AWS KMS keyring.
    final MaterialProviders materialProviders =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsKeyringInput keyringInput =
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(KmsClient.create()).build();
    final IKeyring kmsKeyring = materialProviders.CreateAwsKmsKeyring(keyringInput);

    // 5. Create the required encryption context CMM.
    final ICryptographicMaterialsManager cmm =
        materialProviders.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(kmsKeyring).build());

    final ICryptographicMaterialsManager requiredCMM =
        materialProviders.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .requiredEncryptionContextKeys(requiredEncryptionContextKeys)
                .underlyingCMM(cmm)
                .build());

    // 6. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(requiredCMM, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 7. Reproduce the encryption context.
    // The reproduced encryption context MUST contain a value for
    //        every key in the configured required encryption context keys during encryption with
    //        Required Encryption Context CMM.
    final Map<String, String> reproducedEncryptionContext = new HashMap<>();
    reproducedEncryptionContext.put("requiredKey1", "requiredValue1");
    reproducedEncryptionContext.put("requiredKey2", "requiredValue2");

    // 8. Decrypt the data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(requiredCMM, ciphertext, reproducedEncryptionContext);

    // 9. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }
}
