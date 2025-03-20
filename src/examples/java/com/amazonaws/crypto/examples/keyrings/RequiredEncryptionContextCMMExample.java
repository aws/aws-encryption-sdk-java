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
    encryptionContext.put("encryption",              "context");
    encryptionContext.put("is not",                   "secret");
    encryptionContext.put("but adds",                  "useful metadata");
    encryptionContext.put("that can help you",         "be confident that");
    encryptionContext.put("the data you are handling", "is what you think it is");
    encryptionContext.put("𐀂","𐀂");

    // 3. Create list of required encryption context keys.
    // This is a list of keys that must be present in the encryption context.
    final List<String> requiredEncryptionContextKeys =
        Arrays.asList("requiredKey1", "𐀂");

    // 4. Create the AWS KMS keyring.
    final MaterialProviders materialProviders =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsKeyringInput keyringInput =
        CreateAwsKmsKeyringInput.builder().kmsKeyId("arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f").kmsClient(KmsClient.create()).build();
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
    final byte[] ciphertext = new byte[] {
            2, 5, 120, 76, -95, 111, 114, 108, 90, -2, -80, 72, -78, -2, -102, 62, 3, 83, -70, 91, -92, 94, 2, 3, 76, -9, 44, 122, 127, -97, -21, -100, -53, -88, 67, 1, 5, 0, 7, 0, 21, 97, 119, 115, 45, 99, 114, 121, 112, 116, 111, 45, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, 68, 65, 53, 71, 65, 73, 75, 103, 108, 77, 56, 43, 97, 74, 88, 109, 88, 68, 88, 76, 90, 51, 103, 101, 75, 102, 118, 70, 66, 49, 116, 78, 74, 65, 99, 75, 98, 106, 68, 120, 67, 106, 75, 48, 55, 77, 99, 122, 54, 90, 108, 109, 89, 54, 51, 80, 49, 67, 84, 111, 77, 49, 57, 114, 81, 118, 65, 61, 61, 0, 8, 98, 117, 116, 32, 97, 100, 100, 115, 0, 15, 117, 115, 101, 102, 117, 108, 32, 109, 101, 116, 97, 100, 97, 116, 97, 0, 10, 101, 110, 99, 114, 121, 112, 116, 105, 111, 110, 0, 7, 99, 111, 110, 116, 101, 120, 116, 0, 6, 105, 115, 32, 110, 111, 116, 0, 6, 115, 101, 99, 114, 101, 116, 0, 17, 116, 104, 97, 116, 32, 99, 97, 110, 32, 104, 101, 108, 112, 32, 121, 111, 117, 0, 17, 98, 101, 32, 99, 111, 110, 102, 105, 100, 101, 110, 116, 32, 116, 104, 97, 116, 0, 25, 116, 104, 101, 32, 100, 97, 116, 97, 32, 121, 111, 117, 32, 97, 114, 101, 32, 104, 97, 110, 100, 108, 105, 110, 103, 0, 23, 105, 115, 32, 119, 104, 97, 116, 32, 121, 111, 117, 32, 116, 104, 105, 110, 107, 32, 105, 116, 32, 105, 115, 0, 4, -16, -112, -128, -126, 0, 4, -16, -112, -128, -126, 0, 1, 0, 7, 97, 119, 115, 45, 107, 109, 115, 0, 75, 97, 114, 110, 58, 97, 119, 115, 58, 107, 109, 115, 58, 117, 115, 45, 119, 101, 115, 116, 45, 50, 58, 54, 53, 56, 57, 53, 54, 54, 48, 48, 56, 51, 51, 58, 107, 101, 121, 47, 98, 51, 53, 51, 55, 101, 102, 49, 45, 100, 56, 100, 99, 45, 52, 55, 56, 48, 45, 57, 102, 53, 97, 45, 53, 53, 55, 55, 54, 99, 98, 98, 50, 102, 55, 102, 0, -89, 1, 1, 1, 0, 120, 64, -13, -116, 39, 94, 49, 9, 116, 22, -63, 7, 41, 81, 80, 87, 25, 100, -83, -93, -17, 28, 33, -23, 76, -117, -96, -67, -68, -99, 15, -76, 20, 0, 0, 0, 126, 48, 124, 6, 9, 42, -122, 72, -122, -9, 13, 1, 7, 6, -96, 111, 48, 109, 2, 1, 0, 48, 104, 6, 9, 42, -122, 72, -122, -9, 13, 1, 7, 1, 48, 30, 6, 9, 96, -122, 72, 1, 101, 3, 4, 1, 46, 48, 17, 4, 12, 27, -5, -44, -10, -81, -117, -24, 15, 70, 65, 72, 49, 2, 1, 16, -128, 59, -63, -20, -90, -89, -91, -25, -42, 110, -66, 76, -124, -66, 8, -29, 70, -24, 73, 59, -36, 74, 81, -102, -88, -5, 109, 115, -35, 22, 126, -31, 51, 20, -39, 122, 27, 21, 21, -116, 70, -63, -31, -86, -78, 12, -74, 85, -98, -120, 108, -107, -67, -19, 15, 124, 81, 54, 126, -32, -110, 2, 0, 0, 16, 0, -118, -67, 31, -114, 77, -114, 47, -89, 103, -69, 125, -91, 108, 107, 89, -46, 78, -11, -59, -58, 22, 83, -67, 29, 110, -110, 3, 25, -7, 73, -29, -127, 100, -86, -75, 36, -56, 40, -93, 89, 117, 40, 126, 63, 89, -109, -108, -89, -1, -1, -1, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 47, -31, -63, 46, 60, -63, 113, -88, -42, 13, 96, 122, -81, 58, 109, -77, 47, 15, 88, -25, 0, 103, 48, 101, 2, 49, 0, -102, 60, -75, -63, 49, -87, -93, -88, 88, 121, 62, -59, 84, -6, -70, -48, 66, -37, -21, -81, -38, 10, 69, -87, 1, 77, -58, -70, 21, 32, 46, 8, 18, 110, -58, -110, 1, -48, -66, 48, -15, -46, -40, -57, 46, -91, 92, -99, 2, 48, 55, -24, 94, -74, -122, 54, -46, 72, -79, -50, 54, 83, 51, 26, 82, 115, -69, -52, 77, 88, 64, 90, 41, -16, -114, -103, -39, -107, -112, -63, 70, -117, 113, 38, 29, -97, -31, 79, -99, -51, 85, -45, -94, -38, -55, -111, -109, 110
    };

    // 7. Reproduce the encryption context.
    // The reproduced encryption context MUST contain a value for
    //        every key in the configured required encryption context keys during encryption with
    //        Required Encryption Context CMM.
    final Map<String, String> reproducedEncryptionContext = new HashMap<>();
    reproducedEncryptionContext.put("requiredKey1", "requiredValue1");
    reproducedEncryptionContext.put("𐀂","𐀂");

    // 8. Decrypt the data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(requiredCMM, ciphertext, reproducedEncryptionContext);

    // 9. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }
}
