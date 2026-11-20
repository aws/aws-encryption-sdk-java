// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * <p>
 * Creates a custom implementation of the CryptoMaterialsManager interface,
 * then uses that implementation to encrypt and decrypt a file using an AWS KMS CMK.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *    key (CMK), see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class CustomCMMExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        final String keyArn = args[0];

        CryptoMaterialsManager cmm = new SigningSuiteOnlyCMM(
            KmsMasterKeyProvider.builder().buildStrict(keyArn)
        );

        encryptAndDecryptWithCMM(cmm);
    }

    static void encryptAndDecryptWithCMM(final CryptoMaterialsManager cmm) {
        // 1. Instantiate the SDK
        // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
        // which enforces that this client only encrypts using committing algorithm suites and enforces
        // that this client will only decrypt encrypted messages that were created with a committing algorithm suite.
        // This is the default commitment policy if you build the client with `AwsCrypto.builder().build()`
        // or `AwsCrypto.standard()`.
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();

        // 2. Create an encryption context
        // Most encrypted data should have an associated encryption context
        // to protect integrity. This sample uses placeholder values.
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 3. Encrypt the data with the provided CMM
        final CryptoResult<byte[], ?> encryptResult = crypto.encryptData(cmm, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // 4. Decrypt the data
        final CryptoResult<byte[], ?> decryptResult = crypto.decryptData(cmm, ciphertext);

        // 5. Verify that the encryption context in the result contains the
        // encryption context supplied to the encryptData method. Because the
        // SDK can add values to the encryption context, don't require that
        // the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 6. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }

    // Custom CMM implementation.
    // This CMM only allows encryption/decryption using signing algorithms.
    // It wraps an underlying CMM implementation and checks its materials
    // to ensure that it is only using signed encryption algorithms.
    public static class SigningSuiteOnlyCMM implements CryptoMaterialsManager {

        // The underlying CMM.
        private CryptoMaterialsManager underlyingCMM;

        // If only a MasterKeyProvider is constructed, the underlying CMM is the default CMM.
        public SigningSuiteOnlyCMM(MasterKeyProvider<?> mkp) {
            this.underlyingCMM = new DefaultCryptoMaterialsManager(mkp);
        }

        // This CMM can wrap any other CMM implementation.
        public SigningSuiteOnlyCMM(CryptoMaterialsManager underlyingCMM) {
            this.underlyingCMM = underlyingCMM;
        }

        @Override
        public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
            EncryptionMaterials materials = underlyingCMM.getMaterialsForEncrypt(request);
            if (materials.getAlgorithm().getTrailingSignatureAlgo() == null) {
                throw new IllegalArgumentException("Algorithm provided to SigningSuiteOnlyCMM is not a supported signing algorithm: " + materials.getAlgorithm());
            }
            return materials;
        }

        @Override
        public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
            if (request.getAlgorithm().getTrailingSignatureAlgo() == null) {
                throw new IllegalArgumentException("Algorithm provided to SigningSuiteOnlyCMM is not a supported signing algorithm: " + request.getAlgorithm());
            }
            return underlyingCMM.decryptMaterials(request);
        }
    }

}
