// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyring.rawrsa;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.RawRsaKeyringBuilder;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * When you store RSA keys, you have to serialize them somehow.
 * <p>
 * This example shows how to configure and use a raw RSA keyring using a DER-encoded RSA private key.
 * <p>
 * The most commonly used encodings for RSA keys tend to be PEM and DER.
 * For parsing PEM-encoded keys, see https://www.bouncycastle.org/docs/pkixdocs1.4/org/bouncycastle/openssl/PEMParser.html
 * <p>
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring
 * <p>
 * In this example, we use the one-step encrypt and decrypt APIs.
 */
public class RawRsaDerEncoded {

    /**
     * Demonstrate an encrypt/decrypt cycle using a raw RSA keyring loaded from a DER-encoded key.
     *
     * @param sourcePlaintext Plaintext to encrypt
     */
    public static void run(final byte[] sourcePlaintext) throws GeneralSecurityException {
        // Instantiate the AWS Encryption SDK.
        final AwsCrypto awsEncryptionSdk = new AwsCrypto();

        // Prepare your encryption context.
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("is not", "secret");
        encryptionContext.put("but adds", "useful metadata");
        encryptionContext.put("that can help you", "be confident that");
        encryptionContext.put("the data you are handling", "is what you think it is");

        // Generate an RSA key pair to use with your keyring.
        // In practice, you should get this key from a secure key management system such as an HSM.
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        // The National Institute of Standards and Technology (NIST) recommends a minimum of 2048-bit keys for RSA.
        // https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths
        kg.initialize(4096);
        final KeyPair keyPair = kg.generateKeyPair();

        // Serialize the RSA keys to DER encoding.
        // This or PEM encoding is likely to be what you get from your key management system in practice.
        byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();
        byte[] privateKeyEncoded = keyPair.getPrivate().getEncoded();

        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Deserialize the RSA private key.
        final PrivateKey privateKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(privateKeyEncoded));

        // Deserialize the RSA public key.
        final PublicKey publicKey = keyFactory.generatePublic(
                new X509EncodedKeySpec(publicKeyEncoded));

        // Create the keyring that determines how your data keys are protected.
        final Keyring keyring = StandardKeyrings.rawRsaBuilder()
                // The key namespace and key name are defined by you
                // and are used by the raw RSA keyring
                // to determine whether it should attempt to decrypt
                // an encrypted data key.
                //
                // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring
                .keyNamespace("some managed raw keys")
                .keyName("my RSA wrapping key")
                .privateKey(privateKey)
                .publicKey(publicKey)
                // The padding scheme tells the raw RSA keyring
                // how to use your wrapping key to encrypt data keys.
                //
                // We recommend using OAEP_SHA256_MGF1.
                // You should not use PKCS1 unless you require it for backwards compatibility.
                .paddingScheme(RawRsaKeyringBuilder.RsaPaddingScheme.OAEP_SHA256_MGF1)
                .build();

        // Encrypt your plaintext data.
        final AwsCryptoResult<byte[]> encryptResult = awsEncryptionSdk.encrypt(
                EncryptRequest.builder()
                        .keyring(keyring)
                        .encryptionContext(encryptionContext)
                        .plaintext(sourcePlaintext).build());
        final byte[] ciphertext = encryptResult.getResult();

        // Demonstrate that the ciphertext and plaintext are different.
        assert !Arrays.equals(ciphertext, sourcePlaintext);

        // Decrypt your encrypted data using the same keyring you used on encrypt.
        //
        // You do not need to specify the encryption context on decrypt because
        // the header of the encrypted message includes the encryption context.
        final AwsCryptoResult<byte[]> decryptResult = awsEncryptionSdk.decrypt(
                DecryptRequest.builder()
                        .keyring(keyring)
                        .ciphertext(ciphertext).build());
        final byte[] decrypted = decryptResult.getResult();

        // Demonstrate that the decrypted plaintext is identical to the original plaintext.
        assert Arrays.equals(decrypted, sourcePlaintext);

        // Verify that the encryption context used in the decrypt operation includes
        // the encryption context that you specified when encrypting.
        // The AWS Encryption SDK can add pairs, so don't require an exact match.
        //
        // In production, always use a meaningful encryption context.
        encryptionContext.forEach((k, v) -> {
            assert v.equals(decryptResult.getEncryptionContext().get(k));
        });
    }
}
