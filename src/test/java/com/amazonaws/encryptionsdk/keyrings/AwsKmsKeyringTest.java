/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.MismatchedDataKeyException;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao.DecryptDataKeyResult;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.ENCRYPTED_DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.GENERATED_DATA_KEY;
import static com.amazonaws.encryptionsdk.keyrings.KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AwsKmsKeyringTest {

    private static final CryptoAlgorithm ALGORITHM_SUITE = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
    private static final SecretKey PLAINTEXT_DATA_KEY = new SecretKeySpec(generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());
    private static final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
    private static final String GENERATOR_KEY_ID = "arn:aws:kms:us-east-1:999999999999:key/generator-89ab-cdef-fedc-ba9876543210";
    private static final String KEY_ID_1 = "arn:aws:kms:us-east-1:999999999999:key/key1-23bv-sdfs-werw-234323nfdsf";
    private static final String KEY_ID_2 = "arn:aws:kms:us-east-1:999999999999:key/key2-02ds-wvjs-aswe-a4923489273";
    private static final AwsKmsCmkId GENERATOR_KEY = AwsKmsCmkId.fromString(GENERATOR_KEY_ID);
    private static final AwsKmsCmkId KEY_1 = AwsKmsCmkId.fromString(KEY_ID_1);
    private static final AwsKmsCmkId KEY_2 = AwsKmsCmkId.fromString(KEY_ID_2);
    private static final EncryptedDataKey ENCRYPTED_GENERATOR_KEY = new KeyBlob(AWS_KMS_PROVIDER_ID,
            GENERATOR_KEY_ID.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    private static final EncryptedDataKey ENCRYPTED_KEY_1 = new KeyBlob(AWS_KMS_PROVIDER_ID,
            KEY_ID_1.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    private static final EncryptedDataKey ENCRYPTED_KEY_2 = new KeyBlob(AWS_KMS_PROVIDER_ID,
            KEY_ID_2.getBytes(PROVIDER_ENCODING), generate(ALGORITHM_SUITE.getDataKeyLength()));
    private static final KeyringTraceEntry ENCRYPTED_GENERATOR_KEY_TRACE =
            new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, GENERATOR_KEY_ID, ENCRYPTED_DATA_KEY, SIGNED_ENCRYPTION_CONTEXT);
    private static final KeyringTraceEntry ENCRYPTED_KEY_1_TRACE =
            new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, KEY_ID_1, ENCRYPTED_DATA_KEY, SIGNED_ENCRYPTION_CONTEXT);
    private static final KeyringTraceEntry ENCRYPTED_KEY_2_TRACE =
            new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, KEY_ID_2, ENCRYPTED_DATA_KEY, SIGNED_ENCRYPTION_CONTEXT);
    private static final KeyringTraceEntry GENERATED_DATA_KEY_TRACE =
            new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, GENERATOR_KEY_ID, GENERATED_DATA_KEY);
    @Mock(lenient = true) private DataKeyEncryptionDao dataKeyEncryptionDao;
    private Keyring keyring;

    @BeforeEach
    void setup() {
        when(dataKeyEncryptionDao.encryptDataKey(GENERATOR_KEY, PLAINTEXT_DATA_KEY, ENCRYPTION_CONTEXT)).thenReturn(ENCRYPTED_GENERATOR_KEY);
        when(dataKeyEncryptionDao.encryptDataKey(KEY_1, PLAINTEXT_DATA_KEY, ENCRYPTION_CONTEXT)).thenReturn(ENCRYPTED_KEY_1);
        when(dataKeyEncryptionDao.encryptDataKey(KEY_2, PLAINTEXT_DATA_KEY, ENCRYPTION_CONTEXT)).thenReturn(ENCRYPTED_KEY_2);

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_GENERATOR_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
                .thenReturn(new DecryptDataKeyResult(GENERATOR_KEY_ID, PLAINTEXT_DATA_KEY));
        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_1, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
                .thenReturn(new DecryptDataKeyResult(KEY_ID_1, PLAINTEXT_DATA_KEY));
        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_2, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
                .thenReturn(new DecryptDataKeyResult(KEY_ID_2, PLAINTEXT_DATA_KEY));

        List<AwsKmsCmkId> keyIds = new ArrayList<>();
        keyIds.add(AwsKmsCmkId.fromString(KEY_ID_1));
        keyIds.add(AwsKmsCmkId.fromString(KEY_ID_2));
        keyring = new AwsKmsKeyring(dataKeyEncryptionDao, keyIds, AwsKmsCmkId.fromString(GENERATOR_KEY_ID), false);
    }

    @Test
    void testMalformedArns() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(new KeyBlob(AWS_KMS_PROVIDER_ID, "arn:badArn".getBytes(PROVIDER_ENCODING), new byte[]{}));
        encryptedDataKeys.add(ENCRYPTED_KEY_1);

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);
        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());

        decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        // Malformed Arn for a non KMS provider shouldn't fail
        encryptedDataKeys.clear();
        encryptedDataKeys.add(new KeyBlob("OtherProviderId", "arn:badArn".getBytes(PROVIDER_ENCODING), new byte[]{}));
        assertFalse(keyring.onDecrypt(decryptionMaterials, encryptedDataKeys).hasCleartextDataKey());
    }

    @Test
    void testGeneratorKeyInKeyIds() {
        assertThrows(IllegalArgumentException.class, () -> new AwsKmsKeyring(dataKeyEncryptionDao,
                Collections.singletonList(AwsKmsCmkId.fromString(GENERATOR_KEY_ID)),
                AwsKmsCmkId.fromString(GENERATOR_KEY_ID), false));
    }

    @Test
    void testNotDiscoveryNoKeysIds() {
        assertThrows(IllegalArgumentException.class, () -> new AwsKmsKeyring(dataKeyEncryptionDao,
                null,null, false));
    }

    @Test
    void testDiscoveryWithKeyId() {
        assertThrows(IllegalArgumentException.class, () -> new AwsKmsKeyring(dataKeyEncryptionDao,
                null,
                AwsKmsCmkId.fromString(GENERATOR_KEY_ID), true));
        assertThrows(IllegalArgumentException.class, () -> new AwsKmsKeyring(dataKeyEncryptionDao,
                Collections.singletonList(AwsKmsCmkId.fromString(GENERATOR_KEY_ID)),
                null, true));
    }

    @Test
    void testEncryptDecryptExistingDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setCleartextDataKey(PLAINTEXT_DATA_KEY)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertEquals(3, encryptionMaterials.getEncryptedDataKeys().size());
        assertEncryptedDataKeyEquals(ENCRYPTED_KEY_1, encryptionMaterials.getEncryptedDataKeys().get(0));
        assertEncryptedDataKeyEquals(ENCRYPTED_KEY_2, encryptionMaterials.getEncryptedDataKeys().get(1));
        assertEncryptedDataKeyEquals(ENCRYPTED_GENERATOR_KEY, encryptionMaterials.getEncryptedDataKeys().get(2));

        assertEquals(3, encryptionMaterials.getKeyringTrace().getEntries().size());
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(ENCRYPTED_GENERATOR_KEY_TRACE));
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(ENCRYPTED_KEY_1_TRACE));
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(ENCRYPTED_KEY_2_TRACE));

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_GENERATOR_KEY);
        encryptedDataKeys.add(ENCRYPTED_KEY_1);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());

        KeyringTraceEntry expectedKeyringTraceEntry = new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, GENERATOR_KEY_ID, KeyringTraceFlag.DECRYPTED_DATA_KEY, KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT);
        assertEquals(expectedKeyringTraceEntry, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testEncryptNullDataKey() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        when(dataKeyEncryptionDao.generateDataKey(GENERATOR_KEY, ALGORITHM_SUITE, ENCRYPTION_CONTEXT))
                .thenReturn(new DataKeyEncryptionDao.GenerateDataKeyResult(PLAINTEXT_DATA_KEY, ENCRYPTED_GENERATOR_KEY));
        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertEquals(PLAINTEXT_DATA_KEY, encryptionMaterials.getCleartextDataKey());

        assertEquals(4, encryptionMaterials.getKeyringTrace().getEntries().size());
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(GENERATED_DATA_KEY_TRACE));
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(ENCRYPTED_GENERATOR_KEY_TRACE));
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(ENCRYPTED_KEY_1_TRACE));
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(ENCRYPTED_KEY_2_TRACE));

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_GENERATOR_KEY);
        encryptedDataKeys.add(ENCRYPTED_KEY_1);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());

        KeyringTraceEntry expectedKeyringTraceEntry = new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, GENERATOR_KEY_ID, KeyringTraceFlag.DECRYPTED_DATA_KEY, KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT);
        assertEquals(expectedKeyringTraceEntry, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testEncryptNullGenerator() {
        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setCleartextDataKey(PLAINTEXT_DATA_KEY)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        Keyring keyring = new AwsKmsKeyring(dataKeyEncryptionDao,
                Collections.singletonList(AwsKmsCmkId.fromString(KEY_ID_1)), null, false);

        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertEquals(1, encryptionMaterials.getEncryptedDataKeys().size());
        assertEncryptedDataKeyEquals(ENCRYPTED_KEY_1, encryptionMaterials.getEncryptedDataKeys().get(0));

        assertEquals(PLAINTEXT_DATA_KEY, encryptionMaterials.getCleartextDataKey());

        assertEquals(1, encryptionMaterials.getKeyringTrace().getEntries().size());
        assertTrue(encryptionMaterials.getKeyringTrace().getEntries().contains(ENCRYPTED_KEY_1_TRACE));
    }

    @Test
    void testDiscoveryEncrypt() {
        keyring = new AwsKmsKeyring(dataKeyEncryptionDao, null, null, true);

        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();
        encryptionMaterials = keyring.onEncrypt(encryptionMaterials);

        assertFalse(encryptionMaterials.hasCleartextDataKey());
        assertEquals(0, encryptionMaterials.getKeyringTrace().getEntries().size());
    }

    @Test
    void testEncryptNoGeneratorOrCleartextDataKey() {
        keyring = new AwsKmsKeyring(dataKeyEncryptionDao,
                Collections.singletonList(AwsKmsCmkId.fromString(KEY_ID_1)), null, false);

        EncryptionMaterials encryptionMaterials = EncryptionMaterials.newBuilder().setAlgorithm(ALGORITHM_SUITE).build();
        assertThrows(AwsCryptoException.class, () -> keyring.onEncrypt(encryptionMaterials));
    }

    @Test
    void testDecryptFirstKeyFails() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_1, ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenThrow(new CannotUnwrapDataKeyException());

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY_1);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());

        KeyringTraceEntry expectedKeyringTraceEntry = new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, KEY_ID_2, KeyringTraceFlag.DECRYPTED_DATA_KEY, KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT);
        assertEquals(expectedKeyringTraceEntry, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testDecryptMismatchedDataKeyException() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        when(dataKeyEncryptionDao.decryptDataKey(ENCRYPTED_KEY_1, ALGORITHM_SUITE, ENCRYPTION_CONTEXT)).thenThrow(new MismatchedDataKeyException());

        assertThrows(MismatchedDataKeyException.class, () -> keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_KEY_1)));
    }

    @Test
    void testDecryptFirstKeyWrongProvider() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        EncryptedDataKey wrongProviderKey = new KeyBlob("OtherProvider", KEY_ID_1.getBytes(PROVIDER_ENCODING), new byte[]{});

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(wrongProviderKey);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());

        KeyringTraceEntry expectedKeyringTraceEntry = new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, KEY_ID_2, KeyringTraceFlag.DECRYPTED_DATA_KEY, KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT);
        assertEquals(expectedKeyringTraceEntry, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testDiscoveryDecrypt() {
        keyring = new AwsKmsKeyring(dataKeyEncryptionDao, null, null, true);

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>();
        encryptedDataKeys.add(ENCRYPTED_KEY_1);
        encryptedDataKeys.add(ENCRYPTED_KEY_2);
        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, encryptedDataKeys);

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());

        KeyringTraceEntry expectedKeyringTraceEntry = new KeyringTraceEntry(AWS_KMS_PROVIDER_ID, KEY_ID_1, KeyringTraceFlag.DECRYPTED_DATA_KEY, KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT);
        assertEquals(expectedKeyringTraceEntry, decryptionMaterials.getKeyringTrace().getEntries().get(0));
    }

    @Test
    void testDecryptAlreadyDecryptedDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setCleartextDataKey(PLAINTEXT_DATA_KEY)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, Collections.singletonList(ENCRYPTED_GENERATOR_KEY));

        assertEquals(PLAINTEXT_DATA_KEY, decryptionMaterials.getCleartextDataKey());
        assertEquals(0, decryptionMaterials.getKeyringTrace().getEntries().size());
    }

    @Test
    void testDecryptNoDataKey() {
        DecryptionMaterials decryptionMaterials = DecryptionMaterials.newBuilder()
                .setAlgorithm(ALGORITHM_SUITE)
                .setEncryptionContext(ENCRYPTION_CONTEXT)
                .build();

        decryptionMaterials = keyring.onDecrypt(decryptionMaterials, Collections.emptyList());

        assertFalse(decryptionMaterials.hasCleartextDataKey());
        assertEquals(0, decryptionMaterials.getKeyringTrace().getEntries().size());
    }

    private void assertEncryptedDataKeyEquals(EncryptedDataKey expected, EncryptedDataKey actual) {
        assertEquals(expected.getProviderId(), actual.getProviderId());
        assertArrayEquals(expected.getProviderInformation(), actual.getProviderInformation());
        assertArrayEquals(expected.getEncryptedDataKey(), actual.getEncryptedDataKey());
    }
}
