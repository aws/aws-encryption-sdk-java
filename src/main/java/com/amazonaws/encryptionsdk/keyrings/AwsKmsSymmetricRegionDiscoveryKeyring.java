/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.arn.Arn;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.DataKeyEncryptionDao;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;

import java.util.List;
import java.util.Optional;

import static com.amazonaws.encryptionsdk.EncryptedDataKey.PROVIDER_ENCODING;
import static com.amazonaws.encryptionsdk.internal.Constants.AWS_KMS_PROVIDER_ID;
import static java.util.Objects.requireNonNull;

/**
 * A keyring which interacts with AWS Key Management Service (KMS)
 * to decrypt data keys using a specified AWS SDK KMS service client for a specific AWS region.
 */
public class AwsKmsSymmetricRegionDiscoveryKeyring implements Keyring {

    private final DataKeyEncryptionDao dataKeyEncryptionDao;
    private final Optional<String> awsAccountId;
    private final String awsRegion;

    AwsKmsSymmetricRegionDiscoveryKeyring(DataKeyEncryptionDao dataKeyEncryptionDao, String awsRegion, String awsAccountId) {
        requireNonNull(dataKeyEncryptionDao, "dataKeyEncryptionDao is required");
        requireNonNull(awsRegion, "AWS region is required");

        this.dataKeyEncryptionDao = dataKeyEncryptionDao;
        this.awsRegion = awsRegion;
        this.awsAccountId = Optional.ofNullable(awsAccountId);
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials encryptionMaterials) {
        throw new AwsCryptoException("The AWS KMS Region Discovery keyring cannot be used for encryption");
    }

    @Override
    public DecryptionMaterials onDecrypt(DecryptionMaterials decryptionMaterials, List<? extends EncryptedDataKey> encryptedDataKeys) {
        requireNonNull(decryptionMaterials, "decryptionMaterials are required");
        requireNonNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.hasCleartextDataKey() || encryptedDataKeys.isEmpty()) {
            return decryptionMaterials;
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (okToDecrypt(encryptedDataKey)) {
                try {
                    final DataKeyEncryptionDao.DecryptDataKeyResult result = dataKeyEncryptionDao.decryptDataKey(
                        encryptedDataKey, decryptionMaterials.getAlgorithm(), decryptionMaterials.getEncryptionContext());

                    return decryptionMaterials.withCleartextDataKey(
                        result.getPlaintextDataKey(),
                        new KeyringTraceEntry(
                            AWS_KMS_PROVIDER_ID,
                            result.getKeyArn(),
                            KeyringTraceFlag.DECRYPTED_DATA_KEY,
                            KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT));
                } catch (CannotUnwrapDataKeyException e) {
                    continue;
                }
            }
        }

        return decryptionMaterials;
    }

    private boolean okToDecrypt(EncryptedDataKey encryptedDataKey) {
        // Only attempt to decrypt keys provided by KMS
        if (!encryptedDataKey.getProviderId().equals(AWS_KMS_PROVIDER_ID)) {
            return false;
        }

        // If the key ID cannot be parsed, skip it
        String keyName = new String(encryptedDataKey.getProviderInformation(), PROVIDER_ENCODING);
        if (!AwsKmsCmkId.isKeyIdWellFormed(keyName)) {
            return false;
        }

        // Determine the ARN
        final Optional<Arn> arn = AwsKmsCmkId.getArnFromKeyName(keyName);
        if (!arn.isPresent()) {
            return false;
        }

        // If an AWS account ID is provided,
        // this keyring must only decrypt encrypted data keys
        // that were encrypted using an AWS KMS CMK in that AWS account
        if (awsAccountId.isPresent() && !awsAccountId.get().equals(arn.get().getAccountId())) {
            return false;
        }

        // Finally, determine if the region matches the keyring's client's region
        return arn.get().getRegion().equalsIgnoreCase(awsRegion);
    }
}
