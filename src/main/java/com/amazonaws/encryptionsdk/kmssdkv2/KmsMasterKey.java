/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.encryptionsdk.kmssdkv2;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.encryptionsdk.kms.KmsMethods;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ApiName;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

/**
 * Represents a single Customer Master Key (CMK) and is used to encrypt/decrypt data with {@link
 * AwsCrypto}.
 *
 * <p>This component is not multi-Region key aware, and will treat every AWS KMS identifier as
 * regionally isolated.
 */
public final class KmsMasterKey extends MasterKey<KmsMasterKey> implements KmsMethods {
  private static final ApiName API_NAME =
      ApiName.builder().name(VersionInfo.apiName()).version(VersionInfo.versionNumber()).build();
  private static final Consumer<AwsRequestOverrideConfiguration.Builder> API_NAME_INTERCEPTOR =
      builder -> builder.addApiName(API_NAME);

  private final Supplier<KmsClient> clientSupplier_;
  private final MasterKeyProvider<KmsMasterKey> sourceProvider_;
  private final String id_;
  private final List<String> grantTokens_ = new ArrayList<>();

  static KmsMasterKey getInstance(
      final Supplier<KmsClient> clientSupplier,
      final String id,
      final MasterKeyProvider<KmsMasterKey> provider) {
    return new KmsMasterKey(clientSupplier, id, provider);
  }

  private KmsMasterKey(
      final Supplier<KmsClient> clientSupplier,
      final String id,
      final MasterKeyProvider<KmsMasterKey> provider) {
    clientSupplier_ = clientSupplier;
    id_ = id;
    sourceProvider_ = provider;
  }

  @Override
  public String getProviderId() {
    return sourceProvider_.getDefaultProviderId();
  }

  @Override
  public String getKeyId() {
    return id_;
  }

  @Override
  public DataKey<KmsMasterKey> generateDataKey(
      final CryptoAlgorithm algorithm, final Map<String, String> encryptionContext) {
    final GenerateDataKeyResponse gdkResponse =
        clientSupplier_
            .get()
            .generateDataKey(
                GenerateDataKeyRequest.builder()
                    .overrideConfiguration(API_NAME_INTERCEPTOR)
                    .keyId(getKeyId())
                    .numberOfBytes(algorithm.getDataKeyLength())
                    .encryptionContext(encryptionContext)
                    .grantTokens(grantTokens_)
                    .build());

    final ByteBuffer plaintextBuffer = gdkResponse.plaintext().asByteBuffer();
    if (plaintextBuffer.limit() != algorithm.getDataKeyLength()) {
      throw new IllegalStateException("Received an unexpected number of bytes from KMS");
    }

    final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
    plaintextBuffer.get(rawKey);

    final ByteBuffer ciphertextBlobBuffer = gdkResponse.ciphertextBlob().asByteBuffer();
    final byte[] encryptedKey = new byte[ciphertextBlobBuffer.remaining()];
    ciphertextBlobBuffer.get(encryptedKey);

    final String gdkResponseKeyId = gdkResponse.keyId();

    final SecretKeySpec key = new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo());
    return new DataKey<>(
        key, encryptedKey, gdkResponseKeyId.getBytes(StandardCharsets.UTF_8), this);
  }

  @Override
  public void setGrantTokens(final List<String> grantTokens) {
    grantTokens_.clear();
    grantTokens_.addAll(grantTokens);
  }

  @Override
  public List<String> getGrantTokens() {
    return grantTokens_;
  }

  @Override
  public void addGrantToken(final String grantToken) {
    grantTokens_.add(grantToken);
  }

  @Override
  public DataKey<KmsMasterKey> encryptDataKey(
      final CryptoAlgorithm algorithm,
      final Map<String, String> encryptionContext,
      final DataKey<?> dataKey) {
    final SecretKey key = dataKey.getKey();
    if (!key.getFormat().equals("RAW")) {
      throw new IllegalArgumentException("Only RAW encoded keys are supported");
    }
    try {
      final EncryptResponse encryptResponse =
          clientSupplier_
              .get()
              .encrypt(
                  EncryptRequest.builder()
                      .overrideConfiguration(API_NAME_INTERCEPTOR)
                      .keyId(id_)
                      .plaintext(SdkBytes.fromByteArray(key.getEncoded()))
                      .encryptionContext(encryptionContext)
                      .grantTokens(grantTokens_)
                      .build());

      final ByteBuffer ciphertextBlobBuffer = encryptResponse.ciphertextBlob().asByteBuffer();
      final byte[] edk = new byte[ciphertextBlobBuffer.remaining()];
      ciphertextBlobBuffer.get(edk);

      final String encryptResultKeyId = encryptResponse.keyId();

      return new DataKey<>(
          dataKey.getKey(), edk, encryptResultKeyId.getBytes(StandardCharsets.UTF_8), this);
    } catch (final AwsServiceException asex) {
      throw new AwsCryptoException(asex);
    }
  }

  @Override
  public DataKey<KmsMasterKey> decryptDataKey(
      final CryptoAlgorithm algorithm,
      final Collection<? extends EncryptedDataKey> encryptedDataKeys,
      final Map<String, String> encryptionContext)
      throws UnsupportedProviderException, AwsCryptoException {
    final List<Exception> exceptions = new ArrayList<>();
    for (final EncryptedDataKey edk : encryptedDataKeys) {
      try {
        final String edkKeyId = new String(edk.getProviderInformation(), StandardCharsets.UTF_8);
        if (!edkKeyId.equals(id_)) {
          continue;
        }
        final DecryptResponse decryptResponse =
            clientSupplier_
                .get()
                .decrypt(
                    DecryptRequest.builder()
                        .overrideConfiguration(API_NAME_INTERCEPTOR)
                        .ciphertextBlob(SdkBytes.fromByteArray(edk.getEncryptedDataKey()))
                        .encryptionContext(encryptionContext)
                        .grantTokens(grantTokens_)
                        .keyId(edkKeyId)
                        .build());

        final String decryptResponseKeyId = decryptResponse.keyId();
        if (decryptResponseKeyId == null) {
          throw new IllegalStateException("Received an empty keyId from KMS");
        }
        if (decryptResponseKeyId.equals(id_)) {
          final ByteBuffer plaintextBuffer = decryptResponse.plaintext().asByteBuffer();
          if (plaintextBuffer.limit() != algorithm.getDataKeyLength()) {
            throw new IllegalStateException("Received an unexpected number of bytes from KMS");
          }

          final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
          plaintextBuffer.get(rawKey);

          return new DataKey<>(
              new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo()),
              edk.getEncryptedDataKey(),
              edk.getProviderInformation(),
              this);
        }
      } catch (final AwsServiceException awsex) {
        exceptions.add(awsex);
      }
    }

    throw buildCannotDecryptDksException(exceptions);
  }
}
