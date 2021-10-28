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

package com.amazonaws.encryptionsdk.kms;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.VersionInfo;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Represents a single Customer Master Key (CMK) and is used to encrypt/decrypt data with {@link
 * AwsCrypto}.
 */
public final class KmsMasterKey extends MasterKey<KmsMasterKey> implements KmsMethods {
  private final Supplier<AWSKMS> kms_;
  private final MasterKeyProvider<KmsMasterKey> sourceProvider_;
  private final String id_;
  private final List<String> grantTokens_ = new ArrayList<>();

  private <T extends AmazonWebServiceRequest> T updateUserAgent(T request) {
    request.getRequestClientOptions().appendUserAgent(VersionInfo.USER_AGENT);

    return request;
  }

  /** @deprecated Use a {@link KmsMasterKeyProvider} to obtain {@link KmsMasterKey}s. */
  @Deprecated
  public static KmsMasterKey getInstance(final AWSCredentials creds, final String keyId) {
    return new KmsMasterKeyProvider(creds, keyId).getMasterKey(keyId);
  }

  /** @deprecated Use a {@link KmsMasterKeyProvider} to obtain {@link KmsMasterKey}s. */
  @Deprecated
  public static KmsMasterKey getInstance(final AWSCredentialsProvider creds, final String keyId) {
    return new KmsMasterKeyProvider(creds, keyId).getMasterKey(keyId);
  }

  static KmsMasterKey getInstance(
      final Supplier<AWSKMS> kms, final String id, final MasterKeyProvider<KmsMasterKey> provider) {
    return new KmsMasterKey(kms, id, provider);
  }

  private KmsMasterKey(
      final Supplier<AWSKMS> kms, final String id, final MasterKeyProvider<KmsMasterKey> provider) {
    kms_ = kms;
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
    final GenerateDataKeyResult gdkResult =
        kms_.get()
            .generateDataKey(
                updateUserAgent(
                    new GenerateDataKeyRequest()
                        .withKeyId(getKeyId())
                        .withNumberOfBytes(algorithm.getDataKeyLength())
                        .withEncryptionContext(encryptionContext)
                        .withGrantTokens(grantTokens_)));
    final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
    gdkResult.getPlaintext().get(rawKey);
    if (gdkResult.getPlaintext().remaining() > 0) {
      throw new IllegalStateException("Recieved an unexpected number of bytes from KMS");
    }
    final byte[] encryptedKey = new byte[gdkResult.getCiphertextBlob().remaining()];
    gdkResult.getCiphertextBlob().get(encryptedKey);

    final SecretKeySpec key = new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo());
    return new DataKey<>(
        key, encryptedKey, gdkResult.getKeyId().getBytes(StandardCharsets.UTF_8), this);
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
      final EncryptResult encryptResult =
          kms_.get()
              .encrypt(
                  updateUserAgent(
                      new EncryptRequest()
                          .withKeyId(id_)
                          .withPlaintext(ByteBuffer.wrap(key.getEncoded()))
                          .withEncryptionContext(encryptionContext)
                          .withGrantTokens(grantTokens_)));
      final byte[] edk = new byte[encryptResult.getCiphertextBlob().remaining()];
      encryptResult.getCiphertextBlob().get(edk);
      return new DataKey<>(
          dataKey.getKey(), edk, encryptResult.getKeyId().getBytes(StandardCharsets.UTF_8), this);
    } catch (final AmazonServiceException asex) {
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
        final DecryptResult decryptResult =
            kms_.get()
                .decrypt(
                    updateUserAgent(
                        new DecryptRequest()
                            .withCiphertextBlob(ByteBuffer.wrap(edk.getEncryptedDataKey()))
                            .withEncryptionContext(encryptionContext)
                            .withGrantTokens(grantTokens_)
                            .withKeyId(edkKeyId)));
        if (decryptResult.getKeyId() == null) {
          throw new IllegalStateException("Received an empty keyId from KMS");
        }
        if (decryptResult.getKeyId().equals(id_)) {
          final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
          decryptResult.getPlaintext().get(rawKey);
          if (decryptResult.getPlaintext().remaining() > 0) {
            throw new IllegalStateException("Received an unexpected number of bytes from KMS");
          }
          return new DataKey<>(
              new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo()),
              edk.getEncryptedDataKey(),
              edk.getProviderInformation(),
              this);
        }
      } catch (final AmazonServiceException awsex) {
        exceptions.add(awsex);
      }
    }

    throw buildCannotDecryptDksException(exceptions);
  }
}
