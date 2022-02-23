// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kms;

import static com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo.*;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfo;
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
import java.util.*;
import java.util.function.Supplier;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.5
// # MUST implement the Master Key Interface (../master-key-
// # interface.md#interface)
//
// = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.7
// # MUST be unchanged from the Master Key interface.
//
// = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.8
// # MUST be unchanged from the Master Key interface.
/**
 * Represents a single Aws KMS key and is used to encrypt/decrypt data with {@link AwsCrypto}. This
 * key may be a multi region key, in which case this component is able to recognize different
 * regional replicas of this multi region key as the same.
 */
public final class AwsKmsMrkAwareMasterKey extends MasterKey<AwsKmsMrkAwareMasterKey>
    implements KmsMethods {
  private static final String USER_AGENT = VersionInfo.loadUserAgent();
  private final AWSKMS kmsClient_;
  private final List<String> grantTokens_ = new ArrayList<>();
  private final String awsKmsIdentifier_;
  private final MasterKeyProvider<AwsKmsMrkAwareMasterKey> sourceProvider_;

  private static <T extends AmazonWebServiceRequest> T updateUserAgent(T request) {
    request.getRequestClientOptions().appendUserAgent(USER_AGENT);

    return request;
  }

  /**
   * A light builder method.
   *
   * @see KmsMasterKey#getInstance(Supplier, String, MasterKeyProvider)
   * @param kms An AWS KMS Client
   * @param awsKmsIdentifier An identifier for an AWS KMS key. May be a raw resource.
   */
  static AwsKmsMrkAwareMasterKey getInstance(
      final AWSKMS kms,
      final String awsKmsIdentifier,
      final MasterKeyProvider<AwsKmsMrkAwareMasterKey> provider) {
    return new AwsKmsMrkAwareMasterKey(awsKmsIdentifier, kms, provider);
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
  // # On initialization, the caller MUST provide:
  private AwsKmsMrkAwareMasterKey(
      final String awsKmsIdentifier,
      final AWSKMS kmsClient,
      final MasterKeyProvider<AwsKmsMrkAwareMasterKey> provider) {

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    // # The AWS KMS key identifier MUST NOT be null or empty.
    //
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    // # The AWS KMS
    // # key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
    // # valid-aws-kms-identifier).
    validAwsKmsIdentifier(awsKmsIdentifier);

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    // # The AWS KMS SDK client MUST not be null.
    if (kmsClient == null) {
      throw new IllegalArgumentException(
          "AwsKmsMrkAwareMasterKey must be configured with an AWS KMS client.");
    }

    if (provider == null) {
      throw new IllegalArgumentException(
          "AwsKmsMrkAwareMasterKey must be configured with a source provider.");
    }

    kmsClient_ = kmsClient;
    awsKmsIdentifier_ = awsKmsIdentifier;
    sourceProvider_ = provider;
  }

  @Override
  public String getProviderId() {
    return sourceProvider_.getDefaultProviderId();
  }

  @Override
  public String getKeyId() {
    return awsKmsIdentifier_;
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
  // # The master key MUST be able to be configured with an optional list of
  // # Grant Tokens.
  //
  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
  // = type=exception
  // # This configuration SHOULD be on initialization and
  // # SHOULD be immutable.
  // The existing KMS Master Key
  // sets grants in this way, so we continue this interface.
  /** Clears and sets all grant tokens on this instance. This is not thread safe. */
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

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
  // # The inputs MUST be the same as the Master Key Generate Data Key
  // # (../master-key-interface.md#generate-data-key) interface.
  /**
   * This is identical behavior to
   *
   * @see KmsMasterKey#generateDataKey(CryptoAlgorithm, Map)
   */
  @Override
  public DataKey<AwsKmsMrkAwareMasterKey> generateDataKey(
      final CryptoAlgorithm algorithm, final Map<String, String> encryptionContext) {
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
    // # This
    // # master key MUST use the configured AWS KMS client to make an AWS KMS
    // # GenerateDatakey (https://docs.aws.amazon.com/kms/latest/APIReference/
    // # API_GenerateDataKey.html) request constructed as follows:
    final GenerateDataKeyResult gdkResult =
        kmsClient_.generateDataKey(
            updateUserAgent(
                new GenerateDataKeyRequest()
                    .withKeyId(awsKmsIdentifier_)
                    .withNumberOfBytes(algorithm.getDataKeyLength())
                    .withEncryptionContext(encryptionContext)
                    .withGrantTokens(grantTokens_)));
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
    // # If the call succeeds the AWS KMS Generate Data Key response's
    // # "Plaintext" MUST match the key derivation input length specified by
    // # the algorithm suite included in the input.
    if (gdkResult.getPlaintext().limit() != algorithm.getDataKeyLength()) {
      throw new IllegalStateException("Received an unexpected number of bytes from KMS");
    }

    final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
    gdkResult.getPlaintext().get(rawKey);

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
    // # The response's "KeyId"
    // # MUST be valid.
    final String gdkResultKeyId = gdkResult.getKeyId();
    if (parseInfoFromKeyArn(gdkResultKeyId) == null) {
      throw new IllegalStateException("Received an empty or invalid keyId from KMS");
    }

    final byte[] encryptedKey = new byte[gdkResult.getCiphertextBlob().remaining()];
    gdkResult.getCiphertextBlob().get(encryptedKey);

    final SecretKeySpec key = new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo());
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
    // # The output MUST be the same as the Master Key Generate Data Key
    // # (../master-key-interface.md#generate-data-key) interface.
    return new DataKey<>(
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        // # The response's "Plaintext" MUST be the plaintext in
        // # the output.
        key,
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        // # The response's cipher text blob MUST be used as the
        // # returned as the ciphertext for the encrypted data key in the output.
        encryptedKey,
        gdkResultKeyId.getBytes(StandardCharsets.UTF_8),
        this);
  }

  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
  // # The inputs MUST be the same as the Master Key Encrypt Data Key
  // # (../master-key-interface.md#encrypt-data-key) interface.
  /** @see KmsMasterKey#encryptDataKey(CryptoAlgorithm, Map, DataKey) */
  @Override
  public DataKey<AwsKmsMrkAwareMasterKey> encryptDataKey(
      final CryptoAlgorithm algorithm,
      final Map<String, String> encryptionContext,
      final DataKey<?> dataKey) {
    final SecretKey key = dataKey.getKey();
    if (!key.getFormat().equals("RAW")) {
      throw new IllegalArgumentException("Only RAW encoded keys are supported");
    }

    try {
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
      // # The master
      // # key MUST use the configured AWS KMS client to make an AWS KMS Encrypt
      // # (https://docs.aws.amazon.com/kms/latest/APIReference/
      // # API_Encrypt.html) request constructed as follows:
      final EncryptResult encryptResult =
          kmsClient_.encrypt(
              updateUserAgent(
                  new EncryptRequest()
                      .withKeyId(awsKmsIdentifier_)
                      .withPlaintext(ByteBuffer.wrap(key.getEncoded()))
                      .withEncryptionContext(encryptionContext)
                      .withGrantTokens(grantTokens_)));

      final byte[] edk = new byte[encryptResult.getCiphertextBlob().remaining()];
      encryptResult.getCiphertextBlob().get(edk);
      final String encryptResultKeyId = encryptResult.getKeyId();
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
      // # The AWS KMS Encrypt response MUST contain a valid "KeyId".
      if (parseInfoFromKeyArn(encryptResultKeyId) == null) {
        throw new IllegalStateException("Received an empty or invalid keyId from KMS");
      }

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
      // # The output MUST be the same as the Master Key Encrypt Data Key
      // # (../master-key-interface.md#encrypt-data-key) interface.
      return new DataKey<>(
          dataKey.getKey(),
          // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
          // # The
          // # response's cipher text blob MUST be used as the "ciphertext" for the
          // # encrypted data key.
          edk,
          encryptResultKeyId.getBytes(StandardCharsets.UTF_8),
          this);
    } catch (final AmazonServiceException asex) {
      throw new AwsCryptoException(asex);
    }
  }

  /**
   * Will attempt to decrypt if awsKmsArnMatchForDecrypt returns true in {@link
   * AwsKmsMrkAwareMasterKey#filterEncryptedDataKeys(String, AwsKmsCmkArnInfo, EncryptedDataKey)}.
   * An extension of {@link KmsMasterKey#decryptDataKey(CryptoAlgorithm, Collection, Map)} but with
   * an awareness of the properties of multi-Region keys.
   */
  @Override
  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
  // # The inputs MUST be the same as the Master Key Decrypt Data Key
  // # (../master-key-interface.md#decrypt-data-key) interface.
  public DataKey<AwsKmsMrkAwareMasterKey> decryptDataKey(
      final CryptoAlgorithm algorithm,
      final Collection<? extends EncryptedDataKey> encryptedDataKeys,
      final Map<String, String> encryptionContext)
      throws AwsCryptoException {
    final List<Exception> exceptions = new ArrayList<>();
    final String providerId = this.getProviderId();

    return encryptedDataKeys.stream()
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        // # The set of encrypted data keys MUST first be filtered to match this
        // # master key's configuration.
        .filter(edk -> filterEncryptedDataKeys(providerId, awsKmsIdentifier_, edk))
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        // # For each encrypted data key in the filtered set, one at a time, the
        // # master key MUST attempt to decrypt the data key.
        .map(
            edk -> {
              try {
                return decryptSingleEncryptedDataKey(
                    this,
                    kmsClient_,
                    awsKmsIdentifier_,
                    grantTokens_,
                    algorithm,
                    edk,
                    encryptionContext);
              } catch (final AmazonServiceException amazonServiceException) {
                // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
                // # If this attempt
                // # results in an error, then these errors MUST be collected.
                exceptions.add(amazonServiceException);
              }
              return null;
            })
        /* Need to filter null
         * because an Optional
         * of a null is crazy.
         * Therefore `findFirst` will throw
         * if it sees `null`.
         */
        .filter(Objects::nonNull)
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        // # If the AWS KMS response satisfies the requirements then it MUST be
        // # use and this function MUST return and not attempt to decrypt any more
        // # encrypted data keys.
        /* Order is important.
         * Process the encrypted data keys in the order they exist in the encrypted message.
         */
        .findFirst()
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        // # If all the input encrypted data keys have been processed then this
        // # function MUST yield an error that includes all the collected errors.
        //
        // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        // # The output MUST be the same as the Master Key Decrypt Data Key
        // # (../master-key-interface.md#decrypt-data-key) interface.
        .orElseThrow(() -> buildCannotDecryptDksException(exceptions));
  }

  /**
   * Pure function for decrypting and encrypted data key. This is refactored out of `decryptDataKey`
   * to facilitate testing to ensure correctness.
   */
  static DataKey<AwsKmsMrkAwareMasterKey> decryptSingleEncryptedDataKey(
      final AwsKmsMrkAwareMasterKey masterKey,
      final AWSKMS client,
      final String awsKmsIdentifier,
      final List<String> grantTokens,
      final CryptoAlgorithm algorithm,
      final EncryptedDataKey edk,
      final Map<String, String> encryptionContext) {

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // # To decrypt the encrypted data key this master key MUST use the
    // # configured AWS KMS client to make an AWS KMS Decrypt
    // # (https://docs.aws.amazon.com/kms/latest/APIReference/
    // # API_Decrypt.html) request constructed as follows:
    final DecryptResult decryptResult =
        client.decrypt(
            updateUserAgent(
                new DecryptRequest()
                    .withCiphertextBlob(ByteBuffer.wrap(edk.getEncryptedDataKey()))
                    .withEncryptionContext(encryptionContext)
                    .withGrantTokens(grantTokens)
                    .withKeyId(awsKmsIdentifier)));

    final String decryptResultKeyId = decryptResult.getKeyId();
    if (decryptResultKeyId == null) {
      throw new IllegalStateException("Received an empty keyId from KMS");
    }
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // # If the call succeeds then the response's "KeyId" MUST be equal to the
    // # configured AWS KMS key identifier otherwise the function MUST collect
    // # an error.
    if (!awsKmsIdentifier.equals(decryptResultKeyId)) {
      throw new IllegalStateException(
          "Received an invalid response from KMS Decrypt call: Unexpected keyId.");
    }

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // # The response's "Plaintext"'s length MUST equal the length
    // # required by the requested algorithm suite otherwise the function MUST
    // # collect an error.
    if (decryptResult.getPlaintext().limit() != algorithm.getDataKeyLength()) {
      throw new IllegalStateException("Received an unexpected number of bytes from KMS");
    }

    final byte[] rawKey = new byte[algorithm.getDataKeyLength()];
    decryptResult.getPlaintext().get(rawKey);

    return new DataKey<>(
        new SecretKeySpec(rawKey, algorithm.getDataKeyAlgo()),
        edk.getEncryptedDataKey(),
        edk.getProviderInformation(),
        masterKey);
  }

  /**
   * A pure function to filter encrypted data keys. This function is refactored out from
   * `decryptDataKey` to facilitate testing and ensure correctness.
   *
   * <p>An AWS KMS Master key should only attempt to process an Encrypted Data Key if the
   * information in the Encrypted Data Key matches the master keys configuration.
   */
  static boolean filterEncryptedDataKeys(
      final String providerId, final String awsKmsIdentifier_, final EncryptedDataKey edk) {
    final String edkKeyId = new String(edk.getProviderInformation(), StandardCharsets.UTF_8);

    final AwsKmsCmkArnInfo providerArnInfo = parseInfoFromKeyArn(edkKeyId);

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // # Additionally each provider info MUST be a valid AWS KMS ARN
    // # (aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of
    // # "key".
    if (providerArnInfo == null || !"key".equals(providerArnInfo.getResourceType())) {
      throw new IllegalStateException("Invalid provider info in message.");
    }

    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // # To match the encrypted data key's
    // # provider ID MUST exactly match the value "aws-kms" and the the
    // # function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-for-
    // # decrypt.md#implementation) called with the configured AWS KMS key
    // # identifier and the encrypted data key's provider info MUST return
    // # "true".
    return edk.getProviderId().equals(providerId)
        && awsKmsArnMatchForDecrypt(awsKmsIdentifier_, edkKeyId);
  }
}
