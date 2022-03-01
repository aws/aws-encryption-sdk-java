// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk.kmssdkv2;

import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.jupiter.api.DisplayName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

@RunWith(Enclosed.class)
public class AwsKmsMrkAwareMasterKeyTest {

  public static class getInstance {

    @Test
    public void basic_use() {
      KmsClient client = spy(new MockKmsClient());
      MasterKeyProvider mkp = mock(MasterKeyProvider.class);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
      // = type=test
      // # On initialization, the caller MUST provide:
      final AwsKmsMrkAwareMasterKey test =
          AwsKmsMrkAwareMasterKey.getInstance(
              client,
              "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
              mkp);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.5
      // = type=test
      // # MUST implement the Master Key Interface (../master-key-
      // # interface.md#interface)
      assertTrue(MasterKey.class.isInstance(test));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    // = type=test
    // # The AWS KMS key identifier MUST NOT be null or empty.
    public void requires_valid_identifiers() {
      KmsClient client = spy(new MockKmsClient());
      MasterKeyProvider mkp = mock(MasterKeyProvider.class);

      assertThrows(
          IllegalArgumentException.class,
          () -> AwsKmsMrkAwareMasterKey.getInstance(client, "", mkp));
      assertThrows(
          IllegalArgumentException.class,
          () -> AwsKmsMrkAwareMasterKey.getInstance(client, null, mkp));

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
      // = type=test
      // # The AWS KMS
      // # key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
      // # valid-aws-kms-identifier).
      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKey.getInstance(
                  client, "arn:aws:dynamodb:us-east-2:123456789012:table/myDynamoDBTable", mkp));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    // = type=test
    // # The AWS KMS SDK client MUST not be null.
    public void requires_valid_client() {
      MasterKeyProvider mkp = mock(MasterKeyProvider.class);

      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKey.getInstance(
                  null,
                  "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
                  mkp));
    }

    @Test
    @DisplayName("Precondition: A provider is required.")
    public void requires_valid_provider() {
      KmsClient client = spy(new MockKmsClient());

      assertThrows(
          IllegalArgumentException.class,
          () ->
              AwsKmsMrkAwareMasterKey.getInstance(
                  client,
                  "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
                  null));
    }
  }

  public static class generateDataKey {

    @Test
    public void basic_use() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

      final KmsClient client = mock(KmsClient.class);
      when(client.generateDataKey((GenerateDataKeyRequest) any()))
          .thenReturn(
              GenerateDataKeyResponse.builder()
                  .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
                  .keyId(keyIdentifier)
                  .ciphertextBlob(SdkBytes.fromByteArray(new byte[10]))
                  .build());
      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn("aws-kms");
      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
      // = type=test
      // # The master key MUST be able to be configured with an optional list of
      // # Grant Tokens.
      masterKey.setGrantTokens(GRANT_TOKENS);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
      // = type=test
      // # The inputs MUST be the same as the Master Key Generate Data Key
      // # (../master-key-interface.md#generate-data-key) interface.
      DataKey<AwsKmsMrkAwareMasterKey> test =
          masterKey.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT);
      ArgumentCaptor<GenerateDataKeyRequest> gr =
          ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
      // = type=test
      // # This
      // # master key MUST use the configured AWS KMS client to make an AWS KMS
      // # GenerateDatakey (https://docs.aws.amazon.com/kms/latest/APIReference/
      // # API_GenerateDataKey.html) request constructed as follows:
      verify(client, times(1)).generateDataKey(gr.capture());

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
      // = type=test
      // # The output MUST be the same as the Master Key Generate Data Key
      // # (../master-key-interface.md#generate-data-key) interface.
      assertTrue(DataKey.class.isInstance(test));

      GenerateDataKeyRequest actualRequest = gr.getValue();

      assertEquals(keyIdentifier, actualRequest.keyId());
      assertEquals(GRANT_TOKENS, actualRequest.grantTokens());
      assertEquals(ENCRYPTION_CONTEXT, actualRequest.encryptionContext());
      assertEquals(ALGORITHM_SUITE.getDataKeyLength(), actualRequest.numberOfBytes().longValue());
      assertTrue(actualRequest.overrideConfiguration().isPresent());
      assertTrue(
          actualRequest
              .overrideConfiguration()
              .get()
              .apiNames()
              .contains(AwsKmsMrkAwareMasterKey.API_NAME));

      assertNotNull(test.getKey());
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
      // = type=test
      // # The response's "Plaintext" MUST be the plaintext in
      // # the output.
      assertEquals(ALGORITHM_SUITE.getDataKeyLength(), test.getKey().getEncoded().length);
      assertEquals(ALGORITHM_SUITE.getDataKeyAlgo(), test.getKey().getAlgorithm());
      assertNotNull(test.getEncryptedDataKey());
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
      // = type=test
      // # The response's cipher text blob MUST be used as the
      // # returned as the ciphertext for the encrypted data key in the output.
      assertEquals(10, test.getEncryptedDataKey().length);
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
    // = type=test
    // # If the call succeeds the AWS KMS Generate Data Key response's
    // # "Plaintext" MUST match the key derivation input length specified by
    // # the algorithm suite included in the input.
    public void length_must_match() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      // I use more, because less _should_ trigger an underflow... but the condition should _always_
      // fail
      final int wrongLength = ALGORITHM_SUITE.getDataKeyLength() + 1;

      final KmsClient client = mock(KmsClient.class);
      when(client.generateDataKey((GenerateDataKeyRequest) any()))
          .thenReturn(
              GenerateDataKeyResponse.builder()
                  .plaintext(SdkBytes.fromByteArray(new byte[wrongLength]))
                  .keyId(keyIdentifier)
                  .ciphertextBlob(SdkBytes.fromByteArray(new byte[10]))
                  .build());
      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn("aws-kms");
      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);

      assertThrows(
          IllegalStateException.class,
          () -> masterKey.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
    }

    @Test
    @DisplayName(
        "Exceptional Postcondition: Must have an AWS KMS ARN from AWS KMS generateDataKey.")
    public void need_an_arn() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

      final KmsClient client = mock(KmsClient.class);
      when(client.generateDataKey((GenerateDataKeyRequest) any()))
          .thenReturn(
              GenerateDataKeyResponse.builder()
                  .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
                  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
                  // = type=test
                  // # The response's "KeyId"
                  // # MUST be valid.
                  .keyId("b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
                  .ciphertextBlob(SdkBytes.fromByteArray(new byte[10]))
                  .build());
      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn("aws-kms");
      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);

      assertThrows(
          IllegalStateException.class,
          () -> masterKey.generateDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT));
    }
  }

  public static class encryptDataKey {
    @Test
    public void basic_use() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final SecretKey SECRET_KEY =
          new SecretKeySpec(
              generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());

      final MasterKeyProvider<AwsKmsMrkAwareMasterKey> mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn("aws-kms");

      final DataKey dataKey =
          new DataKey(
              SECRET_KEY,
              new byte[0],
              "aws-kms".getBytes(StandardCharsets.UTF_8),
              mock(MasterKey.class));

      final KmsClient client = mock(KmsClient.class);
      when(client.encrypt((EncryptRequest) any()))
          .thenReturn(
              EncryptResponse.builder()
                  .keyId(keyIdentifier)
                  .ciphertextBlob(SdkBytes.fromByteArray(new byte[10]))
                  .build());

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
      // = type=test
      // # The inputs MUST be the same as the Master Key Encrypt Data Key
      // # (../master-key-interface.md#encrypt-data-key) interface.
      DataKey<AwsKmsMrkAwareMasterKey> test =
          masterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
      // = type=test
      // # The output MUST be the same as the Master Key Encrypt Data Key
      // # (../master-key-interface.md#encrypt-data-key) interface.
      assertTrue(DataKey.class.isInstance(test));

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
      // = type=test
      // # The master
      // # key MUST use the configured AWS KMS client to make an AWS KMS Encrypt
      // # (https://docs.aws.amazon.com/kms/latest/APIReference/
      // # API_Encrypt.html) request constructed as follows:
      verify(client, times(1)).encrypt((EncryptRequest) any());
      ArgumentCaptor<EncryptRequest> gr = ArgumentCaptor.forClass(EncryptRequest.class);
      verify(client, times(1)).encrypt(gr.capture());

      final EncryptRequest actualRequest = gr.getValue();

      assertEquals(keyIdentifier, actualRequest.keyId());
      assertEquals(GRANT_TOKENS, actualRequest.grantTokens());
      assertEquals(ENCRYPTION_CONTEXT, actualRequest.encryptionContext());
      assertTrue(actualRequest.overrideConfiguration().isPresent());
      assertTrue(
          actualRequest
              .overrideConfiguration()
              .get()
              .apiNames()
              .contains(AwsKmsMrkAwareMasterKey.API_NAME));

      assertNotNull(test.getKey());
      assertEquals(ALGORITHM_SUITE.getDataKeyLength(), test.getKey().getEncoded().length);
      assertEquals(ALGORITHM_SUITE.getDataKeyAlgo(), test.getKey().getAlgorithm());
      assertNotNull(test.getEncryptedDataKey());
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
      // = type=test
      // # The
      // # response's cipher text blob MUST be used as the "ciphertext" for the
      // # encrypted data key.
      assertEquals(10, test.getEncryptedDataKey().length);
    }

    @Test
    @DisplayName("Precondition: The key format MUST be RAW.")
    public void secret_key_must_be_raw() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final MasterKeyProvider<AwsKmsMrkAwareMasterKey> mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn("aws-kms");

      // Test "stuff" here
      final SecretKey SECRET_KEY = mock(SecretKeySpec.class);
      when(SECRET_KEY.getFormat()).thenReturn("NOT-RAW");

      final DataKey dataKey =
          new DataKey(
              SECRET_KEY,
              new byte[0],
              "aws-kms".getBytes(StandardCharsets.UTF_8),
              mock(MasterKey.class));

      final KmsClient client = mock(KmsClient.class);
      when(client.encrypt((EncryptRequest) any()))
          .thenReturn(
              EncryptResponse.builder()
                  .keyId(keyIdentifier)
                  .ciphertextBlob(SdkBytes.fromByteArray(new byte[10]))
                  .build());

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      assertThrows(
          "Only RAW encoded keys are supported",
          IllegalArgumentException.class,
          () -> masterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey));
    }

    @Test
    @DisplayName("Postcondition: Must have an AWS KMS ARN from AWS KMS encrypt.")
    public void need_an_arn() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final SecretKey SECRET_KEY =
          new SecretKeySpec(
              generate(ALGORITHM_SUITE.getDataKeyLength()), ALGORITHM_SUITE.getDataKeyAlgo());

      final MasterKeyProvider<AwsKmsMrkAwareMasterKey> mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn("aws-kms");

      final DataKey dataKey =
          new DataKey(
              SECRET_KEY,
              new byte[0],
              "aws-kms".getBytes(StandardCharsets.UTF_8),
              mock(MasterKey.class));

      final KmsClient client = mock(KmsClient.class);
      when(client.encrypt((EncryptRequest) any()))
          .thenReturn(
              EncryptResponse.builder()
                  // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
                  // = type=test
                  // # The AWS KMS Encrypt response MUST contain a valid "KeyId".
                  .keyId("b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
                  .ciphertextBlob(SdkBytes.fromByteArray(new byte[10]))
                  .build());

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      assertThrows(
          IllegalStateException.class,
          () -> masterKey.encryptDataKey(ALGORITHM_SUITE, ENCRYPTION_CONTEXT, dataKey));
    }
  }

  public static class filterEncryptedDataKeys {
    @Test
    public void basic_use() {
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      final EncryptedDataKey edk =
          new KeyBlob(providerId, keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      assertTrue(AwsKmsMrkAwareMasterKey.filterEncryptedDataKeys(providerId, keyIdentifier, edk));
    }

    @Test
    public void mrk_specific() {
      /* This may be overkill,
       * but the whole point
       * of multi-region optimization
       * is this fuzzy match.
       */
      final String configuredIdentifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final String ekdIdentifier =
          "arn:aws:kms:us-east-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";

      final String providerId = "aws-kms";
      final EncryptedDataKey edk =
          new KeyBlob(providerId, ekdIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      assertTrue(
          AwsKmsMrkAwareMasterKey.filterEncryptedDataKeys(providerId, configuredIdentifier, edk));
    }

    @Test
    public void provider_info_must_be_arn() {
      final String configuredIdentifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final String rawKeyId = "mrk-edb7fe6942894d32ac46dbb1c922d574";
      final String alias =
          "arn:aws:kms:us-west-2:111122223333:alias/mrk-edb7fe6942894d32ac46dbb1c922d574";

      final String providerId = "aws-kms";
      final EncryptedDataKey edkNotArn =
          new KeyBlob(providerId, rawKeyId.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final EncryptedDataKey edkAliasArn =
          new KeyBlob(providerId, rawKeyId.getBytes(StandardCharsets.UTF_8), new byte[10]);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
      // = type=test
      // # Additionally each provider info MUST be a valid AWS KMS ARN
      // # (aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of
      // # "key".
      assertThrows(
          IllegalStateException.class,
          () ->
              AwsKmsMrkAwareMasterKey.filterEncryptedDataKeys(
                  providerId, configuredIdentifier, edkNotArn));
      assertThrows(
          IllegalStateException.class,
          () ->
              AwsKmsMrkAwareMasterKey.filterEncryptedDataKeys(
                  providerId, configuredIdentifier, edkAliasArn));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // = type=test
    // # To match the encrypted data key's
    // # provider ID MUST exactly match the value "aws-kms" and the the
    // # function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-for-
    // # decrypt.md#implementation) called with the configured AWS KMS key
    // # identifier and the encrypted data key's provider info MUST return
    // # "true".
    public void may_not_match() {
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      final EncryptedDataKey edk =
          new KeyBlob(providerId, keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      assertFalse(
          AwsKmsMrkAwareMasterKey.filterEncryptedDataKeys("not-aws-kms", keyIdentifier, edk));

      assertFalse(
          AwsKmsMrkAwareMasterKey.filterEncryptedDataKeys(
              providerId,
              "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574",
              edk));
    }
  }

  public static class decryptSingleEncryptedDataKey {
    @Test
    public void basic_use() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      final EncryptedDataKey edk =
          new KeyBlob(providerId, keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn(providerId);

      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenReturn(
              DecryptResponse.builder()
                  .keyId(keyIdentifier)
                  .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
                  .build());

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      DataKey<AwsKmsMrkAwareMasterKey> test =
          AwsKmsMrkAwareMasterKey.decryptSingleEncryptedDataKey(
              any(), client, keyIdentifier, GRANT_TOKENS, ALGORITHM_SUITE, edk, ENCRYPTION_CONTEXT);

      verify(client, times(1)).decrypt((DecryptRequest) any());
      ArgumentCaptor<DecryptRequest> gr = ArgumentCaptor.forClass(DecryptRequest.class);
      verify(client, times(1)).decrypt(gr.capture());

      final DecryptRequest actualRequest = gr.getValue();

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
      // = type=test
      // # To decrypt the encrypted data key this master key MUST use the
      // # configured AWS KMS client to make an AWS KMS Decrypt
      // # (https://docs.aws.amazon.com/kms/latest/APIReference/
      // # API_Decrypt.html) request constructed as follows:
      assertEquals(keyIdentifier, actualRequest.keyId());
      assertEquals(GRANT_TOKENS, actualRequest.grantTokens());
      assertEquals(ENCRYPTION_CONTEXT, actualRequest.encryptionContext());
      assertTrue(actualRequest.overrideConfiguration().isPresent());
      assertTrue(
          actualRequest
              .overrideConfiguration()
              .get()
              .apiNames()
              .contains(AwsKmsMrkAwareMasterKey.API_NAME));

      assertNotNull(test.getKey());
      assertEquals(ALGORITHM_SUITE.getDataKeyLength(), test.getKey().getEncoded().length);
      assertEquals(ALGORITHM_SUITE.getDataKeyAlgo(), test.getKey().getAlgorithm());
    }

    @Test
    @DisplayName("Exceptional Postcondition: Must have a CMK ARN from AWS KMS to match.")
    public void expect_key_arn() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      final EncryptedDataKey edk =
          new KeyBlob(providerId, keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn(providerId);

      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenReturn(
              DecryptResponse.builder()
                  .keyId(null)
                  .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
                  .build());

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      assertThrows(
          IllegalStateException.class,
          () ->
              AwsKmsMrkAwareMasterKey.decryptSingleEncryptedDataKey(
                  any(),
                  client,
                  keyIdentifier,
                  GRANT_TOKENS,
                  ALGORITHM_SUITE,
                  edk,
                  ENCRYPTION_CONTEXT));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // = type=test
    // # If the call succeeds then the response's "KeyId" MUST be equal to the
    // # configured AWS KMS key identifier otherwise the function MUST collect
    // # an error.
    public void returned_arn_must_match() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      final EncryptedDataKey edk =
          new KeyBlob(providerId, keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn(providerId);

      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenReturn(
              DecryptResponse.builder()
                  .keyId("arn:aws:kms:us-west-2:658956600833:key/something-else")
                  .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
                  .build());

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      assertThrows(
          IllegalStateException.class,
          () ->
              AwsKmsMrkAwareMasterKey.decryptSingleEncryptedDataKey(
                  any(),
                  client,
                  keyIdentifier,
                  GRANT_TOKENS,
                  ALGORITHM_SUITE,
                  edk,
                  ENCRYPTION_CONTEXT));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // = type=test
    // # The response's "Plaintext"'s length MUST equal the length
    // # required by the requested algorithm suite otherwise the function MUST
    // # collect an error.
    public void key_length_must_match() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      // I use more, because less _should_ trigger an underflow... but the condition should _always_
      // fail
      final int wrongLength = ALGORITHM_SUITE.getDataKeyLength() + 1;
      final EncryptedDataKey edk =
          new KeyBlob(providerId, keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn(providerId);

      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenReturn(
              DecryptResponse.builder()
                  .keyId(keyIdentifier)
                  .plaintext(SdkBytes.fromByteArray(new byte[wrongLength]))
                  .build());

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      assertThrows(
          IllegalStateException.class,
          () ->
              AwsKmsMrkAwareMasterKey.decryptSingleEncryptedDataKey(
                  any(),
                  client,
                  keyIdentifier,
                  GRANT_TOKENS,
                  ALGORITHM_SUITE,
                  edk,
                  ENCRYPTION_CONTEXT));
    }
  }

  public static class decryptDataKey {

    @Test
    public void basic_use() {
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:111122223333:key/mrk-edb7fe6942894d32ac46dbb1c922d574";
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final byte[] cipherText = new byte[10];
      final String providerId = "aws-kms";
      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn(providerId);

      final EncryptedDataKey edk1 =
          new KeyBlob("aws-kms", keyIdentifier.getBytes(StandardCharsets.UTF_8), cipherText);
      final EncryptedDataKey edk2 =
          new KeyBlob("aws-kms", keyIdentifier.getBytes(StandardCharsets.UTF_8), cipherText);

      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenReturn(
              DecryptResponse.builder()
                  .keyId(keyIdentifier)
                  .plaintext(SdkBytes.fromByteArray(new byte[ALGORITHM_SUITE.getDataKeyLength()]))
                  .build());

      final AwsKmsMrkAwareMasterKey mk =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      mk.setGrantTokens(GRANT_TOKENS);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
      // = type=test
      // # The inputs MUST be the same as the Master Key Decrypt Data Key
      // # (../master-key-interface.md#decrypt-data-key) interface.
      final DataKey<AwsKmsMrkAwareMasterKey> test =
          mk.decryptDataKey(ALGORITHM_SUITE, Arrays.asList(edk1, edk2), ENCRYPTION_CONTEXT);

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
      // = type=test
      // # For each encrypted data key in the filtered set, one at a time, the
      // # master key MUST attempt to decrypt the data key.
      //
      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
      // = type=test
      // # If the AWS KMS response satisfies the requirements then it MUST be
      // # use and this function MUST return and not attempt to decrypt any more
      // # encrypted data keys.
      verify(client, times((1)))
          .decrypt(
              DecryptRequest.builder()
                  .overrideConfiguration(
                      builder -> builder.addApiName(AwsKmsMrkAwareMasterKey.API_NAME))
                  .grantTokens(GRANT_TOKENS)
                  .encryptionContext(ENCRYPTION_CONTEXT)
                  .keyId(keyIdentifier)
                  .ciphertextBlob(SdkBytes.fromByteArray(cipherText))
                  .build());

      // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
      // = type=test
      // # The output MUST be the same as the Master Key Decrypt Data Key
      // # (../master-key-interface.md#decrypt-data-key) interface.
      assertTrue(DataKey.class.isInstance(test));
    }

    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // = type=test
    // # The set of encrypted data keys MUST first be filtered to match this
    // # master key's configuration.
    public void edk_match() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      final String clientErrMsg = "asdf";
      final EncryptedDataKey edk1 =
          new KeyBlob("not-aws-kms", keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final EncryptedDataKey edk2 =
          new KeyBlob(
              providerId, "not-key-identifier".getBytes(StandardCharsets.UTF_8), new byte[10]);

      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn(providerId);

      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenThrow(AwsServiceException.builder().message(clientErrMsg).build());
      final RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      final AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);
      masterKey.setGrantTokens(GRANT_TOKENS);

      final CannotUnwrapDataKeyException testProviderNotMatch =
          assertThrows(
              "Unable to decrypt any data keys",
              CannotUnwrapDataKeyException.class,
              () ->
                  masterKey.decryptDataKey(
                      ALGORITHM_SUITE, Arrays.asList(edk1), ENCRYPTION_CONTEXT));
      assertEquals(0, testProviderNotMatch.getSuppressed().length);

      final IllegalStateException testArnNotMatch =
          assertThrows(
              "Unable to decrypt any data keys",
              IllegalStateException.class,
              () ->
                  masterKey.decryptDataKey(
                      ALGORITHM_SUITE, Arrays.asList(edk2), ENCRYPTION_CONTEXT));
      assertEquals(0, testArnNotMatch.getSuppressed().length);
    }

    @Test
    @DisplayName("Exceptional Postcondition: Master key was unable to decrypt.")
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // = type=test
    // # If this attempt
    // # results in an error, then these errors MUST be collected.
    //
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    // = type=test
    // # If all the input encrypted data keys have been processed then this
    // # function MUST yield an error that includes all the collected errors.
    public void exception_wrapped() {
      final CryptoAlgorithm ALGORITHM_SUITE =
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
      final List<String> GRANT_TOKENS = Collections.singletonList("testGrantToken");
      final Map<String, String> ENCRYPTION_CONTEXT = Collections.singletonMap("myKey", "myValue");
      final String keyIdentifier =
          "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
      final String providerId = "aws-kms";
      final String clientErrMsg = "asdf";
      final EncryptedDataKey edk =
          new KeyBlob(providerId, keyIdentifier.getBytes(StandardCharsets.UTF_8), new byte[10]);

      final MasterKeyProvider mkp = mock(MasterKeyProvider.class);
      when(mkp.getDefaultProviderId()).thenReturn(providerId);

      final KmsClient client = mock(KmsClient.class);
      when(client.decrypt((DecryptRequest) any()))
          .thenThrow(AwsServiceException.builder().message(clientErrMsg).build());

      RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
      when(supplier.getClient(any())).thenReturn(client);

      AwsKmsMrkAwareMasterKey masterKey =
          AwsKmsMrkAwareMasterKey.getInstance(client, keyIdentifier, mkp);

      masterKey.setGrantTokens(GRANT_TOKENS);

      final CannotUnwrapDataKeyException test =
          assertThrows(
              "Unable to decrypt any data keys",
              CannotUnwrapDataKeyException.class,
              () ->
                  masterKey.decryptDataKey(
                      ALGORITHM_SUITE, Arrays.asList(edk), ENCRYPTION_CONTEXT));
      assertEquals(1, test.getSuppressed().length);
      Throwable fromClient = Arrays.stream(test.getSuppressed()).findFirst().get();
      assertTrue(fromClient instanceof AwsServiceException);
      assertTrue(fromClient.getMessage().startsWith(clientErrMsg));
    }
  }

  public static class getMasterKey {
    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.7
    // = type=test
    // # MUST be unchanged from the Master Key interface.
    public void test_get_master_key() throws NoSuchMethodException {
      String methodName = "getMasterKey";
      Class<?>[] parameterTypes = new Class<?>[] {String.class, String.class};
      // Make sure the signature is correct by fetching the base method
      Method baseMethod = MasterKey.class.getDeclaredMethod(methodName, parameterTypes);
      assertNotNull(baseMethod);
      // Assert AwsKmsMrkAwareMasterKey does not declare the same method directly
      assertThrows(
          NoSuchMethodException.class,
          () -> AwsKmsMrkAwareMasterKey.class.getDeclaredMethod(methodName, parameterTypes));
    }
  }

  public static class getMasterKeysForEncryption {
    @Test
    // = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.8
    // = type=test
    // # MUST be unchanged from the Master Key interface.
    public void test_getMasterKeysForEncryption() throws NoSuchMethodException {
      String methodName = "getMasterKeysForEncryption";
      Class<?>[] parameterTypes = new Class<?>[] {MasterKeyRequest.class};

      // Make sure the signature is correct by fetching the base method
      Method baseMethod = MasterKey.class.getDeclaredMethod(methodName, parameterTypes);
      assertNotNull(baseMethod);
      // Assert AwsKmsMrkAwareMasterKey does no declare the same method directly
      assertThrows(
          NoSuchMethodException.class,
          () -> AwsKmsMrkAwareMasterKey.class.getDeclaredMethod(methodName, parameterTypes));
    }
  }
}
