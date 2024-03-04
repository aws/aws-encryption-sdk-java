package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.IClientSupplier;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.GetClientInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * Encrypts and then decrypts data using an AWS KMS Keyring.
 * Demonstrates using a ClientSupplier to customize the KMS SDK Client.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *       key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class CustomizeSDKClient {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);
  // See the AWS SDK for Java V2's Guidance for HTTP Client options:
  // https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/http-configuration.html
  private static final SdkHttpClient singletonHttpClient = ApacheHttpClient.builder().build();

  public static void main(final String[] args) {
    final String keyArn = args[0];

    encryptAndDecryptWithKeyring(keyArn);
  }

  public static class CustomClientSupplier implements IClientSupplier {

    @Override
    public KmsClient GetClient(GetClientInput getClientInput) {
      return KmsClient.builder()
              .region(Region.of(getClientInput.region()))
              .httpClient(singletonHttpClient)
              .build();
    }
  }

  private static final CustomClientSupplier singletonClientSupplier = new CustomClientSupplier();

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

    // 2. Create an AWS KMS Multi-keyring.
    // Instead of allowing the KMS MultiKeyring to create the default KMS Client,
    // we use the client supplier interface to provide a Client.
    final MaterialProviders materialProviders =
            MaterialProviders.builder()
                    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                    .build();
    final CreateAwsKmsMultiKeyringInput multiKeyringInput =
            CreateAwsKmsMultiKeyringInput.builder()
                    .generator(keyArn)
                    .clientSupplier(singletonClientSupplier)
                    .build();
    final IKeyring kmsMultiKeyring = materialProviders.CreateAwsKmsMultiKeyring(multiKeyringInput);

    // 3. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
            Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 4. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
            crypto.encryptData(kmsMultiKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 5. Create an AWS KMS
    // If we use a normal, plain, KMS Keyring, we have to pass a KMS Client.
    // But we could customize this KMS Client to our heart's content.
    final CreateAwsKmsKeyringInput keyringInput = CreateAwsKmsKeyringInput.builder()
            .kmsClient(KmsClient.builder().httpClient(singletonHttpClient).build())
            .kmsKeyId(keyArn)
            .build();

    final IKeyring kmsKeyring = materialProviders.CreateAwsKmsKeyring(keyringInput);

    // 6. Decrypt the data
    final CryptoResult<byte[], ?> decryptResult =
            crypto.decryptData(
                    kmsKeyring,
                    ciphertext,
                    // Verify that the encryption context in the result contains the
                    // encryption context supplied to the encryptData method
                    encryptionContext);

    // 6. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }
}
