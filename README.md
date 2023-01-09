# AWS Encryption SDK for Java

The AWS Encryption SDK enables secure client-side encryption. It uses cryptography best practices to protect your data and protect the encryption keys that protect your data. Each data object is protected with a unique data encryption key, and the data encryption key is protected with a key encryption key called a *wrapping key* or *master key*. The encryption method returns a single, portable [encrypted message](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html) that contains the encrypted data and the encrypted data key, so you don't need to keep track of the data encryption keys for your data. You can use KMS keys in [AWS Key Management Service](https://aws.amazon.com/kms/) (AWS KMS) as wrapping keys. The AWS Encryption SDK also provides APIs to define and use encryption keys from other key providers. 

The AWS Encryption SDK for Java provides methods for encrypting and decrypting strings, byte arrays, and byte streams. For details, see the [example code][examples] and the [Javadoc](https://aws.github.io/aws-encryption-sdk-java).

For more details about the design and architecture of the AWS Encryption SDK, see the [AWS Encryption SDK Developer Guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/).

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

See [Support Policy](./SUPPORT_POLICY.rst) for details on the current support status of all major versions of this library.

## Getting Started

### Required Prerequisites
To use the AWS Encryption SDK for Java you must have:

* **A Java 8 or newer development environment**

  If you do not have one, we recommend [Amazon Corretto](https://aws.amazon.com/corretto/).

  **Note:** If you use the Oracle JDK, you must also download and install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

* **Bouncy Castle** or **Bouncy Castle FIPS**

  The AWS Encryption SDK for Java uses Bouncy Castle to serialize and deserialize cryptographic objects.
  It does not explicitly use Bouncy Castle (or any other [JCA Provider](https://docs.oracle.com/javase/8/docs/api/java/security/Provider.html)) for the underlying cryptography.
  Instead, it uses the platform default, which you can configure or override as documented in the
  [Java Cryptography Architecture (JCA) Reference Guide](https://docs.oracle.com/javase/9/security/java-cryptography-architecture-jca-reference-guide.htm#JSSEC-GUID-2BCFDD85-D533-4E6C-8CE9-29990DEB0190).

  If you do not have Bouncy Castle, go to https://bouncycastle.org/latest_releases.html, then download the provider file that corresponds to your JDK.
  Or, you can pick it up from Maven (groupId: `org.bouncycastle`, artifactId: `bcprov-ext-jdk15on`).

  Beginning in version 1.6.1, the AWS Encryption SDK for Java also works with Bouncy Castle FIPS (groupId: `org.bouncycastle`, artifactId: `bc-fips`)
  as an alternative to non-FIPS Bouncy Castle. For help installing and configuring Bouncy Castle FIPS, see [BC FIPS documentation](https://www.bouncycastle.org/documentation.html), in particular, **User Guides** and **Security Policy**.

### Optional Prerequisites

#### AWS Integration
You don't need an Amazon Web Services (AWS) account to use the AWS Encryption SDK, but some [example code][examples] require an AWS account, an AWS KMS key, and the AWS SDK for Java (either 1.x or 2.x). Note that the `KmsAsyncClient` is not supported, only the synchronous client.

* **To create an AWS account**, go to [Sign In or Create an AWS Account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html) and then choose **I am a new user.** Follow the instructions to create an AWS account.

* **To create a symmetric encryption KMS key in AWS KMS**, see [Creating Keys](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html).

* **To download and install the AWS SDK for Java 2.x**, see [Installing the AWS SDK for Java 2.x](https://docs.aws.amazon.com/sdk-for-java/v2/developer-guide/getting-started.html).

* **To download and install the AWS SDK for Java 1.x**, see [Installing the AWS SDK for Java 1.x](https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/getting-started.html).

#### Amazon Corretto Crypto Provider
Many users find that the Amazon Corretto Crypto Provider (ACCP) significantly improves the performance of the AWS Encryption SDK.
For help installing and using ACCP, see the [amazon-corretto-crypto-provider repository](https://github.com/corretto/amazon-corretto-crypto-provider).

### Download the AWS Encryption SDK for Java
You can get the latest release from Maven:

```xml
<dependency>
  <groupId>com.amazonaws</groupId>
  <artifactId>aws-encryption-sdk-java</artifactId>
  <version>2.4.0</version>
</dependency>
```

### Get Started
To get started with the AWS Encryption SDK for Java

1. Instantiate the AWS Encryption SDK.
2. Define the master key provider.
3. Encrypt and decrypt data.

```java
// This sample code encrypts and then decrypts a string using an AWS KMS key.
// You provide the KMS key ARN and plaintext string as arguments.
package com.amazonaws.crypto.examples;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

public class StringExample {
    private static String keyArn;
    private static String plaintext;

    public static void main(final String[] args) {
        keyArn = args[0];
        plaintext = args[1];

        // Instantiate the SDK
        final AwsCrypto crypto = AwsCrypto.standard();

        // Set up the master key provider
        final KmsMasterKeyProvider prov = KmsMasterKeyProvider.builder().buildStrict(keyArn);

        // Set up the encryption context
        // NOTE: Encrypted data should have associated encryption context
        // to protect its integrity. This example uses placeholder values.
        // For more information about the encryption context, see
        // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
        final Map<String, String> context = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // Encrypt the data
        //        
        final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(prov, plaintext.getBytes(StandardCharsets.UTF_8), context);
        final byte[] ciphertext = encryptResult.getResult();
        System.out.println("Ciphertext: " + Arrays.toString(ciphertext));

        // Decrypt the data
        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(prov, ciphertext);
        // Your application should verify the encryption context and the KMS key to
        // ensure this is the expected ciphertext before returning the plaintext
        if (!decryptResult.getMasterKeyIds().get(0).equals(keyArn)) {
            throw new IllegalStateException("Wrong key id!");
        }

        // The AWS Encryption SDK may add information to the encryption context, so check to
        // ensure all of the values that you specified when encrypting are *included* in the returned encryption context.
        if (!context.entrySet().stream()
            .allMatch( e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
                throw new IllegalStateException("Wrong Encryption Context!");
        }

        assert Arrays.equals(decryptResult.getResult(), plaintext.getBytes(StandardCharsets.UTF_8));

        // The data is correct, so return it. 
        System.out.println("Decrypted: " + new String(decryptResult.getResult(), StandardCharsets.UTF_8));
    }
}
```

You can find more examples in the [example directory][examples].

## Public API

Our [versioning policy](./VERSIONING.rst) applies to all public and protected classes/methods/fields
in the  `com.amazonaws.encryptionsdk` package unless otherwise documented.

The `com.amazonaws.encryptionsdk.internal` package is not included in this public API.

## FAQ

See the [Frequently Asked Questions](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/faq.html) page in the official documentation.

[examples]: https://github.com/aws/aws-encryption-sdk-java/tree/master/src/examples/java/com/amazonaws/crypto/examples
