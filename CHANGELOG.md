# Changelog

## 2.3.2 -- 2021-07-20

### Maintenance

* Bump maven-gpg-plugin from 1.6 to 3.0.1
([#259](https://github.com/aws/aws-encryption-sdk-java/pull/259))
* chore(deps): bump aws-java-sdk from 1.11.704 to 1.12.26
([#284](https://github.com/aws/aws-encryption-sdk-java/pull/284))
([#281](https://github.com/aws/aws-encryption-sdk-java/pull/281))
([#280](https://github.com/aws/aws-encryption-sdk-java/pull/280))
([#278](https://github.com/aws/aws-encryption-sdk-java/pull/278))
* Bump maven-javadoc-plugin from 3.0.1 to 3.3.0
([#267](https://github.com/aws/aws-encryption-sdk-java/pull/267))
* chore: Bump maven-compiler-plugin from 3.8.0 to 3.8.1
([#276](https://github.com/aws/aws-encryption-sdk-java/pull/276))
* chore: Bump fmt-maven-plugin from 2.10 to 2.11
([#275](https://github.com/aws/aws-encryption-sdk-java/pull/275))
* chore: Bump junit-vintage-engine from 5.7.1 to 5.7.2
([#268](https://github.com/aws/aws-encryption-sdk-java/pull/268))
* chore: Bump mockito-core from 3.8.0 to 3.11.2
([#270](https://github.com/aws/aws-encryption-sdk-java/pull/270))
* chore: Add support policy
([#274](https://github.com/aws/aws-encryption-sdk-java/pull/274))

## 2.3.1 -- 2021-06-29

* fix: read project properties from package's own ClassLoader [(PR #269)](https://github.com/aws/aws-encryption-sdk-java/pull/269)

## 2.3.0 -- 2021-06-16

* feat: AWS KMS multi-Region Key support
        
  Added new the master key AwsKmsMrkAwareMasterKey
  and the new master key provider AwsKmsMrkAwareMasterKeyProvider
  that support AWS KMS multi-Region Keys.

  See https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
  for more details about AWS KMS multi-Region Keys.
  
  See https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-mrks
  for more details about how the AWS Encryption SDK interoperates
  with AWS KMS multi-Region keys.

## 2.2.0 -- 2021-05-27

* feat: Improvements to the message decryption process. 

  See https://github.com/aws/aws-encryption-sdk-java/security/advisories/GHSA-55xh-53m6-936r


## 2.0.0 -- 2020-09-24

* feat!: Updates to the AWS Encryption SDK. 4678ffa

### BREAKING CHANGES

* AWS KMS KeyIDs must be specified explicitly or Discovery mode explicitly chosen.
Key committing suites are now default. CommitmentPolicy requires commitment by default.

See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html

## 1.7.0 -- 2020-09-24

* feat: Updates to the AWS Encryption SDK. a6be12a

## 1.6.2 -- 2020-05-26

### Patches
* Validate final frame length does not exceed the frame size in the message header [PR #166](https://github.com/aws/aws-encryption-sdk-java/pull/166)
* Validate entire ciphertext has been processed before returning [PR #191](https://github.com/aws/aws-encryption-sdk-java/pull/191)

### Maintenance
* Update AWS Java SDK version from 1.11.561 to 1.11.704. [PR #186](https://github.com/aws/aws-encryption-sdk-java/pull/186)
* Upgrade Bouncy Castle from 1.61 to 1.65 [PR #179](https://github.com/aws/aws-encryption-sdk-java/pull/179)

## 1.6.1 -- 2019-10-29

### Deprecation Warnings
* Deprecated `AwsCrypto.encryptString()` and `AwsCrypto.decryptString()`.
  Replace your calls to these methods with calls to AwsCrypto.encryptData() and AwsCrypto.decryptData().
  Unlike the deprecated methods, these methods don't perform any Base64 encoding or decoding, so they are fully compatible with other language implementations of the AWS Encryption SDK.
  
  If you need Base64 encoding or decoding for your application, you can add it outside of the AWS Encryption SDK.
  [PR #120](https://github.com/aws/aws-encryption-sdk-java/pull/120)

### Patches
* Correctly validate version [PR #116](https://github.com/aws/aws-encryption-sdk-java/pull/116)
* `ParsedCiphertext` now handles truncated input properly [PR #119](https://github.com/aws/aws-encryption-sdk-java/pull/119)

### Maintenance
* Add support for standard test vectors via `testVectorZip` system property. [PR #127](https://github.com/aws/aws-encryption-sdk-java/pull/127)
* Remove all explicit cryptographic dependencies on BouncyCastle. The AWS Encryption SDK for Java still uses Bouncy Castle for other tasks. PRs
  [#128](https://github.com/aws/aws-encryption-sdk-java/pull/128),
  [#129](https://github.com/aws/aws-encryption-sdk-java/pull/129),
  [#130](https://github.com/aws/aws-encryption-sdk-java/pull/130),
  [#131](https://github.com/aws/aws-encryption-sdk-java/pull/131),
  and [#132](https://github.com/aws/aws-encryption-sdk-java/pull/132).

## 1.6.0 -- 2019-05-31

### Minor Changes
* Remove dependency on Apache Commons Codec 1.12.
* Use Base64 encoder from Bouncy Castle.
* Introduce and use utility methods for Base64 encoding/decoding so that
  switching the codec provider needs to be done only in one place next time.

## 1.5.0 -- 2019-05-30

### Minor Changes
* Added dependency on Apache Commons Codec 1.12.
* Use org.apache.commons.codec.binary.Base64 instead of java.util.Base64 so
  that the SDK can be used on systems that do not have java.util.Base64 but
  support Java 8 language features.

### Maintenance
* Upgrade AWS Java SDK version from 1.11.169 to 1.11.561.
* Upgrade Mockito from 2.23.4 to 2.28.1.
* Upgrade Apache Commons Lang from 3.4 to 3.9.

## 1.4.1 -- 2019-05-10

### Patches
* Cast ByteBuffer to Buffer prior to using some methods so that it works properly in Java 8.

## 1.4.0 -- 2019-05-10

### Minor Changes
* Increased BouncyCastle dependency version to 1.61
* Removed explicit use of BouncyCastle from all cryptography except for EC key generation and RSA encryption/decryption

### Maintenance
* Increased Mockito test dependency version to 2.23.4

## 1.3.6 -- 2018-12-10

### Patches
* Fixed typos in Exception messages (excryption -> encryption) #78
* Fixed DecryptionMaterialsRequest.Builder to copy EncryptionContext #77

### Maintenance
* JML Specifications for CipherBlockHeaders #74
* Minor Java code cleanup #73
* Added JML specs in #72
* Ensure that KeyBlob treats field lengths as unsigned shorts #71

## 1.3.5

### Minor Changes

* Restored the KMS client cache with a fix for the memory leak.
* When using a master key provider that can only service a subset of regions
(e.g. using the deprecated constructors), and requesting a master key from a
region not servicable by that MKP, the exception will now be thrown on first
use of the MK, rather than at getMasterKey time.

## 1.3.4

### Minor Changes

* Removed the KMS client cache, which could result in a memory leak when
decrypting certain malformed ciphertexts. This may reduce performance slightly
in some scenarios.

## 1.3.3

### Minor Changes
* Move the `aws-encryption-sdk-java` repository from `awslabs` to `aws`.
* Log a warning when an unsupported asymmetric algorithm is used with `JceMasterKey`
* Make `JceMasterKey` case insensitive
* Fix bare aliases not using default region

## 1.3.2

### Minor Changes
* Frame size restriction removed again
* Support Builders for use with AWS KMS
* Fix estimateCipherText when used with cached data keys
* Do not automatically set a default region in KmsMasterKeyProvider

## 1.3.1

### Minor changes

* Frame sizes are once again required to be aligned to 16 bytes
  This restriction was relaxed in 1.3.0, but due to compatibility concerns
  we'll put this restriction back in for the time being.

## 1.3.0

### Major changes

* Synchronized version numbers with the Python release
* Added cryptographic materials managers
* Added data key caching
* Moved to deterministic IV generation

### Minor changes

* Added changelog
* Made elliptic curve signatures length deterministic
* Various minor improvements
