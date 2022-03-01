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

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;
import software.amazon.awssdk.services.kms.model.UnsupportedOperationException;

public class MockKmsClient implements KmsClient {
  private static final SecureRandom rnd = new SecureRandom();
  private static final String ACCOUNT_ID = "01234567890";
  private final Map<DecryptMapKey, DecryptResponse> responses_ = new HashMap<>();
  private final Set<String> activeKeys = new HashSet<>();
  private final Map<String, String> keyAliases = new HashMap<>();
  private Region region_ = Region.US_WEST_2;

  @Override
  public final String serviceName() {
    return SERVICE_NAME;
  }

  @Override
  public void close() {}

  @Override
  public CreateAliasResponse createAlias(CreateAliasRequest req) {
    assertExists(req.targetKeyId());

    keyAliases.put("alias/" + req.aliasName(), keyAliases.get(req.targetKeyId()));

    return CreateAliasResponse.builder().build();
  }

  @Override
  public CreateKeyResponse createKey() {
    return createKey(CreateKeyRequest.builder().build());
  }

  @Override
  public CreateKeyResponse createKey(CreateKeyRequest req) {
    String keyId = UUID.randomUUID().toString();
    String arn = "arn:aws:kms:" + region_.id() + ":" + ACCOUNT_ID + ":key/" + keyId;
    activeKeys.add(arn);
    keyAliases.put(keyId, arn);
    keyAliases.put(arn, arn);
    return CreateKeyResponse.builder()
        .keyMetadata(
            KeyMetadata.builder()
                .awsAccountId(ACCOUNT_ID)
                .creationDate(Instant.now())
                .description(req.description())
                .enabled(true)
                .keyId(keyId)
                .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                .arn(arn)
                .build())
        .build();
  }

  @Override
  public DecryptResponse decrypt(DecryptRequest req) {
    DecryptResponse response = responses_.get(new DecryptMapKey(req));
    if (response != null) {
      // Copy it to avoid external modification
      return DecryptResponse.builder()
          .keyId(retrieveArn(response.keyId()))
          .plaintext(SdkBytes.fromByteArray(response.plaintext().asByteArray()))
          .build();
    } else {
      throw InvalidCiphertextException.builder().message("Invalid Ciphertext").build();
    }
  }

  @Override
  public DescribeKeyResponse describeKey(DescribeKeyRequest req) {
    final String arn = retrieveArn(req.keyId());

    return DescribeKeyResponse.builder()
        .keyMetadata(KeyMetadata.builder().arn(arn).keyId(arn).build())
        .build();
  }

  @Override
  public EncryptResponse encrypt(EncryptRequest req) {
    // We internally delegate to encrypt, so as to avoid mockito detecting extra calls to encrypt
    // when spying on the
    // MockKMSClient, we put the real logic into a separate function.
    return encrypt0(req);
  }

  private EncryptResponse encrypt0(EncryptRequest req) {
    String arn = retrieveArn(req.keyId());

    final byte[] cipherText = new byte[512];
    rnd.nextBytes(cipherText);
    DecryptResponse dec =
        DecryptResponse.builder()
            .keyId(retrieveArn(arn))
            .plaintext(SdkBytes.fromByteArray(req.plaintext().asByteArray()))
            .build();
    ByteBuffer ctBuff = ByteBuffer.wrap(cipherText);
    responses_.put(new DecryptMapKey(ctBuff, req.encryptionContext()), dec);

    return EncryptResponse.builder()
        .ciphertextBlob(SdkBytes.fromByteBuffer(ctBuff))
        .keyId(arn)
        .build();
  }

  @Override
  public GenerateDataKeyResponse generateDataKey(GenerateDataKeyRequest req) {
    byte[] pt;
    DataKeySpec keySpec = req.keySpec();
    if (keySpec == null) {
      pt = new byte[req.numberOfBytes()];
    } else {
      switch (keySpec) {
        case AES_256:
          pt = new byte[32];
          break;
        case AES_128:
          pt = new byte[16];
          break;
        default:
          throw UnsupportedOperationException.builder().build();
      }
    }
    rnd.nextBytes(pt);

    String arn = retrieveArn(req.keyId());
    EncryptResponse encryptResponse =
        encrypt0(
            EncryptRequest.builder()
                .keyId(arn)
                .plaintext(SdkBytes.fromByteArray(pt))
                .encryptionContext(req.encryptionContext())
                .build());

    return GenerateDataKeyResponse.builder()
        .keyId(arn)
        .ciphertextBlob(encryptResponse.ciphertextBlob())
        .plaintext(SdkBytes.fromByteArray(pt))
        .build();
  }

  public GenerateDataKeyWithoutPlaintextResponse generateDataKeyWithoutPlaintext(
      GenerateDataKeyWithoutPlaintextRequest req) {
    String arn = retrieveArn(req.keyId());
    GenerateDataKeyRequest generateDataKeyRequest =
        GenerateDataKeyRequest.builder()
            .encryptionContext(req.encryptionContext())
            .grantTokens(req.grantTokens())
            .keyId(arn)
            .keySpec(req.keySpec())
            .numberOfBytes(req.numberOfBytes())
            .build();
    GenerateDataKeyResponse generateDataKey = generateDataKey(generateDataKeyRequest);

    return GenerateDataKeyWithoutPlaintextResponse.builder()
        .ciphertextBlob(generateDataKey.ciphertextBlob())
        .keyId(arn)
        .build();
  }

  public void setRegion(Region req) {
    region_ = req;
  }

  public void deleteKey(final String keyId) {
    final String arn = retrieveArn(keyId);
    activeKeys.remove(arn);
  }

  private String retrieveArn(final String keyId) {
    String arn = keyAliases.get(keyId);
    assertExists(arn);
    return arn;
  }

  private void assertExists(String keyId) {
    if (keyAliases.containsKey(keyId)) {
      keyId = keyAliases.get(keyId);
    }
    if (keyId == null || !activeKeys.contains(keyId)) {
      throw NotFoundException.builder().message("Key doesn't exist: " + keyId).build();
    }
  }

  private static class DecryptMapKey {
    private final ByteBuffer cipherText;
    private final Map<String, String> ec;

    public DecryptMapKey(DecryptRequest req) {
      cipherText = req.ciphertextBlob().asByteBuffer();
      if (req.encryptionContext() != null) {
        ec = Collections.unmodifiableMap(new HashMap<>(req.encryptionContext()));
      } else {
        ec = Collections.emptyMap();
      }
    }

    public DecryptMapKey(ByteBuffer ctBuff, Map<String, String> ec) {
      cipherText = ctBuff.asReadOnlyBuffer();
      if (ec != null) {
        this.ec = Collections.unmodifiableMap(new HashMap<>(ec));
      } else {
        this.ec = Collections.emptyMap();
      }
    }

    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((cipherText == null) ? 0 : cipherText.hashCode());
      result = prime * result + ((ec == null) ? 0 : ec.hashCode());
      return result;
    }

    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (getClass() != obj.getClass()) return false;
      DecryptMapKey other = (DecryptMapKey) obj;
      if (cipherText == null) {
        if (other.cipherText != null) return false;
      } else if (!cipherText.equals(other.cipherText)) return false;
      if (ec == null) {
        if (other.ec != null) return false;
      } else if (!ec.equals(other.ec)) return false;
      return true;
    }

    public String toString() {
      return "DecryptMapKey [cipherText=" + cipherText + ", ec=" + ec + "]";
    }
  }
}
