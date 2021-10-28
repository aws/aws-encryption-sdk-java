// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.multi.MultipleProviderFactory.buildMultiProvider;
import static java.util.Collections.singletonMap;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import org.junit.Test;

public class DefaultCryptoMaterialsManagerTest {
  private static final MasterKey<?> mk1 = new StaticMasterKey("mk1");
  private static final MasterKey<?> mk2 = new StaticMasterKey("mk2");
  private static final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;

  @Test
  public void encrypt_testBasicFunctionality() throws Exception {
    EncryptionMaterialsRequest req =
        EncryptionMaterialsRequest.newBuilder().setCommitmentPolicy(commitmentPolicy).build();
    EncryptionMaterials result = new DefaultCryptoMaterialsManager(mk1).getMaterialsForEncrypt(req);

    assertNotNull(result.getCleartextDataKey());
    assertNotNull(result.getEncryptionContext());
    assertEquals(
        CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, result.getAlgorithm());
    assertEquals(1, result.getEncryptedDataKeys().size());
    assertEquals(1, result.getMasterKeys().size());
    assertEquals(mk1, result.getMasterKeys().get(0));
  }

  @Test
  public void encrypt_noSignatureKeyOnUnsignedAlgo() throws Exception {
    CryptoAlgorithm[] algorithms =
        new CryptoAlgorithm[] {
          CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256,
          CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF,
          CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256,
          CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_NO_KDF,
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256,
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
        };

    for (CryptoAlgorithm algo : algorithms) {
      EncryptionMaterialsRequest req =
          EncryptionMaterialsRequest.newBuilder()
              .setCommitmentPolicy(commitmentPolicy)
              .setRequestedAlgorithm(algo)
              .build();
      EncryptionMaterials result =
          new DefaultCryptoMaterialsManager(mk1).getMaterialsForEncrypt(req);

      assertNull(result.getTrailingSignatureKey());
      assertEquals(0, result.getEncryptionContext().size());
      assertEquals(algo, result.getAlgorithm());
    }
  }

  @Test
  public void encrypt_hasSignatureKeyForSignedAlgo() throws Exception {
    CryptoAlgorithm[] algorithms =
        new CryptoAlgorithm[] {
          CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
          CryptoAlgorithm.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
          CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        };

    for (CryptoAlgorithm algo : algorithms) {

      EncryptionMaterialsRequest req =
          EncryptionMaterialsRequest.newBuilder()
              .setCommitmentPolicy(commitmentPolicy)
              .setRequestedAlgorithm(algo)
              .build();
      EncryptionMaterials result =
          new DefaultCryptoMaterialsManager(mk1).getMaterialsForEncrypt(req);

      assertNotNull(result.getTrailingSignatureKey());
      assertEquals(1, result.getEncryptionContext().size());
      assertNotNull(result.getEncryptionContext().get(Constants.EC_PUBLIC_KEY_FIELD));
      assertEquals(algo, result.getAlgorithm());
    }
  }

  @Test
  public void encrypt_dispatchesMultipleMasterKeys() throws Exception {
    MasterKey<?> mk1_spy = spy(mk1);
    MasterKey<?> mk2_spy = spy(mk2);

    DataKey[] mk1_datakey = new DataKey[1];

    doAnswer(
            invocation -> {
              Object dk = invocation.callRealMethod();
              mk1_datakey[0] = (DataKey) dk;

              return dk;
            })
        .when(mk1_spy)
        .generateDataKey(any(), any());

    MasterKeyProvider<?> mkp = buildMultiProvider(mk1_spy, mk2_spy);

    EncryptionMaterialsRequest req =
        EncryptionMaterialsRequest.newBuilder()
            .setCommitmentPolicy(commitmentPolicy)
            .setContext(singletonMap("foo", "bar"))
            .build();

    EncryptionMaterials result = new DefaultCryptoMaterialsManager(mkp).getMaterialsForEncrypt(req);

    //noinspection unchecked
    verify(mk1_spy)
        .generateDataKey(
            any(),
            // there's a weird generics issue here without downcasting to (Map)
            (Map) argThat((Map m) -> Objects.equals(m.get("foo"), "bar")));

    //noinspection unchecked
    verify(mk2_spy)
        .encryptDataKey(
            any(),
            (Map) argThat((Map m) -> Objects.equals(m.get("foo"), "bar")),
            same(mk1_datakey[0]));

    assertArrayEquals(
        mk1_datakey[0].getKey().getEncoded(), result.getCleartextDataKey().getEncoded());
  }

  @Test
  public void encrypt_forwardsPlaintextWhenAvailable() throws Exception {
    MasterKey<?> mk1_spy = spy(mk1);

    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder()
            .setCommitmentPolicy(commitmentPolicy)
            .setPlaintext(new byte[1])
            .build();
    new DefaultCryptoMaterialsManager(mk1_spy).getMaterialsForEncrypt(request);

    verify(mk1_spy)
        .getMasterKeysForEncryption(
            argThat(req -> Arrays.equals(req.getPlaintext(), new byte[1]) && !req.isStreaming()));
  }

  @Test
  public void encrypt_forwardsPlaintextSizeWhenAvailable() throws Exception {
    MasterKey<?> mk1_spy = spy(mk1);

    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder()
            .setCommitmentPolicy(commitmentPolicy)
            .setPlaintextSize(1)
            .build();
    new DefaultCryptoMaterialsManager(mk1_spy).getMaterialsForEncrypt(request);

    verify(mk1_spy)
        .getMasterKeysForEncryption(argThat(req -> req.getSize() == 1 && !req.isStreaming()));
  }

  @Test
  public void encrypt_setsStreamingWhenNoSizeAvailable() throws Exception {
    MasterKey<?> mk1_spy = spy(mk1);

    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder().setCommitmentPolicy(commitmentPolicy).build();
    new DefaultCryptoMaterialsManager(mk1_spy).getMaterialsForEncrypt(request);

    verify(mk1_spy).getMasterKeysForEncryption(argThat(MasterKeyRequest::isStreaming));
  }

  @Test(expected = IllegalArgumentException.class)
  public void encrypt_whenECContextKeyPresent_throws() throws Exception {
    EncryptionMaterialsRequest req =
        EncryptionMaterialsRequest.newBuilder()
            .setCommitmentPolicy(commitmentPolicy)
            .setRequestedAlgorithm(
                CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
            .setContext(singletonMap(Constants.EC_PUBLIC_KEY_FIELD, "some EC key"))
            .build();

    new DefaultCryptoMaterialsManager(mk1).getMaterialsForEncrypt(req);
  }

  @Test(expected = IllegalArgumentException.class)
  public void encrypt_whenNoMasterKeys_throws() throws Exception {
    EncryptionMaterialsRequest req =
        EncryptionMaterialsRequest.newBuilder().setCommitmentPolicy(commitmentPolicy).build();
    new DefaultCryptoMaterialsManager(
            new MasterKeyProvider() {
              @Override
              public String getDefaultProviderId() {
                return "provider ID";
              }

              @Override
              public MasterKey getMasterKey(String provider, String keyId)
                  throws UnsupportedProviderException, NoSuchMasterKeyException {
                throw new NoSuchMasterKeyException();
              }

              @Override
              public List getMasterKeysForEncryption(MasterKeyRequest request) {
                return Collections.emptyList();
              }

              @Override
              public DataKey decryptDataKey(
                  CryptoAlgorithm algorithm, Collection encryptedDataKeys, Map encryptionContext)
                  throws UnsupportedProviderException, AwsCryptoException {
                return null;
              }
            })
        .getMaterialsForEncrypt(req);
  }

  private EncryptionMaterials easyGenMaterials(
      Consumer<EncryptionMaterialsRequest.Builder> customizer) {
    EncryptionMaterialsRequest.Builder request =
        EncryptionMaterialsRequest.newBuilder().setCommitmentPolicy(commitmentPolicy);

    customizer.accept(request);

    return new DefaultCryptoMaterialsManager(mk1).getMaterialsForEncrypt(request.build());
  }

  private DecryptionMaterialsRequest decryptReqFromMaterials(EncryptionMaterials result) {
    return DecryptionMaterialsRequest.newBuilder()
        .setEncryptionContext(result.getEncryptionContext())
        .setEncryptedDataKeys(result.getEncryptedDataKeys())
        .setAlgorithm(result.getAlgorithm())
        .build();
  }

  @Test
  public void decrypt_testSimpleRoundTrip() throws Exception {
    for (CryptoAlgorithm algorithm : CryptoAlgorithm.values()) {
      // Only test algorithms without key commitment
      if (algorithm.getMessageFormatVersion() != 1) {
        continue;
      }
      EncryptionMaterials encryptMaterials =
          easyGenMaterials(builder -> builder.setRequestedAlgorithm(algorithm));

      DecryptionMaterials decryptMaterials =
          new DefaultCryptoMaterialsManager(mk1)
              .decryptMaterials(decryptReqFromMaterials(encryptMaterials));

      assertArrayEquals(
          decryptMaterials.getDataKey().getKey().getEncoded(),
          encryptMaterials.getCleartextDataKey().getEncoded());

      if (encryptMaterials.getTrailingSignatureKey() == null) {
        assertNull(decryptMaterials.getTrailingSignatureKey());
      } else {
        Signature sig =
            Signature.getInstance(
                TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm).getHashAndSignAlgorithm());

        sig.initSign(encryptMaterials.getTrailingSignatureKey());

        byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);

        sig.update(data);
        byte[] signature = sig.sign();

        sig.initVerify(decryptMaterials.getTrailingSignatureKey());

        sig.update(data);
        sig.verify(signature);
      }
    }
  }

  @Test(expected = CannotUnwrapDataKeyException.class)
  public void decrypt_onDecryptFailure() throws Exception {
    new DefaultCryptoMaterialsManager(mock(MasterKeyProvider.class))
        .decryptMaterials(decryptReqFromMaterials(easyGenMaterials(ignored -> {})));
  }

  @Test
  public void decrypt_whenTrailingSigMissing_throwsException() throws Exception {
    for (CryptoAlgorithm algorithm : CryptoAlgorithm.values()) {
      // Only test algorithms without key commitment
      if (algorithm.getMessageFormatVersion() != 1) {
        continue;
      }
      if (algorithm.getTrailingSignatureLength() == 0) {
        continue;
      }

      EncryptionMaterials encryptMaterials =
          easyGenMaterials(builder -> builder.setRequestedAlgorithm(algorithm));

      DecryptionMaterialsRequest request =
          DecryptionMaterialsRequest.newBuilder()
              .setEncryptedDataKeys(encryptMaterials.getEncryptedDataKeys())
              .setAlgorithm(algorithm)
              .setEncryptionContext(Collections.emptyMap())
              .build();

      try {
        new DefaultCryptoMaterialsManager(mk1).decryptMaterials(request);
        fail("expected exception");
      } catch (AwsCryptoException e) {
        // ok
        continue;
      }
    }
  }
}
