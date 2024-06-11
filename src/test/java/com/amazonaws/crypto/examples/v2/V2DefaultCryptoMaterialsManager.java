// @formatter:off
// This is copy-paste and has formatting issues.
package com.amazonaws.crypto.examples.v2;

import static com.amazonaws.encryptionsdk.internal.Utils.assertNonNull;

import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.internal.Constants;
import com.amazonaws.encryptionsdk.internal.TrailingSignatureAlgorithm;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
 This is a copy-paste of the DefaultCryptoMaterialsManager implementation
 from the final commit of the V2 ESDK: 1870a082358d59e32c60d74116d6f43c0efa466b
 ESDK V3 implicitly changed the contract between CMMs and the ESDK.
 After V3, DecryptMaterials has an `encryptionContext` attribute,
 and CMMs are expected to set this attribute.
 The V3 commit modified this DefaultCMM's `decryptMaterials` implementation
 to set encryptionContext on returned DecryptionMaterials objects.
 However, there are custom implementations of the legacy native CMM
 that do not set encryptionContext.
 This CMM is used to explicitly assert that the V2 implementation of
 the DefaultCMM is compatible with V3 logic,
 which implicitly asserts that custom implementations of V2-compatible CMMs
 are also compatible with V3 logic.
*/
public class V2DefaultCryptoMaterialsManager implements CryptoMaterialsManager {
  private final MasterKeyProvider<?> mkp;

  private final CryptoAlgorithm DEFAULT_CRYPTO_ALGORITHM =
      CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

  /**
   * @param mkp The master key provider to delegate to
   */
  public V2DefaultCryptoMaterialsManager(MasterKeyProvider<?> mkp) {
    assertNonNull(mkp, "mkp");
    this.mkp = mkp;
  }

  @Override
  public EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request) {
    Map<String, String> context = request.getContext();

    CryptoAlgorithm algo = request.getRequestedAlgorithm();
    CommitmentPolicy commitmentPolicy = request.getCommitmentPolicy();
    // Set default according to commitment policy
    if (algo == null && commitmentPolicy == CommitmentPolicy.ForbidEncryptAllowDecrypt) {
      algo = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    } else if (algo == null) {
      algo = CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    }

    KeyPair trailingKeys = null;
    if (algo.getTrailingSignatureLength() > 0) {
      try {
        trailingKeys = generateTrailingSigKeyPair(algo);
        if (context.containsKey(Constants.EC_PUBLIC_KEY_FIELD)) {
          throw new IllegalArgumentException(
              "EncryptionContext contains reserved field " + Constants.EC_PUBLIC_KEY_FIELD);
        }
        // make mutable
        context = new HashMap<>(context);
        context.put(Constants.EC_PUBLIC_KEY_FIELD, serializeTrailingKeyForEc(algo, trailingKeys));
      } catch (final GeneralSecurityException ex) {
        throw new AwsCryptoException(ex);
      }
    }

    final MasterKeyRequest.Builder mkRequestBuilder = MasterKeyRequest.newBuilder();
    mkRequestBuilder.setEncryptionContext(context);

    mkRequestBuilder.setStreaming(request.getPlaintextSize() == -1);
    if (request.getPlaintext() != null) {
      mkRequestBuilder.setPlaintext(request.getPlaintext());
    } else {
      mkRequestBuilder.setSize(request.getPlaintextSize());
    }

    @SuppressWarnings("unchecked")
    final List<MasterKey> mks =
        (List<MasterKey>)
            assertNonNull(mkp, "provider").getMasterKeysForEncryption(mkRequestBuilder.build());

    if (mks.isEmpty()) {
      throw new IllegalArgumentException("No master keys provided");
    }

    DataKey<?> dataKey = mks.get(0).generateDataKey(algo, context);

    List<KeyBlob> keyBlobs = new ArrayList<>(mks.size());
    keyBlobs.add(new KeyBlob(dataKey));

    for (int i = 1; i < mks.size(); i++) {
      //noinspection unchecked
      keyBlobs.add(new KeyBlob(mks.get(i).encryptDataKey(algo, context, dataKey)));
    }

    //noinspection unchecked
    return EncryptionMaterials.newBuilder()
        .setAlgorithm(algo)
        .setCleartextDataKey(dataKey.getKey())
        .setEncryptedDataKeys(keyBlobs)
        .setEncryptionContext(context)
        .setTrailingSignatureKey(trailingKeys == null ? null : trailingKeys.getPrivate())
        .setMasterKeys(mks)
        .build();
  }

  @Override
  public DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request) {
    DataKey<?> dataKey =
        mkp.decryptDataKey(
            request.getAlgorithm(), request.getEncryptedDataKeys(), request.getEncryptionContext());

    if (dataKey == null) {
      throw new CannotUnwrapDataKeyException("Could not decrypt any data keys");
    }

    PublicKey pubKey = null;
    if (request.getAlgorithm().getTrailingSignatureLength() > 0) {
      try {
        String serializedPubKey = request.getEncryptionContext().get(Constants.EC_PUBLIC_KEY_FIELD);

        if (serializedPubKey == null) {
          throw new AwsCryptoException("Missing trailing signature public key");
        }

        pubKey = deserializeTrailingKeyFromEc(request.getAlgorithm(), serializedPubKey);
      } catch (final IllegalStateException ex) {
        throw new AwsCryptoException(ex);
      }
    } else if (request.getEncryptionContext().containsKey(Constants.EC_PUBLIC_KEY_FIELD)) {
      throw new AwsCryptoException("Trailing signature public key found for non-signed algorithm");
    }

    return DecryptionMaterials.newBuilder()
        .setDataKey(dataKey)
        .setTrailingSignatureKey(pubKey)
        .build();
  }

  private PublicKey deserializeTrailingKeyFromEc(CryptoAlgorithm algo, String pubKey) {
    return TrailingSignatureAlgorithm.forCryptoAlgorithm(algo).deserializePublicKey(pubKey);
  }

  private static String serializeTrailingKeyForEc(CryptoAlgorithm algo, KeyPair trailingKeys) {
    return TrailingSignatureAlgorithm.forCryptoAlgorithm(algo)
        .serializePublicKey(trailingKeys.getPublic());
  }

  private static KeyPair generateTrailingSigKeyPair(CryptoAlgorithm algo)
      throws GeneralSecurityException {
    return TrailingSignatureAlgorithm.forCryptoAlgorithm(algo).generateKey();
  }
}
// @formatter:on