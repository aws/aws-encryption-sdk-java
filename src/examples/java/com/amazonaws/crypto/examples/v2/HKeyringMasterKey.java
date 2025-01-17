package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.*;

public class HKeyringMasterKey extends MasterKey<HKeyringMasterKey> {

  final private IKeyring hKeyring;
  final private CreateAwsKmsHierarchicalKeyringInput hKeyringInput;
  final private MaterialProviders mpl;

  public HKeyringMasterKey(
          CreateAwsKmsHierarchicalKeyringInput input
  ) {
    if (input.branchKeyIdSupplier() != null) throw new UnsupportedProviderException("branchKeyIdSupplier must be null");
    if (input.branchKeyId() == null) throw new UnsupportedProviderException("branchKeyId cannot be null");
    hKeyringInput = input;
    mpl =
            MaterialProviders.builder()
                    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                    .build();
    hKeyring = mpl.CreateAwsKmsHierarchicalKeyring(hKeyringInput);
  }

  @Override
  public String getProviderId() {
    return "aws-kms-hierarchy";
  }

  @Override
  public String getKeyId() {
    return this.hKeyringInput.branchKeyId();
  }

  /**
   * Generates a new {@link DataKey} which is protected by this {@link MasterKey} for use with
   * {@code algorithm} and associated with the provided {@code encryptionContext}.
   *
   * @param algorithm
   * @param encryptionContext
   */
  @Override
  public DataKey<HKeyringMasterKey> generateDataKey(CryptoAlgorithm algorithm, Map<String, String> encryptionContext) {
    AlgorithmSuiteInfo algorithmSuiteInfo = ValidateAndConvertAlgo(algorithm);
    EncryptionMaterials encryptionMaterials = EncryptionMaterials.builder()
            .algorithmSuite(algorithmSuiteInfo)
            .encryptionContext(encryptionContext)
            .encryptedDataKeys(Collections.emptyList())
            .requiredEncryptionContextKeys(Collections.emptyList())
            .build();
    OnEncryptInput eInput = OnEncryptInput.builder()
            .materials(encryptionMaterials)
            .build();
    OnEncryptOutput onEncryptOutput = hKeyring.OnEncrypt(eInput);
    software.amazon.cryptography.materialproviders.model.EncryptedDataKey encryptedDataKey = onEncryptOutput.materials().encryptedDataKeys().get(0);
    return new DataKey<>(
            new SecretKeySpec(onEncryptOutput.materials().plaintextDataKey().array(), algorithm.getDataKeyAlgo()),
            encryptedDataKey.ciphertext().array(),
            encryptedDataKey.keyProviderInfo().array(),
            this);
  }

  /**
   * Returns a new copy of the provided {@code dataKey} which is protected by this {@link MasterKey}
   * for use with {@code algorithm} and associated with the provided {@code encryptionContext}.
   *
   * @param algorithm
   * @param encryptionContext
   * @param dataKey
   */
  @Override
  public DataKey<HKeyringMasterKey> encryptDataKey(
          CryptoAlgorithm algorithm,
          Map<String, String> encryptionContext,
          DataKey<?> dataKey
  ) {
    AlgorithmSuiteInfo algorithmSuiteInfo = ValidateAndConvertAlgo(algorithm);
    final SecretKey key = dataKey.getKey();
    if (!key.getFormat().equals("RAW")) {
      throw new IllegalArgumentException(
              "Can only re-encrypt data keys which are in RAW format, not "
                      + dataKey.getKey().getFormat());
    }
    EncryptionMaterials encryptionMaterials = EncryptionMaterials.builder()
            .algorithmSuite(algorithmSuiteInfo)
            .encryptionContext(encryptionContext)
            .encryptedDataKeys(Collections.emptyList())
            .requiredEncryptionContextKeys(Collections.emptyList())
            .plaintextDataKey(ByteBuffer.wrap(dataKey.getKey().getEncoded()))
            .build();
    OnEncryptInput eInput = OnEncryptInput.builder()
            .materials(encryptionMaterials)
            .build();
    OnEncryptOutput onEncryptOutput = hKeyring.OnEncrypt(eInput);
    software.amazon.cryptography.materialproviders.model.EncryptedDataKey encryptedDataKey = onEncryptOutput.materials().encryptedDataKeys().get(0);
    return new DataKey<>(
            key,
            encryptedDataKey.ciphertext().array(),
            encryptedDataKey.keyProviderInfo().array(),
            this);
  }

  /**
   * Iterates through {@code encryptedDataKeys} and returns the first one which can be successfully
   * decrypted.
   *
   * @param algorithm
   * @param encryptedDataKeys
   * @param encryptionContext
   * @return a DataKey if one can be decrypted, otherwise returns {@code null}
   * @throws UnsupportedProviderException if the {@code encryptedDataKey} is associated with an
   *                                      unsupported provider
   * @throws CannotUnwrapDataKeyException if the {@code encryptedDataKey} cannot be decrypted
   */
  @Override
  public DataKey<HKeyringMasterKey> decryptDataKey(
          CryptoAlgorithm algorithm,
          Collection<? extends EncryptedDataKey> encryptedDataKeys,
          Map<String, String> encryptionContext
  ) throws UnsupportedProviderException, AwsCryptoException
  {
    AlgorithmSuiteInfo algorithmSuiteInfo = ValidateAndConvertAlgo(algorithm);
    if (encryptedDataKeys.size() != 1) {
      // TODO: If needed, we could refactor this to properly support multiple EDKs, it would not be hard.
      throw new UnsupportedProviderException("Alas, this Master Key Provider can work with one (1) Encrypted Data Key; got " + encryptedDataKeys.size());
    }
    List<EncryptedDataKey> nativeEDKS = EDKCollectionToNative(encryptedDataKeys);
    List<software.amazon.cryptography.materialproviders.model.EncryptedDataKey> mplEDKS = EDKCollectionToMPL(encryptedDataKeys);
    DecryptionMaterials decryptionMaterials = DecryptionMaterials.builder()
            .algorithmSuite(algorithmSuiteInfo)
            .encryptionContext(encryptionContext)
            .requiredEncryptionContextKeys(Collections.emptyList())
            .build();
    OnDecryptInput onDecryptInput = OnDecryptInput.builder()
            .encryptedDataKeys(mplEDKS)
            .materials(decryptionMaterials)
            .build();
    OnDecryptOutput onDecryptOutput = this.hKeyring.OnDecrypt(onDecryptInput);
    if (onDecryptOutput.materials().plaintextDataKey() != null) {
      if (onDecryptOutput.materials().plaintextDataKey().array().length != algorithm.getDataKeyLength())
        throw new AwsCryptoException("Decrypted Data Key is incorrect length!");
      return new DataKey<>(
              new SecretKeySpec(onDecryptOutput.materials().plaintextDataKey().array(), algorithm.getDataKeyAlgo()),
              nativeEDKS.get(0).getEncryptedDataKey(),
              nativeEDKS.get(0).getProviderInformation(),
              this
      );
    }
    return null;
  }

  private List<software.amazon.cryptography.materialproviders.model.EncryptedDataKey> EDKCollectionToMPL(
          Collection<? extends EncryptedDataKey> encryptedDataKeys
  ) {
    List<software.amazon.cryptography.materialproviders.model.EncryptedDataKey> mplEDKS =
            new ArrayList<>(encryptedDataKeys.size());

    for (EncryptedDataKey keyBlob : encryptedDataKeys) {
      mplEDKS.add(
              software.amazon.cryptography.materialproviders.model.EncryptedDataKey.builder()
                      .keyProviderId(keyBlob.getProviderId())
                      .keyProviderInfo(
                              ByteBuffer.wrap(
                                      keyBlob.getProviderInformation(), 0, keyBlob.getProviderInformation().length))
                      .ciphertext(
                              ByteBuffer.wrap(
                                      keyBlob.getEncryptedDataKey(), 0, keyBlob.getEncryptedDataKey().length))
                      .build());
    }
    return mplEDKS;
  }

  private List<EncryptedDataKey> EDKCollectionToNative(
          Collection<? extends EncryptedDataKey> encryptedDataKeys
  ) {
    List<EncryptedDataKey> nativeEDKS = new ArrayList<>(encryptedDataKeys.size());
    nativeEDKS.addAll(encryptedDataKeys);
    return nativeEDKS;
  }

  private AlgorithmSuiteInfo ValidateAndConvertAlgo(
          CryptoAlgorithm algorithm
  ) {
    if (algorithm.getTrailingSignatureAlgo() != null) {
      throw new UnsupportedProviderException("The HKeyringMasterKey provider does not support trailing signature algorithms!");
    }
    return mpl.GetAlgorithmSuiteInfo(ByteBuffer.allocate(2).putShort((short) algorithm.getValue()));
  }
}
