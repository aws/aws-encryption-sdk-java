// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.DecryptionHandler;
import com.amazonaws.encryptionsdk.internal.EncryptionHandler;
import com.amazonaws.encryptionsdk.internal.LazyMessageCryptoHandler;
import com.amazonaws.encryptionsdk.internal.MessageCryptoHandler;
import com.amazonaws.encryptionsdk.internal.ProcessingSummary;
import com.amazonaws.encryptionsdk.internal.SignaturePolicy;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsHandler;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

/**
 * Provides the primary entry-point to the AWS Encryption SDK. All encryption and decryption
 * operations should start here. Most people will want to use either {@link
 * #encryptData(MasterKeyProvider, byte[], Map)} and {@link #decryptData(MasterKeyProvider, byte[])}
 * to encrypt/decrypt things.
 *
 * <p>The core concepts (and classes) in this SDK are:
 *
 * <ul>
 *   <li>{@link AwsCrypto}
 *   <li>{@link DataKey}
 *   <li>{@link MasterKey}
 *   <li>{@link MasterKeyProvider}
 * </ul>
 *
 * <p>{@link AwsCrypto} provides the primary way to encrypt/decrypt data. It can operate on
 * byte-arrays, streams, or {@link java.lang.String Strings}. This data is encrypted using the
 * specifed {@link CryptoAlgorithm} and a {@link DataKey} which is unique to each encrypted message.
 * This {@code DataKey} is then encrypted using one (or more) {@link MasterKey MasterKeys}. The
 * process is reversed on decryption with the code selecting a copy of the {@code DataKey} protected
 * by a usable {@code MasterKey}, decrypting the {@code DataKey}, and then decrypted the message.
 *
 * <p>The main way to get a {@code MasterKey} is through the use of a {@link MasterKeyProvider}.
 * This provides a common interface for the AwsEncryptionSdk to find and retrieve {@code
 * MasterKeys}. (Some {@code MasterKeys} can also be constructed directly.)
 *
 * <p>{@code AwsCrypto} uses the {@code MasterKeyProvider} to determine which {@code MasterKeys}
 * should be used to encrypt the {@code DataKeys} by calling {@link
 * MasterKeyProvider#getMasterKeysForEncryption(MasterKeyRequest)} . When more than one {@code
 * MasterKey} is returned, the first {@code MasterKeys} is used to create the {@code DataKeys} by
 * calling {@link MasterKey#generateDataKey(CryptoAlgorithm, java.util.Map)} . All of the other
 * {@code MasterKeys} are then used to re-encrypt that {@code DataKey} with {@link
 * MasterKey#encryptDataKey(CryptoAlgorithm, java.util.Map, DataKey)} . This list of {@link
 * EncryptedDataKey EncryptedDataKeys} (the same {@code DataKey} possibly encrypted multiple times)
 * is stored in the {@link com.amazonaws.encryptionsdk.model.CiphertextHeaders}.
 *
 * <p>{@code AwsCrypto} also uses the {@code MasterKeyProvider} to decrypt one of the {@link
 * EncryptedDataKey EncryptedDataKeys} from the header to retrieve the actual {@code DataKey}
 * necessary to decrypt the message.
 *
 * <p>Any place a {@code MasterKeyProvider} is used, a {@link MasterKey} can be used instead. The
 * {@code MasterKey} will behave as a {@code MasterKeyProvider} which is only capable of providing
 * itself. This is often useful when only one {@code MasterKey} is being used.
 *
 * <p>Note regarding the use of generics: This library makes heavy use of generics to provide type
 * safety to advanced developers. The great majority of users should be able to just use the
 * provided type parameters or the {@code ?} wildcard.
 */
@SuppressWarnings("WeakerAccess") // this is a public API
public class AwsCrypto {
  private static final Map<String, String> EMPTY_MAP = Collections.emptyMap();

  // These are volatile because we allow unsynchronized writes via our setters,
  // and without setting volatile we could see strange results.
  // E.g. copying these to a local might give different values on subsequent reads from the local.
  // By setting them volatile we ensure that proper memory barriers are applied
  // to ensure things behave in a sensible manner.
  private volatile CryptoAlgorithm encryptionAlgorithm_ = null;
  private volatile int encryptionFrameSize_ = getDefaultFrameSize();

  private static final CommitmentPolicy DEFAULT_COMMITMENT_POLICY =
      CommitmentPolicy.RequireEncryptRequireDecrypt;
  private final CommitmentPolicy commitmentPolicy_;
  private final MaterialProviders materialProviders_;

  /**
   * The maximum number of encrypted data keys to unwrap (resp. wrap) on decrypt (resp. encrypt), if
   * positive. If zero, do not limit EDKs.
   */
  private final int maxEncryptedDataKeys_;

  private AwsCrypto(Builder builder) {
    commitmentPolicy_ =
        builder.commitmentPolicy_ == null ? DEFAULT_COMMITMENT_POLICY : builder.commitmentPolicy_;
    if (builder.encryptionAlgorithm_ != null
        && !commitmentPolicy_.algorithmAllowedForEncrypt(builder.encryptionAlgorithm_)) {
      if (commitmentPolicy_ == CommitmentPolicy.ForbidEncryptAllowDecrypt) {
        throw new AwsCryptoException(
            "Configuration conflict. Cannot encrypt due to CommitmentPolicy "
                + commitmentPolicy_
                + " requiring only non-committed messages. Algorithm ID was "
                + builder.encryptionAlgorithm_
                + ". See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html");
      } else {
        throw new AwsCryptoException(
            "Configuration conflict. Cannot encrypt due to CommitmentPolicy "
                + commitmentPolicy_
                + " requiring only committed messages. Algorithm ID was "
                + builder.encryptionAlgorithm_
                + ". See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html");
      }
    }
    encryptionAlgorithm_ = builder.encryptionAlgorithm_;
    encryptionFrameSize_ = builder.encryptionFrameSize_;
    maxEncryptedDataKeys_ = builder.maxEncryptedDataKeys_;
    materialProviders_ = builder.materialProviders_;
  }

  public static class Builder {
    private CryptoAlgorithm encryptionAlgorithm_;
    private int encryptionFrameSize_ = getDefaultFrameSize();
    private CommitmentPolicy commitmentPolicy_;
    private int maxEncryptedDataKeys_ = CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS;
    private MaterialProviders materialProviders_ = null;

    private Builder() {}

    private Builder(final AwsCrypto client) {
      encryptionAlgorithm_ = client.encryptionAlgorithm_;
      encryptionFrameSize_ = client.encryptionFrameSize_;
      commitmentPolicy_ = client.commitmentPolicy_;
      maxEncryptedDataKeys_ = client.maxEncryptedDataKeys_;
      materialProviders_ = client.materialProviders_;
    }

    /**
     * Sets the {@link CryptoAlgorithm} to encrypt with. The Aws Crypto client will use the last
     * crypto algorithm set with either {@link
     * AwsCrypto.Builder#withEncryptionAlgorithm(CryptoAlgorithm)} or {@link
     * #setEncryptionAlgorithm(CryptoAlgorithm)} to encrypt with.
     *
     * @param encryptionAlgorithm The {@link CryptoAlgorithm}
     * @return The Builder, for method chaining
     */
    public Builder withEncryptionAlgorithm(CryptoAlgorithm encryptionAlgorithm) {
      this.encryptionAlgorithm_ = encryptionAlgorithm;
      return this;
    }

    /**
     * Sets the {@link MaterialProviders} for cryptographic operations.
     *
     * @param materialProviders The {@link MaterialProviders}
     * @return The Builder, for method chaining
     */
    public Builder withMaterialProviders(MaterialProviders materialProviders) {
      this.materialProviders_ = materialProviders;
      return this;
    }

    /**
     * Sets the frame size of the encrypted messages that the Aws Crypto client produces. The Aws
     * Crypto client will use the last frame size set with either {@link
     * AwsCrypto.Builder#withEncryptionFrameSize(int)} or {@link #setEncryptionFrameSize(int)}.
     *
     * @param frameSize The frame size to produce encrypted messages with.
     * @return The Builder, for method chaining
     */
    public Builder withEncryptionFrameSize(int frameSize) {
      this.encryptionFrameSize_ = frameSize;
      return this;
    }

    /**
     * Sets the {@link CommitmentPolicy} of this Aws Crypto client.
     *
     * @param commitmentPolicy The commitment policy to enforce during encryption and decryption
     * @return The Builder, for method chaining
     */
    public Builder withCommitmentPolicy(CommitmentPolicy commitmentPolicy) {
      Utils.assertNonNull(commitmentPolicy, "commitmentPolicy");
      this.commitmentPolicy_ = commitmentPolicy;
      return this;
    }

    /**
     * Sets the maximum number of encrypted data keys that this Aws Crypto client will wrap when
     * encrypting, or unwrap when decrypting, a single message.
     *
     * @param maxEncryptedDataKeys The maximum number of encrypted data keys; must be positive
     * @return The Builder, for method chaining
     */
    public Builder withMaxEncryptedDataKeys(int maxEncryptedDataKeys) {
      if (maxEncryptedDataKeys < 1) {
        throw new IllegalArgumentException("maxEncryptedDataKeys must be positive");
      }
      this.maxEncryptedDataKeys_ = maxEncryptedDataKeys;
      return this;
    }

    public AwsCrypto build() {
      if (materialProviders_ == null) {
        materialProviders_ =
            MaterialProviders.builder()
                .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                .build();
      }
      return new AwsCrypto(this);
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static AwsCrypto standard() {
    return AwsCrypto.builder().build();
  }

  /**
   * Returns the frame size to use for encryption when none is explicitly selected. Currently it is
   * 4096.
   */
  public static int getDefaultFrameSize() {
    return 4096;
  }

  /**
   * Sets the {@link CryptoAlgorithm} to use when <em>encrypting</em> data. This has no impact on
   * decryption.
   */
  public void setEncryptionAlgorithm(final CryptoAlgorithm alg) {
    if (!commitmentPolicy_.algorithmAllowedForEncrypt(alg)) {
      if (commitmentPolicy_ == CommitmentPolicy.ForbidEncryptAllowDecrypt) {
        throw new AwsCryptoException(
            "Configuration conflict. Cannot encrypt due to CommitmentPolicy "
                + commitmentPolicy_
                + " requiring only non-committed messages. Algorithm ID was "
                + alg
                + ". See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html");
      } else {
        throw new AwsCryptoException(
            "Configuration conflict. Cannot encrypt due to CommitmentPolicy "
                + commitmentPolicy_
                + " requiring only committed messages. Algorithm ID was "
                + alg
                + ". See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html");
      }
    }
    encryptionAlgorithm_ = alg;
  }

  public CryptoAlgorithm getEncryptionAlgorithm() {
    return encryptionAlgorithm_;
  }

  /**
   * Sets the framing size to use when <em>encrypting</em> data. This has no impact on decryption.
   * If {@code frameSize} is 0, then framing is disabled and the entire plaintext will be encrypted
   * in a single block.
   *
   * <p>Note that during encryption arrays of this size will be allocated. Using extremely large
   * frame sizes may pose compatibility issues when the decryptor is running on 32-bit systems.
   * Additionally, Java VM limits may set a platform-specific upper bound to frame sizes.
   */
  public void setEncryptionFrameSize(final int frameSize) {
    if (frameSize < 0) {
      throw new IllegalArgumentException("frameSize must be non-negative");
    }

    encryptionFrameSize_ = frameSize;
  }

  public int getEncryptionFrameSize() {
    return encryptionFrameSize_;
  }

  /**
   * Returns the best estimate for the output length of encrypting a plaintext with the provided
   * {@code plaintextSize} and {@code encryptionContext}. The actual ciphertext may be shorter.
   *
   * <p>This method is equivalent to calling {@link #estimateCiphertextSize(CryptoMaterialsManager,
   * int, Map)} with a {@link DefaultCryptoMaterialsManager} based on the given provider.
   */
  @Deprecated
  public <K extends MasterKey<K>> long estimateCiphertextSize(
      final MasterKeyProvider<K> provider,
      final int plaintextSize,
      final Map<String, String> encryptionContext) {
    return estimateCiphertextSize(
        new DefaultCryptoMaterialsManager(provider), plaintextSize, encryptionContext);
  }

  /**
   * Returns the best estimate for the output length of encrypting a plaintext with the provided
   * {@code plaintextSize} and {@code encryptionContext}. The actual ciphertext may be shorter.
   *
   * <p>This method is equivalent to calling {@link
   * #estimateCiphertextSize(ICryptographicMaterialsManager, int, Map)} with a {@link
   * ICryptographicMaterialsManager} based on the given keyring.
   */
  public <K extends MasterKey<K>> long estimateCiphertextSize(
      final IKeyring keyring,
      final int plaintextSize,
      final Map<String, String> encryptionContext) {
    CreateDefaultCryptographicMaterialsManagerInput input =
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build();
    return estimateCiphertextSize(
        materialProviders_.CreateDefaultCryptographicMaterialsManager(input),
        plaintextSize,
        encryptionContext);
  }

  /**
   * Returns the best estimate for the output length of encrypting a plaintext with the provided
   * {@code plaintextSize} and {@code encryptionContext}. The actual ciphertext may be shorter.
   */
  @Deprecated
  public long estimateCiphertextSize(
      CryptoMaterialsManager materialsManager,
      final int plaintextSize,
      final Map<String, String> encryptionContext) {
    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(encryptionContext)
            .setRequestedAlgorithm(getEncryptionAlgorithm())
            // We're not actually encrypting any data, so don't consume any bytes from the cache's
            // limits. We do need to
            // pass /something/ though, or the cache will be bypassed (as it'll assume this is a
            // streaming encrypt of
            // unknown size).
            .setPlaintextSize(0)
            .setCommitmentPolicy(commitmentPolicy_)
            .build();

    final MessageCryptoHandler cryptoHandler =
        new EncryptionHandler(
            getEncryptionFrameSize(),
            checkAlgorithm(new CMMHandler(materialsManager).getMaterialsForEncrypt(request)),
            commitmentPolicy_);

    return cryptoHandler.estimateOutputSize(plaintextSize);
  }

  /**
   * Returns the best estimate for the output length of encrypting a plaintext with the provided
   * {@code plaintextSize} and {@code encryptionContext}. The actual ciphertext may be shorter.
   */
  public long estimateCiphertextSize(
      ICryptographicMaterialsManager materialsManager,
      final int plaintextSize,
      final Map<String, String> encryptionContext) {
    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(encryptionContext)
            .setRequestedAlgorithm(getEncryptionAlgorithm())
            // We're not actually encrypting any data, so don't consume any bytes from the cache's
            // limits. We do need to
            // pass /something/ though, or the cache will be bypassed (as it'll assume this is a
            // streaming encrypt of
            // unknown size).
            .setPlaintextSize(0)
            .setCommitmentPolicy(commitmentPolicy_)
            .build();

    final MessageCryptoHandler cryptoHandler =
        new EncryptionHandler(
            getEncryptionFrameSize(),
            checkAlgorithm(new CMMHandler(materialsManager).getMaterialsForEncrypt(request)),
            commitmentPolicy_);

    return cryptoHandler.estimateOutputSize(plaintextSize);
  }

  /**
   * Returns the equivalent to calling {@link #estimateCiphertextSize(MasterKeyProvider, int, Map)}
   * with an empty {@code encryptionContext}.
   */
  @Deprecated
  public <K extends MasterKey<K>> long estimateCiphertextSize(
      final MasterKeyProvider<K> provider, final int plaintextSize) {
    return estimateCiphertextSize(provider, plaintextSize, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #estimateCiphertextSize(IKeyring, int, Map)} with an
   * empty {@code encryptionContext}.
   */
  public <K extends MasterKey<K>> long estimateCiphertextSize(
      final IKeyring keyring, final int plaintextSize) {
    return estimateCiphertextSize(keyring, plaintextSize, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #estimateCiphertextSize(CryptoMaterialsManager, int,
   * Map)} with an empty {@code encryptionContext}.
   */
  @Deprecated
  public long estimateCiphertextSize(
      final CryptoMaterialsManager materialsManager, final int plaintextSize) {
    return estimateCiphertextSize(materialsManager, plaintextSize, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link
   * #estimateCiphertextSize(ICryptographicMaterialsManager, int, Map)} with an empty {@code
   * encryptionContext}.
   */
  public long estimateCiphertextSize(
      final ICryptographicMaterialsManager materialsManager, final int plaintextSize) {
    return estimateCiphertextSize(materialsManager, plaintextSize, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #encryptData(IKeyring, byte[], Map)} with an empty
   * {@code encryptionContext}.
   */
  public <K extends MasterKey<K>> CryptoResult<byte[], ?> encryptData(
      final IKeyring keyring, final byte[] plaintext) {
    return encryptData(keyring, plaintext, EMPTY_MAP);
  }

  /**
   * Returns an encrypted form of {@code plaintext} that has been protected with {@link DataKey
   * DataKeys} that are in turn protected by {@link IKeyring Keyrings} provided by {@code keyring}.
   *
   * <p>This method is equivalent to calling {@link #encryptData(ICryptographicMaterialsManager,
   * byte[], Map)}
   */
  public CryptoResult<byte[], ?> encryptData(
      final IKeyring keyring, final byte[] plaintext, final Map<String, String> encryptionContext) {
    Utils.assertNonNull(keyring, "keyring");
    return encryptData(createDefaultCMM(keyring), plaintext, encryptionContext);
  }

  /**
   * Returns the equivalent to calling {@link #encryptData(ICryptographicMaterialsManager, byte[],
   * Map)} with an empty {@code encryptionContext}.
   */
  public CryptoResult<byte[], ?> encryptData(
      final ICryptographicMaterialsManager materialsManager, final byte[] plaintext) {
    return encryptData(materialsManager, plaintext, EMPTY_MAP);
  }

  /**
   * Returns an encrypted form of {@code plaintext} that has been protected with {@link DataKey
   * DataKeys} that are in turn protected by the given CryptoMaterialsProvider.
   */
  public CryptoResult<byte[], ?> encryptData(
      final ICryptographicMaterialsManager materialsManager,
      final byte[] plaintext,
      final Map<String, String> encryptionContext) {
    Utils.assertNonNull(materialsManager, "materialsManager");

    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(encryptionContext)
            .setRequestedAlgorithm(getEncryptionAlgorithm())
            .setPlaintext(plaintext)
            .setCommitmentPolicy(commitmentPolicy_)
            .build();
    CMMHandler cmmHandler = new CMMHandler(materialsManager);
    EncryptionMaterialsHandler encryptionMaterials =
        checkMaxEncryptedDataKeys(checkAlgorithm(cmmHandler.getMaterialsForEncrypt(request)));
    final MessageCryptoHandler cryptoHandler =
        new EncryptionHandler(getEncryptionFrameSize(), encryptionMaterials, commitmentPolicy_);

    return encryptData(cryptoHandler, plaintext);
  }

  /**
   * Returns an encrypted form of {@code plaintext} that has been protected with {@link DataKey
   * DataKeys} that are in turn protected by {@link MasterKey MasterKeys} provided by {@code
   * provider}.
   *
   * <p>This method is equivalent to calling {@link #encryptData(CryptoMaterialsManager, byte[],
   * Map)} using a {@link DefaultCryptoMaterialsManager} based on the given provider.
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoResult<byte[], K> encryptData(
      final MasterKeyProvider<K> provider,
      final byte[] plaintext,
      final Map<String, String> encryptionContext) {
    Utils.assertNonNull(provider, "provider");
    //noinspection unchecked
    return (CryptoResult<byte[], K>)
        encryptData(new DefaultCryptoMaterialsManager(provider), plaintext, encryptionContext);
  }

  /**
   * Returns an encrypted form of {@code plaintext} that has been protected with {@link DataKey
   * DataKeys} that are in turn protected by the given CryptoMaterialsProvider.
   */
  @Deprecated
  public CryptoResult<byte[], ?> encryptData(
      CryptoMaterialsManager materialsManager,
      final byte[] plaintext,
      final Map<String, String> encryptionContext) {
    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(encryptionContext)
            .setRequestedAlgorithm(getEncryptionAlgorithm())
            .setPlaintext(plaintext)
            .setCommitmentPolicy(commitmentPolicy_)
            .build();

    EncryptionMaterialsHandler encryptionMaterials =
        checkMaxEncryptedDataKeys(
            checkAlgorithm(
                new EncryptionMaterialsHandler(materialsManager.getMaterialsForEncrypt(request))));
    final MessageCryptoHandler cryptoHandler =
        new EncryptionHandler(getEncryptionFrameSize(), encryptionMaterials, commitmentPolicy_);

    return encryptData(cryptoHandler, plaintext);
  }

  private <K extends MasterKey<K>> CryptoResult<byte[], K> encryptData(
      MessageCryptoHandler cryptoHandler, byte[] plaintext) {
    final int outSizeEstimate = cryptoHandler.estimateOutputSize(plaintext.length);
    final byte[] out = new byte[outSizeEstimate];
    int outLen =
        cryptoHandler.processBytes(plaintext, 0, plaintext.length, out, 0).getBytesWritten();
    outLen += cryptoHandler.doFinal(out, outLen);

    final byte[] outBytes = Utils.truncate(out, outLen);

    //noinspection unchecked
    return new CryptoResult(
        outBytes,
        cryptoHandler.getMasterKeys(),
        cryptoHandler.getHeaders(),
        cryptoHandler.getEncryptionContext());
  }

  /**
   * Returns the equivalent to calling {@link #encryptData(MasterKeyProvider, byte[], Map)} with an
   * empty {@code encryptionContext}.
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoResult<byte[], K> encryptData(
      final MasterKeyProvider<K> provider, final byte[] plaintext) {
    return encryptData(provider, plaintext, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #encryptData(CryptoMaterialsManager, byte[], Map)}
   * with an empty {@code encryptionContext}.
   */
  @Deprecated
  public CryptoResult<byte[], ?> encryptData(
      final CryptoMaterialsManager materialsManager, final byte[] plaintext) {
    return encryptData(materialsManager, plaintext, EMPTY_MAP);
  }

  /**
   * Calls {@link #encryptData(MasterKeyProvider, byte[], Map)} on the UTF-8 encoded bytes of {@code
   * plaintext} and base64 encodes the result.
   *
   * @deprecated Use the {@link #encryptData(MasterKeyProvider, byte[], Map)} and {@link
   *     #decryptData(MasterKeyProvider, byte[])} APIs instead. {@code encryptString} and {@code
   *     decryptString} work as expected if you use them together. However, to work with other
   *     language implementations of the AWS Encryption SDK, you need to base64-decode the output of
   *     {@code encryptString} and base64-encode the input to {@code decryptString}. These
   *     deprecated APIs will be removed in the future.
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoResult<String, K> encryptString(
      final MasterKeyProvider<K> provider,
      final String plaintext,
      final Map<String, String> encryptionContext) {
    //noinspection unchecked
    return (CryptoResult<String, K>)
        encryptString(new DefaultCryptoMaterialsManager(provider), plaintext, encryptionContext);
  }

  /**
   * Calls {@link #encryptData(CryptoMaterialsManager, byte[], Map)} on the UTF-8 encoded bytes of
   * {@code plaintext} and base64 encodes the result.
   *
   * @deprecated Use the {@link #encryptData(CryptoMaterialsManager, byte[], Map)} and {@link
   *     #decryptData(CryptoMaterialsManager, byte[])} APIs instead. {@code encryptString} and
   *     {@code decryptString} work as expected if you use them together. However, to work with
   *     other language implementations of the AWS Encryption SDK, you need to base64-decode the
   *     output of {@code encryptString} and base64-encode the input to {@code decryptString}. These
   *     deprecated APIs will be removed in the future.
   */
  @Deprecated
  public CryptoResult<String, ?> encryptString(
      CryptoMaterialsManager materialsManager,
      final String plaintext,
      final Map<String, String> encryptionContext) {
    final CryptoResult<byte[], ?> ctBytes =
        encryptData(
            materialsManager, plaintext.getBytes(StandardCharsets.UTF_8), encryptionContext);
    return new CryptoResult<>(
        Utils.encodeBase64String(ctBytes.getResult()),
        ctBytes.getMasterKeys(),
        ctBytes.getHeaders(),
        ctBytes.getEncryptionContext());
  }

  /**
   * Returns the equivalent to calling {@link #encryptString(MasterKeyProvider, String, Map)} with
   * an empty {@code encryptionContext}.
   *
   * @deprecated Use the {@link #encryptData(MasterKeyProvider, byte[])} and {@link
   *     #decryptData(MasterKeyProvider, byte[])} APIs instead. {@code encryptString} and {@code
   *     decryptString} work as expected if you use them together. However, to work with other
   *     language implementations of the AWS Encryption SDK, you need to base64-decode the output of
   *     {@code encryptString} and base64-encode the input to {@code decryptString}. These
   *     deprecated APIs will be removed in the future.
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoResult<String, K> encryptString(
      final MasterKeyProvider<K> provider, final String plaintext) {
    return encryptString(provider, plaintext, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #encryptString(CryptoMaterialsManager, String, Map)}
   * with an empty {@code encryptionContext}.
   *
   * @deprecated Use the {@link #encryptData(CryptoMaterialsManager, byte[])} and {@link
   *     #decryptData(CryptoMaterialsManager, byte[])} APIs instead. {@code encryptString} and
   *     {@code decryptString} work as expected if you use them together. However, to work with
   *     other language implementations of the AWS Encryption SDK, you need to base64-decode the
   *     output of {@code encryptString} and base64-encode the input to {@code decryptString}. These
   *     deprecated APIs will be removed in the future.
   */
  @Deprecated
  public CryptoResult<String, ?> encryptString(
      final CryptoMaterialsManager materialsManager, final String plaintext) {
    return encryptString(materialsManager, plaintext, EMPTY_MAP);
  }

  /**
   * Decrypts the provided {@code ciphertext} by requesting that the {@code provider} unwrap any
   * usable {@link DataKey} in the ciphertext and then decrypts the ciphertext using that {@code
   * DataKey}.
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoResult<byte[], K> decryptData(
      final MasterKeyProvider<K> provider, final byte[] ciphertext) {
    return decryptData(provider, new ParsedCiphertext(ciphertext, maxEncryptedDataKeys_));
  }

  /**
   * Decrypts the provided ciphertext by delegating to the provided materialsManager to obtain the
   * decrypted {@link DataKey}.
   *
   * @param materialsManager the {@link CryptoMaterialsManager} to use for decryption operations.
   * @param ciphertext the ciphertext to attempt to decrypt.
   * @return the {@link CryptoResult} with the decrypted data.
   */
  @Deprecated
  public CryptoResult<byte[], ?> decryptData(
      final CryptoMaterialsManager materialsManager, final byte[] ciphertext) {
    return decryptData(materialsManager, new ParsedCiphertext(ciphertext, maxEncryptedDataKeys_));
  }

  /** @see #decryptData(MasterKeyProvider, byte[]) */
  @SuppressWarnings("unchecked")
  @Deprecated
  public <K extends MasterKey<K>> CryptoResult<byte[], K> decryptData(
      final MasterKeyProvider<K> provider, final ParsedCiphertext ciphertext) {
    Utils.assertNonNull(provider, "provider");
    return (CryptoResult<byte[], K>)
        decryptData(new DefaultCryptoMaterialsManager(provider), ciphertext);
  }

  /** @see #decryptData(CryptoMaterialsManager, byte[]) */
  @Deprecated
  public CryptoResult<byte[], ?> decryptData(
      final CryptoMaterialsManager materialsManager, final ParsedCiphertext ciphertext) {
    Utils.assertNonNull(materialsManager, "materialsManager");

    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            ciphertext,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);

    return decryptData(cryptoHandler, ciphertext);
  }

  private CryptoResult<byte[], ?> decryptData(
      final MessageCryptoHandler cryptoHandler, final ParsedCiphertext ciphertext) {
    final byte[] ciphertextBytes = ciphertext.getCiphertext();
    final int contentLen = ciphertextBytes.length - ciphertext.getOffset();
    final int outSizeEstimate = cryptoHandler.estimateOutputSize(contentLen);
    final byte[] out = new byte[outSizeEstimate];
    final ProcessingSummary processed =
        cryptoHandler.processBytes(ciphertextBytes, ciphertext.getOffset(), contentLen, out, 0);
    if (processed.getBytesProcessed() != contentLen) {
      throw new BadCiphertextException(
          "Unable to process entire ciphertext. May have trailing data.");
    }
    int outLen = processed.getBytesWritten();
    outLen += cryptoHandler.doFinal(out, outLen);

    final byte[] outBytes = Utils.truncate(out, outLen);

    //noinspection unchecked
    return new CryptoResult(
        outBytes,
        cryptoHandler.getMasterKeys(),
        cryptoHandler.getHeaders(),
        cryptoHandler.getEncryptionContext());
  }

  /**
   * Decrypts the provided ciphertext by delegating to the provided materialsManager to obtain the
   * decrypted {@link DataKey}.
   *
   * @param keyring the {@link IKeyring} to use for decryption operations.
   * @param ciphertext the ciphertext to attempt to decrypt.
   * @return the {@link CryptoResult} with the decrypted data.
   */
  public CryptoResult<byte[], ?> decryptData(final IKeyring keyring, final byte[] ciphertext) {
    return decryptData(keyring, new ParsedCiphertext(ciphertext, maxEncryptedDataKeys_));
  }

  /**
   * Decrypts the provided ciphertext by delegating to the provided materialsManager to obtain the
   * decrypted {@link DataKey}.
   *
   * @param keyring the {@link IKeyring} to use for decryption operations.
   * @param ciphertext the ciphertext to attempt to decrypt.
   * @param encryptionContext The encryption context MUST contain a value for every key in the
   *     configured required encryption context keys during encryption with Required Encryption
   *     Context CMM.
   * @return the {@link CryptoResult} with the decrypted data.
   */
  public CryptoResult<byte[], ?> decryptData(
      final IKeyring keyring,
      final byte[] ciphertext,
      final Map<String, String> encryptionContext) {
    return decryptData(
        keyring, new ParsedCiphertext(ciphertext, maxEncryptedDataKeys_), encryptionContext);
  }

  /** @see #decryptData(IKeyring, byte[]) */
  public CryptoResult<byte[], ?> decryptData(
      final IKeyring keyring, final ParsedCiphertext ciphertext) {
    return decryptData(keyring, ciphertext, EMPTY_MAP);
  }

  /** @see #decryptData(IKeyring, byte[], Map<String, String>) */
  private CryptoResult<byte[], ?> decryptData(
      IKeyring keyring, ParsedCiphertext ciphertext, Map<String, String> encryptionContext) {
    //noinspection unchecked
    Utils.assertNonNull(keyring, "keyring");

    return decryptData(createDefaultCMM(keyring), ciphertext, encryptionContext);
  }

  /**
   * Decrypts the provided ciphertext by delegating to the provided materialsManager to obtain the
   * decrypted {@link DataKey}.
   *
   * @param materialsManager the {@link ICryptographicMaterialsManager} to use for decryption
   *     operations.
   * @param ciphertext the ciphertext to attempt to decrypt.
   * @return the {@link CryptoResult} with the decrypted data.
   */
  public CryptoResult<byte[], ?> decryptData(
      final ICryptographicMaterialsManager materialsManager, final byte[] ciphertext) {
    return decryptData(materialsManager, new ParsedCiphertext(ciphertext, maxEncryptedDataKeys_));
  }

  /**
   * Decrypts the provided ciphertext by delegating to the provided materialsManager to obtain the
   * decrypted {@link DataKey}.
   *
   * @param materialsManager the {@link ICryptographicMaterialsManager} to use for decryption
   *     operations.
   * @param ciphertext the ciphertext to attempt to decrypt.
   * @param encryptionContext The encryption context MUST contain a value for every key in the
   *     configured required encryption context keys during encryption with Required Encryption
   *     Context CMM.
   * @return the {@link CryptoResult} with the decrypted data.
   */
  public CryptoResult<byte[], ?> decryptData(
      final ICryptographicMaterialsManager materialsManager,
      final byte[] ciphertext,
      final Map<String, String> encryptionContext) {
    return decryptData(
        materialsManager,
        new ParsedCiphertext(ciphertext, maxEncryptedDataKeys_),
        encryptionContext);
  }

  /** @see #decryptData(ICryptographicMaterialsManager, byte[]) */
  public CryptoResult<byte[], ?> decryptData(
      final ICryptographicMaterialsManager materialsManager, final ParsedCiphertext ciphertext) {

    return decryptData(materialsManager, ciphertext, EMPTY_MAP);
  }

  /** @see #decryptData(ICryptographicMaterialsManager, byte[]) */
  public CryptoResult<byte[], ?> decryptData(
      final ICryptographicMaterialsManager materialsManager,
      final ParsedCiphertext ciphertext,
      final Map<String, String> encryptionContext) {
    Utils.assertNonNull(materialsManager, "materialsManager");

    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            ciphertext,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);

    return decryptData(cryptoHandler, ciphertext);
  }

  /**
   * Base64 decodes the {@code ciphertext} prior to decryption and then treats the results as a
   * UTF-8 encoded string.
   *
   * @see #decryptData(MasterKeyProvider, byte[])
   * @deprecated Use the {@link #decryptData(MasterKeyProvider, byte[])} and {@link
   *     #encryptData(MasterKeyProvider, byte[], Map)} APIs instead. {@code encryptString} and
   *     {@code decryptString} work as expected if you use them together. However, to work with
   *     other language implementations of the AWS Encryption SDK, you need to base64-decode the
   *     output of {@code encryptString} and base64-encode the input to {@code decryptString}. These
   *     deprecated APIs will be removed in the future.
   */
  @Deprecated
  @SuppressWarnings("unchecked")
  public <K extends MasterKey<K>> CryptoResult<String, K> decryptString(
      final MasterKeyProvider<K> provider, final String ciphertext) {
    return (CryptoResult<String, K>)
        decryptString(new DefaultCryptoMaterialsManager(provider), ciphertext);
  }

  /**
   * Base64 decodes the {@code ciphertext} prior to decryption and then treats the results as a
   * UTF-8 encoded string.
   *
   * @see #decryptData(CryptoMaterialsManager, byte[])
   * @deprecated Use the {@link #decryptData(CryptoMaterialsManager, byte[])} and {@link
   *     #encryptData(CryptoMaterialsManager, byte[], Map)} APIs instead. {@code encryptString} and
   *     {@code decryptString} work as expected if you use them together. However, to work with
   *     other language implementations of the AWS Encryption SDK, you need to base64-decode the
   *     output of {@code encryptString} and base64-encode the input to {@code decryptString}. These
   *     deprecated APIs will be removed in the future.
   */
  @Deprecated
  public CryptoResult<String, ?> decryptString(
      final CryptoMaterialsManager provider, final String ciphertext) {
    Utils.assertNonNull(provider, "provider");
    final byte[] ciphertextBytes;
    try {
      ciphertextBytes = Utils.decodeBase64String(Utils.assertNonNull(ciphertext, "ciphertext"));
    } catch (final IllegalArgumentException ex) {
      throw new BadCiphertextException("Invalid base 64", ex);
    }
    final CryptoResult<byte[], ?> ptBytes = decryptData(provider, ciphertextBytes);
    //noinspection unchecked
    return new CryptoResult(
        new String(ptBytes.getResult(), StandardCharsets.UTF_8),
        ptBytes.getMasterKeys(),
        ptBytes.getHeaders(),
        ptBytes.getEncryptionContext());
  }

  /**
   * Returns a {@link CryptoOutputStream} which encrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * @see #encryptData(MasterKeyProvider, byte[], Map)
   * @see javax.crypto.CipherOutputStream
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
      final MasterKeyProvider<K> provider,
      final OutputStream os,
      final Map<String, String> encryptionContext) {
    //noinspection unchecked
    return (CryptoOutputStream<K>)
        createEncryptingStream(new DefaultCryptoMaterialsManager(provider), os, encryptionContext);
  }

  /**
   * Returns a {@link CryptoOutputStream} which encrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * @see #encryptData(IKeyring, byte[], Map)
   * @see javax.crypto.CipherOutputStream
   */
  public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
      final IKeyring keyring, final OutputStream os, final Map<String, String> encryptionContext) {
    //noinspection unchecked
    return (CryptoOutputStream<K>)
        createEncryptingStream(createDefaultCMM(keyring), os, encryptionContext);
  }

  /**
   * Returns a {@link CryptoOutputStream} which encrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * @see #encryptData(MasterKeyProvider, byte[], Map)
   * @see javax.crypto.CipherOutputStream
   */
  @Deprecated
  public CryptoOutputStream<?> createEncryptingStream(
      final CryptoMaterialsManager materialsManager,
      final OutputStream os,
      final Map<String, String> encryptionContext) {
    return new CryptoOutputStream<>(
        os, getEncryptingStreamHandler(new CMMHandler(materialsManager), encryptionContext));
  }

  /**
   * Returns a {@link CryptoOutputStream} which encrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * @see #encryptData(IKeyring, byte[], Map)
   * @see javax.crypto.CipherOutputStream
   */
  public CryptoOutputStream<?> createEncryptingStream(
      final ICryptographicMaterialsManager materialsManager,
      final OutputStream os,
      final Map<String, String> encryptionContext) {
    return new CryptoOutputStream<>(
        os, getEncryptingStreamHandler(new CMMHandler(materialsManager), encryptionContext));
  }

  /**
   * Returns the equivalent to calling {@link #createEncryptingStream(MasterKeyProvider,
   * OutputStream, Map)} with an empty {@code encryptionContext}.
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
      final MasterKeyProvider<K> provider, final OutputStream os) {
    return createEncryptingStream(provider, os, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #createEncryptingStream(IKeyring, OutputStream, Map)}
   * with an empty {@code encryptionContext}.
   */
  public <K extends MasterKey<K>> CryptoOutputStream<K> createEncryptingStream(
      final IKeyring keyring, final OutputStream os) {
    return createEncryptingStream(keyring, os, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #createEncryptingStream(CryptoMaterialsManager,
   * OutputStream, Map)} with an empty {@code encryptionContext}.
   */
  @Deprecated
  public CryptoOutputStream<?> createEncryptingStream(
      final CryptoMaterialsManager materialsManager, final OutputStream os) {
    return createEncryptingStream(materialsManager, os, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link
   * #createEncryptingStream(ICryptographicMaterialsManager, OutputStream, Map)} with an empty
   * {@code encryptionContext}.
   */
  public CryptoOutputStream<?> createEncryptingStream(
      final ICryptographicMaterialsManager materialsManager, final OutputStream os) {
    return createEncryptingStream(materialsManager, os, EMPTY_MAP);
  }

  /**
   * Returns a {@link CryptoInputStream} which encrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * @see #encryptData(MasterKeyProvider, byte[], Map)
   * @see javax.crypto.CipherInputStream
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
      final MasterKeyProvider<K> provider,
      final InputStream is,
      final Map<String, String> encryptionContext) {
    //noinspection unchecked
    return (CryptoInputStream<K>)
        createEncryptingStream(new DefaultCryptoMaterialsManager(provider), is, encryptionContext);
  }

  /**
   * Returns a {@link CryptoInputStream} which encrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * @see #encryptData(IKeyring, byte[], Map)
   * @see javax.crypto.CipherInputStream
   */
  public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
      final IKeyring keyring, final InputStream is, final Map<String, String> encryptionContext) {
    ICryptographicMaterialsManager materialsManager = createDefaultCMM(keyring);
    //noinspection unchecked
    return (CryptoInputStream<K>) createEncryptingStream(materialsManager, is, encryptionContext);
  }

  /**
   * Returns a {@link CryptoInputStream} which encrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * @see #encryptData(MasterKeyProvider, byte[], Map)
   * @see javax.crypto.CipherInputStream
   */
  @Deprecated
  public CryptoInputStream<?> createEncryptingStream(
      CryptoMaterialsManager materialsManager,
      final InputStream is,
      final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        getEncryptingStreamHandler(new CMMHandler(materialsManager), encryptionContext);

    return new CryptoInputStream<>(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which encrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * @see #encryptData(IKeyring, byte[], Map)
   * @see javax.crypto.CipherInputStream
   */
  public CryptoInputStream<?> createEncryptingStream(
      ICryptographicMaterialsManager materialsManager,
      final InputStream is,
      final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        getEncryptingStreamHandler(new CMMHandler(materialsManager), encryptionContext);

    return new CryptoInputStream<>(is, cryptoHandler);
  }

  /**
   * Returns the equivalent to calling {@link #createEncryptingStream(MasterKeyProvider,
   * InputStream, Map)} with an empty {@code encryptionContext}.
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
      final MasterKeyProvider<K> provider, final InputStream is) {
    return createEncryptingStream(provider, is, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #createEncryptingStream(MasterKeyProvider,
   * InputStream, Map)} with an empty {@code encryptionContext}.
   */
  public <K extends MasterKey<K>> CryptoInputStream<K> createEncryptingStream(
      final IKeyring keyring, final InputStream is) {
    return createEncryptingStream(keyring, is, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link #createEncryptingStream(CryptoMaterialsManager,
   * InputStream, Map)} with an empty {@code encryptionContext}.
   */
  @Deprecated
  public CryptoInputStream<?> createEncryptingStream(
      final CryptoMaterialsManager materialsManager, final InputStream is) {
    return createEncryptingStream(materialsManager, is, EMPTY_MAP);
  }

  /**
   * Returns the equivalent to calling {@link
   * #createEncryptingStream(ICryptographicMaterialsManager, InputStream, Map)} with an empty {@code
   * encryptionContext}.
   */
  public CryptoInputStream<?> createEncryptingStream(
      final ICryptographicMaterialsManager materialsManager, final InputStream is) {
    return createEncryptingStream(materialsManager, is, EMPTY_MAP);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(MasterKeyProvider, byte[])
   * @see javax.crypto.CipherOutputStream
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoOutputStream<K> createUnsignedMessageDecryptingStream(
      final MasterKeyProvider<K> provider, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            provider,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream<K>(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(IKeyring, byte[])
   * @see javax.crypto.CipherOutputStream
   */
  public <K extends MasterKey<K>> CryptoOutputStream<K> createUnsignedMessageDecryptingStream(
      final IKeyring keyring, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream<K>(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(IKeyring, byte[], Map<String, String>)
   * @see javax.crypto.CipherOutputStream
   */
  public <K extends MasterKey<K>> CryptoOutputStream<K> createUnsignedMessageDecryptingStream(
      final IKeyring keyring, final OutputStream os, final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoOutputStream<K>(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(MasterKeyProvider, byte[])
   * @see javax.crypto.CipherInputStream
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoInputStream<K> createUnsignedMessageDecryptingStream(
      final MasterKeyProvider<K> provider, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            provider,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream<K>(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(IKeyring, byte[])
   * @see javax.crypto.CipherInputStream
   */
  public <K extends MasterKey<K>> CryptoInputStream<K> createUnsignedMessageDecryptingStream(
      final IKeyring keyring, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream<K>(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(IKeyring, byte[], Map<String, String>)
   * @see javax.crypto.CipherInputStream
   */
  public <K extends MasterKey<K>> CryptoInputStream<K> createUnsignedMessageDecryptingStream(
      final IKeyring keyring, final InputStream is, final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoInputStream<K>(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(CryptoMaterialsManager, byte[])
   * @see javax.crypto.CipherOutputStream
   */
  @Deprecated
  public CryptoOutputStream<?> createUnsignedMessageDecryptingStream(
      final CryptoMaterialsManager materialsManager, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(ICryptographicMaterialsManager, byte[])
   * @see javax.crypto.CipherOutputStream
   */
  public CryptoOutputStream<?> createUnsignedMessageDecryptingStream(
      final ICryptographicMaterialsManager materialsManager, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}. This version only accepts unsigned messages.
   *
   * @see #decryptData(ICryptographicMaterialsManager, byte[], Map<String, String>)
   * @see javax.crypto.CipherOutputStream
   */
  public CryptoOutputStream<?> createUnsignedMessageDecryptingStream(
      final ICryptographicMaterialsManager materialsManager,
      final OutputStream os,
      final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoOutputStream(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}. This version only accepts unsigned messages.
   *
   * @see #encryptData(CryptoMaterialsManager, byte[], Map)
   * @see javax.crypto.CipherInputStream
   */
  @Deprecated
  public CryptoInputStream<?> createUnsignedMessageDecryptingStream(
      final CryptoMaterialsManager materialsManager, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}. This version only accepts unsigned messages.
   *
   * @see #encryptData(ICryptographicMaterialsManager, byte[])
   * @see javax.crypto.CipherInputStream
   */
  public CryptoInputStream<?> createUnsignedMessageDecryptingStream(
      final ICryptographicMaterialsManager materialsManager, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}. This version only accepts unsigned messages.
   *
   * @see #encryptData(ICryptographicMaterialsManager, byte[], Map<String, String>)
   * @see javax.crypto.CipherInputStream
   */
  public CryptoInputStream<?> createUnsignedMessageDecryptingStream(
      final ICryptographicMaterialsManager materialsManager,
      final InputStream is,
      final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptForbidDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoInputStream(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been released to the underlying {@link
   * OutputStream}! This behavior can be avoided by using the non-streaming
   * #decryptData(MasterKeyProvider, byte[]) method instead, or
   * #createUnsignedMessageDecryptingStream(MasterKeyProvider, OutputStream) if you do not need to
   * decrypt signed messages.
   *
   * @see #decryptData(MasterKeyProvider, byte[])
   * @see #createUnsignedMessageDecryptingStream(MasterKeyProvider, OutputStream)
   * @see javax.crypto.CipherOutputStream
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoOutputStream<K> createDecryptingStream(
      final MasterKeyProvider<K> provider, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            provider,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream<K>(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been released to the underlying {@link
   * OutputStream}! This behavior can be avoided by using the non-streaming #decryptData(IKeyring,
   * byte[]) method instead, or #createUnsignedMessageDecryptingStream(IKeyring, OutputStream) if
   * you do not need to decrypt signed messages.
   *
   * @see #decryptData(IKeyring, byte[])
   * @see #createUnsignedMessageDecryptingStream(IKeyring, OutputStream)
   * @see javax.crypto.CipherOutputStream
   */
  public <K extends MasterKey<K>> CryptoOutputStream<K> createDecryptingStream(
      final IKeyring keyring, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream<K>(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been released to the underlying {@link
   * OutputStream}! This behavior can be avoided by using the non-streaming #decryptData(IKeyring,
   * byte[], Map<String, String>) method instead, or
   * #createUnsignedMessageDecryptingStream(IKeyring, OutputStream, Map<String, String>) if you do
   * not need to decrypt signed messages.
   *
   * @see #decryptData(IKeyring, byte[], Map<String, String>)
   * @see #createUnsignedMessageDecryptingStream(IKeyring, OutputStream, Map<String, String>)
   * @see javax.crypto.CipherOutputStream
   */
  public <K extends MasterKey<K>> CryptoOutputStream<K> createDecryptingStream(
      final IKeyring keyring, final OutputStream os, final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoOutputStream<K>(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been produced from the {@link InputStream}!
   * This behavior can be avoided by using the non-streaming #decryptData(MasterKeyProvider, byte[])
   * method instead, or #createUnsignedMessageDecryptingStream(MasterKeyProvider, InputStream) if
   * you do not need to decrypt signed messages.
   *
   * @see #decryptData(MasterKeyProvider, byte[])
   * @see #createUnsignedMessageDecryptingStream(MasterKeyProvider, InputStream)
   * @see javax.crypto.CipherInputStream
   */
  @Deprecated
  public <K extends MasterKey<K>> CryptoInputStream<K> createDecryptingStream(
      final MasterKeyProvider<K> provider, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            provider,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream<K>(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been produced from the {@link InputStream}!
   * This behavior can be avoided by using the non-streaming #decryptData(IKeyring, byte[]) method
   * instead, or #createUnsignedMessageDecryptingStream(IKeyring, InputStream) if you do not need to
   * decrypt signed messages.
   *
   * @see #decryptData(IKeyring, byte[])
   * @see #createUnsignedMessageDecryptingStream(IKeyring, InputStream)
   * @see javax.crypto.CipherInputStream
   */
  public <K extends MasterKey<K>> CryptoInputStream<K> createDecryptingStream(
      final IKeyring keyring, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream<K>(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been produced from the {@link InputStream}!
   * This behavior can be avoided by using the non-streaming #decryptData(IKeyring, byte[],
   * Map<String, String>) method instead, or #createUnsignedMessageDecryptingStream(IKeyring,
   * InputStream, Map<String, String>) if you do not need to decrypt signed messages.
   *
   * @see #decryptData(IKeyring, byte[], Map<String, String>)
   * @see #createUnsignedMessageDecryptingStream(IKeyring, InputStream, Map<String, String>)
   * @see javax.crypto.CipherInputStream
   */
  public <K extends MasterKey<K>> CryptoInputStream<K> createDecryptingStream(
      final IKeyring keyring, final InputStream is, final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            createDefaultCMM(keyring),
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoInputStream<K>(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been released to the underlying {@link
   * OutputStream}! This behavior can be avoided by using the non-streaming
   * #decryptData(CryptoMaterialsManager, byte[]) method instead, or
   * #createUnsignedMessageDecryptingStream(CryptoMaterialsManager, OutputStream) if you do not need
   * to decrypt signed messages.
   *
   * @see #decryptData(CryptoMaterialsManager, byte[])
   * @see #createUnsignedMessageDecryptingStream(CryptoMaterialsManager, OutputStream)
   * @see javax.crypto.CipherOutputStream
   */
  @Deprecated
  public CryptoOutputStream<?> createDecryptingStream(
      final CryptoMaterialsManager materialsManager, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been released to the underlying {@link
   * OutputStream}! This behavior can be avoided by using the non-streaming
   * #decryptData(ICryptographicMaterialsManager, byte[]) method instead, or
   * #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, OutputStream) if you do
   * not need to decrypt signed messages.
   *
   * @see #decryptData(ICryptographicMaterialsManager, byte[])
   * @see #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, OutputStream)
   * @see javax.crypto.CipherOutputStream
   */
  public CryptoOutputStream<?> createDecryptingStream(
      final ICryptographicMaterialsManager materialsManager, final OutputStream os) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoOutputStream(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoOutputStream} which decrypts the data prior to passing it onto the
   * underlying {@link OutputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been released to the underlying {@link
   * OutputStream}! This behavior can be avoided by using the non-streaming
   * #decryptData(ICryptographicMaterialsManager, byte[], Map<String, String>) method instead, or
   * #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, OutputStream,
   * Map<String, String>) if you do not need to decrypt signed messages.
   *
   * @see #decryptData(ICryptographicMaterialsManager, byte[], Map<String, String>)
   * @see #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, OutputStream,
   *     Map<String, String>)
   * @see javax.crypto.CipherOutputStream
   */
  public CryptoOutputStream<?> createDecryptingStream(
      final ICryptographicMaterialsManager materialsManager,
      final OutputStream os,
      final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoOutputStream(os, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been produced from the {@link InputStream}!
   * This behavior can be avoided by using the non-streaming #decryptData(CryptoMaterialsManager,
   * byte[]) method instead, or #createUnsignedMessageDecryptingStream(CryptoMaterialsManager,
   * InputStream) if you do not need to decrypt signed messages.
   *
   * @see #decryptData(CryptoMaterialsManager, byte[])
   * @see #createUnsignedMessageDecryptingStream(CryptoMaterialsManager, InputStream)
   * @see javax.crypto.CipherInputStream
   */
  @Deprecated
  public CryptoInputStream<?> createDecryptingStream(
      final CryptoMaterialsManager materialsManager, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been produced from the {@link InputStream}!
   * This behavior can be avoided by using the non-streaming
   * #decryptData(ICryptographicMaterialsManager, byte[]) method instead, or
   * #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, InputStream) if you do
   * not need to decrypt signed messages.
   *
   * @see #decryptData(ICryptographicMaterialsManager, byte[])
   * @see #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, InputStream)
   * @see javax.crypto.CipherInputStream
   */
  public CryptoInputStream<?> createDecryptingStream(
      final ICryptographicMaterialsManager materialsManager, final InputStream is) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_);
    return new CryptoInputStream(is, cryptoHandler);
  }

  /**
   * Returns a {@link CryptoInputStream} which decrypts the data after reading it from the
   * underlying {@link InputStream}.
   *
   * <p>Note that if the encrypted message includes a trailing signature, by necessity it cannot be
   * verified until after the decrypted plaintext has been produced from the {@link InputStream}!
   * This behavior can be avoided by using the non-streaming
   * #decryptData(ICryptographicMaterialsManager, byte[], Map<String, String>) method instead, or
   * #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, InputStream, Map<String,
   * String>) if you do not need to decrypt signed messages.
   *
   * @see #decryptData(ICryptographicMaterialsManager, byte[], Map<String, String>)
   * @see #createUnsignedMessageDecryptingStream(ICryptographicMaterialsManager, InputStream,
   *     Map<String, String>)
   * @see javax.crypto.CipherInputStream
   */
  public CryptoInputStream<?> createDecryptingStream(
      final ICryptographicMaterialsManager materialsManager,
      final InputStream is,
      final Map<String, String> encryptionContext) {
    final MessageCryptoHandler cryptoHandler =
        DecryptionHandler.create(
            materialsManager,
            commitmentPolicy_,
            SignaturePolicy.AllowEncryptAllowDecrypt,
            maxEncryptedDataKeys_,
            encryptionContext);
    return new CryptoInputStream(is, cryptoHandler);
  }

  private MessageCryptoHandler getEncryptingStreamHandler(
      CMMHandler cmmHandler, Map<String, String> encryptionContext) {
    Utils.assertNonNull(cmmHandler, "cmmHandler");
    Utils.assertNonNull(encryptionContext, "encryptionContext");

    EncryptionMaterialsRequest.Builder requestBuilder =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(encryptionContext)
            .setRequestedAlgorithm(getEncryptionAlgorithm())
            .setCommitmentPolicy(commitmentPolicy_);

    return new LazyMessageCryptoHandler(
        info -> {
          // Hopefully we know the input size now, so we can pass it along to the CMM.
          if (info.getMaxInputSize() != -1) {
            requestBuilder.setPlaintextSize(info.getMaxInputSize());
          }

          return new EncryptionHandler(
              getEncryptionFrameSize(),
              checkMaxEncryptedDataKeys(
                  checkAlgorithm(cmmHandler.getMaterialsForEncrypt(requestBuilder.build()))),
              commitmentPolicy_);
        });
  }

  private ICryptographicMaterialsManager createDefaultCMM(IKeyring keyring) {
    CreateDefaultCryptographicMaterialsManagerInput input =
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build();
    return materialProviders_.CreateDefaultCryptographicMaterialsManager(input);
  }

  private EncryptionMaterialsHandler checkAlgorithm(EncryptionMaterialsHandler result) {
    if (encryptionAlgorithm_ != null && result.getAlgorithm() != encryptionAlgorithm_) {
      throw new AwsCryptoException(
          String.format(
              "Materials manager ignored requested algorithm; algorithm %s was set on AwsCrypto "
                  + "but %s was selected",
              encryptionAlgorithm_, result.getAlgorithm()));
    }

    return result;
  }

  private EncryptionMaterialsHandler checkMaxEncryptedDataKeys(
      EncryptionMaterialsHandler materials) {
    if (maxEncryptedDataKeys_ > 0
        && materials.getEncryptedDataKeys().size() > maxEncryptedDataKeys_) {
      throw new AwsCryptoException("Encrypted data keys exceed maxEncryptedDataKeys");
    }
    return materials;
  }
}
