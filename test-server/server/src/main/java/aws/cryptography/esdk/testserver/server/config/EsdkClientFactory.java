package aws.cryptography.esdk.testserver.server.config;

import aws.cryptography.esdk.testserver.server.model.AwsKmsDiscoveryKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsEcdhKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsHierarchicalKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMrkDiscoveryKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMrkMultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.EcdhCurveSpec;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.KmsEcdhKeyAgreementScheme;
import aws.cryptography.esdk.testserver.server.model.KmsRsaEncryptionAlgorithm;
import aws.cryptography.esdk.testserver.server.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawEcdhKeyAgreementScheme;
import aws.cryptography.esdk.testserver.server.model.RawEcdhKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RequiredEncryptionContextCmmConfig;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.registry.RealEsdkClient;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsDiscoveryKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsEcdhKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkDiscoveryKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawEcdhKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.EphemeralPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.materialproviders.model.KmsEcdhStaticConfigurations;
import software.amazon.cryptography.materialproviders.model.KmsPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.materialproviders.model.KmsPublicKeyDiscoveryInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.PaddingScheme;
import software.amazon.cryptography.materialproviders.model.PublicKeyDiscoveryInput;
import software.amazon.cryptography.materialproviders.model.RawEcdhStaticConfigurations;
import software.amazon.cryptography.materialproviders.model.RawPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.primitives.model.ECDHCurveSpec;

/**
 * Translates a validated {@link ESDKClientConfig} into a {@link RealEsdkClient}
 * backed by the REAL AWS Encryption SDK for Java plus the AWS Cryptographic
 * Material Providers library (Requirement 3.1). The tagged-union config shapes
 * are walked recursively — a Default/RequiredEncryptionContext CMM, and a Multi
 * keyring whose children are themselves keyrings — mirroring the model's
 * recursive variants (Requirement 2.5).
 *
 * <p>This factory assumes the config has already passed {@link ConfigValidator}
 * (exactly one variant member set at each polymorphic node). Any failure to
 * build a real client — an unsupported variant in this pass, or an input the
 * material providers / ESDK reject — is surfaced as a thrown exception; the
 * {@code CreateClient} handler maps that to a {@code GenericServerError} and
 * leaves the registry unchanged (Requirement 3.6).
 *
 * <p>Scope note: the offline-capable variants used by the offline round-trip
 * tests — Raw AES, Raw RSA, Multi, and the Default / RequiredEncryptionContext
 * CMMs — are fully wired. All six AWS KMS keyring variants are also fully wired:
 * {@code AwsKms} (single symmetric key), {@code AwsKmsMrk} (single
 * multi-region key), {@code AwsKmsMultiKeyring} (generator + child keys),
 * {@code AwsKmsRsa} (asymmetric RSA key), {@code AwsKmsDiscovery} (discovery
 * keyring), and {@code AwsKmsHierarchical} (branch keys in a DynamoDB key store
 * wrapped by a KMS key). Every KMS keyring is <em>constructed</em> without a
 * network call —
 * the KMS client is built eagerly but is not invoked — so {@code CreateClient}
 * stays offline; the real AWS KMS calls happen only on {@code Encrypt}/{@code
 * Decrypt} (Requirements 14.1, 14.3, 14.4, 14.14). The Raw ECDH and AWS KMS ECDH
 * keyrings are wired as well. The exceptions are the AWS KMS ECDH keyring when its
 * static configuration omits the sender's public key (fetched via
 * {@code kms:GetPublicKey}), and the
 * {@code AwsKmsRsa} keyring when the modeled config omits the RSA public key: in
 * that case the factory fetches it once via {@code kms:GetPublicKey} at
 * construction (a network call the design explicitly permits at
 * {@code CreateClient} time); supplying {@code publicKey} in the config keeps
 * construction fully offline.
 *
 * <p>The Caching CMM is the ESDK's {@code CachingCryptoMaterialsManager}: the
 * Material Providers Library has no caching CMM, and the ESDK's caching CMM wraps
 * master key providers rather than MPL keyrings. So a top-level Caching config is
 * built over master key providers equivalent to its wrapped Default CMM's keyring
 * (Raw AES and Raw RSA as {@code JceMasterKey}, the AWS KMS keyrings as the KMS
 * master key providers, and Multi as a multi-provider); any other keyring, or a
 * Caching CMM nested under another CMM, is a construction failure.
 */
public final class EsdkClientFactory {

    private final MaterialProviders materialProviders;

    public EsdkClientFactory() {
        this.materialProviders = MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    }

    /**
     * Build a configured real ESDK client from the modeled config.
     *
     * @throws RuntimeException if a real client cannot be constructed; the caller
     *     maps this to a {@code GenericServerError} (Requirement 3.6).
     */
    public EsdkClient create(ESDKClientConfig config) {
        CommitmentPolicy commitmentPolicy = toCommitmentPolicy(config.getCommitmentPolicy().getValue());
        Integer maxEdk = config.getMaxEncryptedDataKeys() == null
            ? null
            : Math.toIntExact(config.getMaxEncryptedDataKeys());
        CachingCmmConfig caching = config.getCmm().getCaching();
        if (caching != null) {
            return new RealEsdkClient(commitmentPolicy, maxEdk, buildCachingCmm(caching));
        }
        ICryptographicMaterialsManager cmm = buildCmm(config.getCmm());
        return new RealEsdkClient(commitmentPolicy, maxEdk, cmm);
    }

    private ICryptographicMaterialsManager buildCmm(CryptographicMaterialsManager cmm) {
        DefaultCmmConfig defaultCmm = cmm.getDefault();
        RequiredEncryptionContextCmmConfig requiredEc = cmm.getRequiredEncryptionContext();
        CachingCmmConfig caching = cmm.getCaching();

        if (defaultCmm != null) {
            IKeyring keyring = buildKeyring(defaultCmm.getKeyring());
            return materialProviders.CreateDefaultCryptographicMaterialsManager(
                CreateDefaultCryptographicMaterialsManagerInput.builder()
                    .keyring(keyring)
                    .build());
        }
        if (requiredEc != null) {
            ICryptographicMaterialsManager underlying = buildCmm(requiredEc.getUnderlyingCMM());
            return materialProviders.CreateRequiredEncryptionContextCMM(
                CreateRequiredEncryptionContextCMMInput.builder()
                    .underlyingCMM(underlying)
                    .requiredEncryptionContextKeys(
                        new ArrayList<>(requiredEc.getRequiredEncryptionContextKeys()))
                    .build());
        }
        if (caching != null) {
            throw new UnsupportedOperationException(
                "a Caching CMM is supported only as the client's top-level CMM");
        }
        throw new IllegalArgumentException(
            "CryptographicMaterialsManager had no variant member set");
    }

    /** Entries the Caching CMM's local cache holds. */
    private static final int CACHE_CAPACITY = 100;

    private static CachingCryptoMaterialsManager buildCachingCmm(CachingCmmConfig config) {
        DefaultCmmConfig underlying = config.getUnderlyingCMM().getDefault();
        if (underlying == null) {
            throw new UnsupportedOperationException(
                "the Caching CMM must wrap a Default CMM: the ESDK's caching CMM wraps master key providers");
        }
        CachingCryptoMaterialsManager.Builder builder = CachingCryptoMaterialsManager.newBuilder()
            .withMasterKeyProvider(toMasterKeyProvider(underlying.getKeyring()))
            .withCache(new LocalCryptoMaterialsCache(CACHE_CAPACITY))
            .withMaxAge(config.getCacheLimitTtlSeconds(), TimeUnit.SECONDS);
        if (config.getPartitionId() != null) {
            builder.withPartitionId(config.getPartitionId());
        }
        if (config.getLimitMessages() != null) {
            builder.withMessageUseLimit(config.getLimitMessages());
        }
        if (config.getLimitBytes() != null) {
            builder.withByteUseLimit(config.getLimitBytes());
        }
        return builder.build();
    }

    /**
     * The master key provider equivalent to {@code keyring}: it writes and reads
     * the same encrypted data keys as the MPL keyring of the same configuration.
     */
    private static MasterKeyProvider<?> toMasterKeyProvider(Keyring keyring) {
        if (keyring.getRawAes() != null) {
            RawAesKeyringConfig rawAes = keyring.getRawAes();
            return JceMasterKey.getInstance(
                new SecretKeySpec(bytes(rawAes.getWrappingKey()), "AES"),
                rawAes.getKeyNamespace(), rawAes.getKeyName(), "AES/GCM/NoPadding");
        }
        if (keyring.getRawRsa() != null) {
            RawRsaKeyringConfig rawRsa = keyring.getRawRsa();
            return JceMasterKey.getInstance(
                rawRsa.getPublicKey() == null ? null : rsaPublicKey(rawRsa.getPublicKey()),
                rawRsa.getPrivateKey() == null ? null : rsaPrivateKey(rawRsa.getPrivateKey()),
                rawRsa.getKeyNamespace(), rawRsa.getKeyName(),
                rsaTransformation(rawRsa.getPaddingScheme().getValue()));
        }
        if (keyring.getAwsKms() != null) {
            requireNoGrantTokens(keyring.getAwsKms().hasGrantTokens()
                && !keyring.getAwsKms().getGrantTokens().isEmpty());
            return KmsMasterKeyProvider.builder().buildStrict(keyring.getAwsKms().getKmsKeyId());
        }
        if (keyring.getAwsKmsMrk() != null) {
            requireNoGrantTokens(keyring.getAwsKmsMrk().hasGrantTokens()
                && !keyring.getAwsKmsMrk().getGrantTokens().isEmpty());
            return AwsKmsMrkAwareMasterKeyProvider.builder()
                .buildStrict(keyring.getAwsKmsMrk().getKmsKeyId());
        }
        if (keyring.getAwsKmsMultiKeyring() != null) {
            AwsKmsMultiKeyringConfig multi = keyring.getAwsKmsMultiKeyring();
            requireNoGrantTokens(multi.hasGrantTokens() && !multi.getGrantTokens().isEmpty());
            return KmsMasterKeyProvider.builder().buildStrict(kmsKeyIds(multi.getGenerator(),
                multi.hasKmsKeyIds() ? multi.getKmsKeyIds() : List.of()));
        }
        if (keyring.getAwsKmsMrkMultiKeyring() != null) {
            AwsKmsMrkMultiKeyringConfig multi = keyring.getAwsKmsMrkMultiKeyring();
            requireNoGrantTokens(multi.hasGrantTokens() && !multi.getGrantTokens().isEmpty());
            return AwsKmsMrkAwareMasterKeyProvider.builder().buildStrict(kmsKeyIds(multi.getGenerator(),
                multi.hasKmsKeyIds() ? multi.getKmsKeyIds() : List.of()));
        }
        if (keyring.getMulti() != null) {
            MultiKeyringConfig multi = keyring.getMulti();
            List<MasterKeyProvider<?>> providers = new ArrayList<>();
            if (multi.getGenerator() != null) {
                providers.add(toMasterKeyProvider(multi.getGenerator()));
            }
            for (Keyring child : multi.getChildKeyrings()) {
                providers.add(toMasterKeyProvider(child));
            }
            return MultipleProviderFactory.buildMultiProvider(providers);
        }
        throw new UnsupportedOperationException(
            "this keyring is not supported under the Caching CMM: the ESDK's caching CMM wraps"
                + " master key providers, and only the Raw AES, Raw RSA, AWS KMS, AWS KMS MRK, AWS KMS"
                + " (MRK) multi, and Multi keyrings have master key provider equivalents");
    }

    private static List<String> kmsKeyIds(String generator, List<String> keyIds) {
        List<String> ids = new ArrayList<>();
        if (generator != null) {
            ids.add(generator);
        }
        ids.addAll(keyIds);
        return ids;
    }

    private static void requireNoGrantTokens(boolean present) {
        if (present) {
            throw new UnsupportedOperationException(
                "grant tokens are not supported under the Caching CMM");
        }
    }

    /** The {@code JceMasterKey} RSA transformation for a modeled padding scheme. */
    private static String rsaTransformation(String paddingScheme) {
        return switch (paddingScheme) {
            case "PKCS1" -> "RSA/ECB/PKCS1Padding";
            case "OAEP_SHA1_MGF1" -> "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
            case "OAEP_SHA256_MGF1" -> "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            case "OAEP_SHA384_MGF1" -> "RSA/ECB/OAEPWithSHA-384AndMGF1Padding";
            case "OAEP_SHA512_MGF1" -> "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
            default -> throw new IllegalArgumentException("Unknown RSA padding scheme: " + paddingScheme);
        };
    }

    private static PublicKey rsaPublicKey(ByteBuffer pem) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pemBody(pem)));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid PEM RSA public key", e);
        }
    }

    private static PrivateKey rsaPrivateKey(ByteBuffer pem) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pemBody(pem)));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid PEM RSA private key", e);
        }
    }

    /** The DER bytes inside a PEM block. */
    private static byte[] pemBody(ByteBuffer pem) {
        String text = new String(bytes(pem), StandardCharsets.US_ASCII)
            .replaceAll("-----[A-Z ]+-----", "")
            .replaceAll("\\s", "");
        return Base64.getDecoder().decode(text);
    }

    private static byte[] bytes(ByteBuffer buffer) {
        byte[] copy = new byte[buffer.remaining()];
        buffer.duplicate().get(copy);
        return copy;
    }

    private IKeyring buildKeyring(Keyring keyring) {
        RawAesKeyringConfig rawAes = keyring.getRawAes();
        RawRsaKeyringConfig rawRsa = keyring.getRawRsa();
        MultiKeyringConfig multi = keyring.getMulti();
        AwsKmsKeyringConfig awsKms = keyring.getAwsKms();
        AwsKmsMrkKeyringConfig awsKmsMrk = keyring.getAwsKmsMrk();
        AwsKmsMultiKeyringConfig awsKmsMulti = keyring.getAwsKmsMultiKeyring();
        AwsKmsMrkMultiKeyringConfig awsKmsMrkMulti = keyring.getAwsKmsMrkMultiKeyring();
        AwsKmsRsaKeyringConfig awsKmsRsa = keyring.getAwsKmsRsa();
        AwsKmsDiscoveryKeyringConfig awsKmsDiscovery = keyring.getAwsKmsDiscovery();
        AwsKmsMrkDiscoveryKeyringConfig awsKmsMrkDiscovery = keyring.getAwsKmsMrkDiscovery();
        AwsKmsHierarchicalKeyringConfig awsKmsHierarchical = keyring.getAwsKmsHierarchical();
        RawEcdhKeyringConfig rawEcdh = keyring.getRawEcdh();
        AwsKmsEcdhKeyringConfig awsKmsEcdh = keyring.getAwsKmsEcdh();

        if (rawAes != null) {
            return materialProviders.CreateRawAesKeyring(
                CreateRawAesKeyringInput.builder()
                    .keyNamespace(rawAes.getKeyNamespace())
                    .keyName(rawAes.getKeyName())
                    .wrappingKey(rawAes.getWrappingKey())
                    .wrappingAlg(AesWrappingAlg.valueOf(rawAes.getWrappingAlg().getValue()))
                    .build());
        }
        if (rawRsa != null) {
            CreateRawRsaKeyringInput.Builder builder = CreateRawRsaKeyringInput.builder()
                .keyNamespace(rawRsa.getKeyNamespace())
                .keyName(rawRsa.getKeyName())
                .paddingScheme(PaddingScheme.valueOf(rawRsa.getPaddingScheme().getValue()));
            if (rawRsa.getPublicKey() != null) {
                builder.publicKey(rawRsa.getPublicKey());
            }
            if (rawRsa.getPrivateKey() != null) {
                builder.privateKey(rawRsa.getPrivateKey());
            }
            return materialProviders.CreateRawRsaKeyring(builder.build());
        }
        if (multi != null) {
            CreateMultiKeyringInput.Builder builder = CreateMultiKeyringInput.builder();
            if (multi.getGenerator() != null) {
                builder.generator(buildKeyring(multi.getGenerator()));
            }
            List<IKeyring> children = new ArrayList<>();
            for (Keyring child : multi.getChildKeyrings()) {
                children.add(buildKeyring(child));
            }
            builder.childKeyrings(children);
            return materialProviders.CreateMultiKeyring(builder.build());
        }
        if (awsKms != null) {
            // Single symmetric KMS key -> the single-key KMS keyring (the faithful
            // mapping for one symmetric key). The KMS client is built eagerly; no
            // network call happens until Encrypt/Decrypt (Requirement 14.1, 14.14).
            CreateAwsKmsKeyringInput.Builder builder = CreateAwsKmsKeyringInput.builder()
                .kmsKeyId(awsKms.getKmsKeyId())
                .kmsClient(kmsClientForKey(awsKms.getKmsKeyId()));
            if (awsKms.hasGrantTokens() && !awsKms.getGrantTokens().isEmpty()) {
                builder.grantTokens(new ArrayList<>(awsKms.getGrantTokens()));
            }
            return materialProviders.CreateAwsKmsKeyring(builder.build());
        }
        if (awsKmsMrk != null) {
            // Single multi-region key -> the single-key MRK-aware KMS keyring.
            CreateAwsKmsMrkKeyringInput.Builder builder = CreateAwsKmsMrkKeyringInput.builder()
                .kmsKeyId(awsKmsMrk.getKmsKeyId())
                .kmsClient(kmsClientForKey(awsKmsMrk.getKmsKeyId()));
            if (awsKmsMrk.hasGrantTokens() && !awsKmsMrk.getGrantTokens().isEmpty()) {
                builder.grantTokens(new ArrayList<>(awsKmsMrk.getGrantTokens()));
            }
            return materialProviders.CreateAwsKmsMrkKeyring(builder.build());
        }
        if (awsKmsMulti != null) {
            CreateAwsKmsMultiKeyringInput.Builder builder = CreateAwsKmsMultiKeyringInput.builder();
            if (awsKmsMulti.getGenerator() != null) {
                builder.generator(awsKmsMulti.getGenerator());
            }
            if (awsKmsMulti.hasKmsKeyIds()) {
                builder.kmsKeyIds(new ArrayList<>(awsKmsMulti.getKmsKeyIds()));
            }
            if (awsKmsMulti.hasGrantTokens() && !awsKmsMulti.getGrantTokens().isEmpty()) {
                builder.grantTokens(new ArrayList<>(awsKmsMulti.getGrantTokens()));
            }
            return materialProviders.CreateAwsKmsMultiKeyring(builder.build());
        }
        if (awsKmsMrkMulti != null) {
            // MRK-aware multi-keyring: an optional MRK generator + child MRK key
            // ids. Mirrors the non-MRK multi-keyring wiring; the MRK-aware form
            // matches multi-region keys across regions on decrypt.
            CreateAwsKmsMrkMultiKeyringInput.Builder builder =
                CreateAwsKmsMrkMultiKeyringInput.builder();
            if (awsKmsMrkMulti.getGenerator() != null) {
                builder.generator(awsKmsMrkMulti.getGenerator());
            }
            if (awsKmsMrkMulti.hasKmsKeyIds()) {
                builder.kmsKeyIds(new ArrayList<>(awsKmsMrkMulti.getKmsKeyIds()));
            }
            if (awsKmsMrkMulti.hasGrantTokens() && !awsKmsMrkMulti.getGrantTokens().isEmpty()) {
                builder.grantTokens(new ArrayList<>(awsKmsMrkMulti.getGrantTokens()));
            }
            return materialProviders.CreateAwsKmsMrkMultiKeyring(builder.build());
        }
        if (awsKmsRsa != null) {
            return buildAwsKmsRsaKeyring(awsKmsRsa);
        }
        if (awsKmsDiscovery != null) {
            return buildAwsKmsDiscoveryKeyring(awsKmsDiscovery);
        }
        if (awsKmsMrkDiscovery != null) {
            return buildAwsKmsMrkDiscoveryKeyring(awsKmsMrkDiscovery);
        }
        if (awsKmsHierarchical != null) {
            return buildAwsKmsHierarchicalKeyring(awsKmsHierarchical);
        }
        if (rawEcdh != null) {
            return buildRawEcdhKeyring(rawEcdh);
        }
        if (awsKmsEcdh != null) {
            return buildAwsKmsEcdhKeyring(awsKmsEcdh);
        }
        throw new IllegalArgumentException("Keyring had no variant member set");
    }

    /** Build the Raw ECDH keyring from its key agreement scheme and curve. */
    private IKeyring buildRawEcdhKeyring(RawEcdhKeyringConfig config) {
        RawEcdhKeyAgreementScheme scheme = config.getKeyAgreementScheme();
        RawEcdhStaticConfigurations.Builder agreement = RawEcdhStaticConfigurations.builder();
        if (scheme.getRawPrivateKeyToStaticPublicKey() != null) {
            agreement.RawPrivateKeyToStaticPublicKey(RawPrivateKeyToStaticPublicKeyInput.builder()
                .senderStaticPrivateKey(scheme.getRawPrivateKeyToStaticPublicKey().getSenderStaticPrivateKey())
                .recipientPublicKey(scheme.getRawPrivateKeyToStaticPublicKey().getRecipientPublicKey())
                .build());
        } else if (scheme.getEphemeralPrivateKeyToStaticPublicKey() != null) {
            agreement.EphemeralPrivateKeyToStaticPublicKey(EphemeralPrivateKeyToStaticPublicKeyInput.builder()
                .recipientPublicKey(scheme.getEphemeralPrivateKeyToStaticPublicKey().getRecipientPublicKey())
                .build());
        } else {
            agreement.PublicKeyDiscovery(PublicKeyDiscoveryInput.builder()
                .recipientStaticPrivateKey(scheme.getPublicKeyDiscovery().getRecipientStaticPrivateKey())
                .build());
        }
        return materialProviders.CreateRawEcdhKeyring(CreateRawEcdhKeyringInput.builder()
            .KeyAgreementScheme(agreement.build())
            .curveSpec(toCurveSpec(config.getCurveSpec()))
            .build());
    }

    /**
     * Build the AWS KMS ECDH keyring. The KMS client is in the region of the
     * sender's (static) or recipient's (discovery) KMS key; construction makes no
     * network call unless the static configuration omits the sender's public key,
     * which the MPL then fetches with {@code kms:GetPublicKey}.
     */
    private IKeyring buildAwsKmsEcdhKeyring(AwsKmsEcdhKeyringConfig config) {
        KmsEcdhKeyAgreementScheme scheme = config.getKeyAgreementScheme();
        KmsEcdhStaticConfigurations.Builder agreement = KmsEcdhStaticConfigurations.builder();
        String kmsKeyId;
        if (scheme.getKmsPrivateKeyToStaticPublicKey() != null) {
            var staticConfig = scheme.getKmsPrivateKeyToStaticPublicKey();
            kmsKeyId = staticConfig.getSenderKmsIdentifier();
            KmsPrivateKeyToStaticPublicKeyInput.Builder input = KmsPrivateKeyToStaticPublicKeyInput.builder()
                .senderKmsIdentifier(kmsKeyId)
                .recipientPublicKey(staticConfig.getRecipientPublicKey());
            if (staticConfig.getSenderPublicKey() != null) {
                input.senderPublicKey(staticConfig.getSenderPublicKey());
            }
            agreement.KmsPrivateKeyToStaticPublicKey(input.build());
        } else {
            kmsKeyId = scheme.getKmsPublicKeyDiscovery().getRecipientKmsIdentifier();
            agreement.KmsPublicKeyDiscovery(KmsPublicKeyDiscoveryInput.builder()
                .recipientKmsIdentifier(kmsKeyId)
                .build());
        }
        CreateAwsKmsEcdhKeyringInput.Builder builder = CreateAwsKmsEcdhKeyringInput.builder()
            .KeyAgreementScheme(agreement.build())
            .curveSpec(toCurveSpec(config.getCurveSpec()))
            .kmsClient(kmsClientForKey(kmsKeyId));
        if (config.hasGrantTokens() && !config.getGrantTokens().isEmpty()) {
            builder.grantTokens(new ArrayList<>(config.getGrantTokens()));
        }
        return materialProviders.CreateAwsKmsEcdhKeyring(builder.build());
    }

    private static ECDHCurveSpec toCurveSpec(EcdhCurveSpec curve) {
        return switch (curve.getValue()) {
            case "ECC_NIST_P256" -> ECDHCurveSpec.ECC_NIST_P256;
            case "ECC_NIST_P384" -> ECDHCurveSpec.ECC_NIST_P384;
            case "ECC_NIST_P521" -> ECDHCurveSpec.ECC_NIST_P521;
            case "SM2" -> ECDHCurveSpec.SM2;
            default -> throw new IllegalArgumentException("Unknown ECDH curve: " + curve.getValue());
        };
    }

    /**
     * Build the AWS KMS RSA keyring (Requirement 14.3, 14.4). The keyring needs
     * the RSA <em>public key</em> bytes (for encrypt), the KMS key id/ARN and a KMS
     * client (for decrypt, which calls {@code kms:Decrypt}), and an RSAES-OAEP
     * encryption algorithm mapped from the modeled {@link KmsRsaEncryptionAlgorithm}.
     *
     * <p>Public-key sourcing: if the modeled config carries {@code publicKey}, it
     * is used and construction stays fully offline. Otherwise the factory fetches
     * it once via {@code kms:GetPublicKey} — a network call the design permits at
     * {@code CreateClient} time (KMS scenarios only run when credentials are
     * present). Either way, no encrypt/decrypt happens at construction.
     */
    private IKeyring buildAwsKmsRsaKeyring(AwsKmsRsaKeyringConfig config) {
        KmsClient kmsClient = kmsClientForKey(config.getKmsKeyId());
        ByteBuffer publicKey = config.getPublicKey();
        if (publicKey == null) {
            // Fetch the RSA public key once from KMS (network call at construction).
            publicKey = kmsClient.getPublicKey(
                    GetPublicKeyRequest.builder().keyId(config.getKmsKeyId()).build())
                .publicKey()
                .asByteBuffer();
        }
        // The ESDK's CreateAwsKmsRsaKeyring expects the public key as PEM, but KMS
        // GetPublicKey returns it as DER (X.509 SubjectPublicKeyInfo). Wrap DER as
        // a PEM "PUBLIC KEY" block (pass through if it is already PEM).
        CreateAwsKmsRsaKeyringInput.Builder builder = CreateAwsKmsRsaKeyringInput.builder()
            .kmsKeyId(config.getKmsKeyId())
            .publicKey(toPublicKeyPem(publicKey))
            .encryptionAlgorithm(toEncryptionAlgorithmSpec(config.getEncryptionAlgorithm()))
            .kmsClient(kmsClient);
        if (config.hasGrantTokens() && !config.getGrantTokens().isEmpty()) {
            builder.grantTokens(new ArrayList<>(config.getGrantTokens()));
        }
        return materialProviders.CreateAwsKmsRsaKeyring(builder.build());
    }

    /**
     * Normalize an RSA public key to PEM, as required by {@code
     * CreateAwsKmsRsaKeyring}. KMS {@code GetPublicKey} returns the key as DER
     * (X.509 {@code SubjectPublicKeyInfo}); this base64-wraps those bytes in a
     * {@code -----BEGIN PUBLIC KEY-----} block. If the input already looks like
     * PEM it is returned unchanged, so a caller-supplied PEM public key works too.
     */
    private static ByteBuffer toPublicKeyPem(ByteBuffer publicKey) {
        byte[] bytes = new byte[publicKey.remaining()];
        publicKey.duplicate().get(bytes);
        String head = new String(bytes, 0, Math.min(bytes.length, 11), StandardCharsets.US_ASCII);
        if (head.startsWith("-----BEGIN")) {
            return ByteBuffer.wrap(bytes);
        }
        String base64 = Base64.getEncoder().encodeToString(bytes);
        StringBuilder pem = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        }
        pem.append("-----END PUBLIC KEY-----\n");
        return ByteBuffer.wrap(pem.toString().getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Build the AWS KMS discovery keyring (Requirement 14.3, 14.4). A discovery
     * keyring is decrypt-only: it needs a KMS client (its region comes from the
     * ambient AWS region / credentials the online Tests supply) and, optionally, a
     * discovery filter scoping decrypt to a partition + account ids. On the
     * round-trip it pairs with an encrypting KMS keyring on the encrypt leg.
     */
    private IKeyring buildAwsKmsDiscoveryKeyring(AwsKmsDiscoveryKeyringConfig config) {
        CreateAwsKmsDiscoveryKeyringInput.Builder builder = CreateAwsKmsDiscoveryKeyringInput.builder()
            .kmsClient(kmsClient());
        aws.cryptography.esdk.testserver.server.model.DiscoveryFilter modeledFilter =
            config.getDiscoveryFilter();
        if (modeledFilter != null) {
            builder.discoveryFilter(
                software.amazon.cryptography.materialproviders.model.DiscoveryFilter.builder()
                    .partition(modeledFilter.getPartition())
                    .accountIds(new ArrayList<>(modeledFilter.getAccountIds()))
                    .build());
        }
        if (config.hasGrantTokens() && !config.getGrantTokens().isEmpty()) {
            builder.grantTokens(new ArrayList<>(config.getGrantTokens()));
        }
        return materialProviders.CreateAwsKmsDiscoveryKeyring(builder.build());
    }

    /**
     * Build the AWS KMS MRK-aware discovery keyring: a decrypt-only discovery
     * keyring normalized to {@code region} (built with a KMS client in that
     * region), so it can decrypt a multi-region key written in another region.
     */
    private IKeyring buildAwsKmsMrkDiscoveryKeyring(AwsKmsMrkDiscoveryKeyringConfig config) {
        CreateAwsKmsMrkDiscoveryKeyringInput.Builder builder =
            CreateAwsKmsMrkDiscoveryKeyringInput.builder()
                .kmsClient(KmsClient.builder().region(Region.of(config.getRegion())).build())
                .region(config.getRegion());
        aws.cryptography.esdk.testserver.server.model.DiscoveryFilter modeledFilter =
            config.getDiscoveryFilter();
        if (modeledFilter != null) {
            builder.discoveryFilter(
                software.amazon.cryptography.materialproviders.model.DiscoveryFilter.builder()
                    .partition(modeledFilter.getPartition())
                    .accountIds(new ArrayList<>(modeledFilter.getAccountIds()))
                    .build());
        }
        if (config.hasGrantTokens() && !config.getGrantTokens().isEmpty()) {
            builder.grantTokens(new ArrayList<>(config.getGrantTokens()));
        }
        return materialProviders.CreateAwsKmsMrkDiscoveryKeyring(builder.build());
    }

    /**
     * Build the AWS KMS hierarchical keyring: branch keys live in a DynamoDB key
     * store and are wrapped by a KMS key. The key store's DynamoDB and KMS clients
     * are built eagerly without a network call; branch-key retrieval reaches
     * DynamoDB and KMS only on {@code Encrypt}/{@code Decrypt}.
     */
    private IKeyring buildAwsKmsHierarchicalKeyring(AwsKmsHierarchicalKeyringConfig config) {
        KeyStore keyStore = KeyStore.builder()
            .KeyStoreConfig(KeyStoreConfig.builder()
                .ddbTableName(config.getKeyStoreTableName())
                .logicalKeyStoreName(config.getLogicalKeyStoreName())
                .kmsConfiguration(KMSConfiguration.builder()
                    .kmsKeyArn(config.getKmsKeyArn())
                    .build())
                .ddbClient(DynamoDbClient.builder().region(Region.of(resolveRegion())).build())
                .kmsClient(kmsClient())
                .build())
            .build();
        return materialProviders.CreateAwsKmsHierarchicalKeyring(
            CreateAwsKmsHierarchicalKeyringInput.builder()
                .keyStore(keyStore)
                .branchKeyId(config.getBranchKeyId())
                .ttlSeconds(config.getTtlSeconds())
                .build());
    }

    /**
     * Construct an AWS KMS client. Building the client performs no network call;
     * the region is resolved from the ambient AWS region provider chain (the
     * {@code AWS_REGION} / configured region the online KMS Tests supply). Key-ARN
     * based keyrings encode their own region, but the client is supplied so
     * discovery (which has no key ARN) and RSA (GetPublicKey) can reach KMS.
     */
    private static KmsClient kmsClient() {
        // Resolve the region explicitly with a safe default so the KMS client
        // never fails region resolution when the ambient provider chain is empty
        // (e.g. a nested server JVM that did not inherit AWS_REGION). The ambient
        // AWS_REGION / aws.region still takes precedence; us-west-2 (where the
        // KMS_Test_Resources live) is the fallback.
        return KmsClient.builder().region(Region.of(resolveRegion())).build();
    }

    /**
     * A KMS client in the key's own region. KMS rejects an ARN whose region
     * differs from the client's region ("Invalid arn &lt;region&gt;"), so a
     * us-east-1 key needs a us-east-1 client even when the ambient region is
     * us-west-2. Falls back to {@link #resolveRegion()} for a bare key id or
     * alias that carries no region.
     */
    private static KmsClient kmsClientForKey(String kmsKeyId) {
        return KmsClient.builder().region(Region.of(regionForKey(kmsKeyId))).build();
    }

    private static String regionForKey(String kmsKeyId) {
        if (kmsKeyId != null && kmsKeyId.startsWith("arn:")) {
            String[] parts = kmsKeyId.split(":");
            if (parts.length > 3 && !isBlank(parts[3])) {
                return parts[3];
            }
        }
        return resolveRegion();
    }

    /**
     * @return the AWS region for the KMS client: {@code aws.region} system
     *     property, then {@code AWS_REGION} / {@code AWS_DEFAULT_REGION}
     *     environment, then the {@code us-west-2} default.
     */
    private static String resolveRegion() {
        String region = System.getProperty("aws.region");
        if (isBlank(region)) {
            region = System.getenv("AWS_REGION");
        }
        if (isBlank(region)) {
            region = System.getenv("AWS_DEFAULT_REGION");
        }
        return isBlank(region) ? "us-west-2" : region.trim();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static EncryptionAlgorithmSpec toEncryptionAlgorithmSpec(
        KmsRsaEncryptionAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException(
                "AwsKmsRsa keyring requires an encryptionAlgorithm (RSAES_OAEP_SHA_1 "
                    + "or RSAES_OAEP_SHA_256)");
        }
        return switch (algorithm.getValue()) {
            case "RSAES_OAEP_SHA_1" -> EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1;
            case "RSAES_OAEP_SHA_256" -> EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;
            default -> throw new IllegalArgumentException(
                "Unknown KMS RSA encryption algorithm: " + algorithm.getValue());
        };
    }

    private static CommitmentPolicy toCommitmentPolicy(String value) {
        return switch (value) {
            case "FORBID_ENCRYPT_ALLOW_DECRYPT" -> CommitmentPolicy.ForbidEncryptAllowDecrypt;
            case "REQUIRE_ENCRYPT_ALLOW_DECRYPT" -> CommitmentPolicy.RequireEncryptAllowDecrypt;
            case "REQUIRE_ENCRYPT_REQUIRE_DECRYPT" -> CommitmentPolicy.RequireEncryptRequireDecrypt;
            default -> throw new IllegalArgumentException("Unknown commitment policy: " + value);
        };
    }
}
