package aws.cryptography.esdk.testserver.server.config;

import aws.cryptography.esdk.testserver.server.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.server.model.AwsKmsHierarchicalKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsMrkMultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.PaddingScheme;
import aws.cryptography.esdk.testserver.server.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RequiredEncryptionContextCmmConfig;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

/**
 * Shared builders for constructing polymorphic config-shape instances in the
 * config property tests. Kept out of the generators so the exactly-one-variant
 * test (P6) and the recursive round-trip test (P7) share one faithful way to
 * build each variant.
 */
final class ConfigTestFactory {

    private ConfigTestFactory() {
    }

    /**
     * The keyring variants used by the exactly-one-variant test. A representative
     * subset of the eight modeled variants — enough to build sets of size zero
     * and of size two-or-more — each easy to construct minimally.
     */
    static final List<String> KEYRING_VARIANTS =
        List.of("awsKms", "awsKmsMrk", "awsKmsMrkMulti", "awsKmsRsa", "awsKmsHierarchical",
            "rawAes", "rawRsa", "multi");

    /** The three CMM variants. */
    static final List<String> CMM_VARIANTS =
        List.of("Default", "RequiredEncryptionContext", "Caching");

    /** Build a {@link Keyring} with exactly the named variant members set. */
    static Keyring keyringWithVariants(Collection<String> variants) {
        Keyring.Builder builder = Keyring.builder();
        for (String variant : variants) {
            switch (variant) {
                case "awsKms" -> builder.awsKms(
                    AwsKmsKeyringConfig.builder().kmsKeyId("kms-key").build());
                case "awsKmsMrk" -> builder.awsKmsMrk(
                    AwsKmsMrkKeyringConfig.builder().kmsKeyId("mrk-key").build());
                case "awsKmsMrkMulti" -> builder.awsKmsMrkMultiKeyring(
                    AwsKmsMrkMultiKeyringConfig.builder().generator("mrk-key").build());
                case "awsKmsRsa" -> builder.awsKmsRsa(
                    AwsKmsRsaKeyringConfig.builder().kmsKeyId("rsa-key").build());
                case "awsKmsHierarchical" -> builder.awsKmsHierarchical(
                    AwsKmsHierarchicalKeyringConfig.builder()
                        .branchKeyId("branch-key")
                        .keyStoreTableName("KeyStoreDdbTable")
                        .logicalKeyStoreName("KeyStoreDdbTable")
                        .kmsKeyArn("arn:aws:kms:us-west-2:111122223333:key/example")
                        .ttlSeconds(600)
                        .build());
                case "rawAes" -> builder.rawAes(rawAes());
                case "rawRsa" -> builder.rawRsa(rawRsa());
                case "multi" -> builder.multi(
                    MultiKeyringConfig.builder().childKeyrings(List.of()).build());
                default -> throw new IllegalArgumentException("Unknown keyring variant: " + variant);
            }
        }
        return builder.build();
    }

    /**
     * Build a {@link CryptographicMaterialsManager} with exactly the named
     * variant members set. Wrapped CMMs/keyrings are minimal valid single-variant
     * instances so that only the top-level cardinality varies.
     */
    static CryptographicMaterialsManager cmmWithVariants(Collection<String> variants) {
        CryptographicMaterialsManager.Builder builder = CryptographicMaterialsManager.builder();
        for (String variant : variants) {
            switch (variant) {
                case "Default" -> builder.defaultMember(
                    DefaultCmmConfig.builder().keyring(singleVariantKeyring()).build());
                case "RequiredEncryptionContext" -> builder.requiredEncryptionContext(
                    RequiredEncryptionContextCmmConfig.builder()
                        .underlyingCMM(defaultCmm())
                        .requiredEncryptionContextKeys(List.of())
                        .build());
                case "Caching" -> builder.caching(
                    CachingCmmConfig.builder()
                        .underlyingCMM(defaultCmm())
                        .cacheLimitTtlSeconds(60)
                        .build());
                default -> throw new IllegalArgumentException("Unknown CMM variant: " + variant);
            }
        }
        return builder.build();
    }

    /** A valid keyring with exactly one variant set (raw AES). */
    static Keyring singleVariantKeyring() {
        return Keyring.builder().rawAes(rawAes()).build();
    }

    /** A valid CMM with exactly one variant set (Default over a raw-AES keyring). */
    static CryptographicMaterialsManager defaultCmm() {
        return CryptographicMaterialsManager.builder()
            .defaultMember(DefaultCmmConfig.builder().keyring(singleVariantKeyring()).build())
            .build();
    }

    private static RawAesKeyringConfig rawAes() {
        return RawAesKeyringConfig.builder()
            .keyNamespace("namespace")
            .keyName("name")
            .wrappingKey(ByteBuffer.wrap("0123456789abcdef".getBytes(StandardCharsets.UTF_8)))
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build();
    }

    private static RawRsaKeyringConfig rawRsa() {
        return RawRsaKeyringConfig.builder()
            .keyNamespace("namespace")
            .keyName("name")
            .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
            .build();
    }
}
