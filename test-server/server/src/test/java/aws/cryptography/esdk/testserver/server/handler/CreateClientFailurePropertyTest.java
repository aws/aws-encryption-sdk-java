package aws.cryptography.esdk.testserver.server.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import aws.cryptography.esdk.testserver.server.config.ConfigValidator;
import aws.cryptography.esdk.testserver.server.config.EsdkClientFactory;
import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.server.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.server.model.CreateClientInput;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.server.model.GenericServerError;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.server.registry.ClientRegistry;
import java.nio.ByteBuffer;
import java.util.List;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

/**
 * Property-based test that a failed {@code CreateClient} leaves the registry
 * unchanged, using jqwik. Runs a minimum of 100 generated iterations. Uses the
 * real {@link ConfigValidator} and {@link EsdkClientFactory}; the generated
 * configs are valid per the exactly-one-variant rule but cause the real ESDK
 * client construction to fail deterministically and offline (an unwired
 * Caching CMM, an AWS KMS RSA keyring missing its encryption algorithm, or a
 * Raw AES keyring whose wrapping key length does not match its wrapping
 * algorithm), nested to varying depth.
 */
class CreateClientFailurePropertyTest {

    // Feature: esdk-test-server, Property 4: Failed CreateClient leaves the registry unchanged
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void failedCreateClientLeavesRegistryUnchanged(
            @ForAll boolean useCachingCmm,
            @ForAll boolean badRsaLeaf,
            @ForAll @IntRange(min = 0, max = 3) int wrapDepth,
            @ForAll @IntRange(min = 0, max = 5) int preexisting) {
        ClientRegistry registry = new ClientRegistry();
        for (int i = 0; i < preexisting; i++) {
            registry.register(ControllableEsdkClient.succeeding());
        }
        int sizeBefore = registry.size();

        CreateClientHandler handler = new CreateClientHandler(
            registry, new ConfigValidator(), new EsdkClientFactory(), new OperationWrapper());

        ESDKClientConfig config = constructionFailingConfig(useCachingCmm, badRsaLeaf, wrapDepth);

        Throwable thrown = null;
        try {
            handler.createClient(CreateClientInput.builder().config(config).build(), null);
        } catch (Throwable t) {
            thrown = t;
        }

        // (3.6, P4) construction failure -> GenericServerError, no ClientId (an
        // exception was thrown, not an output), and the registry is unchanged.
        assertInstanceOf(GenericServerError.class, thrown,
            "a client-construction failure must yield a GenericServerError");
        assertEquals(sizeBefore, registry.size(),
            "a failed CreateClient must leave the registry exactly as it was");
    }

    private static ESDKClientConfig constructionFailingConfig(
            boolean useCachingCmm, boolean badRsaLeaf, int wrapDepth) {
        CryptographicMaterialsManager cmm = useCachingCmm
            ? CryptographicMaterialsManager.builder()
                .caching(CachingCmmConfig.builder()
                    .underlyingCMM(validDefaultCmm())
                    .cacheLimitTtlSeconds(60)
                    .build())
                .build()
            : CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder()
                    .keyring(wrapInMulti(failingLeafKeyring(badRsaLeaf), wrapDepth))
                    .build())
                .build();
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(cmm)
            .build();
    }

    /**
     * A keyring variant that is valid (single variant) but whose construction the
     * factory genuinely rejects, offline and deterministically. {@code badRsaLeaf}
     * picks an AWS KMS RSA keyring that supplies a public key (so no network fetch
     * happens) but omits the required {@code encryptionAlgorithm}, which the
     * factory rejects before touching KMS. The alternative is a Raw AES keyring
     * whose 16-byte wrapping key contradicts its AES-256 wrapping algorithm, which
     * the material providers library rejects at keyring construction.
     */
    private static Keyring failingLeafKeyring(boolean badRsaLeaf) {
        if (badRsaLeaf) {
            return Keyring.builder()
                .awsKmsRsa(AwsKmsRsaKeyringConfig.builder()
                    .kmsKeyId("arn:aws:kms:us-west-2:111122223333:key/no-such-key")
                    .publicKey(ByteBuffer.wrap(new byte[16]))
                    // encryptionAlgorithm deliberately omitted -> factory rejects.
                    .build())
                .build();
        }
        return Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace("ns")
                .keyName("bad-length-key")
                // 16-byte wrapping key with an AES-256 alg -> MPL rejects.
                .wrappingKey(ByteBuffer.wrap(new byte[16]))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())
            .build();
    }

    /** Wrap a keyring in {@code depth} nested Multi keyrings (each a single variant). */
    private static Keyring wrapInMulti(Keyring inner, int depth) {
        Keyring current = inner;
        for (int i = 0; i < depth; i++) {
            current = Keyring.builder()
                .multi(MultiKeyringConfig.builder().childKeyrings(List.of(current)).build())
                .build();
        }
        return current;
    }

    private static CryptographicMaterialsManager validDefaultCmm() {
        RawAesKeyringConfig rawAes = RawAesKeyringConfig.builder()
            .keyNamespace("ns")
            .keyName("n")
            .wrappingKey(ByteBuffer.wrap(new byte[32]))
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build();
        return CryptographicMaterialsManager.builder()
            .defaultMember(DefaultCmmConfig.builder()
                .keyring(Keyring.builder().rawAes(rawAes).build())
                .build())
            .build();
    }
}
