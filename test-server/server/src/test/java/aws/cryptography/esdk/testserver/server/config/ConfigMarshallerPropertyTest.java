package aws.cryptography.esdk.testserver.server.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.esdk.testserver.server.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RequiredEncryptionContextCmmConfig;
import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based test for {@link ConfigMarshaller}'s recursive round-trip through
 * the rpcv2Cbor wire form, using jqwik. Generates arbitrarily nested configs —
 * Multi keyrings containing child keyrings, and Caching / RequiredEncryptionContext
 * CMMs wrapping other CMMs — exercising both recursion points of the model
 * (Requirement 2.5). Runs a minimum of 100 generated iterations.
 */
class ConfigMarshallerPropertyTest {

    private static final int MAX_DEPTH = 4;

    private final ConfigMarshaller marshaller = new ConfigMarshaller();

    // Feature: esdk-test-server, Property 7: Recursive config marshalling round-trips at any depth
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void recursiveConfigRoundTripsAtAnyDepth(@ForAll("nestedConfigs") ESDKClientConfig config) {
        ESDKClientConfig roundTripped = marshaller.roundTrip(config);
        assertEquals(config, roundTripped,
            "marshalling a config to the wire form and back must preserve its structure");
    }

    // -----------------------------------------------------------------------
    // Generators
    // -----------------------------------------------------------------------

    @Provide
    Arbitrary<ESDKClientConfig> nestedConfigs() {
        Arbitrary<CryptographicMaterialsManager> cmms =
            Arbitraries.integers().between(0, MAX_DEPTH).flatMap(this::cmmAtDepth);
        Arbitrary<ESDKCommitmentPolicy> policies =
            Arbitraries.of(ESDKCommitmentPolicy.values());
        Arbitrary<java.util.Optional<Long>> maxEdks =
            Arbitraries.longs().between(1L, 1000L).optional();

        return Combinators.combine(cmms, policies, maxEdks).as((cmm, policy, maxEdk) -> {
            ESDKClientConfig.Builder builder =
                ESDKClientConfig.builder().commitmentPolicy(policy).cmm(cmm);
            maxEdk.ifPresent(builder::maxEncryptedDataKeys);
            return builder.build();
        });
    }

    /** A CMM nested up to {@code depth} levels deep. */
    private Arbitrary<CryptographicMaterialsManager> cmmAtDepth(int depth) {
        Arbitrary<CryptographicMaterialsManager> leaf = keyringAtDepth(1).map(keyring ->
            CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder().keyring(keyring).build())
                .build());
        if (depth <= 0) {
            return leaf;
        }
        Arbitrary<CryptographicMaterialsManager> caching =
            Combinators.combine(cmmAtDepth(depth - 1), Arbitraries.integers().between(1, 86_400))
                .as((inner, ttl) -> CryptographicMaterialsManager.builder()
                    .caching(CachingCmmConfig.builder()
                        .underlyingCMM(inner)
                        .cacheLimitTtlSeconds(ttl)
                        .build())
                    .build());
        Arbitrary<CryptographicMaterialsManager> requiredEc =
            Combinators.combine(cmmAtDepth(depth - 1),
                    Arbitraries.strings().alpha().ofMaxLength(8).list().ofMaxSize(3))
                .as((inner, keys) -> CryptographicMaterialsManager.builder()
                    .requiredEncryptionContext(RequiredEncryptionContextCmmConfig.builder()
                        .underlyingCMM(inner)
                        .requiredEncryptionContextKeys(keys)
                        .build())
                    .build());
        return Arbitraries.oneOf(leaf, caching, requiredEc);
    }

    /** A keyring nested up to {@code depth} levels deep. */
    private Arbitrary<Keyring> keyringAtDepth(int depth) {
        Arbitrary<Keyring> leaf = leafKeyrings();
        if (depth <= 0) {
            return leaf;
        }
        Arbitrary<Keyring> multi = Combinators.combine(
                keyringAtDepth(depth - 1).list().ofMinSize(1).ofMaxSize(3),
                keyringAtDepth(depth - 1).optional())
            .as((children, generator) -> {
                MultiKeyringConfig.Builder builder =
                    MultiKeyringConfig.builder().childKeyrings(children);
                generator.ifPresent(builder::generator);
                return Keyring.builder().multi(builder.build()).build();
            });
        return Arbitraries.oneOf(leaf, multi);
    }

    /**
     * Leaf keyrings backed by an AWS KMS keyring config. String-valued members
     * (no blobs) keep round-trip equality free of ByteBuffer position concerns
     * while still exercising the recursion of the enclosing structures.
     */
    private Arbitrary<Keyring> leafKeyrings() {
        Arbitrary<String> keyIds = Arbitraries.strings().alpha().numeric().ofMinLength(1).ofMaxLength(24);
        Arbitrary<java.util.Optional<List<String>>> grantTokens =
            Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(8).list().ofMinSize(1).ofMaxSize(3).optional();
        return Combinators.combine(keyIds, grantTokens).as((keyId, tokens) -> {
            AwsKmsKeyringConfig.Builder builder = AwsKmsKeyringConfig.builder().kmsKeyId(keyId);
            tokens.ifPresent(builder::grantTokens);
            return Keyring.builder().awsKms(builder.build()).build();
        });
    }
}
