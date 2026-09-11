package aws.cryptography.esdk.testserver.server.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.ESDKClientError;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import java.util.Set;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property-based tests for {@link ConfigValidator}'s exactly-one-variant rule on
 * the tagged-union config shapes, using jqwik. Each property runs a minimum of
 * 100 generated iterations.
 */
class ConfigValidatorPropertyTest {

    private final ConfigValidator validator = new ConfigValidator();

    // Feature: esdk-test-server, Property 6: Polymorphic config requires exactly one variant member
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void keyringWithoutExactlyOneVariantIsRejected(
            @ForAll("nonSingletonKeyringVariants") Set<String> variants) {
        assertTrue(variants.size() != 1, "generator must produce zero or 2+ variants");
        Keyring keyring = ConfigTestFactory.keyringWithVariants(variants);

        ESDKClientError error = assertThrows(ESDKClientError.class,
            () -> validator.validateKeyring(keyring),
            "a Keyring with " + variants.size() + " variant members set must be rejected");
        assertTrue(error.getMessage() != null && !error.getMessage().isEmpty(),
            "ESDKClientError must carry a non-empty message");
    }

    // Feature: esdk-test-server, Property 6: Polymorphic config requires exactly one variant member
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void cmmWithoutExactlyOneVariantIsRejected(
            @ForAll("nonSingletonCmmVariants") Set<String> variants) {
        assertTrue(variants.size() != 1, "generator must produce zero or 2+ variants");
        CryptographicMaterialsManager cmm = ConfigTestFactory.cmmWithVariants(variants);

        ESDKClientError error = assertThrows(ESDKClientError.class,
            () -> validator.validateCmm(cmm),
            "a CMM with " + variants.size() + " variant members set must be rejected");
        assertTrue(error.getMessage() != null && !error.getMessage().isEmpty(),
            "ESDKClientError must carry a non-empty message");
    }

    // Feature: esdk-test-server, Property 6: Polymorphic config requires exactly one variant member
    // Positive control: the boundary case of exactly one variant is accepted, confirming the
    // validator rejects only when the count is not one.
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void exactlyOneVariantIsAccepted(@ForAll("keyringVariant") String keyringVariant,
                                     @ForAll("cmmVariant") String cmmVariant) {
        Keyring keyring = ConfigTestFactory.keyringWithVariants(Set.of(keyringVariant));
        assertDoesNotThrow(() -> validator.validateKeyring(keyring));

        CryptographicMaterialsManager cmm = ConfigTestFactory.cmmWithVariants(Set.of(cmmVariant));
        assertDoesNotThrow(() -> validator.validateCmm(cmm));
    }

    @Provide
    Arbitrary<Set<String>> nonSingletonKeyringVariants() {
        return Arbitraries.subsetOf(ConfigTestFactory.KEYRING_VARIANTS)
            .filter(subset -> subset.size() != 1);
    }

    @Provide
    Arbitrary<Set<String>> nonSingletonCmmVariants() {
        return Arbitraries.subsetOf(ConfigTestFactory.CMM_VARIANTS)
            .filter(subset -> subset.size() != 1);
    }

    @Provide
    Arbitrary<String> keyringVariant() {
        return Arbitraries.of(ConfigTestFactory.KEYRING_VARIANTS);
    }

    @Provide
    Arbitrary<String> cmmVariant() {
        return Arbitraries.of(ConfigTestFactory.CMM_VARIANTS);
    }
}
