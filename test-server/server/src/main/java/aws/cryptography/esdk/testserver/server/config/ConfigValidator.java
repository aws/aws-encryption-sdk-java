package aws.cryptography.esdk.testserver.server.config;

import aws.cryptography.esdk.testserver.server.model.CachingCmmConfig;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKClientError;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.server.model.RequiredEncryptionContextCmmConfig;

/**
 * Enforces the "exactly one variant member set" invariant on the polymorphic
 * config shapes, which are modeled as a tagged union via optional members
 * (Requirement 2.2). Smithy structures permit any subset of optional members,
 * so this invariant is a runtime check, not a type-system guarantee.
 *
 * <p>Every polymorphic shape reachable from an {@link ESDKClientConfig} is
 * validated, recursing through the recursive variants to any nesting depth
 * (Requirement 2.5): {@link CryptographicMaterialsManager} (Default /
 * RequiredEncryptionContext / Caching, where Caching and
 * RequiredEncryptionContext wrap another CMM) and {@link Keyring} (whose Multi
 * variant contains child keyrings and an optional generator keyring).
 *
 * <p>When a polymorphic shape has zero, or two or more, variant members set, the
 * request is rejected with an {@link ESDKClientError} <em>before</em> the
 * operation runs (Requirements 2.3, 2.4). Validation is read-only: it performs
 * no operation and mutates no state.
 */
public final class ConfigValidator {

    /**
     * Validate a whole client config: its CMM and everything nested beneath it.
     *
     * @throws ESDKClientError if any polymorphic shape does not have exactly one
     *     variant member set (Requirements 2.3, 2.4).
     */
    public void validate(ESDKClientConfig config) {
        if (config == null) {
            throw error("ESDKClientConfig", 0, "");
        }
        validateCmm(config.getCmm());
    }

    /**
     * Validate a {@link CryptographicMaterialsManager} and recurse into any
     * wrapped CMM or keyring.
     */
    public void validateCmm(CryptographicMaterialsManager cmm) {
        if (cmm == null) {
            throw error("CryptographicMaterialsManager", 0,
                "Default, RequiredEncryptionContext, Caching");
        }
        DefaultCmmConfig def = cmm.getDefault();
        RequiredEncryptionContextCmmConfig req = cmm.getRequiredEncryptionContext();
        CachingCmmConfig caching = cmm.getCaching();

        int set = 0;
        if (def != null) {
            set++;
        }
        if (req != null) {
            set++;
        }
        if (caching != null) {
            set++;
        }
        if (set != 1) {
            throw error("CryptographicMaterialsManager", set,
                "Default, RequiredEncryptionContext, Caching");
        }

        if (def != null) {
            validateKeyring(def.getKeyring());
        } else if (req != null) {
            validateCmm(req.getUnderlyingCMM());
        } else {
            validateCmm(caching.getUnderlyingCMM());
        }
    }

    /**
     * Validate a {@link Keyring} and recurse into a Multi keyring's generator and
     * child keyrings.
     */
    public void validateKeyring(Keyring keyring) {
        if (keyring == null) {
            throw error("Keyring", 0, keyringVariants());
        }
        int set = 0;
        if (keyring.getAwsKms() != null) {
            set++;
        }
        if (keyring.getAwsKmsMrk() != null) {
            set++;
        }
        if (keyring.getAwsKmsMultiKeyring() != null) {
            set++;
        }
        if (keyring.getAwsKmsMrkMultiKeyring() != null) {
            set++;
        }
        if (keyring.getAwsKmsDiscovery() != null) {
            set++;
        }
        if (keyring.getAwsKmsMrkDiscovery() != null) {
            set++;
        }
        if (keyring.getAwsKmsHierarchical() != null) {
            set++;
        }
        if (keyring.getAwsKmsRsa() != null) {
            set++;
        }
        if (keyring.getRawAes() != null) {
            set++;
        }
        if (keyring.getRawRsa() != null) {
            set++;
        }
        if (keyring.getMulti() != null) {
            set++;
        }
        if (set != 1) {
            throw error("Keyring", set, keyringVariants());
        }

        MultiKeyringConfig multi = keyring.getMulti();
        if (multi != null) {
            if (multi.getGenerator() != null) {
                validateKeyring(multi.getGenerator());
            }
            for (Keyring child : multi.getChildKeyrings()) {
                validateKeyring(child);
            }
        }
    }

    private static String keyringVariants() {
        return "AwsKms, AwsKmsMrk, AwsKmsMultiKeyring, AwsKmsMrkMultiKeyring, "
            + "AwsKmsDiscovery, AwsKmsMrkDiscovery, AwsKmsRsa, AwsKmsHierarchical, RawAes, RawRsa, Multi";
    }

    private static ESDKClientError error(String shape, int set, String variants) {
        return ESDKClientError.builder()
            .message("Polymorphic configuration '" + shape + "' must set exactly one variant "
                + "member (" + variants + "), but " + set + " were set.")
            .build();
    }
}
