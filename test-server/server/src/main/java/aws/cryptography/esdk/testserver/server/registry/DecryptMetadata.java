package aws.cryptography.esdk.testserver.server.registry;

import java.util.Map;

/**
 * What the ESDK read from a message it decrypted: the authenticated encryption
 * context and the algorithm suite, which the decrypt responses expose.
 *
 * @param encryptionContext the message's encryption context.
 * @param algorithmSuiteId the suite's {@code CryptoAlgorithm} name, which matches
 *     the modeled {@code ESDKAlgorithmSuiteId} value.
 */
public record DecryptMetadata(Map<String, String> encryptionContext, String algorithmSuiteId) {
}
