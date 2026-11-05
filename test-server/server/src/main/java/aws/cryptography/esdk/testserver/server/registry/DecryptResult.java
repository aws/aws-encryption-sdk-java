package aws.cryptography.esdk.testserver.server.registry;

/**
 * The result of a blob decrypt.
 *
 * @param plaintext the plaintext bytes.
 * @param metadata the encryption context and suite of the decrypted message.
 */
public record DecryptResult(byte[] plaintext, DecryptMetadata metadata) {
}
