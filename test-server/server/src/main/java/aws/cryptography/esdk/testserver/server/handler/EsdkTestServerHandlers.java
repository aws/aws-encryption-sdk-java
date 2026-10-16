package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.config.ConfigValidator;
import aws.cryptography.esdk.testserver.server.config.EsdkClientFactory;
import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.registry.ClientRegistry;
import aws.cryptography.esdk.testserver.server.service.ESDKTestServer;

/**
 * Wires the generated {@link ESDKTestServer} service to the hand-written
 * operation handlers over one shared, thread-safe {@link ClientRegistry}. This is
 * the single assembly point the launcher (and the concurrency integration test)
 * use to obtain a fully-wired service instance.
 *
 * <p>All five handlers share the same registry so that a {@code ClientId} minted
 * by {@code CreateClient} resolves on subsequent {@code Encrypt}/{@code Decrypt}
 * calls (Requirement 3.7), and so the registry is the single piece of shared
 * mutable state exercised under concurrency (Requirement 3.3).
 */
public final class EsdkTestServerHandlers {

    private final ClientRegistry registry;
    private final CreateClientHandler createClient;
    private final EncryptHandler encrypt;
    private final DecryptHandler decrypt;
    private final EncryptStreamHandler encryptStream;
    private final DecryptStreamHandler decryptStream;

    public EsdkTestServerHandlers() {
        this(new ClientRegistry());
    }

    public EsdkTestServerHandlers(ClientRegistry registry) {
        this.registry = registry;
        OperationWrapper wrapper = new OperationWrapper();
        ConfigValidator validator = new ConfigValidator();
        EsdkClientFactory factory = new EsdkClientFactory();
        ClientIdGuard guard = new ClientIdGuard(registry);

        this.createClient = new CreateClientHandler(registry, validator, factory, wrapper);
        this.encrypt = new EncryptHandler(guard, wrapper);
        this.decrypt = new DecryptHandler(guard, wrapper);
        this.encryptStream = new EncryptStreamHandler(guard, wrapper);
        this.decryptStream = new DecryptStreamHandler(guard, wrapper);
    }

    /** @return the shared registry (for inspection in tests). */
    public ClientRegistry registry() {
        return registry;
    }

    public CreateClientHandler createClientHandler() {
        return createClient;
    }

    public EncryptHandler encryptHandler() {
        return encrypt;
    }

    public DecryptHandler decryptHandler() {
        return decrypt;
    }

    public EncryptStreamHandler encryptStreamHandler() {
        return encryptStream;
    }

    public DecryptStreamHandler decryptStreamHandler() {
        return decryptStream;
    }

    /** Build the generated service wired to these handlers. */
    public ESDKTestServer service() {
        return ESDKTestServer.builder()
            .addCreateClientOperation(createClient)
            .addDecryptOperation(decrypt)
            .addDecryptStreamOperation(decryptStream)
            .addEncryptOperation(encrypt)
            .addEncryptStreamOperation(encryptStream)
            .build();
    }
}
