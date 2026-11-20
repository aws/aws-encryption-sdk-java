package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.model.GenericServerError;
import aws.cryptography.esdk.testserver.server.registry.ClientRegistry;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;

/**
 * Resolves the {@code ClientId} required by every non-{@code CreateClient}
 * operation (Requirement 3.8). An absent, empty, or unknown id yields a
 * {@link GenericServerError}; because the guard throws before any ESDK call is
 * made, no ESDK operation runs and the {@link ClientRegistry} is left unchanged
 * (Requirement 3.9, Property 5).
 */
public final class ClientIdGuard {

    private final ClientRegistry registry;

    public ClientIdGuard(ClientRegistry registry) {
        this.registry = registry;
    }

    /**
     * Resolve a client by id, or throw a {@link GenericServerError} if the id is
     * absent, empty, or not present in the registry.
     *
     * @param clientId the id from the request (the generated shapes substitute an
     *     empty string for an absent required id).
     * @return the resolved client, never {@code null}.
     */
    public EsdkClient resolve(String clientId) {
        return registry.resolve(clientId).orElseThrow(() ->
            GenericServerError.builder()
                .message("No ESDK client is registered under ClientId '"
                    + (clientId == null ? "" : clientId)
                    + "'. Call CreateClient first and pass the returned ClientId.")
                .build());
    }
}
