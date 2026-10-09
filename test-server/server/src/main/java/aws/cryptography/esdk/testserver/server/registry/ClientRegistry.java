package aws.cryptography.esdk.testserver.server.registry;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory, thread-safe registry of configured {@link EsdkClient} instances,
 * keyed by {@code ClientId} (Requirements 3.1-3.5, 3.7).
 *
 * <p>{@link #register(EsdkClient)} generates a fresh UUID-format id that is not
 * equal to any id currently in the registry, stores the client, and returns the
 * id (Requirements 3.1, 3.2, 3.4, 3.5). {@link #resolve(String)} looks a client
 * up by id, returning {@link Optional#empty()} for a {@code null}, empty, or
 * unknown id (Requirement 3.9 is enforced at the handler layer over this miss).
 *
 * <p>Entries are never evicted, so an id resolves to the same client for the
 * lifetime of the server process (Requirement 3.7). The backing map is a
 * {@link ConcurrentHashMap}, and registration uses an atomic
 * {@link ConcurrentMap#putIfAbsent} claim so concurrent registrations never
 * collide on an id and never lose an entry (Requirement 3.3).
 */
public final class ClientRegistry {

    private final ConcurrentMap<String, EsdkClient> clients = new ConcurrentHashMap<>();

    /**
     * Register a client and return a fresh, unique {@code ClientId}.
     *
     * @param client the configured client to store; must not be {@code null}.
     * @return a non-empty, UUID-format id distinct from every id currently in
     *     the registry (Requirements 3.1, 3.2, 3.4).
     */
    public String register(EsdkClient client) {
        Objects.requireNonNull(client, "client cannot be null");
        // Generate ids until one atomically claims a free slot. UUID collisions
        // are astronomically unlikely; the loop makes uniqueness a guarantee
        // rather than a probability, even under concurrent registration.
        while (true) {
            String id = UUID.randomUUID().toString();
            if (clients.putIfAbsent(id, client) == null) {
                return id;
            }
        }
    }

    /**
     * Resolve the client registered under an id.
     *
     * @param clientId the id to look up.
     * @return the registered client, or {@link Optional#empty()} if the id is
     *     {@code null}, empty, or not present in the registry.
     */
    public Optional<EsdkClient> resolve(String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(clients.get(clientId));
    }

    /** @return whether an id is currently present in the registry. */
    public boolean contains(String clientId) {
        return clientId != null && !clientId.isEmpty() && clients.containsKey(clientId);
    }

    /** @return the number of entries currently in the registry. */
    public int size() {
        return clients.size();
    }
}
