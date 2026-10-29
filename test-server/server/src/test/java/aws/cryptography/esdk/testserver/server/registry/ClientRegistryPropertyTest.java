package aws.cryptography.esdk.testserver.server.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import net.jqwik.api.ForAll;
import net.jqwik.api.GenerationMode;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

/**
 * Property-based tests for the {@link ClientRegistry}, using jqwik. Each property
 * runs a minimum of 100 generated iterations.
 */
class ClientRegistryPropertyTest {

    /** Canonical 8-4-4-4-12 hex UUID form (Requirement 3.2). */
    private static final Pattern UUID_FORMAT = Pattern.compile(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    // Feature: esdk-test-server, Property 2: ClientId values are unique and well-formed
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void clientIdsAreUniqueAndWellFormed(@ForAll @IntRange(min = 1, max = 50) int count) {
        ClientRegistry registry = new ClientRegistry();
        Set<String> seen = new HashSet<>();

        for (int i = 0; i < count; i++) {
            String id = registry.register(new StubEsdkClient());

            assertNotNull(id, "ClientId must not be null");
            assertFalse(id.isEmpty(), "ClientId must be non-empty");
            assertTrue(UUID_FORMAT.matcher(id).matches(),
                "ClientId must be UUID-format, but was: " + id);
            assertTrue(seen.add(id),
                "ClientId must be pairwise distinct from every other id, but repeated: " + id);
        }

        assertEquals(count, seen.size(), "every register call must yield a distinct id");
        assertEquals(count, registry.size(), "registry must hold exactly the registered clients");
    }

    // Feature: esdk-test-server, Property 3: CreateClient registers exactly one resolvable client
    @Property(tries = 200, generation = GenerationMode.RANDOMIZED)
    void registerAddsExactlyOneResolvableClient(
            @ForAll @IntRange(min = 0, max = 20) int preexisting,
            @ForAll @IntRange(min = 1, max = 5) int resolveTimes) {
        ClientRegistry registry = new ClientRegistry();
        for (int i = 0; i < preexisting; i++) {
            registry.register(new StubEsdkClient());
        }

        int sizeBefore = registry.size();
        StubEsdkClient client = new StubEsdkClient();

        String id = registry.register(client);

        assertEquals(sizeBefore + 1, registry.size(),
            "a successful register must increase the registry size by exactly one");
        assertTrue(registry.contains(id), "the returned id must be present in the registry");

        // Resolving the returned id any number of times yields the same client.
        for (int i = 0; i < resolveTimes; i++) {
            Optional<EsdkClient> resolved = registry.resolve(id);
            assertTrue(resolved.isPresent(), "the returned id must resolve to a client");
            assertSame(client, resolved.get(),
                "the id must resolve to the same client instance on every request");
        }
    }
}
