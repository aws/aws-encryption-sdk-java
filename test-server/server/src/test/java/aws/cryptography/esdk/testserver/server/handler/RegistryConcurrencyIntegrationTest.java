package aws.cryptography.esdk.testserver.server.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.server.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.server.model.CreateClientInput;
import aws.cryptography.esdk.testserver.server.model.CreateClientOutput;
import aws.cryptography.esdk.testserver.server.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.server.model.DecryptInput;
import aws.cryptography.esdk.testserver.server.model.DecryptOutput;
import aws.cryptography.esdk.testserver.server.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.server.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.server.model.EncryptInput;
import aws.cryptography.esdk.testserver.server.model.EncryptOutput;
import aws.cryptography.esdk.testserver.server.model.Keyring;
import aws.cryptography.esdk.testserver.server.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.server.registry.ClientRegistry;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Integration test for the thread-safe {@link ClientRegistry} under concurrency
 * (Requirement 3.3). It drives the fully-wired Java server handlers over one
 * shared registry from many threads in parallel — each thread repeatedly calls
 * {@code CreateClient} (constructing a real offline Raw-AES ESDK client),
 * round-trips a blob through {@code Encrypt}/{@code Decrypt} against the id it was
 * given, and resolves that id — stressing the shared registry the same way a
 * running server's dispatch would. It asserts every minted {@code ClientId} is
 * unique, resolvable, and that no registrations are lost.
 */
class RegistryConcurrencyIntegrationTest {

    private static final byte[] PLAINTEXT =
        "concurrent-round-trip-plaintext".getBytes(StandardCharsets.UTF_8);

    @Test
    void registryIsThreadSafeUnderConcurrentCreateAndResolve() throws Exception {
        EsdkTestServerHandlers handlers = new EsdkTestServerHandlers();
        ClientRegistry registry = handlers.registry();

        int threadCount = 8;
        int createsPerThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startGate = new CountDownLatch(1);
        List<Future<List<String>>> futures = new ArrayList<>();

        try {
            for (int t = 0; t < threadCount; t++) {
                futures.add(pool.submit(() -> {
                    startGate.await();
                    List<String> ids = new ArrayList<>();
                    for (int i = 0; i < createsPerThread; i++) {
                        CreateClientOutput created = handlers.createClientHandler().createClient(
                            CreateClientInput.builder().config(rawAesConfig()).build(), null);
                        String clientId = created.getClientId();
                        ids.add(clientId);

                        // Round-trip a blob against the referenced client.
                        EncryptOutput encrypted = handlers.encryptHandler().encrypt(
                            EncryptInput.builder()
                                .clientId(clientId)
                                .plaintext(ByteBuffer.wrap(PLAINTEXT))
                                .build(),
                            null);
                        DecryptOutput decrypted = handlers.decryptHandler().decrypt(
                            DecryptInput.builder()
                                .clientId(clientId)
                                .ciphertext(encrypted.getCiphertext())
                                .build(),
                            null);
                        assertArrayEquals(PLAINTEXT, toArray(decrypted.getPlaintext()),
                            "each client's blob round-trip must preserve the plaintext");

                        // Concurrent resolves must always find the entry.
                        assertTrue(registry.resolve(clientId).isPresent(),
                            "a freshly registered ClientId must resolve");
                    }
                    return ids;
                }));
            }

            startGate.countDown();

            Set<String> allIds = new HashSet<>();
            List<String> collected = new ArrayList<>();
            for (Future<List<String>> future : futures) {
                collected.addAll(future.get(120, TimeUnit.SECONDS));
            }
            allIds.addAll(collected);

            int expected = threadCount * createsPerThread;
            assertEquals(expected, collected.size(),
                "every CreateClient call must have returned an id");
            assertEquals(expected, allIds.size(),
                "every minted ClientId must be unique across all threads");
            assertEquals(expected, registry.size(),
                "the registry must retain exactly one entry per successful CreateClient");
            for (String id : Collections.unmodifiableSet(allIds)) {
                assertTrue(registry.resolve(id).isPresent(),
                    "every minted ClientId must remain resolvable after the stress run");
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static ESDKClientConfig rawAesConfig() {
        RawAesKeyringConfig rawAes = RawAesKeyringConfig.builder()
            .keyNamespace("concurrency-namespace")
            .keyName("concurrency-key")
            .wrappingKey(ByteBuffer.wrap(new byte[32]))
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build();
        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder()
                    .keyring(Keyring.builder().rawAes(rawAes).build())
                    .build())
                .build())
            .build();
    }

    private static byte[] toArray(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}
