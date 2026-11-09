package aws.cryptography.esdk.testserver.server.launcher;

import aws.cryptography.esdk.testserver.server.handler.EsdkTestServerHandlers;
import software.amazon.smithy.java.server.Server;

/**
 * A minimal, runnable bootstrap for the Java {@code Language_Server}.
 *
 * <p>It instantiates the generated {@code ESDKTestServer} service wired to the
 * hand-written handlers (via {@link EsdkTestServerHandlers}) and starts the
 * smithy-java rpcv2Cbor HTTP server (Netty) bound to a configurable port, so a
 * user (or a manual two-step run) can start a real over-HTTP server and point
 * the single {@code Tests} suite at it purely through runtime configuration
 * (Requirement 7.3).
 *
 * <p>This is intentionally minimal: it does NOT build the full
 * Configuration_Set / source-resolution orchestrator (that is task 7). It is the
 * same single service-assembly point ({@link EsdkTestServerHandlers#service()})
 * that the in-process test harness and the future orchestrator/launcher use, so
 * running here exercises exactly the shipped server wiring: smithy-java-generated
 * request decoding / response &amp; error encoding over one shared, thread-safe
 * {@code Client_Registry}, delegating to the real AWS Encryption SDK for Java.
 *
 * <p>The port is resolved, in precedence order, from:
 * <ol>
 *   <li>the first command-line argument, if present;</li>
 *   <li>the system property {@code esdk.testserver.port};</li>
 *   <li>the environment variable {@code ESDK_TESTSERVER_PORT};</li>
 *   <li>otherwise the default {@code 8080}.</li>
 * </ol>
 *
 * <p>On start it prints the base endpoint URL (host:port) to stdout so callers
 * can discover where to point the {@code Tests}, then blocks until the process
 * is interrupted/terminated, shutting the server down cleanly via a shutdown
 * hook.
 */
public final class ServerBootstrap {

    /** System property carrying the port to bind. */
    public static final String PORT_PROPERTY = "esdk.testserver.port";

    /** Environment variable equivalent of {@link #PORT_PROPERTY}. */
    public static final String PORT_ENV = "ESDK_TESTSERVER_PORT";

    /** Default port when none is configured. */
    public static final int DEFAULT_PORT = 8080;

    private ServerBootstrap() {
    }

    public static void main(String[] args) throws InterruptedException {
        int port = resolvePort(args);

        EsdkTestServerHandlers handlers = new EsdkTestServerHandlers();
        Server server = Server.builder()
            .endpoints(port)
            .addService(handlers.service())
            .build();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down ESDK TestServer (Java) ...");
            server.shutdown().join();
        }, "esdk-testserver-shutdown"));

        server.start();
        System.out.println("ESDK TestServer (Java) listening at http://127.0.0.1:" + port);
        System.out.println("Point the Tests at it with: "
            + "-Desdk.testserver.endpoints=http://127.0.0.1:" + port);
        System.out.println("Press Ctrl-C to stop.");

        // Block the main thread for the lifetime of the process; the shutdown
        // hook performs the clean shutdown on SIGINT/SIGTERM.
        Thread.currentThread().join();
    }

    /**
     * Resolve the port from (in order) the first CLI arg, the system property,
     * the environment variable, or the default. Rejects out-of-range or
     * non-numeric values with a clear error.
     */
    static int resolvePort(String[] args) {
        String raw = null;
        if (args != null && args.length > 0 && args[0] != null && !args[0].isBlank()) {
            raw = args[0].trim();
        } else {
            String property = System.getProperty(PORT_PROPERTY);
            if (property != null && !property.isBlank()) {
                raw = property.trim();
            } else {
                String env = System.getenv(PORT_ENV);
                if (env != null && !env.isBlank()) {
                    raw = env.trim();
                }
            }
        }
        if (raw == null) {
            return DEFAULT_PORT;
        }
        int port;
        try {
            port = Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid port '" + raw + "': must be an integer in 1..65535");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Invalid port " + port + ": must be in the range 1..65535");
        }
        return port;
    }
}
