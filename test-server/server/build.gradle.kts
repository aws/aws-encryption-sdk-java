// Builds the Java Language_Server for the ESDK TestServer service over the
// rpcv2Cbor protocol. The server scaffolding (request decoding, response
// encoding, routing, error serialization) is generated from the single
// source-of-truth Smithy model hosted in the aws-crypto-tools-commons
// repository (esdk/test-server/model), supplied via the REQUIRED `modelDir`
// Gradle property, by the smithy-java `java-codegen` build plugin in SERVER
// mode (Requirement 1.7); only the operation handler bodies are hand-written.
//
// This repository carries NO copy of the model: the orchestrator always passes
// -PmodelDir=<resolved commons root>/esdk/test-server/model, and a developer
// running this module standalone passes it manually.
//
// The wire contract is identical to the one the single generated Java
// Test_Client (commons esdk/test-server/client-java) speaks, because both are
// generated from the same model with the same protocol declared once at the
// service level.

plugins {
    `java-library`
    // Runs the Smithy build (and thus the java-codegen plugin) during the
    // Gradle build. Version comes from gradle.properties via settings.
    id("software.amazon.smithy.gradle.smithy-base")
}

repositories {
    // mavenLocal() is listed FIRST so that when the resolved ESDK Java library
    // source has been installed to the local Maven repository (by the
    // orchestrator's JavaLaunchPlan: mvn versions:set -> install -> revert
    // under a distinct version), a matching
    // `com.amazonaws:aws-encryption-sdk-java:<esdkVersion>` there is consumed
    // as the LIVE source in place of the published GA artifact. The live flow
    // installs a DISTINCT version (e.g. 3.0.2-LIVE-SNAPSHOT) and passes
    // `-PesdkVersion=<that version>`, so head/default runs still resolve the
    // published artifact from Maven Central below and only an explicit live
    // run picks up the local build.
    mavenLocal()
    mavenCentral()
}

// smithy-java 1.x baselines on Java 21. Build with a JDK 21+ (set JAVA_HOME to a
// JDK 21 or newer when invoking Gradle). We intentionally do not pin a Java
// toolchain version here so the build uses whatever compatible JDK 21+ is
// configured for Gradle in the environment / CI, mirroring the client-java
// module.

val smithyJavaVersion: String by project
val smithyProtocolTraitsVersion: String by project
val esdkVersion: String by project
val materialProvidersVersion: String by project
val awsSdkKmsVersion: String by project
val jqwikVersion: String by project
val junitVersion: String by project

dependencies {
    // --- Code generation (smithy build classpath only) ---
    // The smithy-java code generation plugins, discovered by the smithyBuild
    // task via SPI.
    smithyBuild("software.amazon.smithy.java:codegen-plugin:$smithyJavaVersion")
    // The rpcv2Cbor protocol trait definition must be resolvable while the
    // model is built so `smithy.protocols#rpcv2Cbor` is understood by codegen.
    smithyBuild("software.amazon.smithy:smithy-protocol-traits:$smithyProtocolTraitsVersion")

    // --- Runtime dependencies of the generated server ---
    // server-core is required by all generated smithy-java servers (routing,
    // request/response plumbing, the operation/service abstractions).
    api("software.amazon.smithy.java:server-core:$smithyJavaVersion")
    // rpcv2Cbor server protocol implementation (request decoding / response and
    // error encoding), discovered at runtime via SPI; this is the protocol
    // declared once at the service level in the model.
    api("software.amazon.smithy.java:server-rpcv2-cbor:$smithyJavaVersion")
    // The rpcv2Cbor codec is used directly by ConfigMarshaller to round-trip the
    // config shapes through the exact wire form the protocol uses.
    implementation("software.amazon.smithy.java:cbor-codec:$smithyJavaVersion")
    // The runnable ServerBootstrap main() needs the Netty HTTP server provider
    // (the ServerProvider SPI implementation) on its runtime classpath so
    // Server.builder() can bind a real HTTP endpoint. This is required only for
    // the standalone launcher / manual two-step run, not for the generated
    // server sources themselves.
    runtimeOnly("software.amazon.smithy.java:server-netty:$smithyJavaVersion")

    // --- Real ESDK Java delegation (Requirement 3.1, 4.2, 4.3) ---
    // The CreateClient/Encrypt/Decrypt handlers delegate to the REAL AWS
    // Encryption SDK for Java. For this pass we consume the published GA
    // artifact from Maven Central (com.amazonaws:aws-encryption-sdk-java), which
    // transitively pulls in the AWS Cryptographic Material Providers library
    // (software.amazon.cryptography:aws-cryptographic-material-providers) used to
    // construct keyrings and CMMs. This is aligned with the version the live
    // product source declares (aws-crypto-tools-java/esdk/pom.xml -> 3.0.2).
    //
    // LIVE-SOURCE MODE (task 11): `esdkVersion` is overridable via
    // `-PesdkVersion=<v>`. Default runs resolve the published GA artifact from
    // Maven Central. A live run installs THIS repo's working tree to the local
    // Maven repository under a distinct version (e.g. 3.0.2-LIVE-SNAPSHOT) and
    // passes `-PesdkVersion=3.0.2-LIVE-SNAPSHOT`; combined with mavenLocal()
    // above, the server then delegates to the LIVE ESDK Java build rather than
    // the published artifact. The ESDK Java `mvn install` consumes the AWS
    // Cryptographic Material Providers library as a published artifact (the
    // esdk/pom.xml declares aws-cryptographic-material-providers:<v> from Maven
    // Central), so no heavy Dafny/Smithy-Dafny transpile is required to build
    // the live Java source.
    implementation("com.amazonaws:aws-encryption-sdk-java:$esdkVersion")
    // The handlers/config factory import the Material Providers keyring & CMM
    // types directly, so declare the library explicitly (rather than leaning on
    // the ESDK's transitive compile scope). Version aligned with the ESDK.
    implementation("software.amazon.cryptography:aws-cryptographic-material-providers:$materialProvidersVersion")
    // The AWS SDK KMS client. The Material Providers library above declares this
    // only at `runtime` scope, but the EsdkClientFactory references KmsClient,
    // EncryptionAlgorithmSpec, and GetPublicKeyRequest directly to fully wire the
    // five KMS keyring variants (AwsKms/AwsKmsMrk/AwsKmsMultiKeyring/AwsKmsRsa/
    // AwsKmsDiscovery, task 15.3), so it must be on the compile classpath. Pinned
    // to the version the Material Providers BOM (2.26.3) resolves. Construction of
    // a KMS keyring performs no network call; only Encrypt/Decrypt reach AWS KMS.
    implementation("software.amazon.awssdk:kms:$awsSdkKmsVersion")
    // The hierarchical keyring's branch-key store reads from DynamoDB.
    implementation("software.amazon.awssdk:dynamodb:$awsSdkKmsVersion")

    // --- Test dependencies ---
    // jqwik: the established Java property-based testing library used for the
    // harness-logic property tests (do not hand-roll PBT).
    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

// The shared model is owned by the model/ package; this server only consumes
// it. Disable the formatter so building the server never rewrites the single
// source-of-truth model file (Requirement 1.1).
smithy {
    format.set(false)
}

// Use the single source-of-truth model hosted in the Commons_Repository
// (Requirement 1.7) rather than a copy. The location is supplied via the
// REQUIRED `modelDir` Gradle property; fail fast with a clear message when it
// is absent so a bare `./gradlew build` cannot silently pick up a stale or
// wrong model.
val modelDir: String = providers.gradleProperty("modelDir").orNull
    ?: throw GradleException(
        "The Java Language_Server consumes the Smithy model from the commons repository: " +
            "pass -PmodelDir=<abs path to the commons esdk/test-server/model>"
    )

sourceSets {
    main {
        smithy {
            srcDir(modelDir)
        }
    }
}

// Add the generated server sources/resources to the main sourceSet so they are
// compiled alongside the hand-written handlers.
afterEvaluate {
    val serverPath = smithy.getPluginProjectionPath(smithy.sourceProjection.get(), "java-codegen").get()
    sourceSets {
        main {
            java {
                srcDir("$serverPath/java")
            }
            resources {
                srcDir("$serverPath/resources")
            }
        }
    }
}

// Ensure code generation runs before compilation / resource processing.
tasks.named("compileJava") {
    dependsOn("smithyBuild")
}

tasks.named("processResources") {
    dependsOn("smithyBuild")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        // jqwik registers its own JUnit Platform engine; include it explicitly.
        includeEngines("jqwik", "junit-jupiter")
    }
}

// A minimal runnable launcher for the Java Language_Server (task 5 support, NOT
// the full orchestrator of task 7). Starts the smithy-java rpcv2Cbor HTTP server
// on a configurable port so a user can run a real over-HTTP round trip manually:
//
//   Terminal 1 (start the server on port 8080):
//     JAVA_HOME=<jdk21+> ./gradlew runServer
//     # or choose a port:
//     JAVA_HOME=<jdk21+> ./gradlew runServer --args="9090"
//     # or:  JAVA_HOME=<jdk21+> ./gradlew runServer -Pport=9090
//
//   Terminal 2 (point the Tests at it — from ../../tests):
//     JAVA_HOME=<jdk21+> ./gradlew test -Desdk.testserver.endpoints=http://127.0.0.1:8080
//
// The port may also be supplied via -Pport=<n>, the system property
// esdk.testserver.port, or the ESDK_TESTSERVER_PORT env var (see ServerBootstrap).
tasks.register<JavaExec>("runServer") {
    group = "application"
    description = "Start the Java Language_Server (rpcv2Cbor HTTP) on a configurable port."
    mainClass.set("aws.cryptography.esdk.testserver.server.launcher.ServerBootstrap")
    classpath = sourceSets["main"].runtimeClasspath
    // Allow `-Pport=<n>` as a convenience in addition to CLI args / sys prop / env.
    (project.findProperty("port") as String?)?.let {
        systemProperty("esdk.testserver.port", it)
    }
}
