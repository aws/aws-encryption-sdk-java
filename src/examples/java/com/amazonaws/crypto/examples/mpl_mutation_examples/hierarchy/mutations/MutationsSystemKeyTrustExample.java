package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.AdminProvider;
import software.amazon.cryptography.keystoreadmin.KeyStoreAdmin;
import software.amazon.cryptography.keystoreadmin.model.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;

import static com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationsProvider.executeInitialize;
import static com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations.MutationsProvider.workPage;

/**
 * To ensure a Mutation is applied consistently to all items
 * of a Branch Key,
 * the library persists the Mutation into the Key Store's Storage.
 * An agent with write access to this storage
 * could manipulate the persisted Mutation.
 * To mitigate this risk,
 * AWS Crypto Tools recommends using a KMS System Key.
 * However,
 * if the storage is trusted,
 * this is not needed.
 * This example demonstrates a Trust Storage configuration,
 * which assumes the storage can only be written to by trusted actors.
 */
public class MutationsSystemKeyTrustExample {

  public static String End2End(
    @Nonnull final String identifier,
    @Nonnull final String terminalKmsArn
  ) {
    return End2End(identifier, terminalKmsArn, null, null, null);
  }

  public static String End2End(
    @Nonnull final String identifier,
    @Nonnull final String terminalKmsArn,
    @Nullable KeyStoreAdmin admin,
    @Nullable Mutations mutations,
    @Nullable KeyManagementStrategy strategy
  ) {
    // 1. Create a System Key object, thought this is the default
    SystemKey systemKey = MutationsProvider.TrustStorage();

    // 2. Mutation's persisted objects will not be protected by client side cryptography
    assert mutations == null ||
    Objects.equals(mutations.TerminalKmsArn(), terminalKmsArn);
    admin =
      admin == null
        ? AdminProvider.admin(
          Fixtures.TEST_KEYSTORE_NAME,
          Fixtures.TEST_LOGICAL_KEYSTORE_NAME,
          Fixtures.ddbClientWest2
        )
        : admin;
    mutations =
      mutations == null
        ? MutationsProvider.defaultMutation(terminalKmsArn)
        : mutations;
    strategy = strategy == null ? AdminProvider.strategy(null) : strategy;
    InitializeMutationInput initInput = InitializeMutationInput
      .builder()
      .Mutations(mutations)
      .Identifier(identifier)
      .Strategy(strategy)
      .SystemKey(systemKey)
      .build();

    // InitializeMutation will NOT protect the Mutation Commitment and Mutation Index with the System Key
    MutationToken token = executeInitialize(
      identifier,
      admin,
      initInput,
      "InitLogs"
    );

    ApplyMutationResult result;
    boolean exThrown = false;

    // 3. But if you ask MPL to start protecting it, it will fail, because it is too late.
    try {
      result =
        workPage(
          identifier,
          MutationsProvider.KmsSystemKey(Fixtures.KSA_SYSTEM_KEY),
          token,
          strategy,
          admin,
          1
        );
    } catch (MutationVerificationException ex) {
      System.out.println(
        "Apply with wrong SystemKey failed with: \n" +
        ex.getClass().getSimpleName() +
        ": " +
        ex.getMessage()
      );
      exThrown = true;
    }

    // The Mutation can be completed with the correct System Key
    result = workPage(identifier, systemKey, token, strategy, admin, 99);
    assert exThrown;
    assert result.CompleteMutation() != null;
    return identifier;
  }
}
