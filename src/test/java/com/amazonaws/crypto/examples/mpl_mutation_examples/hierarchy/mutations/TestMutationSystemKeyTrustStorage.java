package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.CreateKeyExample;
import org.testng.annotations.Test;

public class TestMutationSystemKeyTrustStorage {

  static final String testPrefix =
    "java-test-mutation-system-key-trust-example-";

  @Test
  public void test() {
    final String branchKeyId =
      testPrefix + java.util.UUID.randomUUID().toString();
    CreateKeyExample.CreateKey(Fixtures.MRK_ARN_WEST, branchKeyId, null);
    MutationsSystemKeyTrustExample.End2End(
      branchKeyId,
      Fixtures.KEYSTORE_KMS_ARN
    );
    DdbHelper.DeleteBranchKey(
      branchKeyId,
      Fixtures.TEST_KEYSTORE_NAME,
      "1",
      null
    );
  }
}
