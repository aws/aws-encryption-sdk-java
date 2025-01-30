package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy.mutations;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import org.testng.annotations.Test;
public class ScanForInFlightMutationsTest {

  @Test
  public void testScanForInFlightMutations() {
    ScanForInFlightMutations underTest = new ScanForInFlightMutations(
      Fixtures.ddbClientWest2,
      Fixtures.TEST_KEYSTORE_NAME,
      null
    );
    ScanForInFlightMutations.PageResult actual = underTest.scanForMutationCommitment(null);
    assert actual.lastEvaluatedKey() !=
    null : "Last Evaluated Key is null! There are far fewer Mutations in-flight than expected.";
    assert !actual
      .inFlightMutations()
      .isEmpty() : "There are no mutations in-flight! That is wrong.";
    final short pageLimit = 5;
    short pageIndex = 0;
    while (actual.lastEvaluatedKey() != null && pageIndex < pageLimit) {
      actual = underTest.scanForMutationCommitment(actual.lastEvaluatedKey());
      if (!actual.inFlightMutations().isEmpty()) {
        System.out.println(actual.inFlightMutations());
      }
      pageIndex++;
    }
  }
}
