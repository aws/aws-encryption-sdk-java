package com.amazonaws.encryptionsdk;

import java.util.concurrent.TimeUnit;
import org.junit.ClassRule;
import org.junit.experimental.categories.Categories;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.junit.runner.Description;
import org.junit.runner.RunWith;
import org.junit.runner.Runner;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;
import org.junit.runners.model.Statement;

/**
 * This test suite is intended to assist in rapid development; it filters out some of the slower,
 * more exhaustive tests in the overall test suite to allow for a rapid edit-test cycle.
 */
@RunWith(FastTestsOnlySuite.CustomRunner.class)
@Suite.SuiteClasses({AllTestsSuite.class})
@Categories.ExcludeCategory(SlowTestCategory.class)
public class FastTestsOnlySuite {
  private static InheritableThreadLocal<Boolean> IS_FAST_TEST_SUITE_ACTIVE =
      new InheritableThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
          return false;
        }
      };

  // This method is used to adjust DataProviders to provide a smaller subset of their test cases
  // when the fast tests
  // are selected
  public static boolean isFastTestSuiteActive() {
    return IS_FAST_TEST_SUITE_ACTIVE.get();
  }

  // Require that this fast suite completes relatively quickly. If you're seeing this timeout get
  // hit, it's time to
  // pare down tests some more. As a general rule of thumb, we should avoid any single test taking
  // more than 10s, and
  // try to keep the number of such slow tests to a minimum.
  @ClassRule public static Timeout timeout = new Timeout(2, TimeUnit.MINUTES);

  @ClassRule public static EnableFastSuite enableFastSuite = new EnableFastSuite();

  // TestRules run over the execution of tests, but not over the generation of parameterized test
  // data...
  private static class EnableFastSuite implements TestRule {
    @Override
    public Statement apply(Statement base, Description description) {
      return new Statement() {
        @Override
        public void evaluate() throws Throwable {
          Boolean oldValue = IS_FAST_TEST_SUITE_ACTIVE.get();

          try {
            IS_FAST_TEST_SUITE_ACTIVE.set(true);
            base.evaluate();
          } finally {
            IS_FAST_TEST_SUITE_ACTIVE.set(oldValue);
          }
        }
      };
    }
  }

  // ... so we also need a custom TestRunner that will pass the flag on to the parameterized test
  // data generators.
  public static class CustomRunner extends Categories {
    public CustomRunner(Class<?> klass, RunnerBuilder builder) throws InitializationError {
      super(
          klass,
          new RunnerBuilder() {
            @Override
            public Runner runnerForClass(Class<?> testClass) throws Throwable {
              Boolean oldValue = IS_FAST_TEST_SUITE_ACTIVE.get();

              try {
                IS_FAST_TEST_SUITE_ACTIVE.set(true);
                Runner r = builder.runnerForClass(testClass);
                return r;
              } finally {
                IS_FAST_TEST_SUITE_ACTIVE.set(oldValue);
              }
            }
          });
    }
  }
}
