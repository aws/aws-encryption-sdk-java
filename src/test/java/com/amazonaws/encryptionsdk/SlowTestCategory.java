package com.amazonaws.encryptionsdk;

/**
 * JUnit category marking tests to be excluded from the FastTestsOnlySuite. Usage: <code>
 *     @Category(SlowTestCategory.class)
 *     @Test
 *     public void mySlowTest() {
 *         // encrypt a couple terabytes of test data
 *     }
 * </code>
 */
public interface SlowTestCategory {}
