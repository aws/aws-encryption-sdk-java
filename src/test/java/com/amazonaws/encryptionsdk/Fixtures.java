package com.amazonaws.encryptionsdk;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Fixtures {
  public enum Variation {
    Empty,
    A,
    B,
    AB,
    BA,
    C,
    CE
  }

  public static Map<String, String> generateEncryptionContext(Variation v) {
    Map<String, String> encryptionContext = new HashMap<>();

    switch (v) {
      case A:
        encryptionContext.put("keyA", "valA");
        break;
      case B:
        encryptionContext.put("keyB", "valB");
        break;
      case AB:
      case BA:
        encryptionContext.put("keyA", "valA");
        encryptionContext.put("keyB", "valB");
        break;
      case C:
        encryptionContext.put("keyC", "valC");
        break;
      case CE:
        encryptionContext.put("keyC", "valC");
        encryptionContext.put("keyD", "valD");
        break;
    }

    return encryptionContext;
  }

  public static Map<String, String> generateMismatchedEncryptionContext(Variation v) {
    Map<String, String> encryptionContext = new HashMap<>();

    switch (v) {
      case A:
        encryptionContext.put("keyA", "valB");
        break;
      case B:
        encryptionContext.put("keyB", "valA");
        break;
      case AB:
      case BA:
        encryptionContext.put("keyA", "valC");
        encryptionContext.put("keyB", "valD");
        break;
      case C:
        encryptionContext.put("keyC", "valA");
        break;
      case CE:
        encryptionContext.put("keyC", "valA");
        encryptionContext.put("keyD", "valB");
        break;
    }

    return encryptionContext;
  }

  public static List<String> generateEncryptionContextKeys(Variation v) {
    return Stream.of("keyA", "keyB", "keyC", "keyD")
        .filter(
            key -> {
              if (v == Variation.Empty) {
                return false;
              }
              if (v == Variation.A && !key.equals("keyA")) {
                return false;
              }
              if (v == Variation.B && !key.equals("keyB")) {
                return false;
              }
              if (v == Variation.AB && (!key.equals("keyA") && !key.equals("keyB"))) {
                return false;
              }
              if (v == Variation.BA && (!key.equals("keyB") && !key.equals("keyA"))) {
                return false;
              }
              if (v == Variation.C && !key.equals("keyC")) {
                return false;
              }
              if (v == Variation.CE && (!key.equals("keyC") && !key.equals("keyD"))) {
                return false;
              }
              return true;
            })
        .collect(Collectors.toList());
  }

  public static Map<String, String> getReservedEncryptionContextMap() {
    Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("aws-crypto-public-key", "not a real public key");
    return encryptionContext;
  }

  public static List<String> getReservedEncryptionContextKey() {
    List<String> ecKeys = new ArrayList();
    ecKeys.add("aws-crypto-public-key");
    return ecKeys;
  }
}
