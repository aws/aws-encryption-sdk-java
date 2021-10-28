package com.amazonaws.encryptionsdk.caching;

interface MsClock {
  MsClock WALLCLOCK = System::currentTimeMillis;

  public long timestamp();
}
