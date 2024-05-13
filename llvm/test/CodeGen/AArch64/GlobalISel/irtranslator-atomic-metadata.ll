; NOTE: Assertions have been autogenerated by utils/update_mir_test_checks.py
; RUN: llc -mtriple=aarch64-- -mcpu=falkor -mattr=+lse -O0 -aarch64-enable-atomic-cfg-tidy=0 -stop-after=irtranslator -global-isel -verify-machineinstrs %s -o - | FileCheck %s

define i32 @atomicrmw_volatile(ptr %ptr) {
  ; CHECK-LABEL: name: atomicrmw_volatile
  ; CHECK: bb.1 (%ir-block.0):
  ; CHECK:   liveins: $x0
  ; CHECK:   [[COPY:%[0-9]+]]:_(p0) = COPY $x0
  ; CHECK:   [[C:%[0-9]+]]:_(s32) = G_CONSTANT i32 1
  ; CHECK:   [[ATOMICRMW_ADD:%[0-9]+]]:_(s32) = G_ATOMICRMW_ADD [[COPY]](p0), [[C]] :: (volatile load store monotonic (s32) on %ir.ptr)
  ; CHECK:   $w0 = COPY [[ATOMICRMW_ADD]](s32)
  ; CHECK:   RET_ReallyLR implicit $w0
  %oldval = atomicrmw volatile add ptr %ptr, i32 1 monotonic
  ret i32 %oldval
}

define i32 @atomicrmw_falkor(ptr %ptr) {
  ; CHECK-LABEL: name: atomicrmw_falkor
  ; CHECK: bb.1 (%ir-block.0):
  ; CHECK:   liveins: $x0
  ; CHECK:   [[COPY:%[0-9]+]]:_(p0) = COPY $x0
  ; CHECK:   [[C:%[0-9]+]]:_(s32) = G_CONSTANT i32 1
  ; CHECK:   [[ATOMICRMW_ADD:%[0-9]+]]:_(s32) = G_ATOMICRMW_ADD [[COPY]](p0), [[C]] :: ("aarch64-strided-access" load store monotonic (s32) on %ir.ptr)
  ; CHECK:   $w0 = COPY [[ATOMICRMW_ADD]](s32)
  ; CHECK:   RET_ReallyLR implicit $w0
  %oldval = atomicrmw add ptr %ptr, i32 1 monotonic, !falkor.strided.access !0
  ret i32 %oldval
}

define i32 @atomicrmw_volatile_falkor(ptr %ptr) {
  ; CHECK-LABEL: name: atomicrmw_volatile_falkor
  ; CHECK: bb.1 (%ir-block.0):
  ; CHECK:   liveins: $x0
  ; CHECK:   [[COPY:%[0-9]+]]:_(p0) = COPY $x0
  ; CHECK:   [[C:%[0-9]+]]:_(s32) = G_CONSTANT i32 1
  ; CHECK:   [[ATOMICRMW_ADD:%[0-9]+]]:_(s32) = G_ATOMICRMW_ADD [[COPY]](p0), [[C]] :: (volatile "aarch64-strided-access" load store monotonic (s32) on %ir.ptr)
  ; CHECK:   $w0 = COPY [[ATOMICRMW_ADD]](s32)
  ; CHECK:   RET_ReallyLR implicit $w0
  %oldval = atomicrmw volatile add ptr %ptr, i32 1 monotonic, !falkor.strided.access !0
  ret i32 %oldval
}

define i32 @cmpxchg_volatile(ptr %addr) {
  ; CHECK-LABEL: name: cmpxchg_volatile
  ; CHECK: bb.1 (%ir-block.0):
  ; CHECK:   liveins: $x0
  ; CHECK:   [[COPY:%[0-9]+]]:_(p0) = COPY $x0
  ; CHECK:   [[C:%[0-9]+]]:_(s32) = G_CONSTANT i32 0
  ; CHECK:   [[C1:%[0-9]+]]:_(s32) = G_CONSTANT i32 1
  ; CHECK:   [[ATOMIC_CMPXCHG_WITH_SUCCESS:%[0-9]+]]:_(s32), [[ATOMIC_CMPXCHG_WITH_SUCCESS1:%[0-9]+]]:_(s1) = G_ATOMIC_CMPXCHG_WITH_SUCCESS [[COPY]](p0), [[C]], [[C1]] :: (volatile load store monotonic monotonic (s32) on %ir.addr)
  ; CHECK:   $w0 = COPY [[ATOMIC_CMPXCHG_WITH_SUCCESS]](s32)
  ; CHECK:   RET_ReallyLR implicit $w0
  %val_success = cmpxchg volatile ptr %addr, i32 0, i32 1 monotonic monotonic
  %value_loaded = extractvalue { i32, i1 } %val_success, 0
  ret i32 %value_loaded
}

define i32 @cmpxchg_falkor(ptr %addr) {
  ; CHECK-LABEL: name: cmpxchg_falkor
  ; CHECK: bb.1 (%ir-block.0):
  ; CHECK:   liveins: $x0
  ; CHECK:   [[COPY:%[0-9]+]]:_(p0) = COPY $x0
  ; CHECK:   [[C:%[0-9]+]]:_(s32) = G_CONSTANT i32 0
  ; CHECK:   [[C1:%[0-9]+]]:_(s32) = G_CONSTANT i32 1
  ; CHECK:   [[ATOMIC_CMPXCHG_WITH_SUCCESS:%[0-9]+]]:_(s32), [[ATOMIC_CMPXCHG_WITH_SUCCESS1:%[0-9]+]]:_(s1) = G_ATOMIC_CMPXCHG_WITH_SUCCESS [[COPY]](p0), [[C]], [[C1]] :: ("aarch64-strided-access" load store monotonic monotonic (s32) on %ir.addr)
  ; CHECK:   $w0 = COPY [[ATOMIC_CMPXCHG_WITH_SUCCESS]](s32)
  ; CHECK:   RET_ReallyLR implicit $w0
  %val_success = cmpxchg ptr %addr, i32 0, i32 1 monotonic monotonic, !falkor.strided.access !0
  %value_loaded = extractvalue { i32, i1 } %val_success, 0
  ret i32 %value_loaded
}

define i32 @cmpxchg_volatile_falkor(ptr %addr) {
  ; CHECK-LABEL: name: cmpxchg_volatile_falkor
  ; CHECK: bb.1 (%ir-block.0):
  ; CHECK:   liveins: $x0
  ; CHECK:   [[COPY:%[0-9]+]]:_(p0) = COPY $x0
  ; CHECK:   [[C:%[0-9]+]]:_(s32) = G_CONSTANT i32 0
  ; CHECK:   [[C1:%[0-9]+]]:_(s32) = G_CONSTANT i32 1
  ; CHECK:   [[ATOMIC_CMPXCHG_WITH_SUCCESS:%[0-9]+]]:_(s32), [[ATOMIC_CMPXCHG_WITH_SUCCESS1:%[0-9]+]]:_(s1) = G_ATOMIC_CMPXCHG_WITH_SUCCESS [[COPY]](p0), [[C]], [[C1]] :: (volatile "aarch64-strided-access" load store monotonic monotonic (s32) on %ir.addr)
  ; CHECK:   $w0 = COPY [[ATOMIC_CMPXCHG_WITH_SUCCESS]](s32)
  ; CHECK:   RET_ReallyLR implicit $w0
  %val_success = cmpxchg volatile ptr %addr, i32 0, i32 1 monotonic monotonic, !falkor.strided.access !0
  %value_loaded = extractvalue { i32, i1 } %val_success, 0
  ret i32 %value_loaded
}

!0 = !{}
