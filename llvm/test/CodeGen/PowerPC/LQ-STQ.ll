; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mcpu=pwr10 -verify-machineinstrs -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:   -mattr=+quadword-atomics -ppc-asm-full-reg-names -o - %s | FileCheck %s

%struct.StructA = type { [16 x i8] }

@s1 = dso_local global %struct.StructA { [16 x i8] c"\0B\0C\0D\0E\0F\10\11\12\13\14\15\16\17\18\19\1A" }, align 16

define dso_local void @test() {
; CHECK-LABEL: test:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    plxv vs0, s1@PCREL(0), 1
; CHECK-NEXT:    stxv vs0, -48(r1)
; CHECK-NEXT:    ld r3, -40(r1)
; CHECK-NEXT:    ld r4, -48(r1)
; CHECK-NEXT:    sync
; CHECK-NEXT:    mr r5, r4
; CHECK-NEXT:    mr r4, r3
; CHECK-NEXT:    stq r4, -16(r1)
; CHECK-NEXT:    sync
; CHECK-NEXT:    lq r4, -16(r1)
; CHECK-NEXT:    cmpd cr7, r5, r5
; CHECK-NEXT:    bne- cr7, .+4
; CHECK-NEXT:    isync
; CHECK-NEXT:    std r4, -24(r1)
; CHECK-NEXT:    std r5, -32(r1)
; CHECK-NEXT:    blr
entry:
  %s2 = alloca %struct.StructA, align 16
  %s3 = alloca %struct.StructA, align 16
  %agg.tmp.ensured = alloca %struct.StructA, align 16
  call void @llvm.memcpy.p0.p0.i64(ptr align 16 %agg.tmp.ensured, ptr align 16 @s1, i64 16, i1 false)
  %0 = load i128, ptr %agg.tmp.ensured, align 16
  store atomic i128 %0, ptr %s2 seq_cst, align 16
  %atomic-load = load atomic i128, ptr %s2 seq_cst, align 16
  store i128 %atomic-load, ptr %s3, align 16
  ret void
}

declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg)
