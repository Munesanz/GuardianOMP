; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 2
; RUN: llc -verify-machineinstrs -o - %s -mtriple=aarch64-linux-gnu | FileCheck %s

declare <4 x i16> @llvm.aarch64.neon.vcvtfp2hf(<4 x float>) #2
declare <8 x i8> @llvm.aarch64.neon.tbl1.v8i8(<16 x i8>, <8 x i8>) #2

define <8 x half> @test1(<4 x float> noundef %a) {
; CHECK-LABEL: test1:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fcvtn v0.4h, v0.4s
; CHECK-NEXT:    ret
entry:
  %vcvt_f16_f321.i = tail call <4 x i16> @llvm.aarch64.neon.vcvtfp2hf(<4 x float> %a)
  %0 = bitcast <4 x i16> %vcvt_f16_f321.i to <4 x half>
  %shuffle.i = shufflevector <4 x half> %0, <4 x half> zeroinitializer, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>
  ret <8 x half> %shuffle.i
}

define <8 x i8> @test2(ptr nocapture noundef readonly %in, <8 x i8> noundef %idx) {
; CHECK-LABEL: test2:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    ldr q1, [x0]
; CHECK-NEXT:    shrn v1.8b, v1.8h, #4
; CHECK-NEXT:    tbl v0.8b, { v1.16b }, v0.8b
; CHECK-NEXT:    ret
entry:
  %0 = load <8 x i16>, ptr %in, align 2
  %1 = lshr <8 x i16> %0, <i16 4, i16 4, i16 4, i16 4, i16 4, i16 4, i16 4, i16 4>
  %vshrn_n = trunc <8 x i16> %1 to <8 x i8>
  %vtbl1.i = shufflevector <8 x i8> %vshrn_n, <8 x i8> zeroinitializer, <16 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>
  %vtbl11.i = tail call <8 x i8> @llvm.aarch64.neon.tbl1.v8i8(<16 x i8> %vtbl1.i, <8 x i8> %idx)
  ret <8 x i8> %vtbl11.i
}
