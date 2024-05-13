; NOTE: Assertions have been autogenerated by utils/update_analyze_test_checks.py
; RUN: opt < %s -passes="print<cost-model>" 2>&1 -disable-output -mtriple=riscv32 -mattr=+v,+f,+d,+zfh,+experimental-zvfh -riscv-v-vector-bits-min=-1 | FileCheck %s
; Check that we don't crash querying costs when vectors are not enabled.
; RUN: opt -passes="print<cost-model>" 2>&1 -disable-output -mtriple=riscv32

target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"

define <8 x i8> @trn1.v8i8(<8 x i8> %v0, <8 x i8> %v1) {
; CHECK-LABEL: 'trn1.v8i8'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <8 x i8> %v0, <8 x i8> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <8 x i8> %tmp0
;
  %tmp0 = shufflevector <8 x i8> %v0, <8 x i8> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
  ret <8 x i8> %tmp0
}

define <8 x i8> @trn2.v8i8(<8 x i8> %v0, <8 x i8> %v1) {
; CHECK-LABEL: 'trn2.v8i8'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <8 x i8> %v0, <8 x i8> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <8 x i8> %tmp0
;
  %tmp0 = shufflevector <8 x i8> %v0, <8 x i8> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
  ret <8 x i8> %tmp0
}

define <16 x i8> @trn1.v16i8(<16 x i8> %v0, <16 x i8> %v1) {
; CHECK-LABEL: 'trn1.v16i8'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <16 x i8> %v0, <16 x i8> %v1, <16 x i32> <i32 0, i32 16, i32 2, i32 18, i32 4, i32 20, i32 6, i32 22, i32 8, i32 24, i32 10, i32 26, i32 12, i32 28, i32 14, i32 30>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <16 x i8> %tmp0
;
  %tmp0 = shufflevector <16 x i8> %v0, <16 x i8> %v1, <16 x i32> <i32 0, i32 16, i32 2, i32 18, i32 4, i32 20, i32 6, i32 22, i32 8, i32 24, i32 10, i32 26, i32 12, i32 28, i32 14, i32 30>
  ret <16 x i8> %tmp0
}

define <16 x i8> @trn2.v16i8(<16 x i8> %v0, <16 x i8> %v1) {
; CHECK-LABEL: 'trn2.v16i8'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <16 x i8> %v0, <16 x i8> %v1, <16 x i32> <i32 1, i32 17, i32 3, i32 19, i32 5, i32 21, i32 7, i32 23, i32 9, i32 25, i32 11, i32 27, i32 13, i32 29, i32 15, i32 31>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <16 x i8> %tmp0
;
  %tmp0 = shufflevector <16 x i8> %v0, <16 x i8> %v1, <16 x i32> <i32 1, i32 17, i32 3, i32 19, i32 5, i32 21, i32 7, i32 23, i32 9, i32 25, i32 11, i32 27, i32 13, i32 29, i32 15, i32 31>
  ret <16 x i8> %tmp0
}

define <4 x i16> @trn1.v4i16(<4 x i16> %v0, <4 x i16> %v1) {
; CHECK-LABEL: 'trn1.v4i16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x i16> %v0, <4 x i16> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x i16> %tmp0
;
  %tmp0 = shufflevector <4 x i16> %v0, <4 x i16> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x i16> %tmp0
}

define <4 x i16> @trn2.v4i16(<4 x i16> %v0, <4 x i16> %v1) {
; CHECK-LABEL: 'trn2.v4i16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x i16> %v0, <4 x i16> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x i16> %tmp0
;
  %tmp0 = shufflevector <4 x i16> %v0, <4 x i16> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x i16> %tmp0
}

define <8 x i16> @trn1.v8i16(<8 x i16> %v0, <8 x i16> %v1) {
; CHECK-LABEL: 'trn1.v8i16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <8 x i16> %v0, <8 x i16> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <8 x i16> %tmp0
;
  %tmp0 = shufflevector <8 x i16> %v0, <8 x i16> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
  ret <8 x i16> %tmp0
}

define <8 x i16> @trn2.v8i16(<8 x i16> %v0, <8 x i16> %v1) {
; CHECK-LABEL: 'trn2.v8i16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <8 x i16> %v0, <8 x i16> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <8 x i16> %tmp0
;
  %tmp0 = shufflevector <8 x i16> %v0, <8 x i16> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
  ret <8 x i16> %tmp0
}

define <2 x i32> @trn1.v2i32(<2 x i32> %v0, <2 x i32> %v1) {
; CHECK-LABEL: 'trn1.v2i32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x i32> %v0, <2 x i32> %v1, <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x i32> %tmp0
;
  %tmp0 = shufflevector <2 x i32> %v0, <2 x i32> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x i32> %tmp0
}

define <2 x i32> @trn2.v2i32(<2 x i32> %v0, <2 x i32> %v1) {
; CHECK-LABEL: 'trn2.v2i32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x i32> %v0, <2 x i32> %v1, <2 x i32> <i32 1, i32 3>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x i32> %tmp0
;
  %tmp0 = shufflevector <2 x i32> %v0, <2 x i32> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x i32> %tmp0
}

define <4 x i32> @trn1.v4i32(<4 x i32> %v0, <4 x i32> %v1) {
; CHECK-LABEL: 'trn1.v4i32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x i32> %v0, <4 x i32> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x i32> %tmp0
;
  %tmp0 = shufflevector <4 x i32> %v0, <4 x i32> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x i32> %tmp0
}

define <4 x i32> @trn2.v4i32(<4 x i32> %v0, <4 x i32> %v1) {
; CHECK-LABEL: 'trn2.v4i32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x i32> %v0, <4 x i32> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x i32> %tmp0
;
  %tmp0 = shufflevector <4 x i32> %v0, <4 x i32> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x i32> %tmp0
}

define <2 x i64> @trn1.v2i64(<2 x i64> %v0, <2 x i64> %v1) {
; CHECK-LABEL: 'trn1.v2i64'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x i64> %v0, <2 x i64> %v1, <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x i64> %tmp0
;
  %tmp0 = shufflevector <2 x i64> %v0, <2 x i64> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x i64> %tmp0
}

define <2 x i64> @trn2.v2i64(<2 x i64> %v0, <2 x i64> %v1) {
; CHECK-LABEL: 'trn2.v2i64'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x i64> %v0, <2 x i64> %v1, <2 x i32> <i32 1, i32 3>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x i64> %tmp0
;
  %tmp0 = shufflevector <2 x i64> %v0, <2 x i64> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x i64> %tmp0
}

define <2 x float> @trn1.v2f32(<2 x float> %v0, <2 x float> %v1) {
; CHECK-LABEL: 'trn1.v2f32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x float> %v0, <2 x float> %v1, <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x float> %tmp0
;
  %tmp0 = shufflevector <2 x float> %v0, <2 x float> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x float> %tmp0
}

define <2 x float> @trn2.v2f32(<2 x float> %v0, <2 x float> %v1) {
; CHECK-LABEL: 'trn2.v2f32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x float> %v0, <2 x float> %v1, <2 x i32> <i32 1, i32 3>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x float> %tmp0
;
  %tmp0 = shufflevector <2 x float> %v0, <2 x float> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x float> %tmp0
}

define <4 x float> @trn1.v4f32(<4 x float> %v0, <4 x float> %v1) {
; CHECK-LABEL: 'trn1.v4f32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x float> %v0, <4 x float> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x float> %tmp0
;
  %tmp0 = shufflevector <4 x float> %v0, <4 x float> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x float> %tmp0
}

define <4 x float> @trn2.v4f32(<4 x float> %v0, <4 x float> %v1) {
; CHECK-LABEL: 'trn2.v4f32'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x float> %v0, <4 x float> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x float> %tmp0
;
  %tmp0 = shufflevector <4 x float> %v0, <4 x float> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x float> %tmp0
}

define <2 x double> @trn1.v2f64(<2 x double> %v0, <2 x double> %v1) {
; CHECK-LABEL: 'trn1.v2f64'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x double> %v0, <2 x double> %v1, <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x double> %tmp0
;
  %tmp0 = shufflevector <2 x double> %v0, <2 x double> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x double> %tmp0
}

define <2 x double> @trn2.v2f64(<2 x double> %v0, <2 x double> %v1) {
; CHECK-LABEL: 'trn2.v2f64'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <2 x double> %v0, <2 x double> %v1, <2 x i32> <i32 1, i32 3>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <2 x double> %tmp0
;
  %tmp0 = shufflevector <2 x double> %v0, <2 x double> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x double> %tmp0
}

define <4 x half> @trn1.v4f16(<4 x half> %v0, <4 x half> %v1) {
; CHECK-LABEL: 'trn1.v4f16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x half> %v0, <4 x half> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x half> %tmp0
;
  %tmp0 = shufflevector <4 x half> %v0, <4 x half> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x half> %tmp0
}

define <4 x half> @trn2.v4f16(<4 x half> %v0, <4 x half> %v1) {
; CHECK-LABEL: 'trn2.v4f16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <4 x half> %v0, <4 x half> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <4 x half> %tmp0
;
  %tmp0 = shufflevector <4 x half> %v0, <4 x half> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x half> %tmp0
}

define <8 x half> @trn1.v8f16(<8 x half> %v0, <8 x half> %v1) {
; CHECK-LABEL: 'trn1.v8f16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <8 x half> %v0, <8 x half> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <8 x half> %tmp0
;
  %tmp0 = shufflevector <8 x half> %v0, <8 x half> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
  ret <8 x half> %tmp0
}

define <8 x half> @trn2.v8f16(<8 x half> %v0, <8 x half> %v1) {
; CHECK-LABEL: 'trn2.v8f16'
; CHECK-NEXT:  Cost Model: Found an estimated cost of 11 for instruction: %tmp0 = shufflevector <8 x half> %v0, <8 x half> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
; CHECK-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: ret <8 x half> %tmp0
;
  %tmp0 = shufflevector <8 x half> %v0, <8 x half> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
  ret <8 x half> %tmp0
}
