; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 2
; RUN: llc -mtriple=riscv32 -mattr=+m,+v,+f,+d,+zfh,+experimental-zvfh -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK
; RUN: llc -mtriple=riscv64 -mattr=+m,+v,+f,+d,+zfh,+experimental-zvfh -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK

target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"

define <8 x i8> @trn1.v8i8(<8 x i8> %v0, <8 x i8> %v1) {
; CHECK-LABEL: trn1.v8i8:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vrgather.vv v10, v8, v11
; CHECK-NEXT:    li a0, 170
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vadd.vi v8, v11, -1
; CHECK-NEXT:    vrgather.vv v10, v9, v8, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <8 x i8> %v0, <8 x i8> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
  ret <8 x i8> %tmp0
}

define <8 x i8> @trn2.v8i8(<8 x i8> %v0, <8 x i8> %v1) {
; CHECK-LABEL: trn2.v8i8:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vadd.vi v12, v11, 1
; CHECK-NEXT:    li a0, 170
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vrgather.vv v10, v8, v12
; CHECK-NEXT:    vrgather.vv v10, v9, v11, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <8 x i8> %v0, <8 x i8> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
  ret <8 x i8> %tmp0
}

define <16 x i8> @trn1.v16i8(<16 x i8> %v0, <16 x i8> %v1) {
  %tmp0 = shufflevector <16 x i8> %v0, <16 x i8> %v1, <16 x i32> <i32 0, i32 16, i32 2, i32 18, i32 4, i32 20, i32 6, i32 22, i32 8, i32 24, i32 10, i32 26, i32 12, i32 28, i32 14, i32 30>
  ret <16 x i8> %tmp0
}

define <16 x i8> @trn2.v16i8(<16 x i8> %v0, <16 x i8> %v1) {
  %tmp0 = shufflevector <16 x i8> %v0, <16 x i8> %v1, <16 x i32> <i32 1, i32 17, i32 3, i32 19, i32 5, i32 21, i32 7, i32 23, i32 9, i32 25, i32 11, i32 27, i32 13, i32 29, i32 15, i32 31>
  ret <16 x i8> %tmp0
}

define <4 x i16> @trn1.v4i16(<4 x i16> %v0, <4 x i16> %v1) {
; CHECK-LABEL: trn1.v4i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e16, mf2, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vrgather.vv v10, v8, v11
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vadd.vi v8, v11, -1
; CHECK-NEXT:    vrgather.vv v10, v9, v8, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x i16> %v0, <4 x i16> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x i16> %tmp0
}

define <4 x i16> @trn2.v4i16(<4 x i16> %v0, <4 x i16> %v1) {
; CHECK-LABEL: trn2.v4i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e16, mf2, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vadd.vi v12, v11, 1
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vrgather.vv v10, v8, v12
; CHECK-NEXT:    vrgather.vv v10, v9, v11, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x i16> %v0, <4 x i16> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x i16> %tmp0
}

define <8 x i16> @trn1.v8i16(<8 x i16> %v0, <8 x i16> %v1) {
; CHECK-LABEL: trn1.v8i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e16, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vrgather.vv v10, v8, v11
; CHECK-NEXT:    li a0, 170
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vadd.vi v8, v11, -1
; CHECK-NEXT:    vrgather.vv v10, v9, v8, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <8 x i16> %v0, <8 x i16> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
  ret <8 x i16> %tmp0
}

define <8 x i16> @trn2.v8i16(<8 x i16> %v0, <8 x i16> %v1) {
; CHECK-LABEL: trn2.v8i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e16, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vadd.vi v12, v11, 1
; CHECK-NEXT:    li a0, 170
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vrgather.vv v10, v8, v12
; CHECK-NEXT:    vrgather.vv v10, v9, v11, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <8 x i16> %v0, <8 x i16> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
  ret <8 x i16> %tmp0
}

define <2 x i32> @trn1.v2i32(<2 x i32> %v0, <2 x i32> %v1) {
; CHECK-LABEL: trn1.v2i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 1, e32, mf2, ta, ma
; CHECK-NEXT:    vwaddu.vv v10, v8, v9
; CHECK-NEXT:    li a0, -1
; CHECK-NEXT:    vwmaccu.vx v10, a0, v9
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x i32> %v0, <2 x i32> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x i32> %tmp0
}

define <2 x i32> @trn2.v2i32(<2 x i32> %v0, <2 x i32> %v1) {
; CHECK-LABEL: trn2.v2i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    li a0, 2
; CHECK-NEXT:    vsetivli zero, 1, e8, mf8, ta, ma
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vsetivli zero, 2, e32, mf2, ta, mu
; CHECK-NEXT:    vrgather.vi v10, v8, 1
; CHECK-NEXT:    vrgather.vi v10, v9, 1, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x i32> %v0, <2 x i32> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x i32> %tmp0
}

define <4 x i32> @trn1.v4i32(<4 x i32> %v0, <4 x i32> %v1) {
; CHECK-LABEL: trn1.v4i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e32, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vrgather.vv v10, v8, v11
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vadd.vi v8, v11, -1
; CHECK-NEXT:    vrgather.vv v10, v9, v8, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x i32> %v0, <4 x i32> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x i32> %tmp0
}

define <4 x i32> @trn2.v4i32(<4 x i32> %v0, <4 x i32> %v1) {
; CHECK-LABEL: trn2.v4i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e32, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vadd.vi v12, v11, 1
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vrgather.vv v10, v8, v12
; CHECK-NEXT:    vrgather.vv v10, v9, v11, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x i32> %v0, <4 x i32> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x i32> %tmp0
}

define <2 x i64> @trn1.v2i64(<2 x i64> %v0, <2 x i64> %v1) {
; CHECK-LABEL: trn1.v2i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 2, e64, m1, ta, ma
; CHECK-NEXT:    vslideup.vi v8, v9, 1
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x i64> %v0, <2 x i64> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x i64> %tmp0
}

define <2 x i64> @trn2.v2i64(<2 x i64> %v0, <2 x i64> %v1) {
; CHECK-LABEL: trn2.v2i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    li a0, 2
; CHECK-NEXT:    vsetivli zero, 1, e8, mf8, ta, ma
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vsetivli zero, 2, e64, m1, ta, mu
; CHECK-NEXT:    vrgather.vi v10, v8, 1
; CHECK-NEXT:    vrgather.vi v10, v9, 1, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x i64> %v0, <2 x i64> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x i64> %tmp0
}

define <2 x float> @trn1.v2f32(<2 x float> %v0, <2 x float> %v1) {
; CHECK-LABEL: trn1.v2f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 1, e32, mf2, ta, ma
; CHECK-NEXT:    vwaddu.vv v10, v8, v9
; CHECK-NEXT:    li a0, -1
; CHECK-NEXT:    vwmaccu.vx v10, a0, v9
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x float> %v0, <2 x float> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x float> %tmp0
}

define <2 x float> @trn2.v2f32(<2 x float> %v0, <2 x float> %v1) {
; CHECK-LABEL: trn2.v2f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    li a0, 2
; CHECK-NEXT:    vsetivli zero, 1, e8, mf8, ta, ma
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vsetivli zero, 2, e32, mf2, ta, mu
; CHECK-NEXT:    vrgather.vi v10, v8, 1
; CHECK-NEXT:    vrgather.vi v10, v9, 1, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x float> %v0, <2 x float> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x float> %tmp0
}

define <4 x float> @trn1.v4f32(<4 x float> %v0, <4 x float> %v1) {
; CHECK-LABEL: trn1.v4f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e32, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vrgather.vv v10, v8, v11
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vadd.vi v8, v11, -1
; CHECK-NEXT:    vrgather.vv v10, v9, v8, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x float> %v0, <4 x float> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x float> %tmp0
}

define <4 x float> @trn2.v4f32(<4 x float> %v0, <4 x float> %v1) {
; CHECK-LABEL: trn2.v4f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e32, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vadd.vi v12, v11, 1
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vrgather.vv v10, v8, v12
; CHECK-NEXT:    vrgather.vv v10, v9, v11, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x float> %v0, <4 x float> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x float> %tmp0
}

define <2 x double> @trn1.v2f64(<2 x double> %v0, <2 x double> %v1) {
; CHECK-LABEL: trn1.v2f64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 2, e64, m1, ta, ma
; CHECK-NEXT:    vslideup.vi v8, v9, 1
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x double> %v0, <2 x double> %v1, <2 x i32> <i32 0, i32 2>
  ret <2 x double> %tmp0
}

define <2 x double> @trn2.v2f64(<2 x double> %v0, <2 x double> %v1) {
; CHECK-LABEL: trn2.v2f64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    li a0, 2
; CHECK-NEXT:    vsetivli zero, 1, e8, mf8, ta, ma
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vsetivli zero, 2, e64, m1, ta, mu
; CHECK-NEXT:    vrgather.vi v10, v8, 1
; CHECK-NEXT:    vrgather.vi v10, v9, 1, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <2 x double> %v0, <2 x double> %v1, <2 x i32> <i32 1, i32 3>
  ret <2 x double> %tmp0
}

define <4 x half> @trn1.v4f16(<4 x half> %v0, <4 x half> %v1) {
; CHECK-LABEL: trn1.v4f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e16, mf2, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vrgather.vv v10, v8, v11
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vadd.vi v8, v11, -1
; CHECK-NEXT:    vrgather.vv v10, v9, v8, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x half> %v0, <4 x half> %v1, <4 x i32> <i32 0, i32 4, i32 2, i32 6>
  ret <4 x half> %tmp0
}

define <4 x half> @trn2.v4f16(<4 x half> %v0, <4 x half> %v1) {
; CHECK-LABEL: trn2.v4f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 4, e16, mf2, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vadd.vi v12, v11, 1
; CHECK-NEXT:    li a0, 10
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vrgather.vv v10, v8, v12
; CHECK-NEXT:    vrgather.vv v10, v9, v11, v0.t
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <4 x half> %v0, <4 x half> %v1, <4 x i32> <i32 1, i32 5, i32 3, i32 7>
  ret <4 x half> %tmp0
}

define <8 x half> @trn1.v8f16(<8 x half> %v0, <8 x half> %v1) {
; CHECK-LABEL: trn1.v8f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e16, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vrgather.vv v10, v8, v11
; CHECK-NEXT:    li a0, 170
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vadd.vi v8, v11, -1
; CHECK-NEXT:    vrgather.vv v10, v9, v8, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <8 x half> %v0, <8 x half> %v1, <8 x i32> <i32 0, i32 8, i32 2, i32 10, i32 4, i32 12, i32 6, i32 14>
  ret <8 x half> %tmp0
}

define <8 x half> @trn2.v8f16(<8 x half> %v0, <8 x half> %v1) {
; CHECK-LABEL: trn2.v8f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e16, m1, ta, mu
; CHECK-NEXT:    vid.v v11
; CHECK-NEXT:    vadd.vi v12, v11, 1
; CHECK-NEXT:    li a0, 170
; CHECK-NEXT:    vmv.s.x v0, a0
; CHECK-NEXT:    vrgather.vv v10, v8, v12
; CHECK-NEXT:    vrgather.vv v10, v9, v11, v0.t
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %tmp0 = shufflevector <8 x half> %v0, <8 x half> %v1, <8 x i32> <i32 1, i32 9, i32 3, i32 11, i32 5, i32 13, i32 7, i32 15>
  ret <8 x half> %tmp0
}
