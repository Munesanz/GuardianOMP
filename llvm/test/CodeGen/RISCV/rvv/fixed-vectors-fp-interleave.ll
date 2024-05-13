; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=riscv32 -mattr=+v,+zfh,+experimental-zvfh -riscv-v-vector-bits-min=128 -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,V128,RV32-V128
; RUN: llc -mtriple=riscv64 -mattr=+v,+zfh,+experimental-zvfh -riscv-v-vector-bits-min=128 -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,V128,RV64-V128
; RUN: llc -mtriple=riscv32 -mattr=+v,+zfh,+experimental-zvfh -riscv-v-vector-bits-min=512 -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,V512,RV32-V512
; RUN: llc -mtriple=riscv64 -mattr=+v,+zfh,+experimental-zvfh -riscv-v-vector-bits-min=512 -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,V512,RV64-V512

; Test optimizing interleaves to widening arithmetic.

define <4 x half> @interleave_v2f16(<2 x half> %x, <2 x half> %y) {
; CHECK-LABEL: interleave_v2f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 2, e16, mf4, ta, ma
; CHECK-NEXT:    vwaddu.vv v10, v8, v9
; CHECK-NEXT:    li a0, -1
; CHECK-NEXT:    vwmaccu.vx v10, a0, v9
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %a = shufflevector <2 x half> %x, <2 x half> %y, <4 x i32> <i32 0, i32 2, i32 1, i32 3>
  ret <4 x half> %a
}

; Vector order switched for coverage.
define <4 x float> @interleave_v2f32(<2 x float> %x, <2 x float> %y) {
; CHECK-LABEL: interleave_v2f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 2, e32, mf2, ta, ma
; CHECK-NEXT:    vwaddu.vv v10, v9, v8
; CHECK-NEXT:    li a0, -1
; CHECK-NEXT:    vwmaccu.vx v10, a0, v8
; CHECK-NEXT:    vmv1r.v v8, v10
; CHECK-NEXT:    ret
  %a = shufflevector <2 x float> %x, <2 x float> %y, <4 x i32> <i32 2, i32 0, i32 3, i32 1>
  ret <4 x float> %a
}

; One vXf64 test case to very that we don't optimize it.
; FIXME: Is there better codegen we can do here?
define <4 x double> @interleave_v2f64(<2 x double> %x, <2 x double> %y) {
; RV32-V128-LABEL: interleave_v2f64:
; RV32-V128:       # %bb.0:
; RV32-V128-NEXT:    vmv1r.v v12, v9
; RV32-V128-NEXT:    vsetivli zero, 4, e16, mf2, ta, ma
; RV32-V128-NEXT:    vid.v v9
; RV32-V128-NEXT:    vsrl.vi v14, v9, 1
; RV32-V128-NEXT:    vsetvli zero, zero, e64, m2, ta, mu
; RV32-V128-NEXT:    vrgatherei16.vv v10, v8, v14
; RV32-V128-NEXT:    li a0, 10
; RV32-V128-NEXT:    vmv.s.x v0, a0
; RV32-V128-NEXT:    vrgatherei16.vv v10, v12, v14, v0.t
; RV32-V128-NEXT:    vmv.v.v v8, v10
; RV32-V128-NEXT:    ret
;
; RV64-V128-LABEL: interleave_v2f64:
; RV64-V128:       # %bb.0:
; RV64-V128-NEXT:    vmv1r.v v12, v9
; RV64-V128-NEXT:    vsetivli zero, 4, e64, m2, ta, mu
; RV64-V128-NEXT:    vid.v v10
; RV64-V128-NEXT:    vsrl.vi v14, v10, 1
; RV64-V128-NEXT:    vrgather.vv v10, v8, v14
; RV64-V128-NEXT:    li a0, 10
; RV64-V128-NEXT:    vmv.s.x v0, a0
; RV64-V128-NEXT:    vrgather.vv v10, v12, v14, v0.t
; RV64-V128-NEXT:    vmv.v.v v8, v10
; RV64-V128-NEXT:    ret
;
; RV32-V512-LABEL: interleave_v2f64:
; RV32-V512:       # %bb.0:
; RV32-V512-NEXT:    vsetivli zero, 4, e16, mf4, ta, ma
; RV32-V512-NEXT:    vid.v v10
; RV32-V512-NEXT:    vsrl.vi v11, v10, 1
; RV32-V512-NEXT:    vsetvli zero, zero, e64, m1, ta, mu
; RV32-V512-NEXT:    li a0, 10
; RV32-V512-NEXT:    vmv.s.x v0, a0
; RV32-V512-NEXT:    vrgatherei16.vv v10, v8, v11
; RV32-V512-NEXT:    vrgatherei16.vv v10, v9, v11, v0.t
; RV32-V512-NEXT:    vmv.v.v v8, v10
; RV32-V512-NEXT:    ret
;
; RV64-V512-LABEL: interleave_v2f64:
; RV64-V512:       # %bb.0:
; RV64-V512-NEXT:    vsetivli zero, 4, e64, m1, ta, mu
; RV64-V512-NEXT:    vid.v v10
; RV64-V512-NEXT:    vsrl.vi v11, v10, 1
; RV64-V512-NEXT:    li a0, 10
; RV64-V512-NEXT:    vmv.s.x v0, a0
; RV64-V512-NEXT:    vrgather.vv v10, v8, v11
; RV64-V512-NEXT:    vrgather.vv v10, v9, v11, v0.t
; RV64-V512-NEXT:    vmv.v.v v8, v10
; RV64-V512-NEXT:    ret
  %a = shufflevector <2 x double> %x, <2 x double> %y, <4 x i32> <i32 0, i32 2, i32 1, i32 3>
  ret <4 x double> %a
}

; Undef elements for coverage
define <8 x half> @interleave_v4f16(<4 x half> %x, <4 x half> %y) {
; V128-LABEL: interleave_v4f16:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 4, e16, mf2, ta, ma
; V128-NEXT:    vwaddu.vv v10, v8, v9
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v10, a0, v9
; V128-NEXT:    vmv1r.v v8, v10
; V128-NEXT:    ret
;
; V512-LABEL: interleave_v4f16:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 4, e16, mf4, ta, ma
; V512-NEXT:    vwaddu.vv v10, v8, v9
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v10, a0, v9
; V512-NEXT:    vmv1r.v v8, v10
; V512-NEXT:    ret
  %a = shufflevector <4 x half> %x, <4 x half> %y, <8 x i32> <i32 0, i32 4, i32 undef, i32 5, i32 2, i32 undef, i32 3, i32 7>
  ret <8 x half> %a
}

define <8 x float> @interleave_v4f32(<4 x float> %x, <4 x float> %y) {
; V128-LABEL: interleave_v4f32:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 4, e32, m1, ta, ma
; V128-NEXT:    vwaddu.vv v10, v8, v9
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v10, a0, v9
; V128-NEXT:    vmv2r.v v8, v10
; V128-NEXT:    ret
;
; V512-LABEL: interleave_v4f32:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 4, e32, mf2, ta, ma
; V512-NEXT:    vwaddu.vv v10, v8, v9
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v10, a0, v9
; V512-NEXT:    vmv1r.v v8, v10
; V512-NEXT:    ret
  %a = shufflevector <4 x float> %x, <4 x float> %y, <8 x i32> <i32 0, i32 4, i32 1, i32 5, i32 2, i32 6, i32 3, i32 7>
  ret <8 x float> %a
}

; Vector order switched for coverage.
define <16 x half> @interleave_v8f16(<8 x half> %x, <8 x half> %y) {
; V128-LABEL: interleave_v8f16:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 8, e16, m1, ta, ma
; V128-NEXT:    vwaddu.vv v10, v9, v8
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v10, a0, v8
; V128-NEXT:    vmv2r.v v8, v10
; V128-NEXT:    ret
;
; V512-LABEL: interleave_v8f16:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 8, e16, mf4, ta, ma
; V512-NEXT:    vwaddu.vv v10, v9, v8
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v10, a0, v8
; V512-NEXT:    vmv1r.v v8, v10
; V512-NEXT:    ret
  %a = shufflevector <8 x half> %x, <8 x half> %y, <16 x i32> <i32 8, i32 0, i32 9, i32 1, i32 10, i32 2, i32 11, i32 3, i32 12, i32 4, i32 13, i32 5, i32 14, i32 6, i32 15, i32 7>
  ret <16 x half> %a
}

define <16 x float> @interleave_v8f32(<8 x float> %x, <8 x float> %y) {
; V128-LABEL: interleave_v8f32:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 8, e32, m2, ta, ma
; V128-NEXT:    vwaddu.vv v12, v8, v10
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v12, a0, v10
; V128-NEXT:    vmv4r.v v8, v12
; V128-NEXT:    ret
;
; V512-LABEL: interleave_v8f32:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 8, e32, mf2, ta, ma
; V512-NEXT:    vwaddu.vv v10, v8, v9
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v10, a0, v9
; V512-NEXT:    vmv1r.v v8, v10
; V512-NEXT:    ret
  %a = shufflevector <8 x float> %x, <8 x float> %y, <16 x i32> <i32 0, i32 8, i32 1, i32 9, i32 2, i32 10, i32 3, i32 11, i32 4, i32 12, i32 5, i32 13, i32 6, i32 14, i32 7, i32 15>
  ret <16 x float> %a
}

define <32 x half> @interleave_v16f16(<16 x half> %x, <16 x half> %y) {
; V128-LABEL: interleave_v16f16:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 16, e16, m2, ta, ma
; V128-NEXT:    vwaddu.vv v12, v8, v10
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v12, a0, v10
; V128-NEXT:    vmv4r.v v8, v12
; V128-NEXT:    ret
;
; V512-LABEL: interleave_v16f16:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 16, e16, mf2, ta, ma
; V512-NEXT:    vwaddu.vv v10, v8, v9
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v10, a0, v9
; V512-NEXT:    vmv1r.v v8, v10
; V512-NEXT:    ret
  %a = shufflevector <16 x half> %x, <16 x half> %y, <32 x i32> <i32 0, i32 16, i32 1, i32 17, i32 2, i32 18, i32 3, i32 19, i32 4, i32 20, i32 5, i32 21, i32 6, i32 22, i32 7, i32 23, i32 8, i32 24, i32 9, i32 25, i32 10, i32 26, i32 11, i32 27, i32 12, i32 28, i32 13, i32 29, i32 14, i32 30, i32 15, i32 31>
  ret <32 x half> %a
}

define <32 x float> @interleave_v16f32(<16 x float> %x, <16 x float> %y) {
; V128-LABEL: interleave_v16f32:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 16, e32, m4, ta, ma
; V128-NEXT:    vwaddu.vv v16, v8, v12
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v16, a0, v12
; V128-NEXT:    vmv8r.v v8, v16
; V128-NEXT:    ret
;
; V512-LABEL: interleave_v16f32:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 16, e32, m1, ta, ma
; V512-NEXT:    vwaddu.vv v10, v8, v9
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v10, a0, v9
; V512-NEXT:    vmv2r.v v8, v10
; V512-NEXT:    ret
  %a = shufflevector <16 x float> %x, <16 x float> %y, <32 x i32> <i32 0, i32 16, i32 1, i32 17, i32 2, i32 18, i32 3, i32 19, i32 4, i32 20, i32 5, i32 21, i32 6, i32 22, i32 7, i32 23, i32 8, i32 24, i32 9, i32 25, i32 10, i32 26, i32 11, i32 27, i32 12, i32 28, i32 13, i32 29, i32 14, i32 30, i32 15, i32 31>
  ret <32 x float> %a
}

define <64 x half> @interleave_v32f16(<32 x half> %x, <32 x half> %y) {
; V128-LABEL: interleave_v32f16:
; V128:       # %bb.0:
; V128-NEXT:    li a0, 32
; V128-NEXT:    vsetvli zero, a0, e16, m4, ta, ma
; V128-NEXT:    vwaddu.vv v16, v8, v12
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v16, a0, v12
; V128-NEXT:    vmv8r.v v8, v16
; V128-NEXT:    ret
;
; V512-LABEL: interleave_v32f16:
; V512:       # %bb.0:
; V512-NEXT:    li a0, 32
; V512-NEXT:    vsetvli zero, a0, e16, m1, ta, ma
; V512-NEXT:    vwaddu.vv v10, v8, v9
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v10, a0, v9
; V512-NEXT:    vmv2r.v v8, v10
; V512-NEXT:    ret
  %a = shufflevector <32 x half> %x, <32 x half> %y, <64 x i32> <i32 0, i32 32, i32 1, i32 33, i32 2, i32 34, i32 3, i32 35, i32 4, i32 36, i32 5, i32 37, i32 6, i32 38, i32 7, i32 39, i32 8, i32 40, i32 9, i32 41, i32 10, i32 42, i32 11, i32 43, i32 12, i32 44, i32 13, i32 45, i32 14, i32 46, i32 15, i32 47, i32 16, i32 48, i32 17, i32 49, i32 18, i32 50, i32 19, i32 51, i32 20, i32 52, i32 21, i32 53, i32 22, i32 54, i32 23, i32 55, i32 24, i32 56, i32 25, i32 57, i32 26, i32 58, i32 27, i32 59, i32 28, i32 60, i32 29, i32 61, i32 30, i32 62, i32 31, i32 63>
  ret <64 x half> %a
}

define <64 x float> @interleave_v32f32(<32 x float> %x, <32 x float> %y) {
; RV32-V128-LABEL: interleave_v32f32:
; RV32-V128:       # %bb.0:
; RV32-V128-NEXT:    addi sp, sp, -16
; RV32-V128-NEXT:    .cfi_def_cfa_offset 16
; RV32-V128-NEXT:    csrr a0, vlenb
; RV32-V128-NEXT:    slli a0, a0, 4
; RV32-V128-NEXT:    sub sp, sp, a0
; RV32-V128-NEXT:    .cfi_escape 0x0f, 0x0d, 0x72, 0x00, 0x11, 0x10, 0x22, 0x11, 0x10, 0x92, 0xa2, 0x38, 0x00, 0x1e, 0x22 # sp + 16 + 16 * vlenb
; RV32-V128-NEXT:    lui a0, %hi(.LCPI10_0)
; RV32-V128-NEXT:    addi a0, a0, %lo(.LCPI10_0)
; RV32-V128-NEXT:    li a1, 32
; RV32-V128-NEXT:    vsetvli zero, a1, e32, m8, ta, ma
; RV32-V128-NEXT:    vle32.v v0, (a0)
; RV32-V128-NEXT:    vmv8r.v v24, v8
; RV32-V128-NEXT:    vrgather.vv v8, v24, v0
; RV32-V128-NEXT:    addi a0, sp, 16
; RV32-V128-NEXT:    vs8r.v v24, (a0) # Unknown-size Folded Spill
; RV32-V128-NEXT:    lui a0, %hi(.LCPI10_1)
; RV32-V128-NEXT:    addi a0, a0, %lo(.LCPI10_1)
; RV32-V128-NEXT:    vle32.v v24, (a0)
; RV32-V128-NEXT:    csrr a0, vlenb
; RV32-V128-NEXT:    slli a0, a0, 3
; RV32-V128-NEXT:    add a0, sp, a0
; RV32-V128-NEXT:    addi a0, a0, 16
; RV32-V128-NEXT:    vs8r.v v24, (a0) # Unknown-size Folded Spill
; RV32-V128-NEXT:    lui a0, 699051
; RV32-V128-NEXT:    addi a0, a0, -1366
; RV32-V128-NEXT:    vsetivli zero, 1, e32, mf2, ta, ma
; RV32-V128-NEXT:    vmv.s.x v0, a0
; RV32-V128-NEXT:    vsetvli zero, a1, e32, m8, ta, mu
; RV32-V128-NEXT:    csrr a0, vlenb
; RV32-V128-NEXT:    slli a0, a0, 3
; RV32-V128-NEXT:    add a0, sp, a0
; RV32-V128-NEXT:    addi a0, a0, 16
; RV32-V128-NEXT:    vl8r.v v24, (a0) # Unknown-size Folded Reload
; RV32-V128-NEXT:    vrgather.vv v8, v16, v24, v0.t
; RV32-V128-NEXT:    vmv.v.v v24, v8
; RV32-V128-NEXT:    vsetivli zero, 16, e32, m4, ta, ma
; RV32-V128-NEXT:    addi a0, sp, 16
; RV32-V128-NEXT:    vl8r.v v8, (a0) # Unknown-size Folded Reload
; RV32-V128-NEXT:    vwaddu.vv v0, v8, v16
; RV32-V128-NEXT:    li a0, -1
; RV32-V128-NEXT:    vwmaccu.vx v0, a0, v16
; RV32-V128-NEXT:    vmv8r.v v8, v0
; RV32-V128-NEXT:    vmv8r.v v16, v24
; RV32-V128-NEXT:    csrr a0, vlenb
; RV32-V128-NEXT:    slli a0, a0, 4
; RV32-V128-NEXT:    add sp, sp, a0
; RV32-V128-NEXT:    addi sp, sp, 16
; RV32-V128-NEXT:    ret
;
; RV64-V128-LABEL: interleave_v32f32:
; RV64-V128:       # %bb.0:
; RV64-V128-NEXT:    addi sp, sp, -16
; RV64-V128-NEXT:    .cfi_def_cfa_offset 16
; RV64-V128-NEXT:    csrr a0, vlenb
; RV64-V128-NEXT:    slli a0, a0, 4
; RV64-V128-NEXT:    sub sp, sp, a0
; RV64-V128-NEXT:    .cfi_escape 0x0f, 0x0d, 0x72, 0x00, 0x11, 0x10, 0x22, 0x11, 0x10, 0x92, 0xa2, 0x38, 0x00, 0x1e, 0x22 # sp + 16 + 16 * vlenb
; RV64-V128-NEXT:    lui a0, %hi(.LCPI10_0)
; RV64-V128-NEXT:    addi a0, a0, %lo(.LCPI10_0)
; RV64-V128-NEXT:    li a1, 32
; RV64-V128-NEXT:    vsetvli zero, a1, e32, m8, ta, ma
; RV64-V128-NEXT:    vle32.v v0, (a0)
; RV64-V128-NEXT:    vmv8r.v v24, v8
; RV64-V128-NEXT:    vrgather.vv v8, v24, v0
; RV64-V128-NEXT:    addi a0, sp, 16
; RV64-V128-NEXT:    vs8r.v v24, (a0) # Unknown-size Folded Spill
; RV64-V128-NEXT:    lui a0, %hi(.LCPI10_1)
; RV64-V128-NEXT:    addi a0, a0, %lo(.LCPI10_1)
; RV64-V128-NEXT:    vle32.v v24, (a0)
; RV64-V128-NEXT:    csrr a0, vlenb
; RV64-V128-NEXT:    slli a0, a0, 3
; RV64-V128-NEXT:    add a0, sp, a0
; RV64-V128-NEXT:    addi a0, a0, 16
; RV64-V128-NEXT:    vs8r.v v24, (a0) # Unknown-size Folded Spill
; RV64-V128-NEXT:    lui a0, 699051
; RV64-V128-NEXT:    addiw a0, a0, -1366
; RV64-V128-NEXT:    vsetivli zero, 1, e32, mf2, ta, ma
; RV64-V128-NEXT:    vmv.s.x v0, a0
; RV64-V128-NEXT:    vsetvli zero, a1, e32, m8, ta, mu
; RV64-V128-NEXT:    csrr a0, vlenb
; RV64-V128-NEXT:    slli a0, a0, 3
; RV64-V128-NEXT:    add a0, sp, a0
; RV64-V128-NEXT:    addi a0, a0, 16
; RV64-V128-NEXT:    vl8r.v v24, (a0) # Unknown-size Folded Reload
; RV64-V128-NEXT:    vrgather.vv v8, v16, v24, v0.t
; RV64-V128-NEXT:    vmv.v.v v24, v8
; RV64-V128-NEXT:    vsetivli zero, 16, e32, m4, ta, ma
; RV64-V128-NEXT:    addi a0, sp, 16
; RV64-V128-NEXT:    vl8r.v v8, (a0) # Unknown-size Folded Reload
; RV64-V128-NEXT:    vwaddu.vv v0, v8, v16
; RV64-V128-NEXT:    li a0, -1
; RV64-V128-NEXT:    vwmaccu.vx v0, a0, v16
; RV64-V128-NEXT:    vmv8r.v v8, v0
; RV64-V128-NEXT:    vmv8r.v v16, v24
; RV64-V128-NEXT:    csrr a0, vlenb
; RV64-V128-NEXT:    slli a0, a0, 4
; RV64-V128-NEXT:    add sp, sp, a0
; RV64-V128-NEXT:    addi sp, sp, 16
; RV64-V128-NEXT:    ret
;
; V512-LABEL: interleave_v32f32:
; V512:       # %bb.0:
; V512-NEXT:    li a0, 32
; V512-NEXT:    vsetvli zero, a0, e32, m2, ta, ma
; V512-NEXT:    vwaddu.vv v12, v8, v10
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v12, a0, v10
; V512-NEXT:    vmv4r.v v8, v12
; V512-NEXT:    ret
  %a = shufflevector <32 x float> %x, <32 x float> %y, <64 x i32> <i32 0, i32 32, i32 1, i32 33, i32 2, i32 34, i32 3, i32 35, i32 4, i32 36, i32 5, i32 37, i32 6, i32 38, i32 7, i32 39, i32 8, i32 40, i32 9, i32 41, i32 10, i32 42, i32 11, i32 43, i32 12, i32 44, i32 13, i32 45, i32 14, i32 46, i32 15, i32 47, i32 16, i32 48, i32 17, i32 49, i32 18, i32 50, i32 19, i32 51, i32 20, i32 52, i32 21, i32 53, i32 22, i32 54, i32 23, i32 55, i32 24, i32 56, i32 25, i32 57, i32 26, i32 58, i32 27, i32 59, i32 28, i32 60, i32 29, i32 61, i32 30, i32 62, i32 31, i32 63>
  ret <64 x float> %a
}

define <4 x half> @unary_interleave_v4f16(<4 x half> %x) {
; V128-LABEL: unary_interleave_v4f16:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 2, e16, mf2, ta, ma
; V128-NEXT:    vslidedown.vi v10, v8, 2
; V128-NEXT:    vsetivli zero, 2, e16, mf4, ta, ma
; V128-NEXT:    vwaddu.vv v9, v8, v10
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v9, a0, v10
; V128-NEXT:    vmv1r.v v8, v9
; V128-NEXT:    ret
;
; V512-LABEL: unary_interleave_v4f16:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 2, e16, mf4, ta, ma
; V512-NEXT:    vslidedown.vi v10, v8, 2
; V512-NEXT:    vwaddu.vv v9, v8, v10
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v9, a0, v10
; V512-NEXT:    vmv1r.v v8, v9
; V512-NEXT:    ret
  %a = shufflevector <4 x half> %x, <4 x half> poison, <4 x i32> <i32 0, i32 2, i32 1, i32 3>
  ret <4 x half> %a
}

define <4 x float> @unary_interleave_v4f32(<4 x float> %x) {
; V128-LABEL: unary_interleave_v4f32:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 2, e32, m1, ta, ma
; V128-NEXT:    vslidedown.vi v10, v8, 2
; V128-NEXT:    vsetivli zero, 2, e32, mf2, ta, ma
; V128-NEXT:    vwaddu.vv v9, v8, v10
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v9, a0, v10
; V128-NEXT:    vmv1r.v v8, v9
; V128-NEXT:    ret
;
; V512-LABEL: unary_interleave_v4f32:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 2, e32, mf2, ta, ma
; V512-NEXT:    vslidedown.vi v10, v8, 2
; V512-NEXT:    vwaddu.vv v9, v8, v10
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v9, a0, v10
; V512-NEXT:    vmv1r.v v8, v9
; V512-NEXT:    ret
  %a = shufflevector <4 x float> %x, <4 x float> poison, <4 x i32> <i32 0, i32 2, i32 1, i32 3>
  ret <4 x float> %a
}

; FIXME: Is there better codegen we can do here?
define <4 x double> @unary_interleave_v4f64(<4 x double> %x) {
; RV32-V128-LABEL: unary_interleave_v4f64:
; RV32-V128:       # %bb.0:
; RV32-V128-NEXT:    lui a0, %hi(.LCPI13_0)
; RV32-V128-NEXT:    addi a0, a0, %lo(.LCPI13_0)
; RV32-V128-NEXT:    vsetivli zero, 4, e64, m2, ta, ma
; RV32-V128-NEXT:    vle16.v v12, (a0)
; RV32-V128-NEXT:    vrgatherei16.vv v10, v8, v12
; RV32-V128-NEXT:    vmv.v.v v8, v10
; RV32-V128-NEXT:    ret
;
; RV64-V128-LABEL: unary_interleave_v4f64:
; RV64-V128:       # %bb.0:
; RV64-V128-NEXT:    lui a0, %hi(.LCPI13_0)
; RV64-V128-NEXT:    addi a0, a0, %lo(.LCPI13_0)
; RV64-V128-NEXT:    vsetivli zero, 4, e64, m2, ta, ma
; RV64-V128-NEXT:    vle64.v v12, (a0)
; RV64-V128-NEXT:    vrgather.vv v10, v8, v12
; RV64-V128-NEXT:    vmv.v.v v8, v10
; RV64-V128-NEXT:    ret
;
; RV32-V512-LABEL: unary_interleave_v4f64:
; RV32-V512:       # %bb.0:
; RV32-V512-NEXT:    lui a0, %hi(.LCPI13_0)
; RV32-V512-NEXT:    addi a0, a0, %lo(.LCPI13_0)
; RV32-V512-NEXT:    vsetivli zero, 4, e64, m1, ta, ma
; RV32-V512-NEXT:    vle16.v v10, (a0)
; RV32-V512-NEXT:    vrgatherei16.vv v9, v8, v10
; RV32-V512-NEXT:    vmv.v.v v8, v9
; RV32-V512-NEXT:    ret
;
; RV64-V512-LABEL: unary_interleave_v4f64:
; RV64-V512:       # %bb.0:
; RV64-V512-NEXT:    lui a0, %hi(.LCPI13_0)
; RV64-V512-NEXT:    addi a0, a0, %lo(.LCPI13_0)
; RV64-V512-NEXT:    vsetivli zero, 4, e64, m1, ta, ma
; RV64-V512-NEXT:    vle64.v v10, (a0)
; RV64-V512-NEXT:    vrgather.vv v9, v8, v10
; RV64-V512-NEXT:    vmv.v.v v8, v9
; RV64-V512-NEXT:    ret
  %a = shufflevector <4 x double> %x, <4 x double> poison, <4 x i32> <i32 0, i32 2, i32 1, i32 3>
  ret <4 x double> %a
}

define <8 x half> @unary_interleave_v8f16(<8 x half> %x) {
; V128-LABEL: unary_interleave_v8f16:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 4, e16, m1, ta, ma
; V128-NEXT:    vslidedown.vi v10, v8, 4
; V128-NEXT:    vsetivli zero, 4, e16, mf2, ta, ma
; V128-NEXT:    vwaddu.vv v9, v8, v10
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v9, a0, v10
; V128-NEXT:    vmv1r.v v8, v9
; V128-NEXT:    ret
;
; V512-LABEL: unary_interleave_v8f16:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 4, e16, mf4, ta, ma
; V512-NEXT:    vslidedown.vi v10, v8, 4
; V512-NEXT:    vwaddu.vv v9, v8, v10
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v9, a0, v10
; V512-NEXT:    vmv1r.v v8, v9
; V512-NEXT:    ret
  %a = shufflevector <8 x half> %x, <8 x half> poison, <8 x i32> <i32 0, i32 4, i32 undef, i32 5, i32 2, i32 undef, i32 3, i32 7>
  ret <8 x half> %a
}

define <8 x float> @unary_interleave_v8f32(<8 x float> %x) {
; V128-LABEL: unary_interleave_v8f32:
; V128:       # %bb.0:
; V128-NEXT:    vsetivli zero, 4, e32, m2, ta, ma
; V128-NEXT:    vslidedown.vi v12, v8, 4
; V128-NEXT:    vsetivli zero, 4, e32, m1, ta, ma
; V128-NEXT:    vwaddu.vv v10, v12, v8
; V128-NEXT:    li a0, -1
; V128-NEXT:    vwmaccu.vx v10, a0, v8
; V128-NEXT:    vmv2r.v v8, v10
; V128-NEXT:    ret
;
; V512-LABEL: unary_interleave_v8f32:
; V512:       # %bb.0:
; V512-NEXT:    vsetivli zero, 4, e32, mf2, ta, ma
; V512-NEXT:    vslidedown.vi v10, v8, 4
; V512-NEXT:    vwaddu.vv v9, v10, v8
; V512-NEXT:    li a0, -1
; V512-NEXT:    vwmaccu.vx v9, a0, v8
; V512-NEXT:    vmv1r.v v8, v9
; V512-NEXT:    ret
  %a = shufflevector <8 x float> %x, <8 x float> poison, <8 x i32> <i32 4, i32 0, i32 undef, i32 1, i32 6, i32 undef, i32 7, i32 3>
  ret <8 x float> %a
}
