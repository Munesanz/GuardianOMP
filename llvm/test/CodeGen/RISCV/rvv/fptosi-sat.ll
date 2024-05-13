; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=riscv32 -mattr=+d,+zfh,+experimental-zvfh,+v -target-abi=ilp32d \
; RUN:     -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,CHECK32
; RUN: llc -mtriple=riscv64 -mattr=+d,+zfh,+experimental-zvfh,+v -target-abi=lp64d \
; RUN:     -verify-machineinstrs < %s | FileCheck %s --check-prefixes=CHECK,CHECK64

; Float

declare <vscale x 2 x i32> @llvm.fptosi.sat.nxv2f32.nxv2i32(<vscale x 2 x float>)
declare <vscale x 4 x i32> @llvm.fptosi.sat.nxv4f32.nxv4i32(<vscale x 4 x float>)
declare <vscale x 8 x i32> @llvm.fptosi.sat.nxv8f32.nxv8i32(<vscale x 8 x float>)
declare <vscale x 4 x i16> @llvm.fptosi.sat.nxv4f32.nxv4i16(<vscale x 4 x float>)
declare <vscale x 8 x i16> @llvm.fptosi.sat.nxv8f32.nxv8i16(<vscale x 8 x float>)
declare <vscale x 2 x i64> @llvm.fptosi.sat.nxv2f32.nxv2i64(<vscale x 2 x float>)
declare <vscale x 4 x i64> @llvm.fptosi.sat.nxv4f32.nxv4i64(<vscale x 4 x float>)

define <vscale x 2 x i32> @test_signed_v2f32_v2i32(<vscale x 2 x float> %f) {
; CHECK-LABEL: test_signed_v2f32_v2i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m1, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfcvt.rtz.x.f.v v8, v8
; CHECK-NEXT:    vmerge.vim v8, v8, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 2 x i32> @llvm.fptosi.sat.nxv2f32.nxv2i32(<vscale x 2 x float> %f)
    ret <vscale x 2 x i32> %x
}

define <vscale x 4 x i32> @test_signed_v4f32_v4i32(<vscale x 4 x float> %f) {
; CHECK-LABEL: test_signed_v4f32_v4i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfcvt.rtz.x.f.v v8, v8
; CHECK-NEXT:    vmerge.vim v8, v8, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i32> @llvm.fptosi.sat.nxv4f32.nxv4i32(<vscale x 4 x float> %f)
    ret <vscale x 4 x i32> %x
}

define <vscale x 8 x i32> @test_signed_v8f32_v8i32(<vscale x 8 x float> %f) {
; CHECK-LABEL: test_signed_v8f32_v8i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m4, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfcvt.rtz.x.f.v v8, v8
; CHECK-NEXT:    vmerge.vim v8, v8, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 8 x i32> @llvm.fptosi.sat.nxv8f32.nxv8i32(<vscale x 8 x float> %f)
    ret <vscale x 8 x i32> %x
}

define <vscale x 4 x i16> @test_signed_v4f32_v4i16(<vscale x 4 x float> %f) {
; CHECK-LABEL: test_signed_v4f32_v4i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, m1, ta, ma
; CHECK-NEXT:    vfncvt.rtz.x.f.w v10, v8
; CHECK-NEXT:    vmerge.vim v8, v10, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i16> @llvm.fptosi.sat.nxv4f32.nxv4i16(<vscale x 4 x float> %f)
    ret <vscale x 4 x i16> %x
}

define <vscale x 8 x i16> @test_signed_v8f32_v8i16(<vscale x 8 x float> %f) {
; CHECK-LABEL: test_signed_v8f32_v8i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m4, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, m2, ta, ma
; CHECK-NEXT:    vfncvt.rtz.x.f.w v12, v8
; CHECK-NEXT:    vmerge.vim v8, v12, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 8 x i16> @llvm.fptosi.sat.nxv8f32.nxv8i16(<vscale x 8 x float> %f)
    ret <vscale x 8 x i16> %x
}

define <vscale x 2 x i64> @test_signed_v2f32_v2i64(<vscale x 2 x float> %f) {
; CHECK-LABEL: test_signed_v2f32_v2i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m1, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfwcvt.rtz.x.f.v v10, v8
; CHECK-NEXT:    vsetvli zero, zero, e64, m2, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v10, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 2 x i64> @llvm.fptosi.sat.nxv2f32.nxv2i64(<vscale x 2 x float> %f)
    ret <vscale x 2 x i64> %x
}

define <vscale x 4 x i64> @test_signed_v4f32_v4i64(<vscale x 4 x float> %f) {
; CHECK-LABEL: test_signed_v4f32_v4i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfwcvt.rtz.x.f.v v12, v8
; CHECK-NEXT:    vsetvli zero, zero, e64, m4, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v12, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i64> @llvm.fptosi.sat.nxv4f32.nxv4i64(<vscale x 4 x float> %f)
    ret <vscale x 4 x i64> %x
}

; Double

declare <vscale x 2 x i32> @llvm.fptosi.sat.nxv2f64.nxv2i32(<vscale x 2 x double>)
declare <vscale x 4 x i32> @llvm.fptosi.sat.nxv4f64.nxv4i32(<vscale x 4 x double>)
declare <vscale x 8 x i32> @llvm.fptosi.sat.nxv8f64.nxv8i32(<vscale x 8 x double>)
declare <vscale x 4 x i16> @llvm.fptosi.sat.nxv4f64.nxv4i16(<vscale x 4 x double>)
declare <vscale x 8 x i16> @llvm.fptosi.sat.nxv8f64.nxv8i16(<vscale x 8 x double>)
declare <vscale x 2 x i64> @llvm.fptosi.sat.nxv2f64.nxv2i64(<vscale x 2 x double>)
declare <vscale x 4 x i64> @llvm.fptosi.sat.nxv4f64.nxv4i64(<vscale x 4 x double>)

define <vscale x 2 x i32> @test_signed_v2f64_v2i32(<vscale x 2 x double> %f) {
; CHECK-LABEL: test_signed_v2f64_v2i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e64, m2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m1, ta, ma
; CHECK-NEXT:    vfncvt.rtz.x.f.w v10, v8
; CHECK-NEXT:    vmerge.vim v8, v10, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 2 x i32> @llvm.fptosi.sat.nxv2f64.nxv2i32(<vscale x 2 x double> %f)
    ret <vscale x 2 x i32> %x
}

define <vscale x 4 x i32> @test_signed_v4f64_v4i32(<vscale x 4 x double> %f) {
; CHECK-LABEL: test_signed_v4f64_v4i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e64, m4, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m2, ta, ma
; CHECK-NEXT:    vfncvt.rtz.x.f.w v12, v8
; CHECK-NEXT:    vmerge.vim v8, v12, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i32> @llvm.fptosi.sat.nxv4f64.nxv4i32(<vscale x 4 x double> %f)
    ret <vscale x 4 x i32> %x
}

define <vscale x 8 x i32> @test_signed_v8f64_v8i32(<vscale x 8 x double> %f) {
; CHECK-LABEL: test_signed_v8f64_v8i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e64, m8, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m4, ta, ma
; CHECK-NEXT:    vfncvt.rtz.x.f.w v16, v8
; CHECK-NEXT:    vmerge.vim v8, v16, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 8 x i32> @llvm.fptosi.sat.nxv8f64.nxv8i32(<vscale x 8 x double> %f)
    ret <vscale x 8 x i32> %x
}

define <vscale x 4 x i16> @test_signed_v4f64_v4i16(<vscale x 4 x double> %f) {
; CHECK-LABEL: test_signed_v4f64_v4i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    lui a0, %hi(.LCPI10_0)
; CHECK-NEXT:    fld fa5, %lo(.LCPI10_0)(a0)
; CHECK-NEXT:    lui a0, %hi(.LCPI10_1)
; CHECK-NEXT:    fld fa4, %lo(.LCPI10_1)(a0)
; CHECK-NEXT:    vsetvli a0, zero, e64, m4, ta, ma
; CHECK-NEXT:    vfmax.vf v12, v8, fa5
; CHECK-NEXT:    vfmin.vf v12, v12, fa4
; CHECK-NEXT:    vsetvli zero, zero, e32, m2, ta, ma
; CHECK-NEXT:    vfncvt.rtz.x.f.w v16, v12
; CHECK-NEXT:    vsetvli zero, zero, e16, m1, ta, ma
; CHECK-NEXT:    vnsrl.wi v12, v16, 0
; CHECK-NEXT:    vsetvli zero, zero, e64, m4, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, m1, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v12, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i16> @llvm.fptosi.sat.nxv4f64.nxv4i16(<vscale x 4 x double> %f)
    ret <vscale x 4 x i16> %x
}

define <vscale x 8 x i16> @test_signed_v8f64_v8i16(<vscale x 8 x double> %f) {
; CHECK-LABEL: test_signed_v8f64_v8i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    lui a0, %hi(.LCPI11_0)
; CHECK-NEXT:    fld fa5, %lo(.LCPI11_0)(a0)
; CHECK-NEXT:    lui a0, %hi(.LCPI11_1)
; CHECK-NEXT:    fld fa4, %lo(.LCPI11_1)(a0)
; CHECK-NEXT:    vsetvli a0, zero, e64, m8, ta, ma
; CHECK-NEXT:    vfmax.vf v16, v8, fa5
; CHECK-NEXT:    vfmin.vf v16, v16, fa4
; CHECK-NEXT:    vsetvli zero, zero, e32, m4, ta, ma
; CHECK-NEXT:    vfncvt.rtz.x.f.w v24, v16
; CHECK-NEXT:    vsetvli zero, zero, e16, m2, ta, ma
; CHECK-NEXT:    vnsrl.wi v16, v24, 0
; CHECK-NEXT:    vsetvli zero, zero, e64, m8, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, m2, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v16, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 8 x i16> @llvm.fptosi.sat.nxv8f64.nxv8i16(<vscale x 8 x double> %f)
    ret <vscale x 8 x i16> %x
}

define <vscale x 2 x i64> @test_signed_v2f64_v2i64(<vscale x 2 x double> %f) {
; CHECK-LABEL: test_signed_v2f64_v2i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e64, m2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfcvt.rtz.x.f.v v8, v8
; CHECK-NEXT:    vmerge.vim v8, v8, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 2 x i64> @llvm.fptosi.sat.nxv2f64.nxv2i64(<vscale x 2 x double> %f)
    ret <vscale x 2 x i64> %x
}

define <vscale x 4 x i64> @test_signed_v4f64_v4i64(<vscale x 4 x double> %f) {
; CHECK-LABEL: test_signed_v4f64_v4i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e64, m4, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfcvt.rtz.x.f.v v8, v8
; CHECK-NEXT:    vmerge.vim v8, v8, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i64> @llvm.fptosi.sat.nxv4f64.nxv4i64(<vscale x 4 x double> %f)
    ret <vscale x 4 x i64> %x
}


; half

declare <vscale x 2 x i32> @llvm.fptosi.sat.nxv2f16.nxv2i32(<vscale x 2 x half>)
declare <vscale x 4 x i32> @llvm.fptosi.sat.nxv4f16.nxv4i32(<vscale x 4 x half>)
declare <vscale x 8 x i32> @llvm.fptosi.sat.nxv8f16.nxv8i32(<vscale x 8 x half>)
declare <vscale x 4 x i16> @llvm.fptosi.sat.nxv4f16.nxv4i16(<vscale x 4 x half>)
declare <vscale x 8 x i16> @llvm.fptosi.sat.nxv8f16.nxv8i16(<vscale x 8 x half>)
declare <vscale x 2 x i64> @llvm.fptosi.sat.nxv2f16.nxv2i64(<vscale x 2 x half>)
declare <vscale x 4 x i64> @llvm.fptosi.sat.nxv4f16.nxv4i64(<vscale x 4 x half>)

define <vscale x 2 x i32> @test_signed_v2f16_v2i32(<vscale x 2 x half> %f) {
; CHECK-LABEL: test_signed_v2f16_v2i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, mf2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfwcvt.rtz.x.f.v v9, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m1, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v9, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 2 x i32> @llvm.fptosi.sat.nxv2f16.nxv2i32(<vscale x 2 x half> %f)
    ret <vscale x 2 x i32> %x
}

define <vscale x 4 x i32> @test_signed_v4f16_v4i32(<vscale x 4 x half> %f) {
; CHECK-LABEL: test_signed_v4f16_v4i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, m1, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfwcvt.rtz.x.f.v v10, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m2, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v10, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i32> @llvm.fptosi.sat.nxv4f16.nxv4i32(<vscale x 4 x half> %f)
    ret <vscale x 4 x i32> %x
}

define <vscale x 8 x i32> @test_signed_v8f16_v8i32(<vscale x 8 x half> %f) {
; CHECK-LABEL: test_signed_v8f16_v8i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, m2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfwcvt.rtz.x.f.v v12, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m4, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v12, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 8 x i32> @llvm.fptosi.sat.nxv8f16.nxv8i32(<vscale x 8 x half> %f)
    ret <vscale x 8 x i32> %x
}

define <vscale x 4 x i16> @test_signed_v4f16_v4i16(<vscale x 4 x half> %f) {
; CHECK-LABEL: test_signed_v4f16_v4i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, m1, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfcvt.rtz.x.f.v v8, v8
; CHECK-NEXT:    vmerge.vim v8, v8, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i16> @llvm.fptosi.sat.nxv4f16.nxv4i16(<vscale x 4 x half> %f)
    ret <vscale x 4 x i16> %x
}

define <vscale x 8 x i16> @test_signed_v8f16_v8i16(<vscale x 8 x half> %f) {
; CHECK-LABEL: test_signed_v8f16_v8i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, m2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfcvt.rtz.x.f.v v8, v8
; CHECK-NEXT:    vmerge.vim v8, v8, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 8 x i16> @llvm.fptosi.sat.nxv8f16.nxv8i16(<vscale x 8 x half> %f)
    ret <vscale x 8 x i16> %x
}

define <vscale x 2 x i64> @test_signed_v2f16_v2i64(<vscale x 2 x half> %f) {
; CHECK-LABEL: test_signed_v2f16_v2i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, mf2, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfwcvt.f.f.v v9, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m1, ta, ma
; CHECK-NEXT:    vfwcvt.rtz.x.f.v v10, v9
; CHECK-NEXT:    vsetvli zero, zero, e64, m2, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v10, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 2 x i64> @llvm.fptosi.sat.nxv2f16.nxv2i64(<vscale x 2 x half> %f)
    ret <vscale x 2 x i64> %x
}

define <vscale x 4 x i64> @test_signed_v4f16_v4i64(<vscale x 4 x half> %f) {
; CHECK-LABEL: test_signed_v4f16_v4i64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, m1, ta, ma
; CHECK-NEXT:    vmfne.vv v0, v8, v8
; CHECK-NEXT:    vfwcvt.f.f.v v10, v8
; CHECK-NEXT:    vsetvli zero, zero, e32, m2, ta, ma
; CHECK-NEXT:    vfwcvt.rtz.x.f.v v12, v10
; CHECK-NEXT:    vsetvli zero, zero, e64, m4, ta, ma
; CHECK-NEXT:    vmerge.vim v8, v12, 0, v0
; CHECK-NEXT:    ret
    %x = call <vscale x 4 x i64> @llvm.fptosi.sat.nxv4f16.nxv4i64(<vscale x 4 x half> %f)
    ret <vscale x 4 x i64> %x
}

;; NOTE: These prefixes are unused and the list is autogenerated. Do not add tests below this line:
; CHECK32: {{.*}}
; CHECK64: {{.*}}
