; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=riscv32 -mattr=+d,+zfh,+experimental-zvfh,+v -target-abi=ilp32d \
; RUN:     -verify-machineinstrs < %s | FileCheck %s
; RUN: llc -mtriple=riscv64 -mattr=+d,+zfh,+experimental-zvfh,+v -target-abi=lp64d \
; RUN:     -verify-machineinstrs < %s | FileCheck %s

declare <vscale x 1 x float> @llvm.experimental.constrained.fptrunc.nxv1f32.nxv1f64(<vscale x 1 x double>, metadata, metadata)
define <vscale x 1 x float> @vfptrunc_nxv1f64_nxv1f32(<vscale x 1 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv1f64_nxv1f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, mf2, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v9, v8
; CHECK-NEXT:    vmv1r.v v8, v9
; CHECK-NEXT:    ret
  %evec = call <vscale x 1 x float> @llvm.experimental.constrained.fptrunc.nxv1f32.nxv1f64(<vscale x 1 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 1 x float> %evec
}

declare <vscale x 1 x half> @llvm.experimental.constrained.fptrunc.nxv1f16.nxv1f64(<vscale x 1 x double>, metadata, metadata)
define <vscale x 1 x half> @vfptrunc_nxv1f64_nxv1f16(<vscale x 1 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv1f64_nxv1f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, mf2, ta, ma
; CHECK-NEXT:    vfncvt.rod.f.f.w v9, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, mf4, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v8, v9
; CHECK-NEXT:    ret
  %evec = call <vscale x 1 x half> @llvm.experimental.constrained.fptrunc.nxv1f16.nxv1f64(<vscale x 1 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 1 x half> %evec
}

declare <vscale x 1 x half> @llvm.experimental.constrained.fptrunc.nxv1f16.nxv1f32(<vscale x 1 x float>, metadata, metadata)
define <vscale x 1 x half> @vfptrunc_nxv1f32_nxv1f16(<vscale x 1 x float> %va) {
; CHECK-LABEL: vfptrunc_nxv1f32_nxv1f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, mf4, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v9, v8
; CHECK-NEXT:    vmv1r.v v8, v9
; CHECK-NEXT:    ret
  %evec = call <vscale x 1 x half> @llvm.experimental.constrained.fptrunc.nxv1f16.nxv1f32(<vscale x 1 x float> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 1 x half> %evec
}

declare <vscale x 2 x float> @llvm.experimental.constrained.fptrunc.nxv2f32.nxv2f64(<vscale x 2 x double>, metadata, metadata)
define <vscale x 2 x float> @vfptrunc_nxv2f64_nxv2f32(<vscale x 2 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv2f64_nxv2f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m1, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v10, v8
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %evec = call <vscale x 2 x float> @llvm.experimental.constrained.fptrunc.nxv2f32.nxv2f64(<vscale x 2 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 2 x float> %evec
}

declare <vscale x 2 x half> @llvm.experimental.constrained.fptrunc.nxv2f16.nxv2f64(<vscale x 2 x double>, metadata, metadata)
define <vscale x 2 x half> @vfptrunc_nxv2f64_nxv2f16(<vscale x 2 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv2f64_nxv2f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m1, ta, ma
; CHECK-NEXT:    vfncvt.rod.f.f.w v10, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, mf2, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v8, v10
; CHECK-NEXT:    ret
  %evec = call <vscale x 2 x half> @llvm.experimental.constrained.fptrunc.nxv2f16.nxv2f64(<vscale x 2 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 2 x half> %evec
}

declare <vscale x 2 x half> @llvm.experimental.constrained.fptrunc.nxv2f16.nxv2f32(<vscale x 2 x float>, metadata, metadata)
define <vscale x 2 x half> @vfptrunc_nxv2f32_nxv2f16(<vscale x 2 x float> %va) {
; CHECK-LABEL: vfptrunc_nxv2f32_nxv2f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, mf2, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v9, v8
; CHECK-NEXT:    vmv1r.v v8, v9
; CHECK-NEXT:    ret
  %evec = call <vscale x 2 x half> @llvm.experimental.constrained.fptrunc.nxv2f16.nxv2f32(<vscale x 2 x float> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 2 x half> %evec
}

declare <vscale x 4 x float> @llvm.experimental.constrained.fptrunc.nxv4f32.nxv4f64(<vscale x 4 x double>, metadata, metadata)
define <vscale x 4 x float> @vfptrunc_nxv4f64_nxv4f32(<vscale x 4 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv4f64_nxv4f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m2, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v12, v8
; CHECK-NEXT:    vmv.v.v v8, v12
; CHECK-NEXT:    ret
  %evec = call <vscale x 4 x float> @llvm.experimental.constrained.fptrunc.nxv4f32.nxv4f64(<vscale x 4 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 4 x float> %evec
}

declare <vscale x 4 x half> @llvm.experimental.constrained.fptrunc.nxv4f16.nxv4f64(<vscale x 4 x double>, metadata, metadata)
define <vscale x 4 x half> @vfptrunc_nxv4f64_nxv4f16(<vscale x 4 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv4f64_nxv4f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m2, ta, ma
; CHECK-NEXT:    vfncvt.rod.f.f.w v12, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, m1, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v8, v12
; CHECK-NEXT:    ret
  %evec = call <vscale x 4 x half> @llvm.experimental.constrained.fptrunc.nxv4f16.nxv4f64(<vscale x 4 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 4 x half> %evec
}

declare <vscale x 4 x half> @llvm.experimental.constrained.fptrunc.nxv4f16.nxv4f32(<vscale x 4 x float>, metadata, metadata)
define <vscale x 4 x half> @vfptrunc_nxv4f32_nxv4f16(<vscale x 4 x float> %va) {
; CHECK-LABEL: vfptrunc_nxv4f32_nxv4f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, m1, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v10, v8
; CHECK-NEXT:    vmv.v.v v8, v10
; CHECK-NEXT:    ret
  %evec = call <vscale x 4 x half> @llvm.experimental.constrained.fptrunc.nxv4f16.nxv4f32(<vscale x 4 x float> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 4 x half> %evec
}

declare <vscale x 8 x float> @llvm.experimental.constrained.fptrunc.nxv8f32.nxv8f64(<vscale x 8 x double>, metadata, metadata)
define <vscale x 8 x float> @vfptrunc_nxv8f64_nxv8f32(<vscale x 8 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv8f64_nxv8f32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m4, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v16, v8
; CHECK-NEXT:    vmv.v.v v8, v16
; CHECK-NEXT:    ret
  %evec = call <vscale x 8 x float> @llvm.experimental.constrained.fptrunc.nxv8f32.nxv8f64(<vscale x 8 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 8 x float> %evec
}

declare <vscale x 8 x half> @llvm.experimental.constrained.fptrunc.nxv8f16.nxv8f64(<vscale x 8 x double>, metadata, metadata)
define <vscale x 8 x half> @vfptrunc_nxv8f64_nxv8f16(<vscale x 8 x double> %va) {
; CHECK-LABEL: vfptrunc_nxv8f64_nxv8f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e32, m4, ta, ma
; CHECK-NEXT:    vfncvt.rod.f.f.w v16, v8
; CHECK-NEXT:    vsetvli zero, zero, e16, m2, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v8, v16
; CHECK-NEXT:    ret
  %evec = call <vscale x 8 x half> @llvm.experimental.constrained.fptrunc.nxv8f16.nxv8f64(<vscale x 8 x double> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 8 x half> %evec
}

declare <vscale x 8 x half> @llvm.experimental.constrained.fptrunc.nxv8f16.nxv8f32(<vscale x 8 x float>, metadata, metadata)
define <vscale x 8 x half> @vfptrunc_nxv8f32_nxv8f16(<vscale x 8 x float> %va) {
; CHECK-LABEL: vfptrunc_nxv8f32_nxv8f16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetvli a0, zero, e16, m2, ta, ma
; CHECK-NEXT:    vfncvt.f.f.w v12, v8
; CHECK-NEXT:    vmv.v.v v8, v12
; CHECK-NEXT:    ret
  %evec = call <vscale x 8 x half> @llvm.experimental.constrained.fptrunc.nxv8f16.nxv8f32(<vscale x 8 x float> %va, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret <vscale x 8 x half> %evec
}
