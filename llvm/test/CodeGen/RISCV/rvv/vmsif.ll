; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: sed 's/iXLen/i32/g' %s | llc -mtriple=riscv32 -mattr=+v \
; RUN:   -verify-machineinstrs | FileCheck %s
; RUN: sed 's/iXLen/i64/g' %s | llc -mtriple=riscv64 -mattr=+v \
; RUN:   -verify-machineinstrs | FileCheck %s
declare <vscale x 1 x i1> @llvm.riscv.vmsif.nxv1i1(
  <vscale x 1 x i1>,
  iXLen);

define <vscale x 1 x i1> @intrinsic_vmsif_m_nxv1i1(<vscale x 1 x i1> %0, iXLen %1) nounwind {
; CHECK-LABEL: intrinsic_vmsif_m_nxv1i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vsetvli zero, a0, e8, mf8, ta, ma
; CHECK-NEXT:    vmsif.m v8, v0
; CHECK-NEXT:    vmv1r.v v0, v8
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 1 x i1> @llvm.riscv.vmsif.nxv1i1(
    <vscale x 1 x i1> %0,
    iXLen %1)
  ret <vscale x 1 x i1> %a
}

declare <vscale x 1 x i1> @llvm.riscv.vmsif.mask.nxv1i1(
  <vscale x 1 x i1>,
  <vscale x 1 x i1>,
  <vscale x 1 x i1>,
  iXLen);

define <vscale x 1 x i1> @intrinsic_vmsif_mask_m_nxv1i1_nxv1i1(<vscale x 1 x i1> %0, <vscale x 1 x i1> %1, <vscale x 1 x i1> %2, iXLen %3) nounwind {
; CHECK-LABEL: intrinsic_vmsif_mask_m_nxv1i1_nxv1i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vmv1r.v v10, v0
; CHECK-NEXT:    vsetvli zero, a0, e8, mf8, tu, mu
; CHECK-NEXT:    vmv1r.v v0, v9
; CHECK-NEXT:    vmsif.m v10, v8, v0.t
; CHECK-NEXT:    vmv1r.v v0, v10
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 1 x i1> @llvm.riscv.vmsif.mask.nxv1i1(
    <vscale x 1 x i1> %0,
    <vscale x 1 x i1> %1,
    <vscale x 1 x i1> %2,
    iXLen %3)
  ret <vscale x 1 x i1> %a
}

declare <vscale x 2 x i1> @llvm.riscv.vmsif.nxv2i1(
  <vscale x 2 x i1>,
  iXLen);

define <vscale x 2 x i1> @intrinsic_vmsif_m_nxv2i1(<vscale x 2 x i1> %0, iXLen %1) nounwind {
; CHECK-LABEL: intrinsic_vmsif_m_nxv2i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vsetvli zero, a0, e8, mf4, ta, ma
; CHECK-NEXT:    vmsif.m v8, v0
; CHECK-NEXT:    vmv1r.v v0, v8
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 2 x i1> @llvm.riscv.vmsif.nxv2i1(
    <vscale x 2 x i1> %0,
    iXLen %1)
  ret <vscale x 2 x i1> %a
}

declare <vscale x 2 x i1> @llvm.riscv.vmsif.mask.nxv2i1(
  <vscale x 2 x i1>,
  <vscale x 2 x i1>,
  <vscale x 2 x i1>,
  iXLen);

define <vscale x 2 x i1> @intrinsic_vmsif_mask_m_nxv2i1_nxv2i1(<vscale x 2 x i1> %0, <vscale x 2 x i1> %1, <vscale x 2 x i1> %2, iXLen %3) nounwind {
; CHECK-LABEL: intrinsic_vmsif_mask_m_nxv2i1_nxv2i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vmv1r.v v10, v0
; CHECK-NEXT:    vsetvli zero, a0, e8, mf4, tu, mu
; CHECK-NEXT:    vmv1r.v v0, v9
; CHECK-NEXT:    vmsif.m v10, v8, v0.t
; CHECK-NEXT:    vmv1r.v v0, v10
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 2 x i1> @llvm.riscv.vmsif.mask.nxv2i1(
    <vscale x 2 x i1> %0,
    <vscale x 2 x i1> %1,
    <vscale x 2 x i1> %2,
    iXLen %3)
  ret <vscale x 2 x i1> %a
}

declare <vscale x 4 x i1> @llvm.riscv.vmsif.nxv4i1(
  <vscale x 4 x i1>,
  iXLen);

define <vscale x 4 x i1> @intrinsic_vmsif_m_nxv4i1(<vscale x 4 x i1> %0, iXLen %1) nounwind {
; CHECK-LABEL: intrinsic_vmsif_m_nxv4i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vsetvli zero, a0, e8, mf2, ta, ma
; CHECK-NEXT:    vmsif.m v8, v0
; CHECK-NEXT:    vmv1r.v v0, v8
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 4 x i1> @llvm.riscv.vmsif.nxv4i1(
    <vscale x 4 x i1> %0,
    iXLen %1)
  ret <vscale x 4 x i1> %a
}

declare <vscale x 4 x i1> @llvm.riscv.vmsif.mask.nxv4i1(
  <vscale x 4 x i1>,
  <vscale x 4 x i1>,
  <vscale x 4 x i1>,
  iXLen);

define <vscale x 4 x i1> @intrinsic_vmsif_mask_m_nxv4i1_nxv4i1(<vscale x 4 x i1> %0, <vscale x 4 x i1> %1, <vscale x 4 x i1> %2, iXLen %3) nounwind {
; CHECK-LABEL: intrinsic_vmsif_mask_m_nxv4i1_nxv4i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vmv1r.v v10, v0
; CHECK-NEXT:    vsetvli zero, a0, e8, mf2, tu, mu
; CHECK-NEXT:    vmv1r.v v0, v9
; CHECK-NEXT:    vmsif.m v10, v8, v0.t
; CHECK-NEXT:    vmv1r.v v0, v10
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 4 x i1> @llvm.riscv.vmsif.mask.nxv4i1(
    <vscale x 4 x i1> %0,
    <vscale x 4 x i1> %1,
    <vscale x 4 x i1> %2,
    iXLen %3)
  ret <vscale x 4 x i1> %a
}

declare <vscale x 8 x i1> @llvm.riscv.vmsif.nxv8i1(
  <vscale x 8 x i1>,
  iXLen);

define <vscale x 8 x i1> @intrinsic_vmsif_m_nxv8i1(<vscale x 8 x i1> %0, iXLen %1) nounwind {
; CHECK-LABEL: intrinsic_vmsif_m_nxv8i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vsetvli zero, a0, e8, m1, ta, ma
; CHECK-NEXT:    vmsif.m v8, v0
; CHECK-NEXT:    vmv.v.v v0, v8
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 8 x i1> @llvm.riscv.vmsif.nxv8i1(
    <vscale x 8 x i1> %0,
    iXLen %1)
  ret <vscale x 8 x i1> %a
}

declare <vscale x 8 x i1> @llvm.riscv.vmsif.mask.nxv8i1(
  <vscale x 8 x i1>,
  <vscale x 8 x i1>,
  <vscale x 8 x i1>,
  iXLen);

define <vscale x 8 x i1> @intrinsic_vmsif_mask_m_nxv8i1_nxv8i1(<vscale x 8 x i1> %0, <vscale x 8 x i1> %1, <vscale x 8 x i1> %2, iXLen %3) nounwind {
; CHECK-LABEL: intrinsic_vmsif_mask_m_nxv8i1_nxv8i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vmv1r.v v10, v0
; CHECK-NEXT:    vsetvli zero, a0, e8, m1, tu, mu
; CHECK-NEXT:    vmv1r.v v0, v9
; CHECK-NEXT:    vmsif.m v10, v8, v0.t
; CHECK-NEXT:    vmv1r.v v0, v10
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 8 x i1> @llvm.riscv.vmsif.mask.nxv8i1(
    <vscale x 8 x i1> %0,
    <vscale x 8 x i1> %1,
    <vscale x 8 x i1> %2,
    iXLen %3)
  ret <vscale x 8 x i1> %a
}

declare <vscale x 16 x i1> @llvm.riscv.vmsif.nxv16i1(
  <vscale x 16 x i1>,
  iXLen);

define <vscale x 16 x i1> @intrinsic_vmsif_m_nxv16i1(<vscale x 16 x i1> %0, iXLen %1) nounwind {
; CHECK-LABEL: intrinsic_vmsif_m_nxv16i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vsetvli zero, a0, e8, m2, ta, ma
; CHECK-NEXT:    vmsif.m v8, v0
; CHECK-NEXT:    vmv1r.v v0, v8
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 16 x i1> @llvm.riscv.vmsif.nxv16i1(
    <vscale x 16 x i1> %0,
    iXLen %1)
  ret <vscale x 16 x i1> %a
}

declare <vscale x 16 x i1> @llvm.riscv.vmsif.mask.nxv16i1(
  <vscale x 16 x i1>,
  <vscale x 16 x i1>,
  <vscale x 16 x i1>,
  iXLen);

define <vscale x 16 x i1> @intrinsic_vmsif_mask_m_nxv16i1_nxv16i1(<vscale x 16 x i1> %0, <vscale x 16 x i1> %1, <vscale x 16 x i1> %2, iXLen %3) nounwind {
; CHECK-LABEL: intrinsic_vmsif_mask_m_nxv16i1_nxv16i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vmv1r.v v10, v0
; CHECK-NEXT:    vsetvli zero, a0, e8, m2, tu, mu
; CHECK-NEXT:    vmv1r.v v0, v9
; CHECK-NEXT:    vmsif.m v10, v8, v0.t
; CHECK-NEXT:    vmv1r.v v0, v10
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 16 x i1> @llvm.riscv.vmsif.mask.nxv16i1(
    <vscale x 16 x i1> %0,
    <vscale x 16 x i1> %1,
    <vscale x 16 x i1> %2,
    iXLen %3)
  ret <vscale x 16 x i1> %a
}

declare <vscale x 32 x i1> @llvm.riscv.vmsif.nxv32i1(
  <vscale x 32 x i1>,
  iXLen);

define <vscale x 32 x i1> @intrinsic_vmsif_m_nxv32i1(<vscale x 32 x i1> %0, iXLen %1) nounwind {
; CHECK-LABEL: intrinsic_vmsif_m_nxv32i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vsetvli zero, a0, e8, m4, ta, ma
; CHECK-NEXT:    vmsif.m v8, v0
; CHECK-NEXT:    vmv1r.v v0, v8
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 32 x i1> @llvm.riscv.vmsif.nxv32i1(
    <vscale x 32 x i1> %0,
    iXLen %1)
  ret <vscale x 32 x i1> %a
}

declare <vscale x 32 x i1> @llvm.riscv.vmsif.mask.nxv32i1(
  <vscale x 32 x i1>,
  <vscale x 32 x i1>,
  <vscale x 32 x i1>,
  iXLen);

define <vscale x 32 x i1> @intrinsic_vmsif_mask_m_nxv32i1_nxv32i1(<vscale x 32 x i1> %0, <vscale x 32 x i1> %1, <vscale x 32 x i1> %2, iXLen %3) nounwind {
; CHECK-LABEL: intrinsic_vmsif_mask_m_nxv32i1_nxv32i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vmv1r.v v10, v0
; CHECK-NEXT:    vsetvli zero, a0, e8, m4, tu, mu
; CHECK-NEXT:    vmv1r.v v0, v9
; CHECK-NEXT:    vmsif.m v10, v8, v0.t
; CHECK-NEXT:    vmv1r.v v0, v10
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 32 x i1> @llvm.riscv.vmsif.mask.nxv32i1(
    <vscale x 32 x i1> %0,
    <vscale x 32 x i1> %1,
    <vscale x 32 x i1> %2,
    iXLen %3)
  ret <vscale x 32 x i1> %a
}

declare <vscale x 64 x i1> @llvm.riscv.vmsif.nxv64i1(
  <vscale x 64 x i1>,
  iXLen);

define <vscale x 64 x i1> @intrinsic_vmsif_m_nxv64i1(<vscale x 64 x i1> %0, iXLen %1) nounwind {
; CHECK-LABEL: intrinsic_vmsif_m_nxv64i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vsetvli zero, a0, e8, m8, ta, ma
; CHECK-NEXT:    vmsif.m v8, v0
; CHECK-NEXT:    vmv1r.v v0, v8
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 64 x i1> @llvm.riscv.vmsif.nxv64i1(
    <vscale x 64 x i1> %0,
    iXLen %1)
  ret <vscale x 64 x i1> %a
}

declare <vscale x 64 x i1> @llvm.riscv.vmsif.mask.nxv64i1(
  <vscale x 64 x i1>,
  <vscale x 64 x i1>,
  <vscale x 64 x i1>,
  iXLen);

define <vscale x 64 x i1> @intrinsic_vmsif_mask_m_nxv64i1_nxv64i1(<vscale x 64 x i1> %0, <vscale x 64 x i1> %1, <vscale x 64 x i1> %2, iXLen %3) nounwind {
; CHECK-LABEL: intrinsic_vmsif_mask_m_nxv64i1_nxv64i1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vmv1r.v v10, v0
; CHECK-NEXT:    vsetvli zero, a0, e8, m8, tu, mu
; CHECK-NEXT:    vmv1r.v v0, v9
; CHECK-NEXT:    vmsif.m v10, v8, v0.t
; CHECK-NEXT:    vmv1r.v v0, v10
; CHECK-NEXT:    ret
entry:
  %a = call <vscale x 64 x i1> @llvm.riscv.vmsif.mask.nxv64i1(
    <vscale x 64 x i1> %0,
    <vscale x 64 x i1> %1,
    <vscale x 64 x i1> %2,
    iXLen %3)
  ret <vscale x 64 x i1> %a
}
