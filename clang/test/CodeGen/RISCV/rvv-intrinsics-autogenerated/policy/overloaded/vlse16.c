// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -target-feature +zfh \
// RUN:   -target-feature +experimental-zvfh -disable-O0-optnone  \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vlse16_v_f16mf4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x half> @llvm.riscv.vlse.nxv1f16.i64(<vscale x 1 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x half> [[TMP0]]
//
vfloat16mf4_t test_vlse16_v_f16mf4_tu(vfloat16mf4_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x half> @llvm.riscv.vlse.nxv2f16.i64(<vscale x 2 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x half> [[TMP0]]
//
vfloat16mf2_t test_vlse16_v_f16mf2_tu(vfloat16mf2_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x half> @llvm.riscv.vlse.nxv4f16.i64(<vscale x 4 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x half> [[TMP0]]
//
vfloat16m1_t test_vlse16_v_f16m1_tu(vfloat16m1_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x half> @llvm.riscv.vlse.nxv8f16.i64(<vscale x 8 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x half> [[TMP0]]
//
vfloat16m2_t test_vlse16_v_f16m2_tu(vfloat16m2_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x half> @llvm.riscv.vlse.nxv16f16.i64(<vscale x 16 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x half> [[TMP0]]
//
vfloat16m4_t test_vlse16_v_f16m4_tu(vfloat16m4_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x half> @llvm.riscv.vlse.nxv32f16.i64(<vscale x 32 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x half> [[TMP0]]
//
vfloat16m8_t test_vlse16_v_f16m8_tu(vfloat16m8_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16mf4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vlse.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vint16mf4_t test_vlse16_v_i16mf4_tu(vint16mf4_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vlse.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vint16mf2_t test_vlse16_v_i16mf2_tu(vint16mf2_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vlse.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vint16m1_t test_vlse16_v_i16m1_tu(vint16m1_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vlse.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vint16m2_t test_vlse16_v_i16m2_tu(vint16m2_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vlse.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vint16m4_t test_vlse16_v_i16m4_tu(vint16m4_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vlse.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vint16m8_t test_vlse16_v_i16m8_tu(vint16m8_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16mf4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vlse.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vuint16mf4_t test_vlse16_v_u16mf4_tu(vuint16mf4_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vlse.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vuint16mf2_t test_vlse16_v_u16mf2_tu(vuint16mf2_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vlse.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vuint16m1_t test_vlse16_v_u16m1_tu(vuint16m1_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vlse.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vuint16m2_t test_vlse16_v_u16m2_tu(vuint16m2_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vlse.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vuint16m4_t test_vlse16_v_u16m4_tu(vuint16m4_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vlse.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vuint16m8_t test_vlse16_v_u16m8_tu(vuint16m8_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tu(maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16mf4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x half> @llvm.riscv.vlse.mask.nxv1f16.i64(<vscale x 1 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 1 x half> [[TMP0]]
//
vfloat16mf4_t test_vlse16_v_f16mf4_tum(vbool64_t mask, vfloat16mf4_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x half> @llvm.riscv.vlse.mask.nxv2f16.i64(<vscale x 2 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 2 x half> [[TMP0]]
//
vfloat16mf2_t test_vlse16_v_f16mf2_tum(vbool32_t mask, vfloat16mf2_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x half> @llvm.riscv.vlse.mask.nxv4f16.i64(<vscale x 4 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 4 x half> [[TMP0]]
//
vfloat16m1_t test_vlse16_v_f16m1_tum(vbool16_t mask, vfloat16m1_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x half> @llvm.riscv.vlse.mask.nxv8f16.i64(<vscale x 8 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 8 x half> [[TMP0]]
//
vfloat16m2_t test_vlse16_v_f16m2_tum(vbool8_t mask, vfloat16m2_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x half> @llvm.riscv.vlse.mask.nxv16f16.i64(<vscale x 16 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 16 x half> [[TMP0]]
//
vfloat16m4_t test_vlse16_v_f16m4_tum(vbool4_t mask, vfloat16m4_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x half> @llvm.riscv.vlse.mask.nxv32f16.i64(<vscale x 32 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 32 x half> [[TMP0]]
//
vfloat16m8_t test_vlse16_v_f16m8_tum(vbool2_t mask, vfloat16m8_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16mf4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vlse.mask.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vint16mf4_t test_vlse16_v_i16mf4_tum(vbool64_t mask, vint16mf4_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vlse.mask.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vint16mf2_t test_vlse16_v_i16mf2_tum(vbool32_t mask, vint16mf2_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vlse.mask.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vint16m1_t test_vlse16_v_i16m1_tum(vbool16_t mask, vint16m1_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vlse.mask.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vint16m2_t test_vlse16_v_i16m2_tum(vbool8_t mask, vint16m2_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vlse.mask.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vint16m4_t test_vlse16_v_i16m4_tum(vbool4_t mask, vint16m4_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vlse.mask.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vint16m8_t test_vlse16_v_i16m8_tum(vbool2_t mask, vint16m8_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16mf4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vlse.mask.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vuint16mf4_t test_vlse16_v_u16mf4_tum(vbool64_t mask, vuint16mf4_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vlse.mask.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vuint16mf2_t test_vlse16_v_u16mf2_tum(vbool32_t mask, vuint16mf2_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vlse.mask.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vuint16m1_t test_vlse16_v_u16m1_tum(vbool16_t mask, vuint16m1_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vlse.mask.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vuint16m2_t test_vlse16_v_u16m2_tum(vbool8_t mask, vuint16m2_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vlse.mask.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vuint16m4_t test_vlse16_v_u16m4_tum(vbool4_t mask, vuint16m4_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vlse.mask.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vuint16m8_t test_vlse16_v_u16m8_tum(vbool2_t mask, vuint16m8_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tum(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16mf4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x half> @llvm.riscv.vlse.mask.nxv1f16.i64(<vscale x 1 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 1 x half> [[TMP0]]
//
vfloat16mf4_t test_vlse16_v_f16mf4_tumu(vbool64_t mask, vfloat16mf4_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x half> @llvm.riscv.vlse.mask.nxv2f16.i64(<vscale x 2 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 2 x half> [[TMP0]]
//
vfloat16mf2_t test_vlse16_v_f16mf2_tumu(vbool32_t mask, vfloat16mf2_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x half> @llvm.riscv.vlse.mask.nxv4f16.i64(<vscale x 4 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 4 x half> [[TMP0]]
//
vfloat16m1_t test_vlse16_v_f16m1_tumu(vbool16_t mask, vfloat16m1_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x half> @llvm.riscv.vlse.mask.nxv8f16.i64(<vscale x 8 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 8 x half> [[TMP0]]
//
vfloat16m2_t test_vlse16_v_f16m2_tumu(vbool8_t mask, vfloat16m2_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x half> @llvm.riscv.vlse.mask.nxv16f16.i64(<vscale x 16 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 16 x half> [[TMP0]]
//
vfloat16m4_t test_vlse16_v_f16m4_tumu(vbool4_t mask, vfloat16m4_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_f16m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x half> @llvm.riscv.vlse.mask.nxv32f16.i64(<vscale x 32 x half> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 32 x half> [[TMP0]]
//
vfloat16m8_t test_vlse16_v_f16m8_tumu(vbool2_t mask, vfloat16m8_t maskedoff, const _Float16 *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16mf4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vlse.mask.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vint16mf4_t test_vlse16_v_i16mf4_tumu(vbool64_t mask, vint16mf4_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vlse.mask.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vint16mf2_t test_vlse16_v_i16mf2_tumu(vbool32_t mask, vint16mf2_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vlse.mask.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vint16m1_t test_vlse16_v_i16m1_tumu(vbool16_t mask, vint16m1_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vlse.mask.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vint16m2_t test_vlse16_v_i16m2_tumu(vbool8_t mask, vint16m2_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vlse.mask.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vint16m4_t test_vlse16_v_i16m4_tumu(vbool4_t mask, vint16m4_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_i16m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vlse.mask.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vint16m8_t test_vlse16_v_i16m8_tumu(vbool2_t mask, vint16m8_t maskedoff, const int16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16mf4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vlse.mask.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vuint16mf4_t test_vlse16_v_u16mf4_tumu(vbool64_t mask, vuint16mf4_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vlse.mask.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vuint16mf2_t test_vlse16_v_u16mf2_tumu(vbool32_t mask, vuint16mf2_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vlse.mask.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vuint16m1_t test_vlse16_v_u16m1_tumu(vbool16_t mask, vuint16m1_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vlse.mask.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vuint16m2_t test_vlse16_v_u16m2_tumu(vbool8_t mask, vuint16m2_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vlse.mask.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vuint16m4_t test_vlse16_v_u16m4_tumu(vbool4_t mask, vuint16m4_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlse16_v_u16m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vlse.mask.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vuint16m8_t test_vlse16_v_u16m8_tumu(vbool2_t mask, vuint16m8_t maskedoff, const uint16_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlse16_tumu(mask, maskedoff, base, bstride, vl);
}

