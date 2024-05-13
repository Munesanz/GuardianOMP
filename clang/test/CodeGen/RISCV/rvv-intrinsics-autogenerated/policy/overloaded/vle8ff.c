// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -target-feature +zfh \
// RUN:   -target-feature +experimental-zvfh -disable-O0-optnone  \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, i64 } @llvm.riscv.vleff.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP1]]
//
vint8mf8_t test_vle8ff_v_i8mf8_tu(vint8mf8_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, i64 } @llvm.riscv.vleff.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP1]]
//
vint8mf4_t test_vle8ff_v_i8mf4_tu(vint8mf4_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, i64 } @llvm.riscv.vleff.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP1]]
//
vint8mf2_t test_vle8ff_v_i8mf2_tu(vint8mf2_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, i64 } @llvm.riscv.vleff.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP1]]
//
vint8m1_t test_vle8ff_v_i8m1_tu(vint8m1_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, i64 } @llvm.riscv.vleff.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP1]]
//
vint8m2_t test_vle8ff_v_i8m2_tu(vint8m2_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, i64 } @llvm.riscv.vleff.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP1]]
//
vint8m4_t test_vle8ff_v_i8m4_tu(vint8m4_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 64 x i8>, i64 } @llvm.riscv.vleff.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP1]]
//
vint8m8_t test_vle8ff_v_i8m8_tu(vint8m8_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, i64 } @llvm.riscv.vleff.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP1]]
//
vuint8mf8_t test_vle8ff_v_u8mf8_tu(vuint8mf8_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, i64 } @llvm.riscv.vleff.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP1]]
//
vuint8mf4_t test_vle8ff_v_u8mf4_tu(vuint8mf4_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, i64 } @llvm.riscv.vleff.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP1]]
//
vuint8mf2_t test_vle8ff_v_u8mf2_tu(vuint8mf2_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, i64 } @llvm.riscv.vleff.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP1]]
//
vuint8m1_t test_vle8ff_v_u8m1_tu(vuint8m1_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, i64 } @llvm.riscv.vleff.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP1]]
//
vuint8m2_t test_vle8ff_v_u8m2_tu(vuint8m2_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, i64 } @llvm.riscv.vleff.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP1]]
//
vuint8m4_t test_vle8ff_v_u8m4_tu(vuint8m4_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 64 x i8>, i64 } @llvm.riscv.vleff.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP1]]
//
vuint8m8_t test_vle8ff_v_u8m8_tu(vuint8m8_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tu(maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, i64 } @llvm.riscv.vleff.mask.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP1]]
//
vint8mf8_t test_vle8ff_v_i8mf8_tum(vbool64_t mask, vint8mf8_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, i64 } @llvm.riscv.vleff.mask.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP1]]
//
vint8mf4_t test_vle8ff_v_i8mf4_tum(vbool32_t mask, vint8mf4_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, i64 } @llvm.riscv.vleff.mask.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP1]]
//
vint8mf2_t test_vle8ff_v_i8mf2_tum(vbool16_t mask, vint8mf2_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, i64 } @llvm.riscv.vleff.mask.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP1]]
//
vint8m1_t test_vle8ff_v_i8m1_tum(vbool8_t mask, vint8m1_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, i64 } @llvm.riscv.vleff.mask.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP1]]
//
vint8m2_t test_vle8ff_v_i8m2_tum(vbool4_t mask, vint8m2_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, i64 } @llvm.riscv.vleff.mask.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP1]]
//
vint8m4_t test_vle8ff_v_i8m4_tum(vbool2_t mask, vint8m4_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 64 x i8>, i64 } @llvm.riscv.vleff.mask.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP1]]
//
vint8m8_t test_vle8ff_v_i8m8_tum(vbool1_t mask, vint8m8_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, i64 } @llvm.riscv.vleff.mask.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP1]]
//
vuint8mf8_t test_vle8ff_v_u8mf8_tum(vbool64_t mask, vuint8mf8_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, i64 } @llvm.riscv.vleff.mask.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP1]]
//
vuint8mf4_t test_vle8ff_v_u8mf4_tum(vbool32_t mask, vuint8mf4_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, i64 } @llvm.riscv.vleff.mask.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP1]]
//
vuint8mf2_t test_vle8ff_v_u8mf2_tum(vbool16_t mask, vuint8mf2_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, i64 } @llvm.riscv.vleff.mask.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP1]]
//
vuint8m1_t test_vle8ff_v_u8m1_tum(vbool8_t mask, vuint8m1_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, i64 } @llvm.riscv.vleff.mask.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP1]]
//
vuint8m2_t test_vle8ff_v_u8m2_tum(vbool4_t mask, vuint8m2_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, i64 } @llvm.riscv.vleff.mask.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP1]]
//
vuint8m4_t test_vle8ff_v_u8m4_tum(vbool2_t mask, vuint8m4_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 64 x i8>, i64 } @llvm.riscv.vleff.mask.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP1]]
//
vuint8m8_t test_vle8ff_v_u8m8_tum(vbool1_t mask, vuint8m8_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tum(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, i64 } @llvm.riscv.vleff.mask.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP1]]
//
vint8mf8_t test_vle8ff_v_i8mf8_tumu(vbool64_t mask, vint8mf8_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, i64 } @llvm.riscv.vleff.mask.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP1]]
//
vint8mf4_t test_vle8ff_v_i8mf4_tumu(vbool32_t mask, vint8mf4_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, i64 } @llvm.riscv.vleff.mask.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP1]]
//
vint8mf2_t test_vle8ff_v_i8mf2_tumu(vbool16_t mask, vint8mf2_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, i64 } @llvm.riscv.vleff.mask.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP1]]
//
vint8m1_t test_vle8ff_v_i8m1_tumu(vbool8_t mask, vint8m1_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, i64 } @llvm.riscv.vleff.mask.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP1]]
//
vint8m2_t test_vle8ff_v_i8m2_tumu(vbool4_t mask, vint8m2_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, i64 } @llvm.riscv.vleff.mask.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP1]]
//
vint8m4_t test_vle8ff_v_i8m4_tumu(vbool2_t mask, vint8m4_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_i8m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 64 x i8>, i64 } @llvm.riscv.vleff.mask.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP1]]
//
vint8m8_t test_vle8ff_v_i8m8_tumu(vbool1_t mask, vint8m8_t maskedoff, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, i64 } @llvm.riscv.vleff.mask.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP1]]
//
vuint8mf8_t test_vle8ff_v_u8mf8_tumu(vbool64_t mask, vuint8mf8_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, i64 } @llvm.riscv.vleff.mask.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP1]]
//
vuint8mf4_t test_vle8ff_v_u8mf4_tumu(vbool32_t mask, vuint8mf4_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, i64 } @llvm.riscv.vleff.mask.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP1]]
//
vuint8mf2_t test_vle8ff_v_u8mf2_tumu(vbool16_t mask, vuint8mf2_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, i64 } @llvm.riscv.vleff.mask.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP1]]
//
vuint8m1_t test_vle8ff_v_u8m1_tumu(vbool8_t mask, vuint8m1_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, i64 } @llvm.riscv.vleff.mask.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP1]]
//
vuint8m2_t test_vle8ff_v_u8m2_tumu(vbool4_t mask, vuint8m2_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, i64 } @llvm.riscv.vleff.mask.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP1]]
//
vuint8m4_t test_vle8ff_v_u8m4_tumu(vbool2_t mask, vuint8m4_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vle8ff_v_u8m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 64 x i8>, i64 } @llvm.riscv.vleff.mask.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], ptr [[BASE:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 64 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store i64 [[TMP2]], ptr [[NEW_VL:%.*]], align 8
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP1]]
//
vuint8m8_t test_vle8ff_v_u8m8_tumu(vbool1_t mask, vuint8m8_t maskedoff, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vle8ff_tumu(mask, maskedoff, base, new_vl, vl);
}

