// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -target-feature +zfh \
// RUN:   -target-feature +experimental-zvfh -disable-O0-optnone  \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vmslt_vv_i8mf8_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i8.nxv1i8.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i8> [[OP1:%.*]], <vscale x 1 x i8> [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vv_i8mf8_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint8mf8_t op1, vint8mf8_t op2, size_t vl) {
  return __riscv_vmslt_vv_i8mf8_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i8mf8_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i8.i8.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i8> [[OP1:%.*]], i8 [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vx_i8mf8_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint8mf8_t op1, int8_t op2, size_t vl) {
  return __riscv_vmslt_vx_i8mf8_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i8mf4_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i8.nxv2i8.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i8> [[OP1:%.*]], <vscale x 2 x i8> [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vv_i8mf4_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint8mf4_t op1, vint8mf4_t op2, size_t vl) {
  return __riscv_vmslt_vv_i8mf4_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i8mf4_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i8.i8.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i8> [[OP1:%.*]], i8 [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vx_i8mf4_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint8mf4_t op1, int8_t op2, size_t vl) {
  return __riscv_vmslt_vx_i8mf4_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i8mf2_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i8.nxv4i8.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i8> [[OP1:%.*]], <vscale x 4 x i8> [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vv_i8mf2_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint8mf2_t op1, vint8mf2_t op2, size_t vl) {
  return __riscv_vmslt_vv_i8mf2_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i8mf2_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i8.i8.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i8> [[OP1:%.*]], i8 [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vx_i8mf2_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint8mf2_t op1, int8_t op2, size_t vl) {
  return __riscv_vmslt_vx_i8mf2_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i8m1_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i8.nxv8i8.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i8> [[OP1:%.*]], <vscale x 8 x i8> [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vv_i8m1_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint8m1_t op1, vint8m1_t op2, size_t vl) {
  return __riscv_vmslt_vv_i8m1_b8_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i8m1_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i8.i8.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i8> [[OP1:%.*]], i8 [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vx_i8m1_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint8m1_t op1, int8_t op2, size_t vl) {
  return __riscv_vmslt_vx_i8m1_b8_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i8m2_b4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i1> @llvm.riscv.vmslt.mask.nxv16i8.nxv16i8.i64(<vscale x 16 x i1> [[MASKEDOFF:%.*]], <vscale x 16 x i8> [[OP1:%.*]], <vscale x 16 x i8> [[OP2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
vbool4_t test_vmslt_vv_i8m2_b4_mu(vbool4_t mask, vbool4_t maskedoff, vint8m2_t op1, vint8m2_t op2, size_t vl) {
  return __riscv_vmslt_vv_i8m2_b4_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i8m2_b4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i1> @llvm.riscv.vmslt.mask.nxv16i8.i8.i64(<vscale x 16 x i1> [[MASKEDOFF:%.*]], <vscale x 16 x i8> [[OP1:%.*]], i8 [[OP2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
vbool4_t test_vmslt_vx_i8m2_b4_mu(vbool4_t mask, vbool4_t maskedoff, vint8m2_t op1, int8_t op2, size_t vl) {
  return __riscv_vmslt_vx_i8m2_b4_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i8m4_b2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i1> @llvm.riscv.vmslt.mask.nxv32i8.nxv32i8.i64(<vscale x 32 x i1> [[MASKEDOFF:%.*]], <vscale x 32 x i8> [[OP1:%.*]], <vscale x 32 x i8> [[OP2:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i1> [[TMP0]]
//
vbool2_t test_vmslt_vv_i8m4_b2_mu(vbool2_t mask, vbool2_t maskedoff, vint8m4_t op1, vint8m4_t op2, size_t vl) {
  return __riscv_vmslt_vv_i8m4_b2_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i8m4_b2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i1> @llvm.riscv.vmslt.mask.nxv32i8.i8.i64(<vscale x 32 x i1> [[MASKEDOFF:%.*]], <vscale x 32 x i8> [[OP1:%.*]], i8 [[OP2:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i1> [[TMP0]]
//
vbool2_t test_vmslt_vx_i8m4_b2_mu(vbool2_t mask, vbool2_t maskedoff, vint8m4_t op1, int8_t op2, size_t vl) {
  return __riscv_vmslt_vx_i8m4_b2_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i8m8_b1_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 64 x i1> @llvm.riscv.vmslt.mask.nxv64i8.nxv64i8.i64(<vscale x 64 x i1> [[MASKEDOFF:%.*]], <vscale x 64 x i8> [[OP1:%.*]], <vscale x 64 x i8> [[OP2:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 64 x i1> [[TMP0]]
//
vbool1_t test_vmslt_vv_i8m8_b1_mu(vbool1_t mask, vbool1_t maskedoff, vint8m8_t op1, vint8m8_t op2, size_t vl) {
  return __riscv_vmslt_vv_i8m8_b1_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i8m8_b1_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 64 x i1> @llvm.riscv.vmslt.mask.nxv64i8.i8.i64(<vscale x 64 x i1> [[MASKEDOFF:%.*]], <vscale x 64 x i8> [[OP1:%.*]], i8 [[OP2:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 64 x i1> [[TMP0]]
//
vbool1_t test_vmslt_vx_i8m8_b1_mu(vbool1_t mask, vbool1_t maskedoff, vint8m8_t op1, int8_t op2, size_t vl) {
  return __riscv_vmslt_vx_i8m8_b1_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i16mf4_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i16.nxv1i16.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i16> [[OP1:%.*]], <vscale x 1 x i16> [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vv_i16mf4_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint16mf4_t op1, vint16mf4_t op2, size_t vl) {
  return __riscv_vmslt_vv_i16mf4_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i16mf4_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i16.i16.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i16> [[OP1:%.*]], i16 [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vx_i16mf4_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint16mf4_t op1, int16_t op2, size_t vl) {
  return __riscv_vmslt_vx_i16mf4_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i16mf2_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i16.nxv2i16.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i16> [[OP1:%.*]], <vscale x 2 x i16> [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vv_i16mf2_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint16mf2_t op1, vint16mf2_t op2, size_t vl) {
  return __riscv_vmslt_vv_i16mf2_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i16mf2_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i16.i16.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i16> [[OP1:%.*]], i16 [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vx_i16mf2_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint16mf2_t op1, int16_t op2, size_t vl) {
  return __riscv_vmslt_vx_i16mf2_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i16m1_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i16.nxv4i16.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i16> [[OP1:%.*]], <vscale x 4 x i16> [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vv_i16m1_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint16m1_t op1, vint16m1_t op2, size_t vl) {
  return __riscv_vmslt_vv_i16m1_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i16m1_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i16.i16.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i16> [[OP1:%.*]], i16 [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vx_i16m1_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint16m1_t op1, int16_t op2, size_t vl) {
  return __riscv_vmslt_vx_i16m1_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i16m2_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i16.nxv8i16.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i16> [[OP1:%.*]], <vscale x 8 x i16> [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vv_i16m2_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint16m2_t op1, vint16m2_t op2, size_t vl) {
  return __riscv_vmslt_vv_i16m2_b8_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i16m2_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i16.i16.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i16> [[OP1:%.*]], i16 [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vx_i16m2_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint16m2_t op1, int16_t op2, size_t vl) {
  return __riscv_vmslt_vx_i16m2_b8_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i16m4_b4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i1> @llvm.riscv.vmslt.mask.nxv16i16.nxv16i16.i64(<vscale x 16 x i1> [[MASKEDOFF:%.*]], <vscale x 16 x i16> [[OP1:%.*]], <vscale x 16 x i16> [[OP2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
vbool4_t test_vmslt_vv_i16m4_b4_mu(vbool4_t mask, vbool4_t maskedoff, vint16m4_t op1, vint16m4_t op2, size_t vl) {
  return __riscv_vmslt_vv_i16m4_b4_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i16m4_b4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i1> @llvm.riscv.vmslt.mask.nxv16i16.i16.i64(<vscale x 16 x i1> [[MASKEDOFF:%.*]], <vscale x 16 x i16> [[OP1:%.*]], i16 [[OP2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
vbool4_t test_vmslt_vx_i16m4_b4_mu(vbool4_t mask, vbool4_t maskedoff, vint16m4_t op1, int16_t op2, size_t vl) {
  return __riscv_vmslt_vx_i16m4_b4_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i16m8_b2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i1> @llvm.riscv.vmslt.mask.nxv32i16.nxv32i16.i64(<vscale x 32 x i1> [[MASKEDOFF:%.*]], <vscale x 32 x i16> [[OP1:%.*]], <vscale x 32 x i16> [[OP2:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i1> [[TMP0]]
//
vbool2_t test_vmslt_vv_i16m8_b2_mu(vbool2_t mask, vbool2_t maskedoff, vint16m8_t op1, vint16m8_t op2, size_t vl) {
  return __riscv_vmslt_vv_i16m8_b2_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i16m8_b2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i1> @llvm.riscv.vmslt.mask.nxv32i16.i16.i64(<vscale x 32 x i1> [[MASKEDOFF:%.*]], <vscale x 32 x i16> [[OP1:%.*]], i16 [[OP2:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i1> [[TMP0]]
//
vbool2_t test_vmslt_vx_i16m8_b2_mu(vbool2_t mask, vbool2_t maskedoff, vint16m8_t op1, int16_t op2, size_t vl) {
  return __riscv_vmslt_vx_i16m8_b2_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i32mf2_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i32.nxv1i32.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i32> [[OP1:%.*]], <vscale x 1 x i32> [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vv_i32mf2_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint32mf2_t op1, vint32mf2_t op2, size_t vl) {
  return __riscv_vmslt_vv_i32mf2_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i32mf2_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i32.i32.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i32> [[OP1:%.*]], i32 [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vx_i32mf2_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint32mf2_t op1, int32_t op2, size_t vl) {
  return __riscv_vmslt_vx_i32mf2_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i32m1_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i32.nxv2i32.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i32> [[OP1:%.*]], <vscale x 2 x i32> [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vv_i32m1_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint32m1_t op1, vint32m1_t op2, size_t vl) {
  return __riscv_vmslt_vv_i32m1_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i32m1_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i32.i32.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i32> [[OP1:%.*]], i32 [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vx_i32m1_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint32m1_t op1, int32_t op2, size_t vl) {
  return __riscv_vmslt_vx_i32m1_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i32m2_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i32.nxv4i32.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i32> [[OP1:%.*]], <vscale x 4 x i32> [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vv_i32m2_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint32m2_t op1, vint32m2_t op2, size_t vl) {
  return __riscv_vmslt_vv_i32m2_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i32m2_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i32.i32.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i32> [[OP1:%.*]], i32 [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vx_i32m2_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint32m2_t op1, int32_t op2, size_t vl) {
  return __riscv_vmslt_vx_i32m2_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i32m4_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i32.nxv8i32.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i32> [[OP1:%.*]], <vscale x 8 x i32> [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vv_i32m4_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint32m4_t op1, vint32m4_t op2, size_t vl) {
  return __riscv_vmslt_vv_i32m4_b8_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i32m4_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i32.i32.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i32> [[OP1:%.*]], i32 [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vx_i32m4_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint32m4_t op1, int32_t op2, size_t vl) {
  return __riscv_vmslt_vx_i32m4_b8_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i32m8_b4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i1> @llvm.riscv.vmslt.mask.nxv16i32.nxv16i32.i64(<vscale x 16 x i1> [[MASKEDOFF:%.*]], <vscale x 16 x i32> [[OP1:%.*]], <vscale x 16 x i32> [[OP2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
vbool4_t test_vmslt_vv_i32m8_b4_mu(vbool4_t mask, vbool4_t maskedoff, vint32m8_t op1, vint32m8_t op2, size_t vl) {
  return __riscv_vmslt_vv_i32m8_b4_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i32m8_b4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i1> @llvm.riscv.vmslt.mask.nxv16i32.i32.i64(<vscale x 16 x i1> [[MASKEDOFF:%.*]], <vscale x 16 x i32> [[OP1:%.*]], i32 [[OP2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
vbool4_t test_vmslt_vx_i32m8_b4_mu(vbool4_t mask, vbool4_t maskedoff, vint32m8_t op1, int32_t op2, size_t vl) {
  return __riscv_vmslt_vx_i32m8_b4_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i64m1_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i64.nxv1i64.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i64> [[OP1:%.*]], <vscale x 1 x i64> [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vv_i64m1_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint64m1_t op1, vint64m1_t op2, size_t vl) {
  return __riscv_vmslt_vv_i64m1_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i64m1_b64_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i1> @llvm.riscv.vmslt.mask.nxv1i64.i64.i64(<vscale x 1 x i1> [[MASKEDOFF:%.*]], <vscale x 1 x i64> [[OP1:%.*]], i64 [[OP2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i1> [[TMP0]]
//
vbool64_t test_vmslt_vx_i64m1_b64_mu(vbool64_t mask, vbool64_t maskedoff, vint64m1_t op1, int64_t op2, size_t vl) {
  return __riscv_vmslt_vx_i64m1_b64_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i64m2_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i64.nxv2i64.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i64> [[OP1:%.*]], <vscale x 2 x i64> [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vv_i64m2_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint64m2_t op1, vint64m2_t op2, size_t vl) {
  return __riscv_vmslt_vv_i64m2_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i64m2_b32_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i1> @llvm.riscv.vmslt.mask.nxv2i64.i64.i64(<vscale x 2 x i1> [[MASKEDOFF:%.*]], <vscale x 2 x i64> [[OP1:%.*]], i64 [[OP2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i1> [[TMP0]]
//
vbool32_t test_vmslt_vx_i64m2_b32_mu(vbool32_t mask, vbool32_t maskedoff, vint64m2_t op1, int64_t op2, size_t vl) {
  return __riscv_vmslt_vx_i64m2_b32_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i64m4_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i64.nxv4i64.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i64> [[OP1:%.*]], <vscale x 4 x i64> [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vv_i64m4_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint64m4_t op1, vint64m4_t op2, size_t vl) {
  return __riscv_vmslt_vv_i64m4_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i64m4_b16_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i1> @llvm.riscv.vmslt.mask.nxv4i64.i64.i64(<vscale x 4 x i1> [[MASKEDOFF:%.*]], <vscale x 4 x i64> [[OP1:%.*]], i64 [[OP2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i1> [[TMP0]]
//
vbool16_t test_vmslt_vx_i64m4_b16_mu(vbool16_t mask, vbool16_t maskedoff, vint64m4_t op1, int64_t op2, size_t vl) {
  return __riscv_vmslt_vx_i64m4_b16_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vv_i64m8_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i64.nxv8i64.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i64> [[OP1:%.*]], <vscale x 8 x i64> [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vv_i64m8_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint64m8_t op1, vint64m8_t op2, size_t vl) {
  return __riscv_vmslt_vv_i64m8_b8_mu(mask, maskedoff, op1, op2, vl);
}

// CHECK-RV64-LABEL: @test_vmslt_vx_i64m8_b8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i1> @llvm.riscv.vmslt.mask.nxv8i64.i64.i64(<vscale x 8 x i1> [[MASKEDOFF:%.*]], <vscale x 8 x i64> [[OP1:%.*]], i64 [[OP2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i1> [[TMP0]]
//
vbool8_t test_vmslt_vx_i64m8_b8_mu(vbool8_t mask, vbool8_t maskedoff, vint64m8_t op1, int64_t op2, size_t vl) {
  return __riscv_vmslt_vx_i64m8_b8_mu(mask, maskedoff, op1, op2, vl);
}

