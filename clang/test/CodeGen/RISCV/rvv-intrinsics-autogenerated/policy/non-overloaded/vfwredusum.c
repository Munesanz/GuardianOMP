// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -target-feature +zfh \
// RUN:   -target-feature +experimental-zvfh -disable-O0-optnone  \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16mf4_f32m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.nxv2f32.nxv1f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 1 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16mf4_f32m1_tu(vfloat32m1_t maskedoff, vfloat16mf4_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16mf4_f32m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16mf2_f32m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.nxv2f32.nxv2f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 2 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16mf2_f32m1_tu(vfloat32m1_t maskedoff, vfloat16mf2_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16mf2_f32m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m1_f32m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.nxv2f32.nxv4f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 4 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m1_f32m1_tu(vfloat32m1_t maskedoff, vfloat16m1_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m1_f32m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m2_f32m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.nxv2f32.nxv8f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 8 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m2_f32m1_tu(vfloat32m1_t maskedoff, vfloat16m2_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m2_f32m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m4_f32m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.nxv2f32.nxv16f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 16 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m4_f32m1_tu(vfloat32m1_t maskedoff, vfloat16m4_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m4_f32m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m8_f32m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.nxv2f32.nxv32f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 32 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m8_f32m1_tu(vfloat32m1_t maskedoff, vfloat16m8_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m8_f32m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32mf2_f64m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.nxv1f64.nxv1f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 1 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32mf2_f64m1_tu(vfloat64m1_t maskedoff, vfloat32mf2_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32mf2_f64m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m1_f64m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.nxv1f64.nxv2f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 2 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m1_f64m1_tu(vfloat64m1_t maskedoff, vfloat32m1_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m1_f64m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m2_f64m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.nxv1f64.nxv4f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 4 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m2_f64m1_tu(vfloat64m1_t maskedoff, vfloat32m2_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m2_f64m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m4_f64m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.nxv1f64.nxv8f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 8 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m4_f64m1_tu(vfloat64m1_t maskedoff, vfloat32m4_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m4_f64m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m8_f64m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.nxv1f64.nxv16f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 16 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m8_f64m1_tu(vfloat64m1_t maskedoff, vfloat32m8_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m8_f64m1_tu(maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16mf4_f32m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.mask.nxv2f32.nxv1f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 1 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16mf4_f32m1_tum(vbool64_t mask, vfloat32m1_t maskedoff, vfloat16mf4_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16mf4_f32m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16mf2_f32m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.mask.nxv2f32.nxv2f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 2 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16mf2_f32m1_tum(vbool32_t mask, vfloat32m1_t maskedoff, vfloat16mf2_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16mf2_f32m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m1_f32m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.mask.nxv2f32.nxv4f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 4 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m1_f32m1_tum(vbool16_t mask, vfloat32m1_t maskedoff, vfloat16m1_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m1_f32m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m2_f32m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.mask.nxv2f32.nxv8f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 8 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m2_f32m1_tum(vbool8_t mask, vfloat32m1_t maskedoff, vfloat16m2_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m2_f32m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m4_f32m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.mask.nxv2f32.nxv16f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 16 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m4_f32m1_tum(vbool4_t mask, vfloat32m1_t maskedoff, vfloat16m4_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m4_f32m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f16m8_f32m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwredusum.mask.nxv2f32.nxv32f16.i64(<vscale x 2 x float> [[MASKEDOFF:%.*]], <vscale x 32 x half> [[VECTOR:%.*]], <vscale x 2 x float> [[SCALAR:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwredusum_vs_f16m8_f32m1_tum(vbool2_t mask, vfloat32m1_t maskedoff, vfloat16m8_t vector, vfloat32m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f16m8_f32m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32mf2_f64m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.mask.nxv1f64.nxv1f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 1 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32mf2_f64m1_tum(vbool64_t mask, vfloat64m1_t maskedoff, vfloat32mf2_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32mf2_f64m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m1_f64m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.mask.nxv1f64.nxv2f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 2 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m1_f64m1_tum(vbool32_t mask, vfloat64m1_t maskedoff, vfloat32m1_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m1_f64m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m2_f64m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.mask.nxv1f64.nxv4f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 4 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m2_f64m1_tum(vbool16_t mask, vfloat64m1_t maskedoff, vfloat32m2_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m2_f64m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m4_f64m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.mask.nxv1f64.nxv8f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 8 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m4_f64m1_tum(vbool8_t mask, vfloat64m1_t maskedoff, vfloat32m4_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m4_f64m1_tum(mask, maskedoff, vector, scalar, vl);
}

// CHECK-RV64-LABEL: @test_vfwredusum_vs_f32m8_f64m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwredusum.mask.nxv1f64.nxv16f32.i64(<vscale x 1 x double> [[MASKEDOFF:%.*]], <vscale x 16 x float> [[VECTOR:%.*]], <vscale x 1 x double> [[SCALAR:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwredusum_vs_f32m8_f64m1_tum(vbool4_t mask, vfloat64m1_t maskedoff, vfloat32m8_t vector, vfloat64m1_t scalar, size_t vl) {
  return __riscv_vfwredusum_vs_f32m8_f64m1_tum(mask, maskedoff, vector, scalar, vl);
}

