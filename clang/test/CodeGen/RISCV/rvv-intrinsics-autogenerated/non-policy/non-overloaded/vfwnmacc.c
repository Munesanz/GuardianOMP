// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -target-feature +zfh \
// RUN:   -target-feature +experimental-zvfh -disable-O0-optnone  \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x float> @llvm.riscv.vfwnmacc.nxv1f32.nxv1f16.nxv1f16.i64(<vscale x 1 x float> [[VD:%.*]], <vscale x 1 x half> [[VS1:%.*]], <vscale x 1 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x float> [[TMP0]]
//
vfloat32mf2_t test_vfwnmacc_vv_f32mf2(vfloat32mf2_t vd, vfloat16mf4_t vs1, vfloat16mf4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32mf2(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x float> @llvm.riscv.vfwnmacc.nxv1f32.f16.nxv1f16.i64(<vscale x 1 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 1 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x float> [[TMP0]]
//
vfloat32mf2_t test_vfwnmacc_vf_f32mf2(vfloat32mf2_t vd, _Float16 vs1, vfloat16mf4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32mf2(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwnmacc.nxv2f32.nxv2f16.nxv2f16.i64(<vscale x 2 x float> [[VD:%.*]], <vscale x 2 x half> [[VS1:%.*]], <vscale x 2 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwnmacc_vv_f32m1(vfloat32m1_t vd, vfloat16mf2_t vs1, vfloat16mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m1(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwnmacc.nxv2f32.f16.nxv2f16.i64(<vscale x 2 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 2 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwnmacc_vf_f32m1(vfloat32m1_t vd, _Float16 vs1, vfloat16mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m1(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x float> @llvm.riscv.vfwnmacc.nxv4f32.nxv4f16.nxv4f16.i64(<vscale x 4 x float> [[VD:%.*]], <vscale x 4 x half> [[VS1:%.*]], <vscale x 4 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x float> [[TMP0]]
//
vfloat32m2_t test_vfwnmacc_vv_f32m2(vfloat32m2_t vd, vfloat16m1_t vs1, vfloat16m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m2(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x float> @llvm.riscv.vfwnmacc.nxv4f32.f16.nxv4f16.i64(<vscale x 4 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 4 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x float> [[TMP0]]
//
vfloat32m2_t test_vfwnmacc_vf_f32m2(vfloat32m2_t vd, _Float16 vs1, vfloat16m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m2(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x float> @llvm.riscv.vfwnmacc.nxv8f32.nxv8f16.nxv8f16.i64(<vscale x 8 x float> [[VD:%.*]], <vscale x 8 x half> [[VS1:%.*]], <vscale x 8 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x float> [[TMP0]]
//
vfloat32m4_t test_vfwnmacc_vv_f32m4(vfloat32m4_t vd, vfloat16m2_t vs1, vfloat16m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m4(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x float> @llvm.riscv.vfwnmacc.nxv8f32.f16.nxv8f16.i64(<vscale x 8 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 8 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x float> [[TMP0]]
//
vfloat32m4_t test_vfwnmacc_vf_f32m4(vfloat32m4_t vd, _Float16 vs1, vfloat16m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m4(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x float> @llvm.riscv.vfwnmacc.nxv16f32.nxv16f16.nxv16f16.i64(<vscale x 16 x float> [[VD:%.*]], <vscale x 16 x half> [[VS1:%.*]], <vscale x 16 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 16 x float> [[TMP0]]
//
vfloat32m8_t test_vfwnmacc_vv_f32m8(vfloat32m8_t vd, vfloat16m4_t vs1, vfloat16m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m8(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x float> @llvm.riscv.vfwnmacc.nxv16f32.f16.nxv16f16.i64(<vscale x 16 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 16 x half> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 16 x float> [[TMP0]]
//
vfloat32m8_t test_vfwnmacc_vf_f32m8(vfloat32m8_t vd, _Float16 vs1, vfloat16m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m8(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwnmacc.nxv1f64.nxv1f32.nxv1f32.i64(<vscale x 1 x double> [[VD:%.*]], <vscale x 1 x float> [[VS1:%.*]], <vscale x 1 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwnmacc_vv_f64m1(vfloat64m1_t vd, vfloat32mf2_t vs1, vfloat32mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m1(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwnmacc.nxv1f64.f32.nxv1f32.i64(<vscale x 1 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 1 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwnmacc_vf_f64m1(vfloat64m1_t vd, float vs1, vfloat32mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m1(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x double> @llvm.riscv.vfwnmacc.nxv2f64.nxv2f32.nxv2f32.i64(<vscale x 2 x double> [[VD:%.*]], <vscale x 2 x float> [[VS1:%.*]], <vscale x 2 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x double> [[TMP0]]
//
vfloat64m2_t test_vfwnmacc_vv_f64m2(vfloat64m2_t vd, vfloat32m1_t vs1, vfloat32m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m2(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x double> @llvm.riscv.vfwnmacc.nxv2f64.f32.nxv2f32.i64(<vscale x 2 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 2 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x double> [[TMP0]]
//
vfloat64m2_t test_vfwnmacc_vf_f64m2(vfloat64m2_t vd, float vs1, vfloat32m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m2(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x double> @llvm.riscv.vfwnmacc.nxv4f64.nxv4f32.nxv4f32.i64(<vscale x 4 x double> [[VD:%.*]], <vscale x 4 x float> [[VS1:%.*]], <vscale x 4 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x double> [[TMP0]]
//
vfloat64m4_t test_vfwnmacc_vv_f64m4(vfloat64m4_t vd, vfloat32m2_t vs1, vfloat32m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m4(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x double> @llvm.riscv.vfwnmacc.nxv4f64.f32.nxv4f32.i64(<vscale x 4 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 4 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x double> [[TMP0]]
//
vfloat64m4_t test_vfwnmacc_vf_f64m4(vfloat64m4_t vd, float vs1, vfloat32m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m4(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x double> @llvm.riscv.vfwnmacc.nxv8f64.nxv8f32.nxv8f32.i64(<vscale x 8 x double> [[VD:%.*]], <vscale x 8 x float> [[VS1:%.*]], <vscale x 8 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x double> [[TMP0]]
//
vfloat64m8_t test_vfwnmacc_vv_f64m8(vfloat64m8_t vd, vfloat32m4_t vs1, vfloat32m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m8(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x double> @llvm.riscv.vfwnmacc.nxv8f64.f32.nxv8f32.i64(<vscale x 8 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 8 x float> [[VS2:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x double> [[TMP0]]
//
vfloat64m8_t test_vfwnmacc_vf_f64m8(vfloat64m8_t vd, float vs1, vfloat32m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m8(vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x float> @llvm.riscv.vfwnmacc.mask.nxv1f32.nxv1f16.nxv1f16.i64(<vscale x 1 x float> [[VD:%.*]], <vscale x 1 x half> [[VS1:%.*]], <vscale x 1 x half> [[VS2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x float> [[TMP0]]
//
vfloat32mf2_t test_vfwnmacc_vv_f32mf2_m(vbool64_t mask, vfloat32mf2_t vd, vfloat16mf4_t vs1, vfloat16mf4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32mf2_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x float> @llvm.riscv.vfwnmacc.mask.nxv1f32.f16.nxv1f16.i64(<vscale x 1 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 1 x half> [[VS2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x float> [[TMP0]]
//
vfloat32mf2_t test_vfwnmacc_vf_f32mf2_m(vbool64_t mask, vfloat32mf2_t vd, _Float16 vs1, vfloat16mf4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32mf2_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwnmacc.mask.nxv2f32.nxv2f16.nxv2f16.i64(<vscale x 2 x float> [[VD:%.*]], <vscale x 2 x half> [[VS1:%.*]], <vscale x 2 x half> [[VS2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwnmacc_vv_f32m1_m(vbool32_t mask, vfloat32m1_t vd, vfloat16mf2_t vs1, vfloat16mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m1_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x float> @llvm.riscv.vfwnmacc.mask.nxv2f32.f16.nxv2f16.i64(<vscale x 2 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 2 x half> [[VS2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x float> [[TMP0]]
//
vfloat32m1_t test_vfwnmacc_vf_f32m1_m(vbool32_t mask, vfloat32m1_t vd, _Float16 vs1, vfloat16mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m1_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x float> @llvm.riscv.vfwnmacc.mask.nxv4f32.nxv4f16.nxv4f16.i64(<vscale x 4 x float> [[VD:%.*]], <vscale x 4 x half> [[VS1:%.*]], <vscale x 4 x half> [[VS2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x float> [[TMP0]]
//
vfloat32m2_t test_vfwnmacc_vv_f32m2_m(vbool16_t mask, vfloat32m2_t vd, vfloat16m1_t vs1, vfloat16m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m2_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x float> @llvm.riscv.vfwnmacc.mask.nxv4f32.f16.nxv4f16.i64(<vscale x 4 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 4 x half> [[VS2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x float> [[TMP0]]
//
vfloat32m2_t test_vfwnmacc_vf_f32m2_m(vbool16_t mask, vfloat32m2_t vd, _Float16 vs1, vfloat16m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m2_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x float> @llvm.riscv.vfwnmacc.mask.nxv8f32.nxv8f16.nxv8f16.i64(<vscale x 8 x float> [[VD:%.*]], <vscale x 8 x half> [[VS1:%.*]], <vscale x 8 x half> [[VS2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x float> [[TMP0]]
//
vfloat32m4_t test_vfwnmacc_vv_f32m4_m(vbool8_t mask, vfloat32m4_t vd, vfloat16m2_t vs1, vfloat16m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m4_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x float> @llvm.riscv.vfwnmacc.mask.nxv8f32.f16.nxv8f16.i64(<vscale x 8 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 8 x half> [[VS2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x float> [[TMP0]]
//
vfloat32m4_t test_vfwnmacc_vf_f32m4_m(vbool8_t mask, vfloat32m4_t vd, _Float16 vs1, vfloat16m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m4_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f32m8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x float> @llvm.riscv.vfwnmacc.mask.nxv16f32.nxv16f16.nxv16f16.i64(<vscale x 16 x float> [[VD:%.*]], <vscale x 16 x half> [[VS1:%.*]], <vscale x 16 x half> [[VS2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 16 x float> [[TMP0]]
//
vfloat32m8_t test_vfwnmacc_vv_f32m8_m(vbool4_t mask, vfloat32m8_t vd, vfloat16m4_t vs1, vfloat16m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f32m8_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f32m8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x float> @llvm.riscv.vfwnmacc.mask.nxv16f32.f16.nxv16f16.i64(<vscale x 16 x float> [[VD:%.*]], half [[VS1:%.*]], <vscale x 16 x half> [[VS2:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 16 x float> [[TMP0]]
//
vfloat32m8_t test_vfwnmacc_vf_f32m8_m(vbool4_t mask, vfloat32m8_t vd, _Float16 vs1, vfloat16m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f32m8_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwnmacc.mask.nxv1f64.nxv1f32.nxv1f32.i64(<vscale x 1 x double> [[VD:%.*]], <vscale x 1 x float> [[VS1:%.*]], <vscale x 1 x float> [[VS2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwnmacc_vv_f64m1_m(vbool64_t mask, vfloat64m1_t vd, vfloat32mf2_t vs1, vfloat32mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m1_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x double> @llvm.riscv.vfwnmacc.mask.nxv1f64.f32.nxv1f32.i64(<vscale x 1 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 1 x float> [[VS2:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 1 x double> [[TMP0]]
//
vfloat64m1_t test_vfwnmacc_vf_f64m1_m(vbool64_t mask, vfloat64m1_t vd, float vs1, vfloat32mf2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m1_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x double> @llvm.riscv.vfwnmacc.mask.nxv2f64.nxv2f32.nxv2f32.i64(<vscale x 2 x double> [[VD:%.*]], <vscale x 2 x float> [[VS1:%.*]], <vscale x 2 x float> [[VS2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x double> [[TMP0]]
//
vfloat64m2_t test_vfwnmacc_vv_f64m2_m(vbool32_t mask, vfloat64m2_t vd, vfloat32m1_t vs1, vfloat32m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m2_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x double> @llvm.riscv.vfwnmacc.mask.nxv2f64.f32.nxv2f32.i64(<vscale x 2 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 2 x float> [[VS2:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 2 x double> [[TMP0]]
//
vfloat64m2_t test_vfwnmacc_vf_f64m2_m(vbool32_t mask, vfloat64m2_t vd, float vs1, vfloat32m1_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m2_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x double> @llvm.riscv.vfwnmacc.mask.nxv4f64.nxv4f32.nxv4f32.i64(<vscale x 4 x double> [[VD:%.*]], <vscale x 4 x float> [[VS1:%.*]], <vscale x 4 x float> [[VS2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x double> [[TMP0]]
//
vfloat64m4_t test_vfwnmacc_vv_f64m4_m(vbool16_t mask, vfloat64m4_t vd, vfloat32m2_t vs1, vfloat32m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m4_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x double> @llvm.riscv.vfwnmacc.mask.nxv4f64.f32.nxv4f32.i64(<vscale x 4 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 4 x float> [[VS2:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 4 x double> [[TMP0]]
//
vfloat64m4_t test_vfwnmacc_vf_f64m4_m(vbool16_t mask, vfloat64m4_t vd, float vs1, vfloat32m2_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m4_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vv_f64m8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x double> @llvm.riscv.vfwnmacc.mask.nxv8f64.nxv8f32.nxv8f32.i64(<vscale x 8 x double> [[VD:%.*]], <vscale x 8 x float> [[VS1:%.*]], <vscale x 8 x float> [[VS2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x double> [[TMP0]]
//
vfloat64m8_t test_vfwnmacc_vv_f64m8_m(vbool8_t mask, vfloat64m8_t vd, vfloat32m4_t vs1, vfloat32m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vv_f64m8_m(mask, vd, vs1, vs2, vl);
}

// CHECK-RV64-LABEL: @test_vfwnmacc_vf_f64m8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x double> @llvm.riscv.vfwnmacc.mask.nxv8f64.f32.nxv8f32.i64(<vscale x 8 x double> [[VD:%.*]], float [[VS1:%.*]], <vscale x 8 x float> [[VS2:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    ret <vscale x 8 x double> [[TMP0]]
//
vfloat64m8_t test_vfwnmacc_vf_f64m8_m(vbool8_t mask, vfloat64m8_t vd, float vs1, vfloat32m4_t vs2, size_t vl) {
  return __riscv_vfwnmacc_vf_f64m8_m(mask, vd, vs1, vs2, vl);
}

