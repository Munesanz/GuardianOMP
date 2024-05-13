// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -disable-O0-optnone \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vse8_v_i8mf8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv1i8.i64(<vscale x 1 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8mf8(int8_t *base, vint8mf8_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8mf4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv2i8.i64(<vscale x 2 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8mf4(int8_t *base, vint8mf4_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv4i8.i64(<vscale x 4 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8mf2(int8_t *base, vint8mf2_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv8i8.i64(<vscale x 8 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m1(int8_t *base, vint8m1_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv16i8.i64(<vscale x 16 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m2(int8_t *base, vint8m2_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv32i8.i64(<vscale x 32 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m4(int8_t *base, vint8m4_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv64i8.i64(<vscale x 64 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m8(int8_t *base, vint8m8_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8mf8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv1i8.i64(<vscale x 1 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8mf8(uint8_t *base, vuint8mf8_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8mf4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv2i8.i64(<vscale x 2 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8mf4(uint8_t *base, vuint8mf4_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv4i8.i64(<vscale x 4 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8mf2(uint8_t *base, vuint8mf2_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv8i8.i64(<vscale x 8 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m1(uint8_t *base, vuint8m1_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv16i8.i64(<vscale x 16 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m2(uint8_t *base, vuint8m2_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv32i8.i64(<vscale x 32 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m4(uint8_t *base, vuint8m4_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.nxv64i8.i64(<vscale x 64 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m8(uint8_t *base, vuint8m8_t value, size_t vl) {
  return __riscv_vse8(base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8mf8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv1i8.i64(<vscale x 1 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8mf8_m(vbool64_t mask, int8_t *base, vint8mf8_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8mf4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv2i8.i64(<vscale x 2 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8mf4_m(vbool32_t mask, int8_t *base, vint8mf4_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv4i8.i64(<vscale x 4 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8mf2_m(vbool16_t mask, int8_t *base, vint8mf2_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv8i8.i64(<vscale x 8 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m1_m(vbool8_t mask, int8_t *base, vint8m1_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv16i8.i64(<vscale x 16 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m2_m(vbool4_t mask, int8_t *base, vint8m2_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv32i8.i64(<vscale x 32 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m4_m(vbool2_t mask, int8_t *base, vint8m4_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_i8m8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv64i8.i64(<vscale x 64 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_i8m8_m(vbool1_t mask, int8_t *base, vint8m8_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8mf8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv1i8.i64(<vscale x 1 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8mf8_m(vbool64_t mask, uint8_t *base, vuint8mf8_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8mf4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv2i8.i64(<vscale x 2 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8mf4_m(vbool32_t mask, uint8_t *base, vuint8mf4_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv4i8.i64(<vscale x 4 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8mf2_m(vbool16_t mask, uint8_t *base, vuint8mf2_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv8i8.i64(<vscale x 8 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m1_m(vbool8_t mask, uint8_t *base, vuint8m1_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv16i8.i64(<vscale x 16 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m2_m(vbool4_t mask, uint8_t *base, vuint8m2_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv32i8.i64(<vscale x 32 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m4_m(vbool2_t mask, uint8_t *base, vuint8m4_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

// CHECK-RV64-LABEL: @test_vse8_v_u8m8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    call void @llvm.riscv.vse.mask.nxv64i8.i64(<vscale x 64 x i8> [[VALUE:%.*]], ptr [[BASE:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret void
//
void test_vse8_v_u8m8_m(vbool1_t mask, uint8_t *base, vuint8m8_t value, size_t vl) {
  return __riscv_vse8(mask, base, value, vl);
}

