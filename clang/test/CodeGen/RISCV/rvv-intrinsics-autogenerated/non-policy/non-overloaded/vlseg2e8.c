// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -disable-O0-optnone \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8mf8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, <vscale x 1 x i8> } @llvm.riscv.vlseg2.nxv1i8.i64(<vscale x 1 x i8> poison, <vscale x 1 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8mf8(vint8mf8_t *v0, vint8mf8_t *v1, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8mf8(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8mf4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, <vscale x 2 x i8> } @llvm.riscv.vlseg2.nxv2i8.i64(<vscale x 2 x i8> poison, <vscale x 2 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8mf4(vint8mf4_t *v0, vint8mf4_t *v1, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8mf4(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, <vscale x 4 x i8> } @llvm.riscv.vlseg2.nxv4i8.i64(<vscale x 4 x i8> poison, <vscale x 4 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8mf2(vint8mf2_t *v0, vint8mf2_t *v1, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8mf2(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, <vscale x 8 x i8> } @llvm.riscv.vlseg2.nxv8i8.i64(<vscale x 8 x i8> poison, <vscale x 8 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8m1(vint8m1_t *v0, vint8m1_t *v1, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8m1(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, <vscale x 16 x i8> } @llvm.riscv.vlseg2.nxv16i8.i64(<vscale x 16 x i8> poison, <vscale x 16 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8m2(vint8m2_t *v0, vint8m2_t *v1, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8m2(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, <vscale x 32 x i8> } @llvm.riscv.vlseg2.nxv32i8.i64(<vscale x 32 x i8> poison, <vscale x 32 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8m4(vint8m4_t *v0, vint8m4_t *v1, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8m4(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8mf8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, <vscale x 1 x i8> } @llvm.riscv.vlseg2.nxv1i8.i64(<vscale x 1 x i8> poison, <vscale x 1 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8mf8(vuint8mf8_t *v0, vuint8mf8_t *v1, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8mf8(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8mf4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, <vscale x 2 x i8> } @llvm.riscv.vlseg2.nxv2i8.i64(<vscale x 2 x i8> poison, <vscale x 2 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8mf4(vuint8mf4_t *v0, vuint8mf4_t *v1, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8mf4(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, <vscale x 4 x i8> } @llvm.riscv.vlseg2.nxv4i8.i64(<vscale x 4 x i8> poison, <vscale x 4 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8mf2(vuint8mf2_t *v0, vuint8mf2_t *v1, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8mf2(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, <vscale x 8 x i8> } @llvm.riscv.vlseg2.nxv8i8.i64(<vscale x 8 x i8> poison, <vscale x 8 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8m1(vuint8m1_t *v0, vuint8m1_t *v1, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8m1(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, <vscale x 16 x i8> } @llvm.riscv.vlseg2.nxv16i8.i64(<vscale x 16 x i8> poison, <vscale x 16 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8m2(vuint8m2_t *v0, vuint8m2_t *v1, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8m2(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, <vscale x 32 x i8> } @llvm.riscv.vlseg2.nxv32i8.i64(<vscale x 32 x i8> poison, <vscale x 32 x i8> poison, ptr [[BASE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8m4(vuint8m4_t *v0, vuint8m4_t *v1, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8m4(v0, v1, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8mf8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, <vscale x 1 x i8> } @llvm.riscv.vlseg2.mask.nxv1i8.i64(<vscale x 1 x i8> poison, <vscale x 1 x i8> poison, ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8mf8_m(vint8mf8_t *v0, vint8mf8_t *v1, vbool64_t mask, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8mf8_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8mf4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, <vscale x 2 x i8> } @llvm.riscv.vlseg2.mask.nxv2i8.i64(<vscale x 2 x i8> poison, <vscale x 2 x i8> poison, ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8mf4_m(vint8mf4_t *v0, vint8mf4_t *v1, vbool32_t mask, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8mf4_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, <vscale x 4 x i8> } @llvm.riscv.vlseg2.mask.nxv4i8.i64(<vscale x 4 x i8> poison, <vscale x 4 x i8> poison, ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8mf2_m(vint8mf2_t *v0, vint8mf2_t *v1, vbool16_t mask, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8mf2_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, <vscale x 8 x i8> } @llvm.riscv.vlseg2.mask.nxv8i8.i64(<vscale x 8 x i8> poison, <vscale x 8 x i8> poison, ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8m1_m(vint8m1_t *v0, vint8m1_t *v1, vbool8_t mask, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8m1_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, <vscale x 16 x i8> } @llvm.riscv.vlseg2.mask.nxv16i8.i64(<vscale x 16 x i8> poison, <vscale x 16 x i8> poison, ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8m2_m(vint8m2_t *v0, vint8m2_t *v1, vbool4_t mask, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8m2_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_i8m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, <vscale x 32 x i8> } @llvm.riscv.vlseg2.mask.nxv32i8.i64(<vscale x 32 x i8> poison, <vscale x 32 x i8> poison, ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_i8m4_m(vint8m4_t *v0, vint8m4_t *v1, vbool2_t mask, const int8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_i8m4_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8mf8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, <vscale x 1 x i8> } @llvm.riscv.vlseg2.mask.nxv1i8.i64(<vscale x 1 x i8> poison, <vscale x 1 x i8> poison, ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8mf8_m(vuint8mf8_t *v0, vuint8mf8_t *v1, vbool64_t mask, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8mf8_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8mf4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, <vscale x 2 x i8> } @llvm.riscv.vlseg2.mask.nxv2i8.i64(<vscale x 2 x i8> poison, <vscale x 2 x i8> poison, ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8mf4_m(vuint8mf4_t *v0, vuint8mf4_t *v1, vbool32_t mask, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8mf4_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, <vscale x 4 x i8> } @llvm.riscv.vlseg2.mask.nxv4i8.i64(<vscale x 4 x i8> poison, <vscale x 4 x i8> poison, ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8mf2_m(vuint8mf2_t *v0, vuint8mf2_t *v1, vbool16_t mask, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8mf2_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, <vscale x 8 x i8> } @llvm.riscv.vlseg2.mask.nxv8i8.i64(<vscale x 8 x i8> poison, <vscale x 8 x i8> poison, ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8m1_m(vuint8m1_t *v0, vuint8m1_t *v1, vbool8_t mask, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8m1_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8m2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 16 x i8>, <vscale x 16 x i8> } @llvm.riscv.vlseg2.mask.nxv16i8.i64(<vscale x 16 x i8> poison, <vscale x 16 x i8> poison, ptr [[BASE:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 16 x i8>, <vscale x 16 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 16 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8m2_m(vuint8m2_t *v0, vuint8m2_t *v1, vbool4_t mask, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8m2_m(v0, v1, mask, base, vl);
}

// CHECK-RV64-LABEL: @test_vlseg2e8_v_u8m4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 32 x i8>, <vscale x 32 x i8> } @llvm.riscv.vlseg2.mask.nxv32i8.i64(<vscale x 32 x i8> poison, <vscale x 32 x i8> poison, ptr [[BASE:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 32 x i8>, <vscale x 32 x i8> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 32 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg2e8_v_u8m4_m(vuint8m4_t *v0, vuint8m4_t *v1, vbool2_t mask, const uint8_t *base, size_t vl) {
  return __riscv_vlseg2e8_v_u8m4_m(v0, v1, mask, base, vl);
}

