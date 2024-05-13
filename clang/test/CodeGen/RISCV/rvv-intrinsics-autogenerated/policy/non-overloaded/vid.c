// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -disable-O0-optnone \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vid_v_u8mf8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i8> @llvm.riscv.vid.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP0]]
//
vuint8mf8_t test_vid_v_u8mf8_tu(vuint8mf8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf8_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i8> @llvm.riscv.vid.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP0]]
//
vuint8mf4_t test_vid_v_u8mf4_tu(vuint8mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf4_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i8> @llvm.riscv.vid.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP0]]
//
vuint8mf2_t test_vid_v_u8mf2_tu(vuint8mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf2_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i8> @llvm.riscv.vid.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP0]]
//
vuint8m1_t test_vid_v_u8m1_tu(vuint8m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m1_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i8> @llvm.riscv.vid.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP0]]
//
vuint8m2_t test_vid_v_u8m2_tu(vuint8m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m2_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i8> @llvm.riscv.vid.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP0]]
//
vuint8m4_t test_vid_v_u8m4_tu(vuint8m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m4_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 64 x i8> @llvm.riscv.vid.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP0]]
//
vuint8m8_t test_vid_v_u8m8_tu(vuint8m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m8_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vid.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vuint16mf4_t test_vid_v_u16mf4_tu(vuint16mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf4_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vid.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vuint16mf2_t test_vid_v_u16mf2_tu(vuint16mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf2_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vid.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vuint16m1_t test_vid_v_u16m1_tu(vuint16m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m1_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vid.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vuint16m2_t test_vid_v_u16m2_tu(vuint16m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m2_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vid.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vuint16m4_t test_vid_v_u16m4_tu(vuint16m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m4_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vid.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vuint16m8_t test_vid_v_u16m8_tu(vuint16m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m8_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32mf2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i32> @llvm.riscv.vid.nxv1i32.i64(<vscale x 1 x i32> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i32> [[TMP0]]
//
vuint32mf2_t test_vid_v_u32mf2_tu(vuint32mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32mf2_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i32> @llvm.riscv.vid.nxv2i32.i64(<vscale x 2 x i32> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i32> [[TMP0]]
//
vuint32m1_t test_vid_v_u32m1_tu(vuint32m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m1_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i32> @llvm.riscv.vid.nxv4i32.i64(<vscale x 4 x i32> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i32> [[TMP0]]
//
vuint32m2_t test_vid_v_u32m2_tu(vuint32m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m2_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i32> @llvm.riscv.vid.nxv8i32.i64(<vscale x 8 x i32> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i32> [[TMP0]]
//
vuint32m4_t test_vid_v_u32m4_tu(vuint32m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m4_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i32> @llvm.riscv.vid.nxv16i32.i64(<vscale x 16 x i32> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 16 x i32> [[TMP0]]
//
vuint32m8_t test_vid_v_u32m8_tu(vuint32m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m8_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m1_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i64> @llvm.riscv.vid.nxv1i64.i64(<vscale x 1 x i64> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 1 x i64> [[TMP0]]
//
vuint64m1_t test_vid_v_u64m1_tu(vuint64m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m1_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m2_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i64> @llvm.riscv.vid.nxv2i64.i64(<vscale x 2 x i64> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 2 x i64> [[TMP0]]
//
vuint64m2_t test_vid_v_u64m2_tu(vuint64m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m2_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m4_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i64> @llvm.riscv.vid.nxv4i64.i64(<vscale x 4 x i64> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 4 x i64> [[TMP0]]
//
vuint64m4_t test_vid_v_u64m4_tu(vuint64m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m4_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m8_tu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i64> @llvm.riscv.vid.nxv8i64.i64(<vscale x 8 x i64> [[MASKEDOFF:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    ret <vscale x 8 x i64> [[TMP0]]
//
vuint64m8_t test_vid_v_u64m8_tu(vuint64m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m8_tu(maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i8> @llvm.riscv.vid.mask.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP0]]
//
vuint8mf8_t test_vid_v_u8mf8_tum(vbool64_t mask, vuint8mf8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf8_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i8> @llvm.riscv.vid.mask.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP0]]
//
vuint8mf4_t test_vid_v_u8mf4_tum(vbool32_t mask, vuint8mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf4_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i8> @llvm.riscv.vid.mask.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP0]]
//
vuint8mf2_t test_vid_v_u8mf2_tum(vbool16_t mask, vuint8mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf2_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i8> @llvm.riscv.vid.mask.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP0]]
//
vuint8m1_t test_vid_v_u8m1_tum(vbool8_t mask, vuint8m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m1_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i8> @llvm.riscv.vid.mask.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP0]]
//
vuint8m2_t test_vid_v_u8m2_tum(vbool4_t mask, vuint8m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m2_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i8> @llvm.riscv.vid.mask.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP0]]
//
vuint8m4_t test_vid_v_u8m4_tum(vbool2_t mask, vuint8m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m4_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 64 x i8> @llvm.riscv.vid.mask.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP0]]
//
vuint8m8_t test_vid_v_u8m8_tum(vbool1_t mask, vuint8m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m8_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vid.mask.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vuint16mf4_t test_vid_v_u16mf4_tum(vbool64_t mask, vuint16mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf4_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vid.mask.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vuint16mf2_t test_vid_v_u16mf2_tum(vbool32_t mask, vuint16mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf2_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vid.mask.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vuint16m1_t test_vid_v_u16m1_tum(vbool16_t mask, vuint16m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m1_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vid.mask.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vuint16m2_t test_vid_v_u16m2_tum(vbool8_t mask, vuint16m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m2_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vid.mask.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vuint16m4_t test_vid_v_u16m4_tum(vbool4_t mask, vuint16m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m4_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vid.mask.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vuint16m8_t test_vid_v_u16m8_tum(vbool2_t mask, vuint16m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m8_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32mf2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i32> @llvm.riscv.vid.mask.nxv1i32.i64(<vscale x 1 x i32> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i32> [[TMP0]]
//
vuint32mf2_t test_vid_v_u32mf2_tum(vbool64_t mask, vuint32mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32mf2_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i32> @llvm.riscv.vid.mask.nxv2i32.i64(<vscale x 2 x i32> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i32> [[TMP0]]
//
vuint32m1_t test_vid_v_u32m1_tum(vbool32_t mask, vuint32m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m1_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i32> @llvm.riscv.vid.mask.nxv4i32.i64(<vscale x 4 x i32> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i32> [[TMP0]]
//
vuint32m2_t test_vid_v_u32m2_tum(vbool16_t mask, vuint32m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m2_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i32> @llvm.riscv.vid.mask.nxv8i32.i64(<vscale x 8 x i32> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i32> [[TMP0]]
//
vuint32m4_t test_vid_v_u32m4_tum(vbool8_t mask, vuint32m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m4_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i32> @llvm.riscv.vid.mask.nxv16i32.i64(<vscale x 16 x i32> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i32> [[TMP0]]
//
vuint32m8_t test_vid_v_u32m8_tum(vbool4_t mask, vuint32m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m8_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m1_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i64> @llvm.riscv.vid.mask.nxv1i64.i64(<vscale x 1 x i64> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i64> [[TMP0]]
//
vuint64m1_t test_vid_v_u64m1_tum(vbool64_t mask, vuint64m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m1_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m2_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i64> @llvm.riscv.vid.mask.nxv2i64.i64(<vscale x 2 x i64> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i64> [[TMP0]]
//
vuint64m2_t test_vid_v_u64m2_tum(vbool32_t mask, vuint64m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m2_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m4_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i64> @llvm.riscv.vid.mask.nxv4i64.i64(<vscale x 4 x i64> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i64> [[TMP0]]
//
vuint64m4_t test_vid_v_u64m4_tum(vbool16_t mask, vuint64m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m4_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m8_tum(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i64> @llvm.riscv.vid.mask.nxv8i64.i64(<vscale x 8 x i64> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 2)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i64> [[TMP0]]
//
vuint64m8_t test_vid_v_u64m8_tum(vbool8_t mask, vuint64m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m8_tum(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i8> @llvm.riscv.vid.mask.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP0]]
//
vuint8mf8_t test_vid_v_u8mf8_tumu(vbool64_t mask, vuint8mf8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf8_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i8> @llvm.riscv.vid.mask.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP0]]
//
vuint8mf4_t test_vid_v_u8mf4_tumu(vbool32_t mask, vuint8mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf4_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i8> @llvm.riscv.vid.mask.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP0]]
//
vuint8mf2_t test_vid_v_u8mf2_tumu(vbool16_t mask, vuint8mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf2_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i8> @llvm.riscv.vid.mask.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP0]]
//
vuint8m1_t test_vid_v_u8m1_tumu(vbool8_t mask, vuint8m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m1_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i8> @llvm.riscv.vid.mask.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP0]]
//
vuint8m2_t test_vid_v_u8m2_tumu(vbool4_t mask, vuint8m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m2_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i8> @llvm.riscv.vid.mask.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP0]]
//
vuint8m4_t test_vid_v_u8m4_tumu(vbool2_t mask, vuint8m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m4_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 64 x i8> @llvm.riscv.vid.mask.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP0]]
//
vuint8m8_t test_vid_v_u8m8_tumu(vbool1_t mask, vuint8m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m8_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vid.mask.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vuint16mf4_t test_vid_v_u16mf4_tumu(vbool64_t mask, vuint16mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf4_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vid.mask.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vuint16mf2_t test_vid_v_u16mf2_tumu(vbool32_t mask, vuint16mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf2_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vid.mask.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vuint16m1_t test_vid_v_u16m1_tumu(vbool16_t mask, vuint16m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m1_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vid.mask.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vuint16m2_t test_vid_v_u16m2_tumu(vbool8_t mask, vuint16m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m2_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vid.mask.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vuint16m4_t test_vid_v_u16m4_tumu(vbool4_t mask, vuint16m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m4_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vid.mask.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vuint16m8_t test_vid_v_u16m8_tumu(vbool2_t mask, vuint16m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m8_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32mf2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i32> @llvm.riscv.vid.mask.nxv1i32.i64(<vscale x 1 x i32> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i32> [[TMP0]]
//
vuint32mf2_t test_vid_v_u32mf2_tumu(vbool64_t mask, vuint32mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32mf2_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i32> @llvm.riscv.vid.mask.nxv2i32.i64(<vscale x 2 x i32> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i32> [[TMP0]]
//
vuint32m1_t test_vid_v_u32m1_tumu(vbool32_t mask, vuint32m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m1_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i32> @llvm.riscv.vid.mask.nxv4i32.i64(<vscale x 4 x i32> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i32> [[TMP0]]
//
vuint32m2_t test_vid_v_u32m2_tumu(vbool16_t mask, vuint32m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m2_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i32> @llvm.riscv.vid.mask.nxv8i32.i64(<vscale x 8 x i32> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i32> [[TMP0]]
//
vuint32m4_t test_vid_v_u32m4_tumu(vbool8_t mask, vuint32m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m4_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i32> @llvm.riscv.vid.mask.nxv16i32.i64(<vscale x 16 x i32> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i32> [[TMP0]]
//
vuint32m8_t test_vid_v_u32m8_tumu(vbool4_t mask, vuint32m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m8_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m1_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i64> @llvm.riscv.vid.mask.nxv1i64.i64(<vscale x 1 x i64> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i64> [[TMP0]]
//
vuint64m1_t test_vid_v_u64m1_tumu(vbool64_t mask, vuint64m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m1_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m2_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i64> @llvm.riscv.vid.mask.nxv2i64.i64(<vscale x 2 x i64> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i64> [[TMP0]]
//
vuint64m2_t test_vid_v_u64m2_tumu(vbool32_t mask, vuint64m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m2_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m4_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i64> @llvm.riscv.vid.mask.nxv4i64.i64(<vscale x 4 x i64> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i64> [[TMP0]]
//
vuint64m4_t test_vid_v_u64m4_tumu(vbool16_t mask, vuint64m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m4_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m8_tumu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i64> @llvm.riscv.vid.mask.nxv8i64.i64(<vscale x 8 x i64> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 0)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i64> [[TMP0]]
//
vuint64m8_t test_vid_v_u64m8_tumu(vbool8_t mask, vuint64m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m8_tumu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i8> @llvm.riscv.vid.mask.nxv1i8.i64(<vscale x 1 x i8> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i8> [[TMP0]]
//
vuint8mf8_t test_vid_v_u8mf8_mu(vbool64_t mask, vuint8mf8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf8_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i8> @llvm.riscv.vid.mask.nxv2i8.i64(<vscale x 2 x i8> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i8> [[TMP0]]
//
vuint8mf4_t test_vid_v_u8mf4_mu(vbool32_t mask, vuint8mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf4_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8mf2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i8> @llvm.riscv.vid.mask.nxv4i8.i64(<vscale x 4 x i8> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i8> [[TMP0]]
//
vuint8mf2_t test_vid_v_u8mf2_mu(vbool16_t mask, vuint8mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8mf2_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m1_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i8> @llvm.riscv.vid.mask.nxv8i8.i64(<vscale x 8 x i8> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i8> [[TMP0]]
//
vuint8m1_t test_vid_v_u8m1_mu(vbool8_t mask, vuint8m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m1_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i8> @llvm.riscv.vid.mask.nxv16i8.i64(<vscale x 16 x i8> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i8> [[TMP0]]
//
vuint8m2_t test_vid_v_u8m2_mu(vbool4_t mask, vuint8m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m2_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i8> @llvm.riscv.vid.mask.nxv32i8.i64(<vscale x 32 x i8> [[MASKEDOFF:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i8> [[TMP0]]
//
vuint8m4_t test_vid_v_u8m4_mu(vbool2_t mask, vuint8m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m4_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u8m8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 64 x i8> @llvm.riscv.vid.mask.nxv64i8.i64(<vscale x 64 x i8> [[MASKEDOFF:%.*]], <vscale x 64 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 64 x i8> [[TMP0]]
//
vuint8m8_t test_vid_v_u8m8_mu(vbool1_t mask, vuint8m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u8m8_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i16> @llvm.riscv.vid.mask.nxv1i16.i64(<vscale x 1 x i16> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i16> [[TMP0]]
//
vuint16mf4_t test_vid_v_u16mf4_mu(vbool64_t mask, vuint16mf4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf4_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16mf2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i16> @llvm.riscv.vid.mask.nxv2i16.i64(<vscale x 2 x i16> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i16> [[TMP0]]
//
vuint16mf2_t test_vid_v_u16mf2_mu(vbool32_t mask, vuint16mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16mf2_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m1_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i16> @llvm.riscv.vid.mask.nxv4i16.i64(<vscale x 4 x i16> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i16> [[TMP0]]
//
vuint16m1_t test_vid_v_u16m1_mu(vbool16_t mask, vuint16m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m1_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i16> @llvm.riscv.vid.mask.nxv8i16.i64(<vscale x 8 x i16> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i16> [[TMP0]]
//
vuint16m2_t test_vid_v_u16m2_mu(vbool8_t mask, vuint16m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m2_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i16> @llvm.riscv.vid.mask.nxv16i16.i64(<vscale x 16 x i16> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i16> [[TMP0]]
//
vuint16m4_t test_vid_v_u16m4_mu(vbool4_t mask, vuint16m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m4_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u16m8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 32 x i16> @llvm.riscv.vid.mask.nxv32i16.i64(<vscale x 32 x i16> [[MASKEDOFF:%.*]], <vscale x 32 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 32 x i16> [[TMP0]]
//
vuint16m8_t test_vid_v_u16m8_mu(vbool2_t mask, vuint16m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u16m8_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32mf2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i32> @llvm.riscv.vid.mask.nxv1i32.i64(<vscale x 1 x i32> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i32> [[TMP0]]
//
vuint32mf2_t test_vid_v_u32mf2_mu(vbool64_t mask, vuint32mf2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32mf2_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m1_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i32> @llvm.riscv.vid.mask.nxv2i32.i64(<vscale x 2 x i32> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i32> [[TMP0]]
//
vuint32m1_t test_vid_v_u32m1_mu(vbool32_t mask, vuint32m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m1_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i32> @llvm.riscv.vid.mask.nxv4i32.i64(<vscale x 4 x i32> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i32> [[TMP0]]
//
vuint32m2_t test_vid_v_u32m2_mu(vbool16_t mask, vuint32m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m2_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i32> @llvm.riscv.vid.mask.nxv8i32.i64(<vscale x 8 x i32> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i32> [[TMP0]]
//
vuint32m4_t test_vid_v_u32m4_mu(vbool8_t mask, vuint32m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m4_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u32m8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 16 x i32> @llvm.riscv.vid.mask.nxv16i32.i64(<vscale x 16 x i32> [[MASKEDOFF:%.*]], <vscale x 16 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 16 x i32> [[TMP0]]
//
vuint32m8_t test_vid_v_u32m8_mu(vbool4_t mask, vuint32m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u32m8_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m1_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 1 x i64> @llvm.riscv.vid.mask.nxv1i64.i64(<vscale x 1 x i64> [[MASKEDOFF:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 1 x i64> [[TMP0]]
//
vuint64m1_t test_vid_v_u64m1_mu(vbool64_t mask, vuint64m1_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m1_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m2_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 2 x i64> @llvm.riscv.vid.mask.nxv2i64.i64(<vscale x 2 x i64> [[MASKEDOFF:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 2 x i64> [[TMP0]]
//
vuint64m2_t test_vid_v_u64m2_mu(vbool32_t mask, vuint64m2_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m2_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m4_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 4 x i64> @llvm.riscv.vid.mask.nxv4i64.i64(<vscale x 4 x i64> [[MASKEDOFF:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 4 x i64> [[TMP0]]
//
vuint64m4_t test_vid_v_u64m4_mu(vbool16_t mask, vuint64m4_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m4_mu(mask, maskedoff, vl);
}

// CHECK-RV64-LABEL: @test_vid_v_u64m8_mu(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call <vscale x 8 x i64> @llvm.riscv.vid.mask.nxv8i64.i64(<vscale x 8 x i64> [[MASKEDOFF:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 1)
// CHECK-RV64-NEXT:    ret <vscale x 8 x i64> [[TMP0]]
//
vuint64m8_t test_vid_v_u64m8_mu(vbool8_t mask, vuint64m8_t maskedoff, size_t vl) {
  return __riscv_vid_v_u64m8_mu(mask, maskedoff, vl);
}

