// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -target-feature +zfh \
// RUN:   -target-feature +experimental-zvfh -disable-O0-optnone  \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vlsseg6e64_v_f64m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } @llvm.riscv.vlsseg6.nxv1f64.i64(<vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP1]], ptr [[V0:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP2]], ptr [[V1:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP3]], ptr [[V2:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP4]], ptr [[V3:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP5]], ptr [[V4:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP6]], ptr [[V5:%.*]], align 8
// CHECK-RV64-NEXT:    ret void
//
void test_vlsseg6e64_v_f64m1(vfloat64m1_t *v0, vfloat64m1_t *v1, vfloat64m1_t *v2, vfloat64m1_t *v3, vfloat64m1_t *v4, vfloat64m1_t *v5, const double *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlsseg6e64_v_f64m1(v0, v1, v2, v3, v4, v5, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlsseg6e64_v_i64m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } @llvm.riscv.vlsseg6.nxv1i64.i64(<vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP1]], ptr [[V0:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP2]], ptr [[V1:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP3]], ptr [[V2:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP4]], ptr [[V3:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP5]], ptr [[V4:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP6]], ptr [[V5:%.*]], align 8
// CHECK-RV64-NEXT:    ret void
//
void test_vlsseg6e64_v_i64m1(vint64m1_t *v0, vint64m1_t *v1, vint64m1_t *v2, vint64m1_t *v3, vint64m1_t *v4, vint64m1_t *v5, const int64_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlsseg6e64_v_i64m1(v0, v1, v2, v3, v4, v5, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlsseg6e64_v_u64m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } @llvm.riscv.vlsseg6.nxv1i64.i64(<vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], i64 [[VL:%.*]])
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP1]], ptr [[V0:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP2]], ptr [[V1:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP3]], ptr [[V2:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP4]], ptr [[V3:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP5]], ptr [[V4:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP6]], ptr [[V5:%.*]], align 8
// CHECK-RV64-NEXT:    ret void
//
void test_vlsseg6e64_v_u64m1(vuint64m1_t *v0, vuint64m1_t *v1, vuint64m1_t *v2, vuint64m1_t *v3, vuint64m1_t *v4, vuint64m1_t *v5, const uint64_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlsseg6e64_v_u64m1(v0, v1, v2, v3, v4, v5, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlsseg6e64_v_f64m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } @llvm.riscv.vlsseg6.mask.nxv1f64.i64(<vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, <vscale x 1 x double> poison, ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP1]], ptr [[V0:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP2]], ptr [[V1:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP3]], ptr [[V2:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP4]], ptr [[V3:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP5]], ptr [[V4:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double>, <vscale x 1 x double> } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x double> [[TMP6]], ptr [[V5:%.*]], align 8
// CHECK-RV64-NEXT:    ret void
//
void test_vlsseg6e64_v_f64m1_m(vfloat64m1_t *v0, vfloat64m1_t *v1, vfloat64m1_t *v2, vfloat64m1_t *v3, vfloat64m1_t *v4, vfloat64m1_t *v5, vbool64_t mask, const double *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlsseg6e64_v_f64m1_m(v0, v1, v2, v3, v4, v5, mask, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlsseg6e64_v_i64m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } @llvm.riscv.vlsseg6.mask.nxv1i64.i64(<vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP1]], ptr [[V0:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP2]], ptr [[V1:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP3]], ptr [[V2:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP4]], ptr [[V3:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP5]], ptr [[V4:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP6]], ptr [[V5:%.*]], align 8
// CHECK-RV64-NEXT:    ret void
//
void test_vlsseg6e64_v_i64m1_m(vint64m1_t *v0, vint64m1_t *v1, vint64m1_t *v2, vint64m1_t *v3, vint64m1_t *v4, vint64m1_t *v5, vbool64_t mask, const int64_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlsseg6e64_v_i64m1_m(v0, v1, v2, v3, v4, v5, mask, base, bstride, vl);
}

// CHECK-RV64-LABEL: @test_vlsseg6e64_v_u64m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } @llvm.riscv.vlsseg6.mask.nxv1i64.i64(<vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, <vscale x 1 x i64> poison, ptr [[BASE:%.*]], i64 [[BSTRIDE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP1]], ptr [[V0:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP2]], ptr [[V1:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP3]], ptr [[V2:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP4]], ptr [[V3:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP5]], ptr [[V4:%.*]], align 8
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64>, <vscale x 1 x i64> } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x i64> [[TMP6]], ptr [[V5:%.*]], align 8
// CHECK-RV64-NEXT:    ret void
//
void test_vlsseg6e64_v_u64m1_m(vuint64m1_t *v0, vuint64m1_t *v1, vuint64m1_t *v2, vuint64m1_t *v3, vuint64m1_t *v4, vuint64m1_t *v5, vbool64_t mask, const uint64_t *base, ptrdiff_t bstride, size_t vl) {
  return __riscv_vlsseg6e64_v_u64m1_m(v0, v1, v2, v3, v4, v5, mask, base, bstride, vl);
}

