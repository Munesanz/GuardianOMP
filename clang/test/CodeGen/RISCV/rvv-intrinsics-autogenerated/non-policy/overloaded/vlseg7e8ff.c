// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -target-feature +zfh \
// RUN:   -target-feature +experimental-zvfh -disable-O0-optnone  \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_i8mf8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv1i8.i64(<vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_i8mf8_m(vint8mf8_t *v0, vint8mf8_t *v1, vint8mf8_t *v2, vint8mf8_t *v3, vint8mf8_t *v4, vint8mf8_t *v5, vint8mf8_t *v6, vbool64_t mask, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_i8mf4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv2i8.i64(<vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_i8mf4_m(vint8mf4_t *v0, vint8mf4_t *v1, vint8mf4_t *v2, vint8mf4_t *v3, vint8mf4_t *v4, vint8mf4_t *v5, vint8mf4_t *v6, vbool32_t mask, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_i8mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv4i8.i64(<vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_i8mf2_m(vint8mf2_t *v0, vint8mf2_t *v1, vint8mf2_t *v2, vint8mf2_t *v3, vint8mf2_t *v4, vint8mf2_t *v5, vint8mf2_t *v6, vbool16_t mask, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_i8m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv8i8.i64(<vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_i8m1_m(vint8m1_t *v0, vint8m1_t *v1, vint8m1_t *v2, vint8m1_t *v3, vint8m1_t *v4, vint8m1_t *v5, vint8m1_t *v6, vbool8_t mask, const int8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_u8mf8_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv1i8.i64(<vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, <vscale x 1 x i8> poison, ptr [[BASE:%.*]], <vscale x 1 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 1 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, <vscale x 1 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_u8mf8_m(vuint8mf8_t *v0, vuint8mf8_t *v1, vuint8mf8_t *v2, vuint8mf8_t *v3, vuint8mf8_t *v4, vuint8mf8_t *v5, vuint8mf8_t *v6, vbool64_t mask, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_u8mf4_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv2i8.i64(<vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, <vscale x 2 x i8> poison, ptr [[BASE:%.*]], <vscale x 2 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 2 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, <vscale x 2 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_u8mf4_m(vuint8mf4_t *v0, vuint8mf4_t *v1, vuint8mf4_t *v2, vuint8mf4_t *v3, vuint8mf4_t *v4, vuint8mf4_t *v5, vuint8mf4_t *v6, vbool32_t mask, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_u8mf2_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv4i8.i64(<vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, <vscale x 4 x i8> poison, ptr [[BASE:%.*]], <vscale x 4 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 4 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, <vscale x 4 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_u8mf2_m(vuint8mf2_t *v0, vuint8mf2_t *v1, vuint8mf2_t *v2, vuint8mf2_t *v3, vuint8mf2_t *v4, vuint8mf2_t *v5, vuint8mf2_t *v6, vbool16_t mask, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

// CHECK-RV64-LABEL: @test_vlseg7e8ff_v_u8m1_m(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } @llvm.riscv.vlseg7ff.mask.nxv8i8.i64(<vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, <vscale x 8 x i8> poison, ptr [[BASE:%.*]], <vscale x 8 x i1> [[MASK:%.*]], i64 [[VL:%.*]], i64 3)
// CHECK-RV64-NEXT:    [[TMP1:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 0
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP1]], ptr [[V0:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP2:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 1
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP2]], ptr [[V1:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP3:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 2
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP3]], ptr [[V2:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP4:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 3
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP4]], ptr [[V3:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP5:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 4
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP5]], ptr [[V4:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP6:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 5
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP6]], ptr [[V5:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP7:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 6
// CHECK-RV64-NEXT:    store <vscale x 8 x i8> [[TMP7]], ptr [[V6:%.*]], align 1
// CHECK-RV64-NEXT:    [[TMP8:%.*]] = extractvalue { <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, <vscale x 8 x i8>, i64 } [[TMP0]], 7
// CHECK-RV64-NEXT:    store i64 [[TMP8]], ptr [[NEW_VL:%.*]], align 1
// CHECK-RV64-NEXT:    ret void
//
void test_vlseg7e8ff_v_u8m1_m(vuint8m1_t *v0, vuint8m1_t *v1, vuint8m1_t *v2, vuint8m1_t *v3, vuint8m1_t *v4, vuint8m1_t *v5, vuint8m1_t *v6, vbool8_t mask, const uint8_t *base, size_t *new_vl, size_t vl) {
  return __riscv_vlseg7e8ff(v0, v1, v2, v3, v4, v5, v6, mask, base, new_vl, vl);
}

