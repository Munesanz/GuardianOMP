// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// RUN: %clang_cc1 -triple thumbv8.1m.main-none-none-eabi -target-feature +mve.fp -mfloat-abi hard -O0 -disable-O0-optnone -S -emit-llvm -o - %s | opt -S -passes=mem2reg,sroa | FileCheck %s
// RUN: %clang_cc1 -triple thumbv8.1m.main-none-none-eabi -target-feature +mve.fp -mfloat-abi hard -O0 -disable-O0-optnone -DPOLYMORPHIC -S -emit-llvm -o - %s | opt -S -passes=mem2reg,sroa | FileCheck %s

// REQUIRES: aarch64-registered-target || arm-registered-target

#include <arm_mve.h>

// CHECK-LABEL: @test_vminvq_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.minv.v16i8(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 0)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i8
// CHECK-NEXT:    ret i8 [[TMP2]]
//
int8_t test_vminvq_s8(int8_t a, int8x16_t b) {
#ifdef POLYMORPHIC
  return vminvq(a, b);
#else  /* POLYMORPHIC */
  return vminvq_s8(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.minv.v8i16(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 0)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i16
// CHECK-NEXT:    ret i16 [[TMP2]]
//
int16_t test_vminvq_s16(int16_t a, int16x8_t b) {
#ifdef POLYMORPHIC
  return vminvq(a, b);
#else  /* POLYMORPHIC */
  return vminvq_s16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call i32 @llvm.arm.mve.minv.v4i32(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 0)
// CHECK-NEXT:    ret i32 [[TMP0]]
//
int32_t test_vminvq_s32(int32_t a, int32x4_t b) {
#ifdef POLYMORPHIC
  return vminvq(a, b);
#else  /* POLYMORPHIC */
  return vminvq_s32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_u8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.minv.v16i8(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 1)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i8
// CHECK-NEXT:    ret i8 [[TMP2]]
//
uint8_t test_vminvq_u8(uint8_t a, uint8x16_t b) {
#ifdef POLYMORPHIC
  return vminvq(a, b);
#else  /* POLYMORPHIC */
  return vminvq_u8(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_u16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.minv.v8i16(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 1)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i16
// CHECK-NEXT:    ret i16 [[TMP2]]
//
uint16_t test_vminvq_u16(uint16_t a, uint16x8_t b) {
#ifdef POLYMORPHIC
  return vminvq(a, b);
#else  /* POLYMORPHIC */
  return vminvq_u16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_u32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call i32 @llvm.arm.mve.minv.v4i32(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 1)
// CHECK-NEXT:    ret i32 [[TMP0]]
//
uint32_t test_vminvq_u32(uint32_t a, uint32x4_t b) {
#ifdef POLYMORPHIC
  return vminvq(a, b);
#else  /* POLYMORPHIC */
  return vminvq_u32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.maxv.v16i8(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 0)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i8
// CHECK-NEXT:    ret i8 [[TMP2]]
//
int8_t test_vmaxvq_s8(int8_t a, int8x16_t b) {
#ifdef POLYMORPHIC
  return vmaxvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxvq_s8(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.maxv.v8i16(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 0)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i16
// CHECK-NEXT:    ret i16 [[TMP2]]
//
int16_t test_vmaxvq_s16(int16_t a, int16x8_t b) {
#ifdef POLYMORPHIC
  return vmaxvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxvq_s16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call i32 @llvm.arm.mve.maxv.v4i32(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 0)
// CHECK-NEXT:    ret i32 [[TMP0]]
//
int32_t test_vmaxvq_s32(int32_t a, int32x4_t b) {
#ifdef POLYMORPHIC
  return vmaxvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxvq_s32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_u8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.maxv.v16i8(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 1)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i8
// CHECK-NEXT:    ret i8 [[TMP2]]
//
uint8_t test_vmaxvq_u8(uint8_t a, uint8x16_t b) {
#ifdef POLYMORPHIC
  return vmaxvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxvq_u8(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_u16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.maxv.v8i16(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 1)
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i16
// CHECK-NEXT:    ret i16 [[TMP2]]
//
uint16_t test_vmaxvq_u16(uint16_t a, uint16x8_t b) {
#ifdef POLYMORPHIC
  return vmaxvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxvq_u16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_u32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call i32 @llvm.arm.mve.maxv.v4i32(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 1)
// CHECK-NEXT:    ret i32 [[TMP0]]
//
uint32_t test_vmaxvq_u32(uint32_t a, uint32x4_t b) {
#ifdef POLYMORPHIC
  return vmaxvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxvq_u32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminavq_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.minav.v16i8(i32 [[TMP0]], <16 x i8> [[B:%.*]])
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i8
// CHECK-NEXT:    ret i8 [[TMP2]]
//
uint8_t test_vminavq_s8(uint8_t a, int8x16_t b) {
#ifdef POLYMORPHIC
  return vminavq(a, b);
#else  /* POLYMORPHIC */
  return vminavq_s8(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminavq_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.minav.v8i16(i32 [[TMP0]], <8 x i16> [[B:%.*]])
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i16
// CHECK-NEXT:    ret i16 [[TMP2]]
//
uint16_t test_vminavq_s16(uint16_t a, int16x8_t b) {
#ifdef POLYMORPHIC
  return vminavq(a, b);
#else  /* POLYMORPHIC */
  return vminavq_s16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminavq_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call i32 @llvm.arm.mve.minav.v4i32(i32 [[A:%.*]], <4 x i32> [[B:%.*]])
// CHECK-NEXT:    ret i32 [[TMP0]]
//
uint32_t test_vminavq_s32(uint32_t a, int32x4_t b) {
#ifdef POLYMORPHIC
  return vminavq(a, b);
#else  /* POLYMORPHIC */
  return vminavq_s32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxavq_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.maxav.v16i8(i32 [[TMP0]], <16 x i8> [[B:%.*]])
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i8
// CHECK-NEXT:    ret i8 [[TMP2]]
//
uint8_t test_vmaxavq_s8(uint8_t a, int8x16_t b) {
#ifdef POLYMORPHIC
  return vmaxavq(a, b);
#else  /* POLYMORPHIC */
  return vmaxavq_s8(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxavq_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.arm.mve.maxav.v8i16(i32 [[TMP0]], <8 x i16> [[B:%.*]])
// CHECK-NEXT:    [[TMP2:%.*]] = trunc i32 [[TMP1]] to i16
// CHECK-NEXT:    ret i16 [[TMP2]]
//
uint16_t test_vmaxavq_s16(uint16_t a, int16x8_t b) {
#ifdef POLYMORPHIC
  return vmaxavq(a, b);
#else  /* POLYMORPHIC */
  return vmaxavq_s16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxavq_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call i32 @llvm.arm.mve.maxav.v4i32(i32 [[A:%.*]], <4 x i32> [[B:%.*]])
// CHECK-NEXT:    ret i32 [[TMP0]]
//
uint32_t test_vmaxavq_s32(uint32_t a, int32x4_t b) {
#ifdef POLYMORPHIC
  return vmaxavq(a, b);
#else  /* POLYMORPHIC */
  return vmaxavq_s32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmvq_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call half @llvm.arm.mve.minnmv.f16.v8f16(half [[A:%.*]], <8 x half> [[B:%.*]])
// CHECK-NEXT:    ret half [[TMP0]]
//
float16_t test_vminnmvq_f16(float16_t a, float16x8_t b) {
#ifdef POLYMORPHIC
  return vminnmvq(a, b);
#else  /* POLYMORPHIC */
  return vminnmvq_f16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmvq_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call float @llvm.arm.mve.minnmv.f32.v4f32(float [[A:%.*]], <4 x float> [[B:%.*]])
// CHECK-NEXT:    ret float [[TMP0]]
//
float32_t test_vminnmvq_f32(float32_t a, float32x4_t b) {
#ifdef POLYMORPHIC
  return vminnmvq(a, b);
#else  /* POLYMORPHIC */
  return vminnmvq_f32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmavq_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call half @llvm.arm.mve.minnmav.f16.v8f16(half [[A:%.*]], <8 x half> [[B:%.*]])
// CHECK-NEXT:    ret half [[TMP0]]
//
float16_t test_vminnmavq_f16(float16_t a, float16x8_t b) {
#ifdef POLYMORPHIC
  return vminnmavq(a, b);
#else  /* POLYMORPHIC */
  return vminnmavq_f16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmavq_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call float @llvm.arm.mve.minnmav.f32.v4f32(float [[A:%.*]], <4 x float> [[B:%.*]])
// CHECK-NEXT:    ret float [[TMP0]]
//
float32_t test_vminnmavq_f32(float32_t a, float32x4_t b) {
#ifdef POLYMORPHIC
  return vminnmavq(a, b);
#else  /* POLYMORPHIC */
  return vminnmavq_f32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmvq_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call half @llvm.arm.mve.maxnmv.f16.v8f16(half [[A:%.*]], <8 x half> [[B:%.*]])
// CHECK-NEXT:    ret half [[TMP0]]
//
float16_t test_vmaxnmvq_f16(float16_t a, float16x8_t b) {
#ifdef POLYMORPHIC
  return vmaxnmvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxnmvq_f16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmvq_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call float @llvm.arm.mve.maxnmv.f32.v4f32(float [[A:%.*]], <4 x float> [[B:%.*]])
// CHECK-NEXT:    ret float [[TMP0]]
//
float32_t test_vmaxnmvq_f32(float32_t a, float32x4_t b) {
#ifdef POLYMORPHIC
  return vmaxnmvq(a, b);
#else  /* POLYMORPHIC */
  return vmaxnmvq_f32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmavq_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call half @llvm.arm.mve.maxnmav.f16.v8f16(half [[A:%.*]], <8 x half> [[B:%.*]])
// CHECK-NEXT:    ret half [[TMP0]]
//
float16_t test_vmaxnmavq_f16(float16_t a, float16x8_t b) {
#ifdef POLYMORPHIC
  return vmaxnmavq(a, b);
#else  /* POLYMORPHIC */
  return vmaxnmavq_f16(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmavq_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = call float @llvm.arm.mve.maxnmav.f32.v4f32(float [[A:%.*]], <4 x float> [[B:%.*]])
// CHECK-NEXT:    ret float [[TMP0]]
//
float32_t test_vmaxnmavq_f32(float32_t a, float32x4_t b) {
#ifdef POLYMORPHIC
  return vmaxnmavq(a, b);
#else  /* POLYMORPHIC */
  return vmaxnmavq_f32(a, b);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_p_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.minv.predicated.v16i8.v16i1(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 0, <16 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i8
// CHECK-NEXT:    ret i8 [[TMP4]]
//
int8_t test_vminvq_p_s8(int8_t a, int8x16_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminvq_p_s8(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_p_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.minv.predicated.v8i16.v8i1(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 0, <8 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i16
// CHECK-NEXT:    ret i16 [[TMP4]]
//
int16_t test_vminvq_p_s16(int16_t a, int16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminvq_p_s16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_p_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call i32 @llvm.arm.mve.minv.predicated.v4i32.v4i1(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 0, <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret i32 [[TMP2]]
//
int32_t test_vminvq_p_s32(int32_t a, int32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminvq_p_s32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_p_u8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.minv.predicated.v16i8.v16i1(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 1, <16 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i8
// CHECK-NEXT:    ret i8 [[TMP4]]
//
uint8_t test_vminvq_p_u8(uint8_t a, uint8x16_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminvq_p_u8(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_p_u16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.minv.predicated.v8i16.v8i1(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 1, <8 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i16
// CHECK-NEXT:    ret i16 [[TMP4]]
//
uint16_t test_vminvq_p_u16(uint16_t a, uint16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminvq_p_u16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminvq_p_u32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call i32 @llvm.arm.mve.minv.predicated.v4i32.v4i1(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 1, <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret i32 [[TMP2]]
//
uint32_t test_vminvq_p_u32(uint32_t a, uint32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminvq_p_u32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_p_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.maxv.predicated.v16i8.v16i1(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 0, <16 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i8
// CHECK-NEXT:    ret i8 [[TMP4]]
//
int8_t test_vmaxvq_p_s8(int8_t a, int8x16_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxvq_p_s8(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_p_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.maxv.predicated.v8i16.v8i1(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 0, <8 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i16
// CHECK-NEXT:    ret i16 [[TMP4]]
//
int16_t test_vmaxvq_p_s16(int16_t a, int16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxvq_p_s16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_p_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call i32 @llvm.arm.mve.maxv.predicated.v4i32.v4i1(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 0, <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret i32 [[TMP2]]
//
int32_t test_vmaxvq_p_s32(int32_t a, int32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxvq_p_s32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_p_u8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.maxv.predicated.v16i8.v16i1(i32 [[TMP0]], <16 x i8> [[B:%.*]], i32 1, <16 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i8
// CHECK-NEXT:    ret i8 [[TMP4]]
//
uint8_t test_vmaxvq_p_u8(uint8_t a, uint8x16_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxvq_p_u8(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_p_u16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.maxv.predicated.v8i16.v8i1(i32 [[TMP0]], <8 x i16> [[B:%.*]], i32 1, <8 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i16
// CHECK-NEXT:    ret i16 [[TMP4]]
//
uint16_t test_vmaxvq_p_u16(uint16_t a, uint16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxvq_p_u16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxvq_p_u32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call i32 @llvm.arm.mve.maxv.predicated.v4i32.v4i1(i32 [[A:%.*]], <4 x i32> [[B:%.*]], i32 1, <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret i32 [[TMP2]]
//
uint32_t test_vmaxvq_p_u32(uint32_t a, uint32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxvq_p_u32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminavq_p_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.minav.predicated.v16i8.v16i1(i32 [[TMP0]], <16 x i8> [[B:%.*]], <16 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i8
// CHECK-NEXT:    ret i8 [[TMP4]]
//
uint8_t test_vminavq_p_s8(uint8_t a, int8x16_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminavq_p_s8(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminavq_p_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.minav.predicated.v8i16.v8i1(i32 [[TMP0]], <8 x i16> [[B:%.*]], <8 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i16
// CHECK-NEXT:    ret i16 [[TMP4]]
//
uint16_t test_vminavq_p_s16(uint16_t a, int16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminavq_p_s16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminavq_p_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call i32 @llvm.arm.mve.minav.predicated.v4i32.v4i1(i32 [[A:%.*]], <4 x i32> [[B:%.*]], <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret i32 [[TMP2]]
//
uint32_t test_vminavq_p_s32(uint32_t a, int32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminavq_p_s32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxavq_p_s8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i8 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.maxav.predicated.v16i8.v16i1(i32 [[TMP0]], <16 x i8> [[B:%.*]], <16 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i8
// CHECK-NEXT:    ret i8 [[TMP4]]
//
uint8_t test_vmaxavq_p_s8(uint8_t a, int8x16_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxavq_p_s8(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxavq_p_s16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[A:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP2:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.arm.mve.maxav.predicated.v8i16.v8i1(i32 [[TMP0]], <8 x i16> [[B:%.*]], <8 x i1> [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = trunc i32 [[TMP3]] to i16
// CHECK-NEXT:    ret i16 [[TMP4]]
//
uint16_t test_vmaxavq_p_s16(uint16_t a, int16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxavq_p_s16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxavq_p_s32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call i32 @llvm.arm.mve.maxav.predicated.v4i32.v4i1(i32 [[A:%.*]], <4 x i32> [[B:%.*]], <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret i32 [[TMP2]]
//
uint32_t test_vmaxavq_p_s32(uint32_t a, int32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxavq_p_s32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmvq_p_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call half @llvm.arm.mve.minnmv.predicated.f16.v8f16.v8i1(half [[A:%.*]], <8 x half> [[B:%.*]], <8 x i1> [[TMP1]])
// CHECK-NEXT:    ret half [[TMP2]]
//
float16_t test_vminnmvq_p_f16(float16_t a, float16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminnmvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminnmvq_p_f16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmvq_p_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call float @llvm.arm.mve.minnmv.predicated.f32.v4f32.v4i1(float [[A:%.*]], <4 x float> [[B:%.*]], <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret float [[TMP2]]
//
float32_t test_vminnmvq_p_f32(float32_t a, float32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminnmvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminnmvq_p_f32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmavq_p_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call half @llvm.arm.mve.minnmav.predicated.f16.v8f16.v8i1(half [[A:%.*]], <8 x half> [[B:%.*]], <8 x i1> [[TMP1]])
// CHECK-NEXT:    ret half [[TMP2]]
//
float16_t test_vminnmavq_p_f16(float16_t a, float16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminnmavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminnmavq_p_f16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vminnmavq_p_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call float @llvm.arm.mve.minnmav.predicated.f32.v4f32.v4i1(float [[A:%.*]], <4 x float> [[B:%.*]], <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret float [[TMP2]]
//
float32_t test_vminnmavq_p_f32(float32_t a, float32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vminnmavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vminnmavq_p_f32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmvq_p_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call half @llvm.arm.mve.maxnmv.predicated.f16.v8f16.v8i1(half [[A:%.*]], <8 x half> [[B:%.*]], <8 x i1> [[TMP1]])
// CHECK-NEXT:    ret half [[TMP2]]
//
float16_t test_vmaxnmvq_p_f16(float16_t a, float16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxnmvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxnmvq_p_f16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmvq_p_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call float @llvm.arm.mve.maxnmv.predicated.f32.v4f32.v4i1(float [[A:%.*]], <4 x float> [[B:%.*]], <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret float [[TMP2]]
//
float32_t test_vmaxnmvq_p_f32(float32_t a, float32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxnmvq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxnmvq_p_f32(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmavq_p_f16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call half @llvm.arm.mve.maxnmav.predicated.f16.v8f16.v8i1(half [[A:%.*]], <8 x half> [[B:%.*]], <8 x i1> [[TMP1]])
// CHECK-NEXT:    ret half [[TMP2]]
//
float16_t test_vmaxnmavq_p_f16(float16_t a, float16x8_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxnmavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxnmavq_p_f16(a, b, p);
#endif /* POLYMORPHIC */
}

// CHECK-LABEL: @test_vmaxnmavq_p_f32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = zext i16 [[P:%.*]] to i32
// CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 [[TMP0]])
// CHECK-NEXT:    [[TMP2:%.*]] = call float @llvm.arm.mve.maxnmav.predicated.f32.v4f32.v4i1(float [[A:%.*]], <4 x float> [[B:%.*]], <4 x i1> [[TMP1]])
// CHECK-NEXT:    ret float [[TMP2]]
//
float32_t test_vmaxnmavq_p_f32(float32_t a, float32x4_t b, mve_pred16_t p) {
#ifdef POLYMORPHIC
  return vmaxnmavq_p(a, b, p);
#else  /* POLYMORPHIC */
  return vmaxnmavq_p_f32(a, b, p);
#endif /* POLYMORPHIC */
}
