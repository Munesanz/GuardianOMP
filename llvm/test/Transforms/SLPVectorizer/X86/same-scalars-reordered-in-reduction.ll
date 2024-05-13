; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 2
; RUN: opt -S -passes=slp-vectorizer -mtriple=x86_64-unknown-linux-gnu < %s | FileCheck %s

define i32 @test() {
; CHECK-LABEL: define i32 @test() {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SQ:%.*]] = alloca [64 x i32], i32 0, align 16
; CHECK-NEXT:    [[TMP0:%.*]] = getelementptr inbounds [64 x i32], ptr [[SQ]], i64 0, i64 1
; CHECK-NEXT:    [[TMP1:%.*]] = load <4 x i32>, ptr [[TMP0]], align 4
; CHECK-NEXT:    [[TMP2:%.*]] = mul <4 x i32> [[TMP1]], <i32 2, i32 3, i32 2, i32 1>
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @llvm.vector.reduce.add.v4i32(<4 x i32> [[TMP2]])
; CHECK-NEXT:    ret i32 [[TMP3]]
;
entry:
  %sq = alloca [64 x i32], i32 0, align 16
  %0 = getelementptr inbounds [64 x i32], ptr %sq, i64 0, i64 1
  %elt_1 = load i32, ptr %0, align 4
  %1 = getelementptr [64 x i32], ptr %sq, i64 0, i64 2
  %elt_2 = load i32, ptr %1, align 8
  %2 = getelementptr [64 x i32], ptr %sq, i64 0, i64 3
  %elt_3 = load i32, ptr %2, align 4
  %3 = getelementptr [64 x i32], ptr %sq, i64 0, i64 4
  %elt_4 = load i32, ptr %3, align 16

  %4 = add i32 %elt_2, %elt_3
  %5 = add i32 %4, %elt_2
  %6 = add i32 %5, %elt_1
  %7 = add i32 %6, %elt_4
  %8 = add i32 %7, %elt_3
  %9 = add i32 %8, %elt_2
  %10 = add i32 %9, %elt_1

  ret i32 %10
}
