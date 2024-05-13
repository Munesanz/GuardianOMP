; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=slp-vectorizer -S -mtriple=x86_64-unknown-linux-gnu < %s | FileCheck %s

define i16 @test() {
; CHECK-LABEL: @test(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A:%.*]] = getelementptr [1000 x i64], ptr null, i64 0, i64 5
; CHECK-NEXT:    [[A1:%.*]] = getelementptr [1000 x i64], ptr null, i64 0, i64 6
; CHECK-NEXT:    [[A2:%.*]] = getelementptr [1000 x i64], ptr null, i64 0, i64 7
; CHECK-NEXT:    br label [[WHILE:%.*]]
; CHECK:       while:
; CHECK-NEXT:    [[PH:%.*]] = phi i64 [ 0, [[ENTRY:%.*]] ], [ [[OP_RDX5:%.*]], [[WHILE]] ]
; CHECK-NEXT:    [[TMP0:%.*]] = load i64, ptr null, align 8
; CHECK-NEXT:    [[TMP1:%.*]] = load i64, ptr null, align 8
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[A1]], align 16
; CHECK-NEXT:    [[TMP3:%.*]] = load <2 x i64>, ptr [[A2]], align 8
; CHECK-NEXT:    [[TMP4:%.*]] = load <4 x i64>, ptr [[A]], align 8
; CHECK-NEXT:    [[TMP5:%.*]] = shufflevector <2 x i64> [[TMP3]], <2 x i64> poison, <8 x i32> <i32 0, i32 1, i32 poison, i32 poison, i32 poison, i32 poison, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP6:%.*]] = insertelement <8 x i64> [[TMP5]], i64 [[TMP1]], i32 2
; CHECK-NEXT:    [[TMP7:%.*]] = insertelement <8 x i64> [[TMP6]], i64 [[TMP2]], i32 3
; CHECK-NEXT:    [[TMP8:%.*]] = shufflevector <4 x i64> [[TMP4]], <4 x i64> poison, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 poison, i32 poison, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP9:%.*]] = shufflevector <8 x i64> [[TMP7]], <8 x i64> [[TMP8]], <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 8, i32 9, i32 10, i32 11>
; CHECK-NEXT:    [[TMP10:%.*]] = shufflevector <8 x i64> [[TMP9]], <8 x i64> zeroinitializer, <8 x i32> <i32 8, i32 8, i32 2, i32 3, i32 4, i32 5, i32 8, i32 8>
; CHECK-NEXT:    [[TMP11:%.*]] = call i64 @llvm.vector.reduce.xor.v8i64(<8 x i64> [[TMP10]])
; CHECK-NEXT:    [[OP_RDX5]] = xor i64 [[TMP0]], [[TMP11]]
; CHECK-NEXT:    br label [[WHILE]]
;
entry:
  %a = getelementptr [1000 x i64], ptr null, i64 0, i64 5
  %a1 = getelementptr [1000 x i64], ptr null, i64 0, i64 6
  %a2 = getelementptr [1000 x i64], ptr null, i64 0, i64 7
  %a3 = getelementptr [1000 x i64], ptr null, i64 0, i64 8
  br label %while

while:
  %ph = phi i64 [ 0, %entry ], [ %xor, %while ]
  %0 = load i64, ptr null, align 8
  %1 = load i64, ptr %a1, align 16
  %2 = load i64, ptr %a2, align 8
  %3 = load i64, ptr %a3, align 16
  %4 = load i64, ptr null, align 8
  %5 = load i64, ptr %a, align 8
  %6 = load i64, ptr %a1, align 16
  %7 = load i64, ptr %a2, align 8
  %8 = load i64, ptr %a3, align 16
  %9 = xor i64 %0, %1
  %10 = xor i64 %9, %2
  %11 = xor i64 %10, %3
  %12 = xor i64 %11, %4
  %13 = xor i64 %12, %0
  %14 = xor i64 %13, %1
  %15 = xor i64 %14, %2
  %16 = xor i64 %15, %3
  %17 = xor i64 %16, %4
  %18 = xor i64 %17, %0
  %19 = xor i64 %18, %1
  %20 = xor i64 %19, %2
  %21 = xor i64 %20, %3
  %22 = xor i64 %21, %4
  %23 = xor i64 %22, %5
  %24 = xor i64 %23, %6
  %25 = xor i64 %24, %2
  %26 = xor i64 %25, %3
  %27 = xor i64 %26, %4
  %28 = xor i64 %27, %5
  %29 = xor i64 %28, %6
  %30 = xor i64 %29, %7
  %31 = xor i64 %30, %8
  %32 = xor i64 %31, %4
  %33 = xor i64 %32, %5
  %34 = xor i64 %33, %6
  %35 = xor i64 %34, %7
  %xor = xor i64 %35, %8
  br label %while
}
