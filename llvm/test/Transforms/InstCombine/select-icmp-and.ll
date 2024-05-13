; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instcombine -S | FileCheck %s

;; ((X & 27) ? 27 : 0)

define i41 @test5(i41 %X) {
; CHECK-LABEL: @test5(
; CHECK-NEXT:    [[Y:%.*]] = and i41 [[X:%.*]], 32
; CHECK-NEXT:    ret i41 [[Y]]
;
  %Y = and i41 %X, 32
  %t = icmp ne i41 %Y, 0
  %V = select i1 %t, i41 32, i41 0
  ret i41 %V
}

;; ((X & 27) ? 27 : 0)

define i1023 @test6(i1023 %X) {
; CHECK-LABEL: @test6(
; CHECK-NEXT:    [[Y:%.*]] = and i1023 [[X:%.*]], 64
; CHECK-NEXT:    ret i1023 [[Y]]
;
  %Y = and i1023 %X, 64
  %t = icmp ne i1023 %Y, 0
  %V = select i1 %t, i1023 64, i1023 0
  ret i1023 %V
}

define i32 @test35(i32 %x) {
; CHECK-LABEL: @test35(
; CHECK-NEXT:    [[CMP:%.*]] = icmp sgt i32 [[X:%.*]], -1
; CHECK-NEXT:    [[COND:%.*]] = select i1 [[CMP]], i32 60, i32 100
; CHECK-NEXT:    ret i32 [[COND]]
;
  %cmp = icmp sge i32 %x, 0
  %cond = select i1 %cmp, i32 60, i32 100
  ret i32 %cond
}

define <2 x i32> @test35vec(<2 x i32> %x) {
; CHECK-LABEL: @test35vec(
; CHECK-NEXT:    [[CMP:%.*]] = icmp sgt <2 x i32> [[X:%.*]], <i32 -1, i32 -1>
; CHECK-NEXT:    [[COND:%.*]] = select <2 x i1> [[CMP]], <2 x i32> <i32 60, i32 60>, <2 x i32> <i32 100, i32 100>
; CHECK-NEXT:    ret <2 x i32> [[COND]]
;
  %cmp = icmp sge <2 x i32> %x, <i32 0, i32 0>
  %cond = select <2 x i1> %cmp, <2 x i32> <i32 60, i32 60>, <2 x i32> <i32 100, i32 100>
  ret <2 x i32> %cond
}

; Make sure we can still perform this optimization with a truncate present
define i32 @test35_with_trunc(i64 %x) {
; CHECK-LABEL: @test35_with_trunc(
; CHECK-NEXT:    [[TMP1:%.*]] = and i64 [[X:%.*]], 2147483648
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i64 [[TMP1]], 0
; CHECK-NEXT:    [[COND:%.*]] = select i1 [[CMP]], i32 60, i32 100
; CHECK-NEXT:    ret i32 [[COND]]
;
  %x1 = trunc i64 %x to i32
  %cmp = icmp sge i32 %x1, 0
  %cond = select i1 %cmp, i32 60, i32 100
  ret i32 %cond
}

define i32 @test36(i32 %x) {
; CHECK-LABEL: @test36(
; CHECK-NEXT:    [[CMP:%.*]] = icmp slt i32 [[X:%.*]], 0
; CHECK-NEXT:    [[COND:%.*]] = select i1 [[CMP]], i32 60, i32 100
; CHECK-NEXT:    ret i32 [[COND]]
;
  %cmp = icmp slt i32 %x, 0
  %cond = select i1 %cmp, i32 60, i32 100
  ret i32 %cond
}

define <2 x i32> @test36vec(<2 x i32> %x) {
; CHECK-LABEL: @test36vec(
; CHECK-NEXT:    [[CMP:%.*]] = icmp slt <2 x i32> [[X:%.*]], zeroinitializer
; CHECK-NEXT:    [[COND:%.*]] = select <2 x i1> [[CMP]], <2 x i32> <i32 60, i32 60>, <2 x i32> <i32 100, i32 100>
; CHECK-NEXT:    ret <2 x i32> [[COND]]
;
  %cmp = icmp slt <2 x i32> %x, <i32 0, i32 0>
  %cond = select <2 x i1> %cmp, <2 x i32> <i32 60, i32 60>, <2 x i32> <i32 100, i32 100>
  ret <2 x i32> %cond
}

define i32 @test37(i32 %x) {
; CHECK-LABEL: @test37(
; CHECK-NEXT:    [[CMP:%.*]] = icmp sgt i32 [[X:%.*]], -1
; CHECK-NEXT:    [[COND:%.*]] = select i1 [[CMP]], i32 1, i32 -1
; CHECK-NEXT:    ret i32 [[COND]]
;
  %cmp = icmp sgt i32 %x, -1
  %cond = select i1 %cmp, i32 1, i32 -1
  ret i32 %cond
}

define <2 x i32> @test37vec(<2 x i32> %x) {
; CHECK-LABEL: @test37vec(
; CHECK-NEXT:    [[CMP:%.*]] = icmp sgt <2 x i32> [[X:%.*]], <i32 -1, i32 -1>
; CHECK-NEXT:    [[COND:%.*]] = select <2 x i1> [[CMP]], <2 x i32> <i32 1, i32 1>, <2 x i32> <i32 -1, i32 -1>
; CHECK-NEXT:    ret <2 x i32> [[COND]]
;
  %cmp = icmp sgt <2 x i32> %x, <i32 -1, i32 -1>
  %cond = select <2 x i1> %cmp, <2 x i32> <i32 1, i32 1>, <2 x i32> <i32 -1, i32 -1>
  ret <2 x i32> %cond
}

define i32 @test65(i64 %x) {
; CHECK-LABEL: @test65(
; CHECK-NEXT:    [[TMP1:%.*]] = and i64 [[X:%.*]], 16
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq i64 [[TMP1]], 0
; CHECK-NEXT:    [[TMP2:%.*]] = select i1 [[DOTNOT]], i32 42, i32 40
; CHECK-NEXT:    ret i32 [[TMP2]]
;
  %1 = and i64 %x, 16
  %2 = icmp ne i64 %1, 0
  %3 = select i1 %2, i32 40, i32 42
  ret i32 %3
}

define <2 x i32> @test65vec(<2 x i64> %x) {
; CHECK-LABEL: @test65vec(
; CHECK-NEXT:    [[TMP1:%.*]] = and <2 x i64> [[X:%.*]], <i64 16, i64 16>
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq <2 x i64> [[TMP1]], zeroinitializer
; CHECK-NEXT:    [[TMP2:%.*]] = select <2 x i1> [[DOTNOT]], <2 x i32> <i32 42, i32 42>, <2 x i32> <i32 40, i32 40>
; CHECK-NEXT:    ret <2 x i32> [[TMP2]]
;
  %1 = and <2 x i64> %x, <i64 16, i64 16>
  %2 = icmp ne <2 x i64> %1, zeroinitializer
  %3 = select <2 x i1> %2, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %3
}

define i32 @test66(i64 %x) {
; CHECK-LABEL: @test66(
; CHECK-NEXT:    [[TMP1:%.*]] = and i64 [[X:%.*]], 4294967296
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq i64 [[TMP1]], 0
; CHECK-NEXT:    [[TMP2:%.*]] = select i1 [[DOTNOT]], i32 42, i32 40
; CHECK-NEXT:    ret i32 [[TMP2]]
;
  %1 = and i64 %x, 4294967296
  %2 = icmp ne i64 %1, 0
  %3 = select i1 %2, i32 40, i32 42
  ret i32 %3
}

define <2 x i32> @test66vec(<2 x i64> %x) {
; CHECK-LABEL: @test66vec(
; CHECK-NEXT:    [[TMP1:%.*]] = and <2 x i64> [[X:%.*]], <i64 4294967296, i64 4294967296>
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq <2 x i64> [[TMP1]], zeroinitializer
; CHECK-NEXT:    [[TMP2:%.*]] = select <2 x i1> [[DOTNOT]], <2 x i32> <i32 42, i32 42>, <2 x i32> <i32 40, i32 40>
; CHECK-NEXT:    ret <2 x i32> [[TMP2]]
;
  %1 = and <2 x i64> %x, <i64 4294967296, i64 4294967296>
  %2 = icmp ne <2 x i64> %1, zeroinitializer
  %3 = select <2 x i1> %2, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %3
}

; Make sure we don't try to optimize a scalar 'and' with a vector select.
define <2 x i32> @test66vec_scalar_and(i64 %x) {
; CHECK-LABEL: @test66vec_scalar_and(
; CHECK-NEXT:    [[TMP1:%.*]] = and i64 [[X:%.*]], 4294967296
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq i64 [[TMP1]], 0
; CHECK-NEXT:    [[TMP2:%.*]] = select i1 [[DOTNOT]], <2 x i32> <i32 42, i32 42>, <2 x i32> <i32 40, i32 40>
; CHECK-NEXT:    ret <2 x i32> [[TMP2]]
;
  %1 = and i64 %x, 4294967296
  %2 = icmp ne i64 %1, 0
  %3 = select i1 %2, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %3
}

define i32 @test67(i16 %x) {
; CHECK-LABEL: @test67(
; CHECK-NEXT:    [[TMP1:%.*]] = and i16 [[X:%.*]], 4
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq i16 [[TMP1]], 0
; CHECK-NEXT:    [[TMP2:%.*]] = select i1 [[DOTNOT]], i32 42, i32 40
; CHECK-NEXT:    ret i32 [[TMP2]]
;
  %1 = and i16 %x, 4
  %2 = icmp ne i16 %1, 0
  %3 = select i1 %2, i32 40, i32 42
  ret i32 %3
}

define <2 x i32> @test67vec(<2 x i16> %x) {
; CHECK-LABEL: @test67vec(
; CHECK-NEXT:    [[TMP1:%.*]] = and <2 x i16> [[X:%.*]], <i16 4, i16 4>
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq <2 x i16> [[TMP1]], zeroinitializer
; CHECK-NEXT:    [[TMP2:%.*]] = select <2 x i1> [[DOTNOT]], <2 x i32> <i32 42, i32 42>, <2 x i32> <i32 40, i32 40>
; CHECK-NEXT:    ret <2 x i32> [[TMP2]]
;
  %1 = and <2 x i16> %x, <i16 4, i16 4>
  %2 = icmp ne <2 x i16> %1, zeroinitializer
  %3 = select <2 x i1> %2, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %3
}

define i32 @test71(i32 %x) {
; CHECK-LABEL: @test71(
; CHECK-NEXT:    [[TMP1:%.*]] = and i32 [[X:%.*]], 128
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq i32 [[TMP1]], 0
; CHECK-NEXT:    [[TMP2:%.*]] = select i1 [[DOTNOT]], i32 42, i32 40
; CHECK-NEXT:    ret i32 [[TMP2]]
;
  %1 = and i32 %x, 128
  %2 = icmp ne i32 %1, 0
  %3 = select i1 %2, i32 40, i32 42
  ret i32 %3
}

define <2 x i32> @test71vec(<2 x i32> %x) {
; CHECK-LABEL: @test71vec(
; CHECK-NEXT:    [[TMP1:%.*]] = and <2 x i32> [[X:%.*]], <i32 128, i32 128>
; CHECK-NEXT:    [[DOTNOT:%.*]] = icmp eq <2 x i32> [[TMP1]], zeroinitializer
; CHECK-NEXT:    [[TMP2:%.*]] = select <2 x i1> [[DOTNOT]], <2 x i32> <i32 42, i32 42>, <2 x i32> <i32 40, i32 40>
; CHECK-NEXT:    ret <2 x i32> [[TMP2]]
;
  %1 = and <2 x i32> %x, <i32 128, i32 128>
  %2 = icmp ne <2 x i32> %1, <i32 0, i32 0>
  %3 = select <2 x i1> %2, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %3
}

define i32 @test72(i32 %x) {
; CHECK-LABEL: @test72(
; CHECK-NEXT:    [[TMP1:%.*]] = and i32 [[X:%.*]], 128
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq i32 [[TMP1]], 0
; CHECK-NEXT:    [[TMP3:%.*]] = select i1 [[TMP2]], i32 40, i32 42
; CHECK-NEXT:    ret i32 [[TMP3]]
;
  %1 = and i32 %x, 128
  %2 = icmp eq i32 %1, 0
  %3 = select i1 %2, i32 40, i32 42
  ret i32 %3
}

define <2 x i32> @test72vec(<2 x i32> %x) {
; CHECK-LABEL: @test72vec(
; CHECK-NEXT:    [[TMP1:%.*]] = and <2 x i32> [[X:%.*]], <i32 128, i32 128>
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq <2 x i32> [[TMP1]], zeroinitializer
; CHECK-NEXT:    [[TMP3:%.*]] = select <2 x i1> [[TMP2]], <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
; CHECK-NEXT:    ret <2 x i32> [[TMP3]]
;
  %1 = and <2 x i32> %x, <i32 128, i32 128>
  %2 = icmp eq <2 x i32> %1, <i32 0, i32 0>
  %3 = select <2 x i1> %2, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %3
}

define i32 @test73(i32 %x) {
; CHECK-LABEL: @test73(
; CHECK-NEXT:    [[TMP1:%.*]] = and i32 [[X:%.*]], 128
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq i32 [[TMP1]], 0
; CHECK-NEXT:    [[TMP3:%.*]] = select i1 [[TMP2]], i32 40, i32 42
; CHECK-NEXT:    ret i32 [[TMP3]]
;
  %1 = trunc i32 %x to i8
  %2 = icmp sgt i8 %1, -1
  %3 = select i1 %2, i32 40, i32 42
  ret i32 %3
}

define <2 x i32> @test73vec(<2 x i32> %x) {
; CHECK-LABEL: @test73vec(
; CHECK-NEXT:    [[TMP1:%.*]] = and <2 x i32> [[X:%.*]], <i32 128, i32 128>
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq <2 x i32> [[TMP1]], zeroinitializer
; CHECK-NEXT:    [[TMP3:%.*]] = select <2 x i1> [[TMP2]], <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
; CHECK-NEXT:    ret <2 x i32> [[TMP3]]
;
  %1 = trunc <2 x i32> %x to <2 x i8>
  %2 = icmp sgt <2 x i8> %1, <i8 -1, i8 -1>
  %3 = select <2 x i1> %2, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %3
}

define i32 @test74(i32 %x) {
; CHECK-LABEL: @test74(
; CHECK-NEXT:    [[TMP1:%.*]] = icmp sgt i32 [[X:%.*]], -1
; CHECK-NEXT:    [[TMP2:%.*]] = select i1 [[TMP1]], i32 40, i32 42
; CHECK-NEXT:    ret i32 [[TMP2]]
;
  %1 = icmp sgt i32 %x, -1
  %2 = select i1 %1, i32 40, i32 42
  ret i32 %2
}

define <2 x i32> @test74vec(<2 x i32> %x) {
; CHECK-LABEL: @test74vec(
; CHECK-NEXT:    [[TMP1:%.*]] = icmp sgt <2 x i32> [[X:%.*]], <i32 -1, i32 -1>
; CHECK-NEXT:    [[TMP2:%.*]] = select <2 x i1> [[TMP1]], <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
; CHECK-NEXT:    ret <2 x i32> [[TMP2]]
;
  %1 = icmp sgt <2 x i32> %x, <i32 -1, i32 -1>
  %2 = select <2 x i1> %1, <2 x i32> <i32 40, i32 40>, <2 x i32> <i32 42, i32 42>
  ret <2 x i32> %2
}

;; Code sequence for (X & 16) ? 16 : 0
define i32 @test15a(i32 %X) {
; CHECK-LABEL: @test15a(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 16
; CHECK-NEXT:    ret i32 [[T1]]
;
  %t1 = and i32 %X, 16
  %t2 = icmp eq i32 %t1, 0
  %t3 = select i1 %t2, i32 0, i32 16
  ret i32 %t3
}

;; Code sequence for (X & 32) ? 0 : 24
define i32 @test15b(i32 %X) {
; CHECK-LABEL: @test15b(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 32
; CHECK-NEXT:    [[T3:%.*]] = xor i32 [[T1]], 32
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %X, 32
  %t2 = icmp eq i32 %t1, 0
  %t3 = select i1 %t2, i32 32, i32 0
  ret i32 %t3
}

;; Alternate code sequence for (X & 16) ? 16 : 0
define i32 @test15c(i32 %X) {
; CHECK-LABEL: @test15c(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 16
; CHECK-NEXT:    ret i32 [[T1]]
;
  %t1 = and i32 %X, 16
  %t2 = icmp eq i32 %t1, 16
  %t3 = select i1 %t2, i32 16, i32 0
  ret i32 %t3
}

;; Alternate code sequence for (X & 16) ? 16 : 0
define i32 @test15d(i32 %X) {
; CHECK-LABEL: @test15d(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 16
; CHECK-NEXT:    ret i32 [[T1]]
;
  %t1 = and i32 %X, 16
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 16, i32 0
  ret i32 %t3
}

;; (a & 128) ? 256 : 0
define i32 @test15e(i32 %X) {
; CHECK-LABEL: @test15e(
; CHECK-NEXT:    [[T1:%.*]] = shl i32 [[X:%.*]], 1
; CHECK-NEXT:    [[T3:%.*]] = and i32 [[T1]], 256
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %X, 128
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 256, i32 0
  ret i32 %t3
}

;; (a & 128) ? 0 : 256
define i32 @test15f(i32 %X) {
; CHECK-LABEL: @test15f(
; CHECK-NEXT:    [[T1:%.*]] = shl i32 [[X:%.*]], 1
; CHECK-NEXT:    [[TMP1:%.*]] = and i32 [[T1]], 256
; CHECK-NEXT:    [[T3:%.*]] = xor i32 [[TMP1]], 256
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %X, 128
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 0, i32 256
  ret i32 %t3
}

;; (a & 8) ? -1 : -9
define i32 @test15g(i32 %X) {
; CHECK-LABEL: @test15g(
; CHECK-NEXT:    [[T3:%.*]] = or i32 [[X:%.*]], -9
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %X, 8
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 -1, i32 -9
  ret i32 %t3
}

;; (a & 8) ? -9 : -1
define i32 @test15h(i32 %X) {
; CHECK-LABEL: @test15h(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 8
; CHECK-NEXT:    [[T3:%.*]] = xor i32 [[T1]], -1
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %X, 8
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 -9, i32 -1
  ret i32 %t3
}

;; (a & 2) ? 577 : 1089
define i32 @test15i(i32 %X) {
; CHECK-LABEL: @test15i(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 2
; CHECK-NEXT:    [[T2_NOT:%.*]] = icmp eq i32 [[T1]], 0
; CHECK-NEXT:    [[T3:%.*]] = select i1 [[T2_NOT]], i32 1089, i32 577
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %X, 2
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 577, i32 1089
  ret i32 %t3
}

;; (a & 2) ? 1089 : 577
define i32 @test15j(i32 %X) {
; CHECK-LABEL: @test15j(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 2
; CHECK-NEXT:    [[T2_NOT:%.*]] = icmp eq i32 [[T1]], 0
; CHECK-NEXT:    [[T3:%.*]] = select i1 [[T2_NOT]], i32 577, i32 1089
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %X, 2
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 1089, i32 577
  ret i32 %t3
}

declare void @use1(i1)

; (X & 8) == 0 ? -3 : -11 --> (X & 8) ^ -3
; Extra cmp use ensures that cmp predicate canonicalization is thwarted.

define i32 @clear_to_set(i32 %x) {
; CHECK-LABEL: @clear_to_set(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 8
; CHECK-NEXT:    [[T2:%.*]] = icmp eq i32 [[T1]], 0
; CHECK-NEXT:    [[T3:%.*]] = xor i32 [[T1]], -3
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %x, 8
  %t2 = icmp eq i32 %t1, 0
  %t3 = select i1 %t2, i32 -3, i32 -11
  call void @use1(i1 %t2)
  ret i32 %t3
}

; (X & 8) == 0 ? -11 : -3 --> (X & 8) | -11
; Extra cmp use ensures that cmp predicate canonicalization is thwarted.

define i32 @clear_to_clear(i32 %x) {
; CHECK-LABEL: @clear_to_clear(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 8
; CHECK-NEXT:    [[T2:%.*]] = icmp eq i32 [[T1]], 0
; CHECK-NEXT:    [[T3:%.*]] = or i32 [[T1]], -11
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %x, 8
  %t2 = icmp eq i32 %t1, 0
  %t3 = select i1 %t2, i32 -11, i32 -3
  call void @use1(i1 %t2)
  ret i32 %t3
}

; (X & 8) != 0 ? -3 : -11 --> (X & 8) | -11
; Extra cmp use ensures that cmp predicate canonicalization is thwarted.

define i32 @set_to_set(i32 %x) {
; CHECK-LABEL: @set_to_set(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 8
; CHECK-NEXT:    [[T2:%.*]] = icmp ne i32 [[T1]], 0
; CHECK-NEXT:    [[T3:%.*]] = or i32 [[T1]], -11
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %x, 8
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 -3, i32 -11
  call void @use1(i1 %t2)
  ret i32 %t3
}

; (X & 8) != 0 ? -3 : -11 --> (X & 8) ^ -3
; Extra cmp use ensures that cmp predicate canonicalization is thwarted.

define i32 @set_to_clear(i32 %x) {
; CHECK-LABEL: @set_to_clear(
; CHECK-NEXT:    [[T1:%.*]] = and i32 [[X:%.*]], 8
; CHECK-NEXT:    [[T2:%.*]] = icmp ne i32 [[T1]], 0
; CHECK-NEXT:    [[T3:%.*]] = xor i32 [[T1]], -3
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i32 [[T3]]
;
  %t1 = and i32 %x, 8
  %t2 = icmp ne i32 %t1, 0
  %t3 = select i1 %t2, i32 -11, i32 -3
  call void @use1(i1 %t2)
  ret i32 %t3
}

; (X & 128) == 0 ? 131 : 3 --> (X & 128) ^ 131

define i8 @clear_to_set_decomposebittest(i8 %x) {
; CHECK-LABEL: @clear_to_set_decomposebittest(
; CHECK-NEXT:    [[TMP1:%.*]] = and i8 [[X:%.*]], -128
; CHECK-NEXT:    [[T3:%.*]] = xor i8 [[TMP1]], -125
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp sgt i8 %x, -1
  %t3 = select i1 %t2, i8 131, i8 3
  ret i8 %t3
}

; (X & 128) == 0 ? 3 : 131 --> (X & 128) | 3

define i8 @clear_to_clear_decomposebittest(i8 %x) {
; CHECK-LABEL: @clear_to_clear_decomposebittest(
; CHECK-NEXT:    [[TMP1:%.*]] = and i8 [[X:%.*]], -128
; CHECK-NEXT:    [[T3:%.*]] = or i8 [[TMP1]], 3
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp sgt i8 %x, -1
  %t3 = select i1 %t2, i8 3, i8 131
  ret i8 %t3
}

; (X & 128) != 0 ? 131 : 3 --> (X & 128) | 3

define i8 @set_to_set_decomposebittest(i8 %x) {
; CHECK-LABEL: @set_to_set_decomposebittest(
; CHECK-NEXT:    [[TMP1:%.*]] = and i8 [[X:%.*]], -128
; CHECK-NEXT:    [[T3:%.*]] = or i8 [[TMP1]], 3
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp slt i8 %x, 0
  %t3 = select i1 %t2, i8 131, i8 3
  ret i8 %t3
}

; (X & 128) != 0 ? 3 : 131 --> (X & 128) ^ 131

define i8 @set_to_clear_decomposebittest(i8 %x) {
; CHECK-LABEL: @set_to_clear_decomposebittest(
; CHECK-NEXT:    [[TMP1:%.*]] = and i8 [[X:%.*]], -128
; CHECK-NEXT:    [[T3:%.*]] = xor i8 [[TMP1]], -125
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp slt i8 %x, 0
  %t3 = select i1 %t2, i8 3, i8 131
  ret i8 %t3
}

; (X & 128) == 0 ? 131 : 3 --> (X & 128) ^ 131
; Extra cmp use to verify that we are not creating extra instructions.

define i8 @clear_to_set_decomposebittest_extra_use(i8 %x) {
; CHECK-LABEL: @clear_to_set_decomposebittest_extra_use(
; CHECK-NEXT:    [[T2:%.*]] = icmp sgt i8 [[X:%.*]], -1
; CHECK-NEXT:    [[T3:%.*]] = select i1 [[T2]], i8 -125, i8 3
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp sgt i8 %x, -1
  %t3 = select i1 %t2, i8 131, i8 3
  call void @use1(i1 %t2)
  ret i8 %t3
}

; (X & 128) == 0 ? 3 : 131 --> (X & 128) | 3
; Extra cmp use to verify that we are not creating extra instructions.

define i8 @clear_to_clear_decomposebittest_extra_use(i8 %x) {
; CHECK-LABEL: @clear_to_clear_decomposebittest_extra_use(
; CHECK-NEXT:    [[T2:%.*]] = icmp sgt i8 [[X:%.*]], -1
; CHECK-NEXT:    [[T3:%.*]] = select i1 [[T2]], i8 3, i8 -125
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp sgt i8 %x, -1
  %t3 = select i1 %t2, i8 3, i8 131
  call void @use1(i1 %t2)
  ret i8 %t3
}

; (X & 128) != 0 ? 131 : 3 --> (X & 128) | 3
; Extra cmp use to verify that we are not creating extra instructions.

define i8 @set_to_set_decomposebittest_extra_use(i8 %x) {
; CHECK-LABEL: @set_to_set_decomposebittest_extra_use(
; CHECK-NEXT:    [[T2:%.*]] = icmp slt i8 [[X:%.*]], 0
; CHECK-NEXT:    [[T3:%.*]] = select i1 [[T2]], i8 -125, i8 3
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp slt i8 %x, 0
  %t3 = select i1 %t2, i8 131, i8 3
  call void @use1(i1 %t2)
  ret i8 %t3
}

; (X & 128) != 0 ? 3 : 131 --> (X & 128) ^ 131
; Extra cmp use to verify that we are not creating extra instructions.

define i8 @set_to_clear_decomposebittest_extra_use(i8 %x) {
; CHECK-LABEL: @set_to_clear_decomposebittest_extra_use(
; CHECK-NEXT:    [[T2:%.*]] = icmp slt i8 [[X:%.*]], 0
; CHECK-NEXT:    [[T3:%.*]] = select i1 [[T2]], i8 3, i8 -125
; CHECK-NEXT:    call void @use1(i1 [[T2]])
; CHECK-NEXT:    ret i8 [[T3]]
;
  %t2 = icmp slt i8 %x, 0
  %t3 = select i1 %t2, i8 3, i8 131
  call void @use1(i1 %t2)
  ret i8 %t3
}

