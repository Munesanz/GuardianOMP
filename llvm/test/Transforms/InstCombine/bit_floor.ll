; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instcombine -S | FileCheck %s

define i32 @bit_floor_32(i32 %x) {
; CHECK-LABEL: @bit_floor_32(
; CHECK-NEXT:    [[EQ0:%.*]] = icmp eq i32 [[X:%.*]], 0
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctlz.i32(i32 [[X]], i1 false), !range [[RNG0:![0-9]+]]
; CHECK-NEXT:    [[TMP2:%.*]] = lshr exact i32 -2147483648, [[TMP1]]
; CHECK-NEXT:    [[SEL:%.*]] = select i1 [[EQ0]], i32 0, i32 [[TMP2]]
; CHECK-NEXT:    ret i32 [[SEL]]
;
  %eq0 = icmp eq i32 %x, 0
  %lshr = lshr i32 %x, 1
  %ctlz = tail call i32 @llvm.ctlz.i32(i32 %lshr, i1 false)
  %sub = sub i32 32, %ctlz
  %shl = shl i32 1, %sub
  %sel = select i1 %eq0, i32 0, i32 %shl
  ret i32 %sel
}

define i64 @bit_floor_64(i64 %x) {
; CHECK-LABEL: @bit_floor_64(
; CHECK-NEXT:    [[EQ0:%.*]] = icmp eq i64 [[X:%.*]], 0
; CHECK-NEXT:    [[TMP1:%.*]] = call i64 @llvm.ctlz.i64(i64 [[X]], i1 false), !range [[RNG1:![0-9]+]]
; CHECK-NEXT:    [[TMP2:%.*]] = lshr exact i64 -9223372036854775808, [[TMP1]]
; CHECK-NEXT:    [[SEL:%.*]] = select i1 [[EQ0]], i64 0, i64 [[TMP2]]
; CHECK-NEXT:    ret i64 [[SEL]]
;
  %eq0 = icmp eq i64 %x, 0
  %lshr = lshr i64 %x, 1
  %ctlz = tail call i64 @llvm.ctlz.i64(i64 %lshr, i1 false)
  %sub = sub i64 64, %ctlz
  %shl = shl i64 1, %sub
  %sel = select i1 %eq0, i64 0, i64 %shl
  ret i64 %sel
}

; Commutted select operands should still be recognized.
define i32 @bit_floor_commuted_operands(i32 %x) {
; CHECK-LABEL: @bit_floor_commuted_operands(
; CHECK-NEXT:    [[NE0_NOT:%.*]] = icmp eq i32 [[X:%.*]], 0
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctlz.i32(i32 [[X]], i1 false), !range [[RNG0]]
; CHECK-NEXT:    [[TMP2:%.*]] = lshr exact i32 -2147483648, [[TMP1]]
; CHECK-NEXT:    [[SEL:%.*]] = select i1 [[NE0_NOT]], i32 0, i32 [[TMP2]]
; CHECK-NEXT:    ret i32 [[SEL]]
;
  %ne0 = icmp ne i32 %x, 0
  %lshr = lshr i32 %x, 1
  %ctlz = tail call i32 @llvm.ctlz.i32(i32 %lshr, i1 false)
  %sub = sub i32 32, %ctlz
  %shl = shl i32 1, %sub
  %sel = select i1 %ne0, i32 %shl, i32 0
  ret i32 %sel
}

; Negative test: lshr used twice
define i32 @bit_floor_lshr_used_twice(i32 %x, ptr %p) {
; CHECK-LABEL: @bit_floor_lshr_used_twice(
; CHECK-NEXT:    [[EQ0:%.*]] = icmp eq i32 [[X:%.*]], 0
; CHECK-NEXT:    [[LSHR:%.*]] = lshr i32 [[X]], 1
; CHECK-NEXT:    [[CTLZ:%.*]] = tail call i32 @llvm.ctlz.i32(i32 [[LSHR]], i1 false), !range [[RNG2:![0-9]+]]
; CHECK-NEXT:    [[SUB:%.*]] = sub nuw nsw i32 32, [[CTLZ]]
; CHECK-NEXT:    [[SHL:%.*]] = shl nuw i32 1, [[SUB]]
; CHECK-NEXT:    [[SEL:%.*]] = select i1 [[EQ0]], i32 0, i32 [[SHL]]
; CHECK-NEXT:    store i32 [[LSHR]], ptr [[P:%.*]], align 4
; CHECK-NEXT:    ret i32 [[SEL]]
;
  %eq0 = icmp eq i32 %x, 0
  %lshr = lshr i32 %x, 1
  %ctlz = tail call i32 @llvm.ctlz.i32(i32 %lshr, i1 false)
  %sub = sub i32 32, %ctlz
  %shl = shl i32 1, %sub
  %sel = select i1 %eq0, i32 0, i32 %shl
  store i32 %lshr, ptr %p, align 4
  ret i32 %sel
}

; Negative test: ctlz used twice
define i32 @bit_floor_ctlz_used_twice(i32 %x, ptr %p) {
; CHECK-LABEL: @bit_floor_ctlz_used_twice(
; CHECK-NEXT:    [[EQ0:%.*]] = icmp eq i32 [[X:%.*]], 0
; CHECK-NEXT:    [[LSHR:%.*]] = lshr i32 [[X]], 1
; CHECK-NEXT:    [[CTLZ:%.*]] = tail call i32 @llvm.ctlz.i32(i32 [[LSHR]], i1 false), !range [[RNG2]]
; CHECK-NEXT:    [[SUB:%.*]] = sub nuw nsw i32 32, [[CTLZ]]
; CHECK-NEXT:    [[SHL:%.*]] = shl nuw i32 1, [[SUB]]
; CHECK-NEXT:    [[SEL:%.*]] = select i1 [[EQ0]], i32 0, i32 [[SHL]]
; CHECK-NEXT:    store i32 [[CTLZ]], ptr [[P:%.*]], align 4
; CHECK-NEXT:    ret i32 [[SEL]]
;
  %eq0 = icmp eq i32 %x, 0
  %lshr = lshr i32 %x, 1
  %ctlz = tail call i32 @llvm.ctlz.i32(i32 %lshr, i1 false)
  %sub = sub i32 32, %ctlz
  %shl = shl i32 1, %sub
  %sel = select i1 %eq0, i32 0, i32 %shl
  store i32 %ctlz, ptr %p, align 4
  ret i32 %sel
}

; Negative test: sub used twice
define i32 @bit_floor_sub_used_twice(i32 %x, ptr %p) {
; CHECK-LABEL: @bit_floor_sub_used_twice(
; CHECK-NEXT:    [[EQ0:%.*]] = icmp eq i32 [[X:%.*]], 0
; CHECK-NEXT:    [[LSHR:%.*]] = lshr i32 [[X]], 1
; CHECK-NEXT:    [[CTLZ:%.*]] = tail call i32 @llvm.ctlz.i32(i32 [[LSHR]], i1 false), !range [[RNG2]]
; CHECK-NEXT:    [[SUB:%.*]] = sub nuw nsw i32 32, [[CTLZ]]
; CHECK-NEXT:    [[SHL:%.*]] = shl nuw i32 1, [[SUB]]
; CHECK-NEXT:    [[SEL:%.*]] = select i1 [[EQ0]], i32 0, i32 [[SHL]]
; CHECK-NEXT:    store i32 [[SUB]], ptr [[P:%.*]], align 4
; CHECK-NEXT:    ret i32 [[SEL]]
;
  %eq0 = icmp eq i32 %x, 0
  %lshr = lshr i32 %x, 1
  %ctlz = tail call i32 @llvm.ctlz.i32(i32 %lshr, i1 false)
  %sub = sub i32 32, %ctlz
  %shl = shl i32 1, %sub
  %sel = select i1 %eq0, i32 0, i32 %shl
  store i32 %sub, ptr %p, align 4
  ret i32 %sel
}

; Negative test: shl used twice
define i32 @bit_floor_shl_used_twice(i32 %x, ptr %p) {
; CHECK-LABEL: @bit_floor_shl_used_twice(
; CHECK-NEXT:    [[EQ0:%.*]] = icmp eq i32 [[X:%.*]], 0
; CHECK-NEXT:    [[LSHR:%.*]] = lshr i32 [[X]], 1
; CHECK-NEXT:    [[CTLZ:%.*]] = tail call i32 @llvm.ctlz.i32(i32 [[LSHR]], i1 false), !range [[RNG2]]
; CHECK-NEXT:    [[SUB:%.*]] = sub nuw nsw i32 32, [[CTLZ]]
; CHECK-NEXT:    [[SHL:%.*]] = shl nuw i32 1, [[SUB]]
; CHECK-NEXT:    [[SEL:%.*]] = select i1 [[EQ0]], i32 0, i32 [[SHL]]
; CHECK-NEXT:    store i32 [[SHL]], ptr [[P:%.*]], align 4
; CHECK-NEXT:    ret i32 [[SEL]]
;
  %eq0 = icmp eq i32 %x, 0
  %lshr = lshr i32 %x, 1
  %ctlz = tail call i32 @llvm.ctlz.i32(i32 %lshr, i1 false)
  %sub = sub i32 32, %ctlz
  %shl = shl i32 1, %sub
  %sel = select i1 %eq0, i32 0, i32 %shl
  store i32 %shl, ptr %p, align 4
  ret i32 %sel
}

; a vector version of @bit_floor_32 above
define <4 x i32> @bit_floor_v4i32(<4 x i32> %x) {
; CHECK-LABEL: @bit_floor_v4i32(
; CHECK-NEXT:    [[EQ0:%.*]] = icmp eq <4 x i32> [[X:%.*]], zeroinitializer
; CHECK-NEXT:    [[TMP1:%.*]] = call <4 x i32> @llvm.ctlz.v4i32(<4 x i32> [[X]], i1 false), !range [[RNG0]]
; CHECK-NEXT:    [[TMP2:%.*]] = lshr exact <4 x i32> <i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648>, [[TMP1]]
; CHECK-NEXT:    [[SEL:%.*]] = select <4 x i1> [[EQ0]], <4 x i32> zeroinitializer, <4 x i32> [[TMP2]]
; CHECK-NEXT:    ret <4 x i32> [[SEL]]
;
  %eq0 = icmp eq <4 x i32> %x, <i32 0, i32 0, i32 0, i32 0>
  %lshr = lshr <4 x i32> %x, <i32 1, i32 1, i32 1, i32 1>
  %ctlz = tail call <4 x i32> @llvm.ctlz.v4i32(<4 x i32> %lshr, i1 false)
  %sub = sub <4 x i32> <i32 32, i32 32, i32 32, i32 32>, %ctlz
  %shl = shl <4 x i32> <i32 1, i32 1, i32 1, i32 1>, %sub
  %sel = select <4 x i1> %eq0, <4 x i32> <i32 0, i32 0, i32 0, i32 0>, <4 x i32> %shl
  ret <4 x i32> %sel
}

declare i32 @llvm.ctlz.i32(i32, i1 immarg)
declare i64 @llvm.ctlz.i64(i64, i1 immarg)
declare <4 x i32> @llvm.ctlz.v4i32(<4 x i32>, i1)
