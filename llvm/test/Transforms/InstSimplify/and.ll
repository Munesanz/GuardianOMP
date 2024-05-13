; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instsimplify -S | FileCheck %s

define i32 @poison(i32 %x) {
; CHECK-LABEL: @poison(
; CHECK-NEXT:    ret i32 poison
;
  %v = and i32 %x, poison
  ret i32 %v
}

; (X | Y) & (X | ~Y) --> X (commuted 8 ways)

define i8 @or_or_not_commute0(i8 %x, i8 %y) {
; CHECK-LABEL: @or_or_not_commute0(
; CHECK-NEXT:    ret i8 [[X:%.*]]
;
  %ynot = xor i8 %y, -1
  %xory = or i8 %x, %y
  %xorynot = or i8 %x, %ynot
  %and = and i8 %xory, %xorynot
  ret i8 %and
}

define <2 x i5> @or_or_not_commute1(<2 x i5> %x, <2 x i5> %y) {
; CHECK-LABEL: @or_or_not_commute1(
; CHECK-NEXT:    ret <2 x i5> [[X:%.*]]
;
  %ynot = xor <2 x i5> %y, <i5 -1, i5 -1>
  %xory = or <2 x i5> %x, %y
  %xorynot = or <2 x i5> %x, %ynot
  %and = and <2 x i5> %xorynot, %xory
  ret <2 x i5> %and
}

define <2 x i8> @or_or_not_commute2(<2 x i8> %x, <2 x i8> %y) {
; CHECK-LABEL: @or_or_not_commute2(
; CHECK-NEXT:    ret <2 x i8> [[X:%.*]]
;
  %ynot = xor <2 x i8> %y, <i8 poison, i8 -1>
  %xory = or <2 x i8> %x, %y
  %xorynot = or <2 x i8> %ynot, %x
  %and = and <2 x i8> %xory, %xorynot
  ret <2 x i8> %and
}

define i8 @or_or_not_commute3(i8 %x, i8 %y) {
; CHECK-LABEL: @or_or_not_commute3(
; CHECK-NEXT:    ret i8 [[X:%.*]]
;
  %ynot = xor i8 %y, -1
  %xory = or i8 %x, %y
  %xorynot = or i8 %ynot, %x
  %and = and i8 %xorynot, %xory
  ret i8 %and
}
define i8 @or_or_not_commute4(i8 %x, i8 %y) {
; CHECK-LABEL: @or_or_not_commute4(
; CHECK-NEXT:    ret i8 [[X:%.*]]
;
  %ynot = xor i8 %y, -1
  %xory = or i8 %y, %x
  %xorynot = or i8 %x, %ynot
  %and = and i8 %xory, %xorynot
  ret i8 %and
}

define i8 @or_or_not_commute5(i8 %x, i8 %y) {
; CHECK-LABEL: @or_or_not_commute5(
; CHECK-NEXT:    ret i8 [[X:%.*]]
;
  %ynot = xor i8 %y, -1
  %xory = or i8 %y, %x
  %xorynot = or i8 %x, %ynot
  %and = and i8 %xorynot, %xory
  ret i8 %and
}

define i8 @or_or_not_commute6(i8 %x, i8 %y) {
; CHECK-LABEL: @or_or_not_commute6(
; CHECK-NEXT:    ret i8 [[X:%.*]]
;
  %ynot = xor i8 %y, -1
  %xory = or i8 %y, %x
  %xorynot = or i8 %ynot, %x
  %and = and i8 %xory, %xorynot
  ret i8 %and
}

define i8 @or_or_not_commute7(i8 %x, i8 %y) {
; CHECK-LABEL: @or_or_not_commute7(
; CHECK-NEXT:    ret i8 [[X:%.*]]
;
  %ynot = xor i8 %y, -1
  %xory = or i8 %y, %x
  %xorynot = or i8 %ynot, %x
  %and = and i8 %xorynot, %xory
  ret i8 %and
}

; negative test - wrong logic op

define i8 @or_xor_not(i8 %x, i8 %y) {
; CHECK-LABEL: @or_xor_not(
; CHECK-NEXT:    [[YNOT:%.*]] = xor i8 [[Y:%.*]], -1
; CHECK-NEXT:    [[XXORY:%.*]] = xor i8 [[Y]], [[X:%.*]]
; CHECK-NEXT:    [[XORYNOT:%.*]] = or i8 [[X]], [[YNOT]]
; CHECK-NEXT:    [[AND:%.*]] = and i8 [[XORYNOT]], [[XXORY]]
; CHECK-NEXT:    ret i8 [[AND]]
;
  %ynot = xor i8 %y, -1
  %xxory = xor i8 %y, %x
  %xorynot = or i8 %x, %ynot
  %and = and i8 %xorynot, %xxory
  ret i8 %and
}

; negative test - must have common operands

define i8 @or_or_not_no_common_op(i8 %x, i8 %y, i8 %z) {
; CHECK-LABEL: @or_or_not_no_common_op(
; CHECK-NEXT:    [[XORZ:%.*]] = or i8 [[Z:%.*]], [[X:%.*]]
; CHECK-NEXT:    [[YNOT:%.*]] = xor i8 [[Y:%.*]], -1
; CHECK-NEXT:    [[XORYNOT:%.*]] = or i8 [[X]], [[YNOT]]
; CHECK-NEXT:    [[AND:%.*]] = and i8 [[XORYNOT]], [[XORZ]]
; CHECK-NEXT:    ret i8 [[AND]]
;
  %xorz = or i8 %z, %x
  %ynot = xor i8 %y, -1
  %xorynot = or i8 %x, %ynot
  %and = and i8 %xorynot, %xorz
  ret i8 %and
}

; ((X | Y) ^ X ) & ((X | Y) ^ Y) --> 0

define i8 @or_xor(i8 %x, i8 %y) {
; CHECK-LABEL: @or_xor(
; CHECK-NEXT:    ret i8 0
;
  %or = or i8 %x, %y
  %xor1 = xor i8 %or, %x
  %xor2 = xor i8 %or, %y
  %and = and i8 %xor1, %xor2
  ret i8 %and
}

; ((X | Y) ^ Y ) & ((X | Y) ^ X) --> 0

define i8 @or_xor_commute1(i8 %x, i8 %y) {
; CHECK-LABEL: @or_xor_commute1(
; CHECK-NEXT:    ret i8 0
;
  %or = or i8 %x, %y
  %xor1 = xor i8 %or, %x
  %xor2 = xor i8 %or, %y
  %and = and i8 %xor2, %xor1
  ret i8 %and
}

; (X ^ (X | Y) ) & (Y ^ (X | Y)) --> 0

define i71 @or_xor_commute2(i71 %x, i71 %y) {
; CHECK-LABEL: @or_xor_commute2(
; CHECK-NEXT:    ret i71 0
;
  %or = or i71 %x, %y
  %xor1 = xor i71 %x, %or
  %xor2 = xor i71 %y, %or
  %and = and i71 %xor1, %xor2
  ret i71 %and
}

; (Y ^ (X | Y) ) & (X ^ (X | Y)) --> 0

define <2 x i64> @or_xor_commute3(<2 x i64> %x, <2 x i64> %y) {
; CHECK-LABEL: @or_xor_commute3(
; CHECK-NEXT:    ret <2 x i64> zeroinitializer
;
  %or = or <2 x i64> %x, %y
  %xor1 = xor <2 x i64> %y, %or
  %xor2 = xor <2 x i64> %x, %or
  %and = and <2 x i64> %xor1, %xor2
  ret <2 x i64> %and
}

; ((X | Y) ^ X ) & (Y ^ (X | Y)) --> 0

define i32 @or_xor_commute4(i32 %x, i32 %y) {
; CHECK-LABEL: @or_xor_commute4(
; CHECK-NEXT:    ret i32 0
;
  %or = or i32 %x, %y
  %xor1 = xor i32 %or, %x
  %xor2 = xor i32 %y, %or
  %and = and i32 %xor1, %xor2
  ret i32 %and
}

; ((X | Y) ^ Y ) & (X ^ (X | Y)) --> 0

define i32 @or_xor_commute5(i32 %x, i32 %y) {
; CHECK-LABEL: @or_xor_commute5(
; CHECK-NEXT:    ret i32 0
;
  %or = or i32 %x, %y
  %xor1 = xor i32 %or, %y
  %xor2 = xor i32 %x, %or
  %and = and i32 %xor1, %xor2
  ret i32 %and
}

; (X ^ (X | Y) ) & ((X | Y) ^ Y) --> 0

define i32 @or_xor_commute6(i32 %x, i32 %y) {
; CHECK-LABEL: @or_xor_commute6(
; CHECK-NEXT:    ret i32 0
;
  %or = or i32 %x, %y
  %xor1 = xor i32 %x, %or
  %xor2 = xor i32 %or, %y
  %and = and i32 %xor1, %xor2
  ret i32 %and
}

; (Y ^ (X | Y) ) & ((X | Y) ^ X) --> 0

define i32 @or_xor_commute7(i32 %x, i32 %y) {
; CHECK-LABEL: @or_xor_commute7(
; CHECK-NEXT:    ret i32 0
;
  %or = or i32 %x, %y
  %xor1 = xor i32 %y, %or
  %xor2 = xor i32 %or, %x
  %and = and i32 %xor1, %xor2
  ret i32 %and
}

; (Y ^ (X | Y) ) & ((X | Y) ^ X) --> 0

define i32 @or_xor_complex_op(i32 %x, i32 %in) {
; CHECK-LABEL: @or_xor_complex_op(
; CHECK-NEXT:    ret i32 0
;
  %y = or i32 %in, 1
  %or = or i32 %x, %y
  %xor1 = xor i32 %y, %or
  %xor2 = xor i32 %or, %x
  %and = and i32 %xor1, %xor2
  ret i32 %and
}

define i32 @or_xor_limitation(i32 %x, i32 %y) {
; CHECK-LABEL: @or_xor_limitation(
; CHECK-NEXT:    [[OR1:%.*]] = or i32 [[Y:%.*]], [[X:%.*]]
; CHECK-NEXT:    [[OR2:%.*]] = or i32 [[X]], [[Y]]
; CHECK-NEXT:    [[XOR1:%.*]] = xor i32 [[Y]], [[OR1]]
; CHECK-NEXT:    [[XOR2:%.*]] = xor i32 [[OR2]], [[X]]
; CHECK-NEXT:    [[AND:%.*]] = and i32 [[XOR1]], [[XOR2]]
; CHECK-NEXT:    ret i32 [[AND]]
;
  %or1 = or i32 %y, %x
  %or2 = or i32 %x, %y
  %xor1 = xor i32 %y, %or1
  %xor2 = xor i32 %or2, %x
  %and = and i32 %xor1, %xor2
  ret i32 %and
}
