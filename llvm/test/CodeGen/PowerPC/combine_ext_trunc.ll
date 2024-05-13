; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=powerpc64le-unknown-unknown -verify-machineinstrs | FileCheck %s

; FIXME: We have implemented the following patterns in DAGCombiner.cpp,
; but we can't get results as expected.

; fold (or (and X, (xor Y, -1)), Y) to (or X, Y)
define i32 @pattern1(i32 %x, i32 %y){
; CHECK-LABEL: pattern1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    xori 5, 4, 65535
; CHECK-NEXT:    xoris 5, 5, 65535
; CHECK-NEXT:    and 3, 3, 5
; CHECK-NEXT:    or 3, 3, 4
; CHECK-NEXT:    blr
    %a = xor i32 %y, -1
    %b = and i32 %x, %a
    %c = or i32 %b, %y
    ret i32 %c
}

; fold (or (and (xor Y, -1), X), Y) to (or X, Y)
define i32 @pattern2(i32 %x, i32 %y){
; CHECK-LABEL: pattern2:
; CHECK:       # %bb.0:
; CHECK-NEXT:    xori 5, 4, 65535
; CHECK-NEXT:    xoris 5, 5, 65535
; CHECK-NEXT:    and 3, 5, 3
; CHECK-NEXT:    or 3, 3, 4
; CHECK-NEXT:    blr
    %a = xor i32 %y, -1
    %b = and i32 %a, %x
    %c = or i32 %b, %y
    ret i32 %c
}

; fold (and (select Cond, 0, -1), X) to (select Cond, 0, X)
define i32 @pattern3(i1 %cond, i32 %x) {
; CHECK-LABEL: pattern3:
; CHECK:       # %bb.0:
; CHECK-NEXT:    li 5, -1
; CHECK-NEXT:    andi. 3, 3, 1
; CHECK-NEXT:    rldic 3, 5, 0, 32
; CHECK-NEXT:    iselgt 3, 0, 3
; CHECK-NEXT:    and 3, 3, 4
; CHECK-NEXT:    blr
  %sel = select i1 %cond, i32 0, i32 -1
  %res = and i32 %sel, %x
  ret i32 %res
}

; fold (or X, (select Cond, -1, 0)) to (select Cond, -1, X)
define i32 @pattern4(i1 %cond, i32 %x) {
; CHECK-LABEL: pattern4:
; CHECK:       # %bb.0:
; CHECK-NEXT:    li 5, -1
; CHECK-NEXT:    andi. 3, 3, 1
; CHECK-NEXT:    rldic 3, 5, 0, 32
; CHECK-NEXT:    li 5, 0
; CHECK-NEXT:    iselgt 3, 3, 5
; CHECK-NEXT:    or 3, 4, 3
; CHECK-NEXT:    blr
  %sel = select i1 %cond, i32 -1, i32 0
  %res = or i32 %x, %sel
  ret i32 %res
}
