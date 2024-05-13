; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; Test use of RISBG vs RISBGN on zEC12.
;
; RUN: llc < %s -mtriple=s390x-linux-gnu -mcpu=zEC12 | FileCheck %s

; On zEC12, we generally prefer RISBGN.
define i64 @f1(i64 %a, i64 %b) {
; CHECK-LABEL: f1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    risbgn %r2, %r3, 60, 62, 0
; CHECK-NEXT:    br %r14
  %anda = and i64 %a, -15
  %andb = and i64 %b, 14
  %or = or i64 %anda, %andb
  ret i64 %or
}

; But we may fall back to RISBG if we can use the condition code.
define i64 @f2(i64 %a, i64 %b, ptr %c) {
; CHECK-LABEL: f2:
; CHECK:       # %bb.0:
; CHECK-NEXT:    risbg %r2, %r3, 60, 62, 0
; CHECK-NEXT:    ipm %r0
; CHECK-NEXT:    risblg %r0, %r0, 31, 159, 35
; CHECK-NEXT:    st %r0, 0(%r4)
; CHECK-NEXT:    br %r14
  %anda = and i64 %a, -15
  %andb = and i64 %b, 14
  %or = or i64 %anda, %andb
  %cmp = icmp sgt i64 %or, 0
  %conv = zext i1 %cmp to i32
  store i32 %conv, ptr %c, align 4
  ret i64 %or
}

