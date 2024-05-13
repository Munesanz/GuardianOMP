; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -passes=loop-unroll -unroll-runtime -unroll-runtime-multi-exit < %s | FileCheck %s

; This loop has a known trip count on the non-latch exit. When performing
; runtime unrolling (at least when using a prologue rather than epilogue) we
; should not fold that exit based on known trip count information prior to
; prologue insertion, as that may change the trip count for the modified loop.

define void @test(i32 %s, i32 %n) {
; CHECK-LABEL: @test(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[N2:%.*]] = add i32 [[S:%.*]], 123
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[I:%.*]] = phi i32 [ [[S]], [[ENTRY:%.*]] ], [ [[I_INC:%.*]], [[LATCH:%.*]] ]
; CHECK-NEXT:    [[C1:%.*]] = icmp eq i32 [[I]], [[N2]]
; CHECK-NEXT:    br i1 [[C1]], label [[EXIT1:%.*]], label [[LATCH]]
; CHECK:       latch:
; CHECK-NEXT:    [[C2:%.*]] = icmp eq i32 [[I]], [[N:%.*]]
; CHECK-NEXT:    [[I_INC]] = add i32 [[I]], 1
; CHECK-NEXT:    br i1 [[C2]], label [[EXIT2:%.*]], label [[LOOP]]
; CHECK:       exit1:
; CHECK-NEXT:    ret void
; CHECK:       exit2:
; CHECK-NEXT:    ret void
;
entry:
  %n2 = add i32 %s, 123
  br label %loop

loop:
  %i = phi i32 [ %s, %entry], [ %i.inc, %latch ]
  %c1 = icmp eq i32 %i, %n2
  br i1 %c1, label %exit1, label %latch

latch:
  %c2 = icmp eq i32 %i, %n
  %i.inc = add i32 %i, 1
  br i1 %c2, label %exit2, label %loop

exit1:
  ret void

exit2:
  ret void
}
