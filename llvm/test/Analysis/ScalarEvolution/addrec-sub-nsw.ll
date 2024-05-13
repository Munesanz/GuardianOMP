; NOTE: Assertions have been autogenerated by utils/update_analyze_test_checks.py UTC_ARGS: --version 2
; RUN: opt -disable-output "-passes=print<scalar-evolution>" < %s 2>&1 | FileCheck %s

define i32 @test_1_non_negative(i32 %n) {
; CHECK-LABEL: 'test_1_non_negative'
; CHECK-NEXT:  Classifying expressions for: @test_1_non_negative
; CHECK-NEXT:    %i = phi i32 [ 0, %entry ], [ %i.next, %loop ]
; CHECK-NEXT:    --> {0,+,1}<nuw><nsw><%loop> U: [0,2147483647) S: [0,2147483647) Exits: (-1 + (1 smax %n))<nsw> LoopDispositions: { %loop: Computable }
; CHECK-NEXT:    %a = sub i32 %n, %i
; CHECK-NEXT:    --> {%n,+,-1}<nw><%loop> U: full-set S: full-set Exits: (1 + (-1 * (1 smax %n))<nsw> + %n) LoopDispositions: { %loop: Computable }
; CHECK-NEXT:    %i.next = add nuw nsw i32 %i, 1
; CHECK-NEXT:    --> {1,+,1}<nuw><nsw><%loop> U: [1,-2147483648) S: [1,-2147483648) Exits: (1 smax %n) LoopDispositions: { %loop: Computable }
; CHECK-NEXT:  Determining loop execution counts for: @test_1_non_negative
; CHECK-NEXT:  Loop %loop: backedge-taken count is (-1 + (1 smax %n))<nsw>
; CHECK-NEXT:  Loop %loop: constant max backedge-taken count is 2147483646
; CHECK-NEXT:  Loop %loop: symbolic max backedge-taken count is (-1 + (1 smax %n))<nsw>
; CHECK-NEXT:  Loop %loop: Predicated backedge-taken count is (-1 + (1 smax %n))<nsw>
; CHECK-NEXT:   Predicates:
; CHECK:       Loop %loop: Trip multiple is 1
;
entry:
  %precond = icmp sge i32 %n, 0
  br i1 %precond, label %loop, label %fail

loop:
  %i = phi i32 [0, %entry], [%i.next, %loop]                      ; 0...n-1
  %a = sub i32 %n, %i                                             ; n...0
  %i.next = add nuw nsw i32 %i, 1
  %cond = icmp slt i32 %i.next, %n
  br i1 %cond, label %loop, label %exit

fail:
  ret i32 -1

exit:
  ret i32 0
}

define i32 @test_2_non_positive(i32 %n) {
; CHECK-LABEL: 'test_2_non_positive'
; CHECK-NEXT:  Classifying expressions for: @test_2_non_positive
; CHECK-NEXT:    %minus.n = mul i32 %n, -1
; CHECK-NEXT:    --> (-1 * %n) U: full-set S: full-set
; CHECK-NEXT:    %i = phi i32 [ 0, %entry ], [ %i.next, %loop ]
; CHECK-NEXT:    --> {0,+,1}<nuw><nsw><%loop> U: [0,2147483647) S: [0,2147483647) Exits: (-1 + (1 smax %n))<nsw> LoopDispositions: { %loop: Computable }
; CHECK-NEXT:    %minus.i = mul i32 %i, -1
; CHECK-NEXT:    --> {0,+,-1}<nsw><%loop> U: [-2147483646,1) S: [-2147483646,1) Exits: (1 + (-1 * (1 smax %n))<nsw>)<nsw> LoopDispositions: { %loop: Computable }
; CHECK-NEXT:    %a = sub i32 %minus.n, %minus.i
; CHECK-NEXT:    --> {(-1 * %n),+,1}<nw><%loop> U: full-set S: full-set Exits: (-1 + (-1 * %n) + (1 smax %n)) LoopDispositions: { %loop: Computable }
; CHECK-NEXT:    %i.next = add nuw nsw i32 %i, 1
; CHECK-NEXT:    --> {1,+,1}<nuw><nsw><%loop> U: [1,-2147483648) S: [1,-2147483648) Exits: (1 smax %n) LoopDispositions: { %loop: Computable }
; CHECK-NEXT:  Determining loop execution counts for: @test_2_non_positive
; CHECK-NEXT:  Loop %loop: backedge-taken count is (-1 + (1 smax %n))<nsw>
; CHECK-NEXT:  Loop %loop: constant max backedge-taken count is 2147483646
; CHECK-NEXT:  Loop %loop: symbolic max backedge-taken count is (-1 + (1 smax %n))<nsw>
; CHECK-NEXT:  Loop %loop: Predicated backedge-taken count is (-1 + (1 smax %n))<nsw>
; CHECK-NEXT:   Predicates:
; CHECK:       Loop %loop: Trip multiple is 1
;
entry:
  %precond = icmp sge i32 %n, 0
  %minus.n = mul i32 %n, -1
  br i1 %precond, label %loop, label %fail

loop:
  %i = phi i32 [0, %entry], [%i.next, %loop]                      ; 0...n-1
  %minus.i = mul i32 %i, -1                                       ; -(n-1)...0
  %a = sub i32 %minus.n, %minus.i                                 ; -n...-1
  %i.next = add nuw nsw i32 %i, 1
  %cond = icmp slt i32 %i.next, %n
  br i1 %cond, label %loop, label %exit

fail:
  ret i32 -1

exit:
  ret i32 0
}
