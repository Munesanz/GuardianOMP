; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=indvars -S < %s | FileCheck %s

; FIXME: In all cases, x is from [0; 1000) and we cannot prove that x + 1 > x.

define void @test_sgt(i32 %x) {
; CHECK-LABEL: @test_sgt(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[PRECONDITION:%.*]] = icmp ult i32 [[X:%.*]], 1000
; CHECK-NEXT:    br i1 [[PRECONDITION]], label [[LOOP_PREHEADER:%.*]], label [[EXIT:%.*]]
; CHECK:       loop.preheader:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i32 [ [[IV_NEXT:%.*]], [[GUARDED:%.*]] ], [ [[X]], [[LOOP_PREHEADER]] ]
; CHECK-NEXT:    [[TMP:%.*]] = add i32 [[IV]], 1
; CHECK-NEXT:    [[GUARD:%.*]] = icmp sgt i32 [[TMP]], [[IV]]
; CHECK-NEXT:    br i1 [[GUARD]], label [[GUARDED]], label [[FAIL:%.*]]
; CHECK:       guarded:
; CHECK-NEXT:    [[IV_NEXT]] = add i32 [[IV]], -1
; CHECK-NEXT:    [[COND:%.*]] = icmp eq i32 [[IV]], 0
; CHECK-NEXT:    br i1 [[COND]], label [[LOOP]], label [[EXIT_LOOPEXIT:%.*]]
; CHECK:       exit.loopexit:
; CHECK-NEXT:    br label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
; CHECK:       fail:
; CHECK-NEXT:    unreachable
;
entry:
  %precondition = icmp ult i32 %x, 1000
  br i1 %precondition, label %loop, label %exit

loop:
  %iv = phi i32 [%x, %entry], [%iv.next, %guarded]
  %tmp = add i32 %iv, 1
  %guard = icmp sgt i32 %tmp, %iv
  br i1 %guard, label %guarded, label %fail

guarded:
  %iv.next = add i32 %iv, -1
  %cond = icmp eq i32 %iv, 0
  br i1 %cond, label %loop, label %exit

exit:
  ret void

fail:
  unreachable
}

define void @test_sge(i32 %x) {
; CHECK-LABEL: @test_sge(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[PRECONDITION:%.*]] = icmp ult i32 [[X:%.*]], 1000
; CHECK-NEXT:    br i1 [[PRECONDITION]], label [[LOOP_PREHEADER:%.*]], label [[EXIT:%.*]]
; CHECK:       loop.preheader:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i32 [ [[IV_NEXT:%.*]], [[GUARDED:%.*]] ], [ [[X]], [[LOOP_PREHEADER]] ]
; CHECK-NEXT:    [[TMP:%.*]] = add i32 [[IV]], 1
; CHECK-NEXT:    [[GUARD:%.*]] = icmp sge i32 [[TMP]], [[IV]]
; CHECK-NEXT:    br i1 [[GUARD]], label [[GUARDED]], label [[FAIL:%.*]]
; CHECK:       guarded:
; CHECK-NEXT:    [[IV_NEXT]] = add i32 [[IV]], -1
; CHECK-NEXT:    [[COND:%.*]] = icmp eq i32 [[IV]], 0
; CHECK-NEXT:    br i1 [[COND]], label [[LOOP]], label [[EXIT_LOOPEXIT:%.*]]
; CHECK:       exit.loopexit:
; CHECK-NEXT:    br label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
; CHECK:       fail:
; CHECK-NEXT:    unreachable
;
entry:
  %precondition = icmp ult i32 %x, 1000
  br i1 %precondition, label %loop, label %exit

loop:
  %iv = phi i32 [%x, %entry], [%iv.next, %guarded]
  %tmp = add i32 %iv, 1
  %guard = icmp sge i32 %tmp, %iv
  br i1 %guard, label %guarded, label %fail

guarded:
  %iv.next = add i32 %iv, -1
  %cond = icmp eq i32 %iv, 0
  br i1 %cond, label %loop, label %exit

exit:
  ret void

fail:
  unreachable
}

define void @test_ugt(i32 %x) {
; CHECK-LABEL: @test_ugt(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[PRECONDITION:%.*]] = icmp ult i32 [[X:%.*]], 1000
; CHECK-NEXT:    br i1 [[PRECONDITION]], label [[LOOP_PREHEADER:%.*]], label [[EXIT:%.*]]
; CHECK:       loop.preheader:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i32 [ [[IV_NEXT:%.*]], [[GUARDED:%.*]] ], [ [[X]], [[LOOP_PREHEADER]] ]
; CHECK-NEXT:    [[TMP:%.*]] = add i32 [[IV]], 1
; CHECK-NEXT:    [[GUARD:%.*]] = icmp ugt i32 [[TMP]], [[IV]]
; CHECK-NEXT:    br i1 [[GUARD]], label [[GUARDED]], label [[FAIL:%.*]]
; CHECK:       guarded:
; CHECK-NEXT:    [[IV_NEXT]] = add i32 [[IV]], -1
; CHECK-NEXT:    [[COND:%.*]] = icmp eq i32 [[IV]], 0
; CHECK-NEXT:    br i1 [[COND]], label [[LOOP]], label [[EXIT_LOOPEXIT:%.*]]
; CHECK:       exit.loopexit:
; CHECK-NEXT:    br label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
; CHECK:       fail:
; CHECK-NEXT:    unreachable
;
entry:
  %precondition = icmp ult i32 %x, 1000
  br i1 %precondition, label %loop, label %exit

loop:
  %iv = phi i32 [%x, %entry], [%iv.next, %guarded]
  %tmp = add i32 %iv, 1
  %guard = icmp ugt i32 %tmp, %iv
  br i1 %guard, label %guarded, label %fail

guarded:
  %iv.next = add i32 %iv, -1
  %cond = icmp eq i32 %iv, 0
  br i1 %cond, label %loop, label %exit

exit:
  ret void

fail:
  unreachable
}


define void @test_uge(i32 %x) {
; CHECK-LABEL: @test_uge(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[PRECONDITION:%.*]] = icmp ult i32 [[X:%.*]], 1000
; CHECK-NEXT:    br i1 [[PRECONDITION]], label [[LOOP_PREHEADER:%.*]], label [[EXIT:%.*]]
; CHECK:       loop.preheader:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i32 [ [[IV_NEXT:%.*]], [[GUARDED:%.*]] ], [ [[X]], [[LOOP_PREHEADER]] ]
; CHECK-NEXT:    [[TMP:%.*]] = add i32 [[IV]], 1
; CHECK-NEXT:    [[GUARD:%.*]] = icmp uge i32 [[TMP]], [[IV]]
; CHECK-NEXT:    br i1 [[GUARD]], label [[GUARDED]], label [[FAIL:%.*]]
; CHECK:       guarded:
; CHECK-NEXT:    [[IV_NEXT]] = add i32 [[IV]], -1
; CHECK-NEXT:    [[COND:%.*]] = icmp eq i32 [[IV]], 0
; CHECK-NEXT:    br i1 [[COND]], label [[LOOP]], label [[EXIT_LOOPEXIT:%.*]]
; CHECK:       exit.loopexit:
; CHECK-NEXT:    br label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
; CHECK:       fail:
; CHECK-NEXT:    unreachable
;
entry:
  %precondition = icmp ult i32 %x, 1000
  br i1 %precondition, label %loop, label %exit

loop:
  %iv = phi i32 [%x, %entry], [%iv.next, %guarded]
  %tmp = add i32 %iv, 1
  %guard = icmp uge i32 %tmp, %iv
  br i1 %guard, label %guarded, label %fail

guarded:
  %iv.next = add i32 %iv, -1
  %cond = icmp eq i32 %iv, 0
  br i1 %cond, label %loop, label %exit

exit:
  ret void

fail:
  unreachable
}
