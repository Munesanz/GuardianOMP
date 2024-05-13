; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -loop-reduce -S < %s | FileCheck %s

; Check when we use an outerloop induction variable inside of an innerloop
; induction value expr, LSR can still choose to use single induction variable
; for the innerloop and share it in multiple induction value exprs.

target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define void @foo(i32 %size, i32 %nsteps, i32 %hsize, ptr %lined, ptr %maxarray) {
; CHECK-LABEL: @foo(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP215:%.*]] = icmp sgt i32 [[SIZE:%.*]], 1
; CHECK-NEXT:    [[T0:%.*]] = zext i32 [[SIZE]] to i64
; CHECK-NEXT:    [[T1:%.*]] = sext i32 [[NSTEPS:%.*]] to i64
; CHECK-NEXT:    [[TMP0:%.*]] = add nsw i64 [[T0]], -1
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[LSR_IV1:%.*]] = phi i64 [ [[LSR_IV_NEXT2:%.*]], [[FOR_INC:%.*]] ], [ 1, [[ENTRY:%.*]] ]
; CHECK-NEXT:    [[INDVARS_IV2:%.*]] = phi i64 [ [[INDVARS_IV_NEXT3:%.*]], [[FOR_INC]] ], [ 0, [[ENTRY]] ]
; CHECK-NEXT:    br i1 [[CMP215]], label [[FOR_BODY2_PREHEADER:%.*]], label [[FOR_INC]]
; CHECK:       for.body2.preheader:
; CHECK-NEXT:    br label [[FOR_BODY2:%.*]]
; CHECK:       for.body2:
; CHECK-NEXT:    [[LSR_IV3:%.*]] = phi ptr [ [[SCEVGEP:%.*]], [[FOR_BODY2]] ], [ [[MAXARRAY:%.*]], [[FOR_BODY2_PREHEADER]] ]
; CHECK-NEXT:    [[LSR_IV:%.*]] = phi i64 [ [[LSR_IV_NEXT:%.*]], [[FOR_BODY2]] ], [ [[TMP0]], [[FOR_BODY2_PREHEADER]] ]
; CHECK-NEXT:    [[SCEVGEP6:%.*]] = getelementptr i8, ptr [[LSR_IV3]], i64 1
; CHECK-NEXT:    [[V1:%.*]] = load i8, ptr [[SCEVGEP6]], align 1
; CHECK-NEXT:    [[SCEVGEP5:%.*]] = getelementptr i8, ptr [[LSR_IV3]], i64 [[TMP0]]
; CHECK-NEXT:    [[V2:%.*]] = load i8, ptr [[SCEVGEP5]], align 1
; CHECK-NEXT:    [[TMPV:%.*]] = xor i8 [[V1]], [[V2]]
; CHECK-NEXT:    [[SCEVGEP4:%.*]] = getelementptr i8, ptr [[LSR_IV3]], i64 [[LSR_IV1]]
; CHECK-NEXT:    store i8 [[TMPV]], ptr [[SCEVGEP4]], align 1
; CHECK-NEXT:    [[LSR_IV_NEXT]] = add nsw i64 [[LSR_IV]], -1
; CHECK-NEXT:    [[SCEVGEP]] = getelementptr i8, ptr [[LSR_IV3]], i64 1
; CHECK-NEXT:    [[EXITCOND:%.*]] = icmp ne i64 [[LSR_IV_NEXT]], 0
; CHECK-NEXT:    br i1 [[EXITCOND]], label [[FOR_BODY2]], label [[FOR_INC_LOOPEXIT:%.*]]
; CHECK:       for.inc.loopexit:
; CHECK-NEXT:    br label [[FOR_INC]]
; CHECK:       for.inc:
; CHECK-NEXT:    [[INDVARS_IV_NEXT3]] = add nuw nsw i64 [[INDVARS_IV2]], 1
; CHECK-NEXT:    [[LSR_IV_NEXT2]] = add nuw nsw i64 [[LSR_IV1]], [[T0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp slt i64 [[INDVARS_IV_NEXT3]], [[T1]]
; CHECK-NEXT:    br i1 [[CMP]], label [[FOR_BODY]], label [[FOR_END_LOOPEXIT:%.*]]
; CHECK:       for.end.loopexit:
; CHECK-NEXT:    ret void
;
entry:
  %cmp215 = icmp sgt i32 %size, 1
  %t0 = zext i32 %size to i64
  %t1 = sext i32 %nsteps to i64
  %sub2 = sub i64 %t0, 2
  br label %for.body

for.body:                                         ; preds = %for.inc, %entry
  %indvars.iv2 = phi i64 [ %indvars.iv.next3, %for.inc ], [ 0, %entry ]
  %t2 = mul nsw i64 %indvars.iv2, %t0
  br i1 %cmp215, label %for.body2.preheader, label %for.inc

for.body2.preheader:                              ; preds = %for.body
  br label %for.body2

; Check LSR only generates two induction variables for for.body2 one for compare and
; one to shared by multiple array accesses.

for.body2:                                        ; preds = %for.body2.preheader, %for.body2
  %indvars.iv = phi i64 [ 1, %for.body2.preheader ], [ %indvars.iv.next, %for.body2 ]
  %arrayidx1 = getelementptr inbounds i8, ptr %maxarray, i64 %indvars.iv
  %v1 = load i8, ptr %arrayidx1, align 1
  %idx2 = add nsw i64 %indvars.iv, %sub2
  %arrayidx2 = getelementptr inbounds i8, ptr %maxarray, i64 %idx2
  %v2 = load i8, ptr %arrayidx2, align 1
  %tmpv = xor i8 %v1, %v2
  %t4 = add nsw i64 %t2, %indvars.iv
  %add.ptr = getelementptr inbounds i8, ptr %maxarray, i64 %t4
  store i8 %tmpv, ptr %add.ptr, align 1
  %indvars.iv.next = add nuw nsw i64 %indvars.iv, 1
  %wide.trip.count = zext i32 %size to i64
  %exitcond = icmp ne i64 %indvars.iv.next, %wide.trip.count
  br i1 %exitcond, label %for.body2, label %for.inc.loopexit

for.inc.loopexit:                                 ; preds = %for.body2
  br label %for.inc

for.inc:                                          ; preds = %for.inc.loopexit, %for.body
  %indvars.iv.next3 = add nuw nsw i64 %indvars.iv2, 1
  %cmp = icmp slt i64 %indvars.iv.next3, %t1
  br i1 %cmp, label %for.body, label %for.end.loopexit

for.end.loopexit:                                 ; preds = %for.inc
  ret void
}
