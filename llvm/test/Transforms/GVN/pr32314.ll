; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -passes=gvn < %s | FileCheck %s

target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; The load in the loop can not bypass the data from the previous loop. The store above it in the loop aliases.
define void @foo() {
; CHECK-LABEL: @foo(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A:%.*]] = alloca [3 x i32], align 4
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.cond.cleanup:
; CHECK-NEXT:    ret void
; CHECK:       for.body:
; CHECK-NEXT:    [[INDVARS_IV:%.*]] = phi i64 [ 1, [[ENTRY:%.*]] ], [ [[INDVARS_IV_NEXT:%.*]], [[FOR_BODY]] ]
; CHECK-NEXT:    [[P_017:%.*]] = phi ptr [ undef, [[ENTRY]] ], [ [[ARRAYIDX3:%.*]], [[FOR_BODY]] ]
; CHECK-NEXT:    [[TMP0:%.*]] = add nsw i64 [[INDVARS_IV]], -1
; CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds [3 x i32], ptr [[A]], i64 0, i64 [[TMP0]]
; CHECK-NEXT:    store i32 50, ptr [[ARRAYIDX]], align 4
; CHECK-NEXT:    [[TMP1:%.*]] = shl i64 [[INDVARS_IV]], 1
; CHECK-NEXT:    [[TMP2:%.*]] = load i32, ptr [[P_017]], align 4
; CHECK-NEXT:    [[TMP3:%.*]] = trunc i64 [[TMP1]] to i32
; CHECK-NEXT:    [[ADD1:%.*]] = add nsw i32 [[TMP2]], [[TMP3]]
; CHECK-NEXT:    [[ARRAYIDX3]] = getelementptr inbounds [3 x i32], ptr [[A]], i64 0, i64 [[INDVARS_IV]]
; CHECK-NEXT:    store i32 60, ptr [[ARRAYIDX3]], align 4
; CHECK-NEXT:    [[INDVARS_IV_NEXT]] = add nuw nsw i64 [[INDVARS_IV]], 1
; CHECK-NEXT:    [[EXITCOND:%.*]] = icmp ne i64 [[INDVARS_IV_NEXT]], 3
; CHECK-NEXT:    br i1 [[EXITCOND]], label [[FOR_BODY]], label [[FOR_COND_CLEANUP:%.*]]
;
entry:
  %a = alloca [3 x i32], align 4
  br label %for.body

for.cond.cleanup:                                 ; preds = %for.body
  ret void

for.body:                                         ; preds = %for.body, %entry
  %indvars.iv = phi i64 [ 1, %entry ], [ %indvars.iv.next, %for.body ]
  %p.017 = phi ptr [ undef, %entry ], [ %arrayidx3, %for.body ]
  %0 = add nsw i64 %indvars.iv, -1
  %arrayidx = getelementptr inbounds [3 x i32], ptr %a, i64 0, i64 %0
  store i32 50, ptr %arrayidx, align 4
  %1 = shl i64 %indvars.iv, 1
  %2 = load i32, ptr %p.017, align 4
  %3 = trunc i64 %1 to i32
  %add1 = add nsw i32 %2, %3
  %arrayidx3 = getelementptr inbounds [3 x i32], ptr %a, i64 0, i64 %indvars.iv
  store i32 60, ptr %arrayidx3, align 4
  %indvars.iv.next = add nuw nsw i64 %indvars.iv, 1
  %exitcond = icmp ne i64 %indvars.iv.next, 3
  br i1 %exitcond, label %for.body, label %for.cond.cleanup
}
