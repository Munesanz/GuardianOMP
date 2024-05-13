; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instcombine -S | FileCheck %s

declare i32 @llvm.smax.i32(i32 %a, i32 %b)
declare i32 @llvm.smin.i32(i32 %a, i32 %b)
declare i32 @llvm.umax.i32(i32 %a, i32 %b)
declare i32 @llvm.umin.i32(i32 %a, i32 %b)

define i32 @uadd_min_max(i32 %a, i32 %b) {
; CHECK-LABEL: @uadd_min_max(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add i32 [[A:%.*]], [[B:%.*]]
; CHECK-NEXT:    ret i32 [[RES]]
;
entry:
  %max = call i32 @llvm.umax.i32(i32 %a, i32 %b)
  %min = call i32 @llvm.umin.i32(i32 %a, i32 %b)
  %res = add i32 %min, %max
  ret i32 %res
}

define i32 @uadd_min_max_comm(i32 %a, i32 %b) {
; CHECK-LABEL: @uadd_min_max_comm(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add i32 [[B:%.*]], [[A:%.*]]
; CHECK-NEXT:    ret i32 [[RES]]
;
entry:
  %max = call i32 @llvm.umax.i32(i32 %b, i32 %a)
  %min = call i32 @llvm.umin.i32(i32 %a, i32 %b)
  %res = add i32 %min, %max
  ret i32 %res
}

define i32 @uadd_min_max_nuw_nsw(i32 %a, i32 %b) {
; CHECK-LABEL: @uadd_min_max_nuw_nsw(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add nuw nsw i32 [[A:%.*]], [[B:%.*]]
; CHECK-NEXT:    ret i32 [[RES]]
;
entry:
  %max = call i32 @llvm.umax.i32(i32 %a, i32 %b)
  %min = call i32 @llvm.umin.i32(i32 %a, i32 %b)
  %res = add nuw nsw i32 %min, %max
  ret i32 %res
}

define i32 @sadd_min_max(i32 %a, i32 %b) {
; CHECK-LABEL: @sadd_min_max(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add i32 [[A:%.*]], [[B:%.*]]
; CHECK-NEXT:    ret i32 [[RES]]
;
entry:
  %max = call i32 @llvm.smax.i32(i32 %a, i32 %b)
  %min = call i32 @llvm.smin.i32(i32 %a, i32 %b)
  %res = add i32 %min, %max
  ret i32 %res
}

define i32 @sadd_min_max_comm(i32 %a, i32 %b) {
; CHECK-LABEL: @sadd_min_max_comm(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add i32 [[B:%.*]], [[A:%.*]]
; CHECK-NEXT:    ret i32 [[RES]]
;
entry:
  %max = call i32 @llvm.smax.i32(i32 %b, i32 %a)
  %min = call i32 @llvm.smin.i32(i32 %a, i32 %b)
  %res = add i32 %min, %max
  ret i32 %res
}

define i32 @sadd_min_max_nuw_nsw(i32 %a, i32 %b) {
; CHECK-LABEL: @sadd_min_max_nuw_nsw(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add nuw nsw i32 [[A:%.*]], [[B:%.*]]
; CHECK-NEXT:    ret i32 [[RES]]
;
entry:
  %max = call i32 @llvm.smax.i32(i32 %a, i32 %b)
  %min = call i32 @llvm.smin.i32(i32 %a, i32 %b)
  %res = add nuw nsw i32 %min, %max
  ret i32 %res
}
