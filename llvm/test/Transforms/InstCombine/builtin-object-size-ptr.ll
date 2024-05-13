; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=instcombine -S < %s | FileCheck %s

; int foo() {
; struct V { char buf1[10];
;            int b;
;            char buf2[10];
;           } var;
;
;           char *p = &var.buf1[1];
;           return __builtin_object_size (p, 0);
; }

%struct.V = type { [10 x i8], i32, [10 x i8] }

define i32 @foo() #0 {
; CHECK-LABEL: @foo(
; CHECK-NEXT:    ret i32 27
;
  %var = alloca %struct.V, align 4
  call void @llvm.lifetime.start.p0(i64 28, ptr %var) #3
  %arrayidx = getelementptr inbounds [10 x i8], ptr %var, i64 0, i64 1
  %t1 = call i64 @llvm.objectsize.i64.p0(ptr %arrayidx, i1 false)
  %conv = trunc i64 %t1 to i32
  call void @llvm.lifetime.end.p0(i64 28, ptr %var) #3
  ret i32 %conv
}

; This used to crash while erasing instructions:
; https://bugs.llvm.org/show_bug.cgi?id=43723

define void @PR43723() {
; CHECK-LABEL: @PR43723(
; CHECK-NEXT:    ret void
;
  %tab = alloca [10 x i8], align 16
  call void @llvm.memset.p0.i64(ptr align 16 %tab, i8 9, i64 10, i1 false)
  %t1 = call ptr @llvm.invariant.start.p0(i64 10, ptr align 16 %tab)
  call void @llvm.invariant.end.p0(ptr %t1, i64 10, ptr align 16 %tab)
  ret void

  uselistorder ptr %tab, { 1, 0, 2 }
}

define void @unknown_use_of_invariant_start(ptr %p) {
; CHECK-LABEL: @unknown_use_of_invariant_start(
; CHECK-NEXT:    ret void
;
  %tab = alloca [10 x i8], align 16
  call void @llvm.memset.p0.i64(ptr align 16 %tab, i8 9, i64 10, i1 false)
  %t1 = call ptr @llvm.invariant.start.p0(i64 10, ptr align 16 %tab)
  call void @llvm.invariant.end.p0(ptr %t1, i64 10, ptr align 16 %tab)
  store ptr %t1, ptr %p
  ret void
}

define ptr @minimal_invariant_start_use(i8 %x) {
; CHECK-LABEL: @minimal_invariant_start_use(
; CHECK-NEXT:    ret ptr poison
;
  %a = alloca i8
  %i = call ptr @llvm.invariant.start.p0(i64 1, ptr %a)
  ret ptr %i
}

declare void @llvm.lifetime.start.p0(i64, ptr nocapture) #1
declare i64 @llvm.objectsize.i64.p0(ptr, i1) #2
declare void @llvm.lifetime.end.p0(i64, ptr nocapture) #1
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #0
declare ptr @llvm.invariant.start.p0(i64 immarg, ptr nocapture) #0
declare void @llvm.invariant.end.p0(ptr, i64 immarg, ptr nocapture) #0
