; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes='early-cse<memssa>' -earlycse-debug-hash -S %s | FileCheck %s

@b = external global i32

define void @patatino() {
; CHECK-LABEL: @patatino(
; CHECK-NEXT:  for.cond:
; CHECK-NEXT:    br i1 true, label [[IF_END:%.*]], label [[FOR_INC:%.*]]
; CHECK:       if.end:
; CHECK-NEXT:    [[TINKYWINKY:%.*]] = load i32, ptr @b, align 4
; CHECK-NEXT:    br i1 true, label [[FOR_INC]], label [[FOR_INC]]
; CHECK:       for.inc:
; CHECK-NEXT:    ret void
;
for.cond:
  br i1 true, label %if.end, label %for.inc

if.end:
  %tinkywinky = load i32, ptr @b
  store i32 %tinkywinky, ptr @b
  br i1 true, label %for.inc, label %for.inc

for.inc:
  ret void
}
