; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i686-- | FileCheck %s

@x = external dso_local global i32                ; <ptr> [#uses=1]

define i32 @test() {
; CHECK-LABEL: test:
; CHECK:       # %bb.0:
; CHECK-NEXT:    movl x, %eax
; CHECK-NEXT:    addl %eax, %eax
; CHECK-NEXT:    retl
        %tmp.0 = load i32, ptr @x           ; <i32> [#uses=1]
        %tmp.1 = shl i32 %tmp.0, 1              ; <i32> [#uses=1]
        ret i32 %tmp.1
}

