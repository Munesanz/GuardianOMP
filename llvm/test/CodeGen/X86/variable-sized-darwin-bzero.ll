; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i686-apple-darwin10 | FileCheck %s

define void @foo(ptr %p, i64 %n) {
; CHECK-LABEL: foo:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    subl $12, %esp
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    movl {{[0-9]+}}(%esp), %eax
; CHECK-NEXT:    movl {{[0-9]+}}(%esp), %ecx
; CHECK-NEXT:    movl %ecx, {{[0-9]+}}(%esp)
; CHECK-NEXT:    movl %eax, (%esp)
; CHECK-NEXT:    calll ___bzero
; CHECK-NEXT:    addl $12, %esp
; CHECK-NEXT:    retl
  call void @llvm.memset.p0.i64(ptr align 4 %p, i8 0, i64 %n, i1 false)
  ret void
}

declare void @llvm.memset.p0.i64(ptr nocapture, i8, i64, i1) nounwind
