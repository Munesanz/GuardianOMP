; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 2
; RUN: llc < %s -mtriple=x86_64 -o - | FileCheck %s

define void @foo(i32 %i) nounwind {
; CHECK-LABEL: foo:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    pushq %rax
; CHECK-NEXT:    cmpl $7, %edi
; CHECK-NEXT:    je .LBB0_3
; CHECK-NEXT:  # %bb.1: # %entry
; CHECK-NEXT:    cmpl $5, %edi
; CHECK-NEXT:    jne .LBB0_4
; CHECK-NEXT:  # %bb.2: # %if.then
; CHECK-NEXT:    callq bar
; CHECK-NEXT:    popq %rax
; CHECK-NEXT:    jmp bar # TAILCALL
; CHECK-NEXT:  .LBB0_3: # %if.then2
; CHECK-NEXT:    callq bar
; CHECK-NEXT:  .LBB0_4: # %if.end3
; CHECK-NEXT:    popq %rax
; CHECK-NEXT:    jmp bar # TAILCALL
entry:
  switch i32 %i, label %if.end3 [
    i32 5, label %if.then
    i32 7, label %if.then2
  ]

if.then:
  tail call void @bar() #0
  br label %if.end3

if.then2:
  tail call void @bar() #0
  br label %if.end3

if.end3:
  tail call void @bar() #0
  ret void
}

define void @foo_tail(i1 %i) nounwind {
; CHECK-LABEL: foo_tail:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    testb $1, %dil
; CHECK-NEXT:    jmp bar # TAILCALL
entry:
  br i1 %i, label %if.then, label %if.else

if.then:
  tail call void @bar() #0
  br label %if.end

if.else:
  tail call void @bar() #0
  br label %if.end

if.end:
  ret void
}

declare dso_local void @bar()

attributes #0 = { nomerge }
