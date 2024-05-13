; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=i686-unknown-linux-gnu -mattr=-sse -verify-machineinstrs < %s | FileCheck %s --check-prefix=X86
; RUN: llc -mtriple=i686-unknown-linux-gnu -mattr=-sse2 -verify-machineinstrs < %s | FileCheck %s --check-prefix=X86
; RUN: llc -mtriple=x86_64-unknown-linux-gnu -verify-machineinstrs < %s | FileCheck %s --check-prefix=X64

declare i32 @llvm.get.rounding()

define i32 @test_flt_rounds() nounwind {
; X86-LABEL: test_flt_rounds:
; X86:       # %bb.0:
; X86-NEXT:    subl $2, %esp
; X86-NEXT:    fnstcw (%esp)
; X86-NEXT:    movzwl (%esp), %ecx
; X86-NEXT:    shrl $9, %ecx
; X86-NEXT:    andb $6, %cl
; X86-NEXT:    movl $45, %eax
; X86-NEXT:    # kill: def $cl killed $cl killed $ecx
; X86-NEXT:    shrl %cl, %eax
; X86-NEXT:    andl $3, %eax
; X86-NEXT:    addl $2, %esp
; X86-NEXT:    retl
;
; X64-LABEL: test_flt_rounds:
; X64:       # %bb.0:
; X64-NEXT:    fnstcw -{{[0-9]+}}(%rsp)
; X64-NEXT:    movzwl -{{[0-9]+}}(%rsp), %ecx
; X64-NEXT:    shrl $9, %ecx
; X64-NEXT:    andb $6, %cl
; X64-NEXT:    movl $45, %eax
; X64-NEXT:    # kill: def $cl killed $cl killed $ecx
; X64-NEXT:    shrl %cl, %eax
; X64-NEXT:    andl $3, %eax
; X64-NEXT:    retq
  %1 = call i32 @llvm.get.rounding()
  ret i32 %1
}

; Make sure we preserve order with fesetround.
define i32 @multiple_flt_rounds() nounwind {
; X86-LABEL: multiple_flt_rounds:
; X86:       # %bb.0: # %entry
; X86-NEXT:    pushl %ebx
; X86-NEXT:    pushl %esi
; X86-NEXT:    subl $20, %esp
; X86-NEXT:    movl $1024, (%esp) # imm = 0x400
; X86-NEXT:    calll fesetround
; X86-NEXT:    fnstcw {{[0-9]+}}(%esp)
; X86-NEXT:    movzwl {{[0-9]+}}(%esp), %ecx
; X86-NEXT:    shrl $9, %ecx
; X86-NEXT:    andb $6, %cl
; X86-NEXT:    movl $45, %esi
; X86-NEXT:    movl $45, %eax
; X86-NEXT:    # kill: def $cl killed $cl killed $ecx
; X86-NEXT:    shrl %cl, %eax
; X86-NEXT:    andl $3, %eax
; X86-NEXT:    xorl %ebx, %ebx
; X86-NEXT:    cmpl $3, %eax
; X86-NEXT:    setne %bl
; X86-NEXT:    movl $0, (%esp)
; X86-NEXT:    calll fesetround
; X86-NEXT:    fnstcw {{[0-9]+}}(%esp)
; X86-NEXT:    movzwl {{[0-9]+}}(%esp), %ecx
; X86-NEXT:    shrl $9, %ecx
; X86-NEXT:    andb $6, %cl
; X86-NEXT:    movl $45, %eax
; X86-NEXT:    # kill: def $cl killed $cl killed $ecx
; X86-NEXT:    shrl %cl, %eax
; X86-NEXT:    andl $3, %eax
; X86-NEXT:    cmpl $1, %eax
; X86-NEXT:    je .LBB1_2
; X86-NEXT:  # %bb.1: # %entry
; X86-NEXT:    incl %ebx
; X86-NEXT:  .LBB1_2: # %entry
; X86-NEXT:    movl $3072, (%esp) # imm = 0xC00
; X86-NEXT:    calll fesetround
; X86-NEXT:    fnstcw {{[0-9]+}}(%esp)
; X86-NEXT:    movzwl {{[0-9]+}}(%esp), %ecx
; X86-NEXT:    shrl $9, %ecx
; X86-NEXT:    andb $6, %cl
; X86-NEXT:    movl $45, %eax
; X86-NEXT:    # kill: def $cl killed $cl killed $ecx
; X86-NEXT:    shrl %cl, %eax
; X86-NEXT:    andl $3, %eax
; X86-NEXT:    cmpl $1, %eax
; X86-NEXT:    sbbl $-1, %ebx
; X86-NEXT:    movl $2048, (%esp) # imm = 0x800
; X86-NEXT:    calll fesetround
; X86-NEXT:    fnstcw {{[0-9]+}}(%esp)
; X86-NEXT:    movzwl {{[0-9]+}}(%esp), %ecx
; X86-NEXT:    shrl $9, %ecx
; X86-NEXT:    andb $6, %cl
; X86-NEXT:    # kill: def $cl killed $cl killed $ecx
; X86-NEXT:    shrl %cl, %esi
; X86-NEXT:    andl $3, %esi
; X86-NEXT:    xorl %ecx, %ecx
; X86-NEXT:    cmpl $2, %esi
; X86-NEXT:    setne %cl
; X86-NEXT:    negl %ecx
; X86-NEXT:    xorl %eax, %eax
; X86-NEXT:    cmpl %ecx, %ebx
; X86-NEXT:    setne %al
; X86-NEXT:    addl $20, %esp
; X86-NEXT:    popl %esi
; X86-NEXT:    popl %ebx
; X86-NEXT:    retl
;
; X64-LABEL: multiple_flt_rounds:
; X64:       # %bb.0: # %entry
; X64-NEXT:    pushq %rbp
; X64-NEXT:    pushq %r14
; X64-NEXT:    pushq %rbx
; X64-NEXT:    subq $16, %rsp
; X64-NEXT:    movl $1024, %edi # imm = 0x400
; X64-NEXT:    callq fesetround
; X64-NEXT:    fnstcw {{[0-9]+}}(%rsp)
; X64-NEXT:    movzwl {{[0-9]+}}(%rsp), %ecx
; X64-NEXT:    shrl $9, %ecx
; X64-NEXT:    andb $6, %cl
; X64-NEXT:    movl $45, %ebx
; X64-NEXT:    movl $45, %eax
; X64-NEXT:    # kill: def $cl killed $cl killed $ecx
; X64-NEXT:    shrl %cl, %eax
; X64-NEXT:    andl $3, %eax
; X64-NEXT:    xorl %r14d, %r14d
; X64-NEXT:    cmpl $3, %eax
; X64-NEXT:    setne %r14b
; X64-NEXT:    xorl %edi, %edi
; X64-NEXT:    callq fesetround
; X64-NEXT:    fnstcw {{[0-9]+}}(%rsp)
; X64-NEXT:    movzwl {{[0-9]+}}(%rsp), %ecx
; X64-NEXT:    shrl $9, %ecx
; X64-NEXT:    andb $6, %cl
; X64-NEXT:    movl $45, %eax
; X64-NEXT:    # kill: def $cl killed $cl killed $ecx
; X64-NEXT:    shrl %cl, %eax
; X64-NEXT:    andl $3, %eax
; X64-NEXT:    leal 1(%r14), %ebp
; X64-NEXT:    cmpl $1, %eax
; X64-NEXT:    cmovel %r14d, %ebp
; X64-NEXT:    movl $3072, %edi # imm = 0xC00
; X64-NEXT:    callq fesetround
; X64-NEXT:    fnstcw {{[0-9]+}}(%rsp)
; X64-NEXT:    movzwl {{[0-9]+}}(%rsp), %ecx
; X64-NEXT:    shrl $9, %ecx
; X64-NEXT:    andb $6, %cl
; X64-NEXT:    movl $45, %eax
; X64-NEXT:    # kill: def $cl killed $cl killed $ecx
; X64-NEXT:    shrl %cl, %eax
; X64-NEXT:    andl $3, %eax
; X64-NEXT:    cmpl $1, %eax
; X64-NEXT:    sbbl $-1, %ebp
; X64-NEXT:    movl $2048, %edi # imm = 0x800
; X64-NEXT:    callq fesetround
; X64-NEXT:    fnstcw {{[0-9]+}}(%rsp)
; X64-NEXT:    movzwl {{[0-9]+}}(%rsp), %ecx
; X64-NEXT:    shrl $9, %ecx
; X64-NEXT:    andb $6, %cl
; X64-NEXT:    # kill: def $cl killed $cl killed $ecx
; X64-NEXT:    shrl %cl, %ebx
; X64-NEXT:    andl $3, %ebx
; X64-NEXT:    xorl %ecx, %ecx
; X64-NEXT:    cmpl $2, %ebx
; X64-NEXT:    setne %cl
; X64-NEXT:    negl %ecx
; X64-NEXT:    xorl %eax, %eax
; X64-NEXT:    cmpl %ecx, %ebp
; X64-NEXT:    setne %al
; X64-NEXT:    addq $16, %rsp
; X64-NEXT:    popq %rbx
; X64-NEXT:    popq %r14
; X64-NEXT:    popq %rbp
; X64-NEXT:    retq
entry:
  %call = tail call i32 @fesetround(i32 1024)
  %0 = tail call i32 @llvm.get.rounding()
  %cmp = icmp ne i32 %0, 3
  %spec.select = zext i1 %cmp to i32
  %call1 = tail call i32 @fesetround(i32 0)
  %1 = tail call i32 @llvm.get.rounding()
  %cmp2 = icmp eq i32 %1, 1
  %inc4 = select i1 %cmp, i32 2, i32 1
  %errs.1 = select i1 %cmp2, i32 %spec.select, i32 %inc4
  %call6 = tail call i32 @fesetround(i32 3072)
  %2 = tail call i32 @llvm.get.rounding()
  %cmp7 = icmp ne i32 %2, 0
  %inc9 = zext i1 %cmp7 to i32
  %spec.select22 = add nuw nsw i32 %errs.1, %inc9
  %call11 = tail call i32 @fesetround(i32 2048)
  %3 = tail call i32 @llvm.get.rounding()
  %cmp12 = icmp ne i32 %3, 2
  %inc14.neg = sext i1 %cmp12 to i32
  %cmp16 = icmp ne i32 %spec.select22, %inc14.neg
  %cond = zext i1 %cmp16 to i32
  ret i32 %cond
}

; Function Attrs: nounwind
declare dso_local i32 @fesetround(i32) local_unnamed_addr #1
