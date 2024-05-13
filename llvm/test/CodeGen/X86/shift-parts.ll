; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=x86_64-- < %s | FileCheck %s
; PR4736

%0 = type { i32, i8, [35 x i8] }

@g_144 = external dso_local global %0, align 8              ; <ptr> [#uses=1]

define i32 @int87(i32 %uint64p_8, i1 %cond) nounwind {
; CHECK-LABEL: int87:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq g_144+24(%rip), %rax
; CHECK-NEXT:    movq g_144+16(%rip), %rcx
; CHECK-NEXT:    movzbl %sil, %edx
; CHECK-NEXT:    shll $6, %edx
; CHECK-NEXT:    .p2align 4, 0x90
; CHECK-NEXT:  .LBB0_1: # %for.cond
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    testb $64, %dl
; CHECK-NEXT:    movq %rcx, %rsi
; CHECK-NEXT:    cmovneq %rax, %rsi
; CHECK-NEXT:    testl %esi, %esi
; CHECK-NEXT:    je .LBB0_1
; CHECK-NEXT:  # %bb.2: # %if.then
; CHECK-NEXT:    movl $1, %eax
; CHECK-NEXT:    retq
entry:
  %srcval4 = load i320, ptr @g_144, align 8 ; <i320> [#uses=1]
  br label %for.cond

for.cond:                                         ; preds = %for.cond, %entry
  %call3.in.in.in.v = select i1 %cond, i320 192, i320 128 ; <i320> [#uses=1]
  %call3.in.in.in = lshr i320 %srcval4, %call3.in.in.in.v ; <i320> [#uses=1]
  %call3.in = trunc i320 %call3.in.in.in to i32   ; <i32> [#uses=1]
  %tobool = icmp eq i32 %call3.in, 0              ; <i1> [#uses=1]
  br i1 %tobool, label %for.cond, label %if.then

if.then:                                          ; preds = %for.cond
  ret i32 1
}
