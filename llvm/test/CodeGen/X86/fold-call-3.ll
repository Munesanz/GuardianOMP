; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-apple-darwin | FileCheck %s
; rdar://6522427
; This command line used to crash due to dangling nodes left after PreprocessISelDAG
; RUN: llc < %s -mtriple=x86_64-apple-darwin -pre-RA-sched=linearize | FileCheck %s --check-prefix=pre-RA

	%"struct.clang::Action" = type { %"struct.clang::ActionBase" }
	%"struct.clang::ActionBase" = type { ptr }
	%"struct.clang::ActionBase::ActionResult<0u>" = type { ptr, i8 }
@NumTrials = internal global i32 10000000		; <ptr> [#uses=2]
@llvm.used = appending global [1 x ptr] [ ptr @_Z25RawPointerPerformanceTestPvRN5clang6ActionE ], section "llvm.metadata"		; <ptr> [#uses=0]

define void @_Z25RawPointerPerformanceTestPvRN5clang6ActionE(ptr %Val, ptr %Actions) nounwind {
; CHECK-LABEL: _Z25RawPointerPerformanceTestPvRN5clang6ActionE:
; CHECK:       ## %bb.0: ## %entry
; CHECK-NEXT:    pushq %rbp
; CHECK-NEXT:    pushq %rbx
; CHECK-NEXT:    subq $24, %rsp
; CHECK-NEXT:    cmpl $0, _NumTrials(%rip)
; CHECK-NEXT:    je LBB0_3
; CHECK-NEXT:  ## %bb.1: ## %bb.nph
; CHECK-NEXT:    movq %rsi, %rbx
; CHECK-NEXT:    movq %rdi, %rax
; CHECK-NEXT:    xorl %ebp, %ebp
; CHECK-NEXT:    .p2align 4, 0x90
; CHECK-NEXT:  LBB0_2: ## %bb
; CHECK-NEXT:    ## =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    movq (%rbx), %rcx
; CHECK-NEXT:    movq %rbx, %rdi
; CHECK-NEXT:    movq %rax, %rsi
; CHECK-NEXT:    callq *560(%rcx)
; CHECK-NEXT:    movq %rax, {{[0-9]+}}(%rsp)
; CHECK-NEXT:    movq %rdx, {{[0-9]+}}(%rsp)
; CHECK-NEXT:    incl %ebp
; CHECK-NEXT:    cmpl _NumTrials(%rip), %ebp
; CHECK-NEXT:    jb LBB0_2
; CHECK-NEXT:  LBB0_3: ## %return
; CHECK-NEXT:    addq $24, %rsp
; CHECK-NEXT:    popq %rbx
; CHECK-NEXT:    popq %rbp
; CHECK-NEXT:    retq
;
; pre-RA-LABEL: _Z25RawPointerPerformanceTestPvRN5clang6ActionE:
; pre-RA:       ## %bb.0: ## %entry
; pre-RA-NEXT:    pushq %rbp
; pre-RA-NEXT:    pushq %rbx
; pre-RA-NEXT:    subq $24, %rsp
; pre-RA-NEXT:    cmpl $0, _NumTrials(%rip)
; pre-RA-NEXT:    je LBB0_3
; pre-RA-NEXT:  ## %bb.1: ## %bb.nph
; pre-RA-NEXT:    movq %rsi, %rbx
; pre-RA-NEXT:    movq %rdi, %rax
; pre-RA-NEXT:    xorl %ebp, %ebp
; pre-RA-NEXT:    .p2align 4, 0x90
; pre-RA-NEXT:  LBB0_2: ## %bb
; pre-RA-NEXT:    ## =>This Inner Loop Header: Depth=1
; pre-RA-NEXT:    movq (%rbx), %rcx
; pre-RA-NEXT:    movq %rbx, %rdi
; pre-RA-NEXT:    movq %rax, %rsi
; pre-RA-NEXT:    callq *560(%rcx)
; pre-RA-NEXT:    incl %ebp
; pre-RA-NEXT:    movq %rax, {{[0-9]+}}(%rsp)
; pre-RA-NEXT:    movq %rdx, {{[0-9]+}}(%rsp)
; pre-RA-NEXT:    cmpl _NumTrials(%rip), %ebp
; pre-RA-NEXT:    jb LBB0_2
; pre-RA-NEXT:  LBB0_3: ## %return
; pre-RA-NEXT:    addq $24, %rsp
; pre-RA-NEXT:    popq %rbx
; pre-RA-NEXT:    popq %rbp
; pre-RA-NEXT:    retq
entry:
  %i = alloca %"struct.clang::ActionBase::ActionResult<0u>", align 8
  %i1 = load i32, ptr @NumTrials, align 4
  %i2 = icmp eq i32 %i1, 0
  br i1 %i2, label %return, label %bb.nph

bb.nph:                                           ; preds = %entry
  %mrv_gep1 = getelementptr %"struct.clang::ActionBase::ActionResult<0u>", ptr %i, i64 0, i32 1
  br label %bb

bb:                                               ; preds = %bb, %bb.nph
  %Trial.01 = phi i32 [ 0, %bb.nph ], [ %i12, %bb ]
  %Val_addr.02 = phi ptr [ %Val, %bb.nph ], [ %i11, %bb ]
  %i6 = load ptr, ptr %Actions, align 8
  %i7 = getelementptr ptr, ptr %i6, i64 70
  %i8 = load ptr, ptr %i7, align 8
  %i10 = call { i64, i64 } %i8(ptr %Actions, ptr %Val_addr.02) #0
  %mrv_gr = extractvalue { i64, i64 } %i10, 0
  store i64 %mrv_gr, ptr %i, align 4
  %mrv_gr2 = extractvalue { i64, i64 } %i10, 1
  store i64 %mrv_gr2, ptr %mrv_gep1, align 4
  %i11 = load ptr, ptr %i, align 8
  %i12 = add i32 %Trial.01, 1
  %i13 = load i32, ptr @NumTrials, align 4
  %i14 = icmp ult i32 %i12, %i13
  br i1 %i14, label %bb, label %return

return:                                           ; preds = %bb, %entry
  ret void
}
