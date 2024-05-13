; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -verify-machineinstrs -mtriple=x86_64-unknown-unknown --show-mc-encoding -mattr=+cmpccxadd | FileCheck %s

define dso_local i32 @test_cmpbexadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpbexadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpoxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe0,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 0)
  ret i32 %0
}

declare i32 @llvm.x86.cmpccxadd32(ptr, i32, i32, i32 immarg)

define dso_local i64 @test_cmpbexadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpbexadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpoxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe0,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 0)
  ret i64 %0
}

declare i64 @llvm.x86.cmpccxadd64(ptr, i64, i64, i32 immarg)

define dso_local i32 @test_cmpbxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpbxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnoxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe1,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 1)
  ret i32 %0
}

define dso_local i64 @test_cmpbxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpbxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnoxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe1,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 1)
  ret i64 %0
}

define dso_local i32 @test_cmplexadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmplexadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpbxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe2,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 2)
  ret i32 %0
}

define dso_local i64 @test_cmplexadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmplexadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpbxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe2,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 2)
  ret i64 %0
}

define dso_local i32 @test_cmplxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmplxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnbxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe3,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 3)
  ret i32 %0
}

define dso_local i64 @test_cmplxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmplxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnbxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe3,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 3)
  ret i64 %0
}

define dso_local i32 @test_cmpnbexadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnbexadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpzxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe4,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 4)
  ret i32 %0
}

define dso_local i64 @test_cmpnbexadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnbexadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpzxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe4,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 4)
  ret i64 %0
}

define dso_local i32 @test_cmpnbxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnbxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnzxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe5,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 5)
  ret i32 %0
}

define dso_local i64 @test_cmpnbxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnbxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnzxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe5,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 5)
  ret i64 %0
}

define dso_local i32 @test_cmpnlexadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnlexadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpbexadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe6,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 6)
  ret i32 %0
}

define dso_local i64 @test_cmpnlexadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnlexadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpbexadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe6,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 6)
  ret i64 %0
}

define dso_local i32 @test_cmpnlxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnlxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnbexadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe7,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 7)
  ret i32 %0
}

define dso_local i64 @test_cmpnlxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnlxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnbexadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe7,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 7)
  ret i64 %0
}

define dso_local i32 @test_cmpnoxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnoxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpsxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe8,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 8)
  ret i32 %0
}

define dso_local i64 @test_cmpnoxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnoxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpsxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe8,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 8)
  ret i64 %0
}

define dso_local i32 @test_cmpnpxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnpxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnsxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xe9,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 9)
  ret i32 %0
}

define dso_local i64 @test_cmpnpxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnpxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnsxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xe9,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 9)
  ret i64 %0
}

define dso_local i32 @test_cmpnsxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnsxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmppxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xea,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 10)
  ret i32 %0
}

define dso_local i64 @test_cmpnsxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnsxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmppxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xea,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 10)
  ret i64 %0
}

define dso_local i32 @test_cmpnzxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpnzxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnpxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xeb,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 11)
  ret i32 %0
}

define dso_local i64 @test_cmpnzxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpnzxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnpxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xeb,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 11)
  ret i64 %0
}

define dso_local i32 @test_cmpoxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpoxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmplxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xec,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 12)
  ret i32 %0
}

define dso_local i64 @test_cmpoxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpoxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmplxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xec,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 12)
  ret i64 %0
}

define dso_local i32 @test_cmppxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmppxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnlxadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xed,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 13)
  ret i32 %0
}

define dso_local i64 @test_cmppxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmppxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnlxadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xed,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 13)
  ret i64 %0
}

define dso_local i32 @test_cmpsxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpsxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmplexadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xee,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 14)
  ret i32 %0
}

define dso_local i64 @test_cmpsxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpsxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmplexadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xee,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 14)
  ret i64 %0
}

define dso_local i32 @test_cmpzxadd32(ptr %__A, i32 %__B, i32 %__C) nounwind {
; CHECK-LABEL: test_cmpzxadd32:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movl %esi, %eax # encoding: [0x89,0xf0]
; CHECK-NEXT:    cmpnlexadd %edx, %eax, (%rdi) # encoding: [0xc4,0xe2,0x69,0xef,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i32 @llvm.x86.cmpccxadd32(ptr %__A, i32 %__B, i32 %__C, i32 15)
  ret i32 %0
}

define dso_local i64 @test_cmpzxadd64(ptr %__A, i64 %__B, i64 %__C) nounwind {
; CHECK-LABEL: test_cmpzxadd64:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq %rsi, %rax # encoding: [0x48,0x89,0xf0]
; CHECK-NEXT:    cmpnlexadd %rdx, %rax, (%rdi) # encoding: [0xc4,0xe2,0xe9,0xef,0x07]
; CHECK-NEXT:    retq # encoding: [0xc3]
entry:
  %0 = tail call i64 @llvm.x86.cmpccxadd64(ptr %__A, i64 %__B, i64 %__C, i32 15)
  ret i64 %0
}
