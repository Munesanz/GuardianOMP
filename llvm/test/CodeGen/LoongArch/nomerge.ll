; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 2
; RUN: llc --mtriple=loongarch64 < %s | FileCheck %s

define void @foo(i32 %i) nounwind {
; CHECK-LABEL: foo:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    addi.d $sp, $sp, -16
; CHECK-NEXT:    st.d $ra, $sp, 8 # 8-byte Folded Spill
; CHECK-NEXT:    bstrpick.d $a0, $a0, 31, 0
; CHECK-NEXT:    ori $a1, $zero, 7
; CHECK-NEXT:    beq $a0, $a1, .LBB0_3
; CHECK-NEXT:  # %bb.1: # %entry
; CHECK-NEXT:    ori $a1, $zero, 5
; CHECK-NEXT:    bne $a0, $a1, .LBB0_4
; CHECK-NEXT:  # %bb.2: # %if.then
; CHECK-NEXT:    bl %plt(bar)
; CHECK-NEXT:    b .LBB0_4
; CHECK-NEXT:  .LBB0_3: # %if.then2
; CHECK-NEXT:    bl %plt(bar)
; CHECK-NEXT:  .LBB0_4: # %if.end3
; CHECK-NEXT:    ld.d $ra, $sp, 8 # 8-byte Folded Reload
; CHECK-NEXT:    addi.d $sp, $sp, 16
; CHECK-NEXT:    b %plt(bar)
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
; CHECK-NEXT:    andi $a0, $a0, 1
; CHECK-NEXT:    b %plt(bar)
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

declare void @bar()

attributes #0 = { nomerge }
