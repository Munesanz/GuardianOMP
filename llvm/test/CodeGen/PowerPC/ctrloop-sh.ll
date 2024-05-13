; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -verify-machineinstrs < %s | FileCheck %s
target datalayout = "E-m:e-p:32:32-i128:64-n32"
target triple = "powerpc-ellcc-linux"

; Function Attrs: nounwind
define void @foo1(ptr %a, ptr readonly %b, ptr readonly %c) #0 {
; CHECK-LABEL: foo1:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    stwu 1, -64(1)
; CHECK-NEXT:    stw 28, 48(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 8, 2048
; CHECK-NEXT:    stw 29, 52(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 6, 0
; CHECK-NEXT:    stw 30, 56(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 7, 7
; CHECK-NEXT:    mtctr 8
; CHECK-NEXT:    addi 8, 1, 16
; CHECK-NEXT:  .LBB0_1: # %for.body
; CHECK-NEXT:    #
; CHECK-NEXT:    lwz 9, 0(4)
; CHECK-NEXT:    lwz 10, 4(4)
; CHECK-NEXT:    lwz 11, 8(4)
; CHECK-NEXT:    lwz 12, 12(4)
; CHECK-NEXT:    lwz 0, 12(5)
; CHECK-NEXT:    stw 6, 44(1)
; CHECK-NEXT:    stw 6, 40(1)
; CHECK-NEXT:    stw 6, 36(1)
; CHECK-NEXT:    stw 6, 32(1)
; CHECK-NEXT:    stw 12, 28(1)
; CHECK-NEXT:    clrlwi 12, 0, 29
; CHECK-NEXT:    stw 11, 24(1)
; CHECK-NEXT:    nand 11, 0, 7
; CHECK-NEXT:    stw 10, 20(1)
; CHECK-NEXT:    subfic 29, 12, 32
; CHECK-NEXT:    stw 9, 16(1)
; CHECK-NEXT:    rlwinm 9, 0, 29, 28, 31
; CHECK-NEXT:    lwzux 10, 9, 8
; CHECK-NEXT:    clrlwi 11, 11, 27
; CHECK-NEXT:    lwz 0, 8(9)
; CHECK-NEXT:    slw 10, 10, 12
; CHECK-NEXT:    lwz 30, 4(9)
; CHECK-NEXT:    lwz 9, 12(9)
; CHECK-NEXT:    slw 28, 30, 12
; CHECK-NEXT:    srw 30, 30, 29
; CHECK-NEXT:    srw 29, 9, 29
; CHECK-NEXT:    slw 9, 9, 12
; CHECK-NEXT:    slw 12, 0, 12
; CHECK-NEXT:    srwi 0, 0, 1
; CHECK-NEXT:    stw 9, 12(3)
; CHECK-NEXT:    or 9, 12, 29
; CHECK-NEXT:    srw 11, 0, 11
; CHECK-NEXT:    stw 9, 8(3)
; CHECK-NEXT:    or 9, 10, 30
; CHECK-NEXT:    stw 9, 0(3)
; CHECK-NEXT:    or 9, 28, 11
; CHECK-NEXT:    stw 9, 4(3)
; CHECK-NEXT:    bdnz .LBB0_1
; CHECK-NEXT:  # %bb.2: # %for.end
; CHECK-NEXT:    lwz 30, 56(1) # 4-byte Folded Reload
; CHECK-NEXT:    lwz 29, 52(1) # 4-byte Folded Reload
; CHECK-NEXT:    lwz 28, 48(1) # 4-byte Folded Reload
; CHECK-NEXT:    addi 1, 1, 64
; CHECK-NEXT:    blr
entry:
  br label %for.body

for.body:                                         ; preds = %for.body, %entry
  %i.02 = phi i32 [ 0, %entry ], [ %inc, %for.body ]
  %0 = load i128, ptr %b, align 16
  %1 = load i128, ptr %c, align 16
  %shl = shl i128 %0, %1
  store i128 %shl, ptr %a, align 16
  %inc = add nsw i32 %i.02, 1
  %exitcond = icmp eq i32 %inc, 2048
  br i1 %exitcond, label %for.end, label %for.body

for.end:                                          ; preds = %for.body
  ret void
}

; Function Attrs: nounwind
define void @foo2(ptr %a, ptr readonly %b, ptr readonly %c) #0 {
; CHECK-LABEL: foo2:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    stwu 1, -64(1)
; CHECK-NEXT:    stw 29, 52(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 7, 2048
; CHECK-NEXT:    stw 30, 56(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 6, 7
; CHECK-NEXT:    mtctr 7
; CHECK-NEXT:    addi 7, 1, 36
; CHECK-NEXT:  .LBB1_1: # %for.body
; CHECK-NEXT:    #
; CHECK-NEXT:    lwz 8, 0(4)
; CHECK-NEXT:    lwz 10, 8(4)
; CHECK-NEXT:    lwz 12, 12(5)
; CHECK-NEXT:    lwz 9, 4(4)
; CHECK-NEXT:    lwz 11, 12(4)
; CHECK-NEXT:    stw 10, 44(1)
; CHECK-NEXT:    rlwinm 10, 12, 29, 28, 31
; CHECK-NEXT:    stw 8, 36(1)
; CHECK-NEXT:    srawi 8, 8, 31
; CHECK-NEXT:    stw 11, 48(1)
; CHECK-NEXT:    clrlwi 11, 12, 29
; CHECK-NEXT:    stw 9, 40(1)
; CHECK-NEXT:    nand 9, 12, 6
; CHECK-NEXT:    stw 8, 32(1)
; CHECK-NEXT:    subfic 30, 11, 32
; CHECK-NEXT:    stw 8, 28(1)
; CHECK-NEXT:    clrlwi 9, 9, 27
; CHECK-NEXT:    stw 8, 24(1)
; CHECK-NEXT:    stw 8, 20(1)
; CHECK-NEXT:    sub 8, 7, 10
; CHECK-NEXT:    lwz 10, 4(8)
; CHECK-NEXT:    lwz 12, 8(8)
; CHECK-NEXT:    lwz 0, 0(8)
; CHECK-NEXT:    lwz 8, 12(8)
; CHECK-NEXT:    srw 29, 12, 11
; CHECK-NEXT:    slw 12, 12, 30
; CHECK-NEXT:    slw 30, 0, 30
; CHECK-NEXT:    srw 8, 8, 11
; CHECK-NEXT:    sraw 0, 0, 11
; CHECK-NEXT:    srw 11, 10, 11
; CHECK-NEXT:    slwi 10, 10, 1
; CHECK-NEXT:    or 8, 12, 8
; CHECK-NEXT:    slw 9, 10, 9
; CHECK-NEXT:    stw 8, 12(3)
; CHECK-NEXT:    or 8, 30, 11
; CHECK-NEXT:    stw 8, 4(3)
; CHECK-NEXT:    or 8, 29, 9
; CHECK-NEXT:    stw 0, 0(3)
; CHECK-NEXT:    stw 8, 8(3)
; CHECK-NEXT:    bdnz .LBB1_1
; CHECK-NEXT:  # %bb.2: # %for.end
; CHECK-NEXT:    lwz 30, 56(1) # 4-byte Folded Reload
; CHECK-NEXT:    lwz 29, 52(1) # 4-byte Folded Reload
; CHECK-NEXT:    addi 1, 1, 64
; CHECK-NEXT:    blr
entry:
  br label %for.body

for.body:                                         ; preds = %for.body, %entry
  %i.02 = phi i32 [ 0, %entry ], [ %inc, %for.body ]
  %0 = load i128, ptr %b, align 16
  %1 = load i128, ptr %c, align 16
  %shl = ashr i128 %0, %1
  store i128 %shl, ptr %a, align 16
  %inc = add nsw i32 %i.02, 1
  %exitcond = icmp eq i32 %inc, 2048
  br i1 %exitcond, label %for.end, label %for.body

for.end:                                          ; preds = %for.body
  ret void
}

; Function Attrs: nounwind
define void @foo3(ptr %a, ptr readonly %b, ptr readonly %c) #0 {
; CHECK-LABEL: foo3:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    stwu 1, -64(1)
; CHECK-NEXT:    stw 28, 48(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 8, 2048
; CHECK-NEXT:    stw 29, 52(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 6, 0
; CHECK-NEXT:    stw 30, 56(1) # 4-byte Folded Spill
; CHECK-NEXT:    li 7, 7
; CHECK-NEXT:    mtctr 8
; CHECK-NEXT:    addi 8, 1, 32
; CHECK-NEXT:  .LBB2_1: # %for.body
; CHECK-NEXT:    #
; CHECK-NEXT:    lwz 10, 4(4)
; CHECK-NEXT:    lwz 0, 12(5)
; CHECK-NEXT:    lwz 9, 0(4)
; CHECK-NEXT:    lwz 11, 8(4)
; CHECK-NEXT:    lwz 12, 12(4)
; CHECK-NEXT:    stw 10, 36(1)
; CHECK-NEXT:    rlwinm 10, 0, 29, 28, 31
; CHECK-NEXT:    stw 6, 28(1)
; CHECK-NEXT:    sub 10, 8, 10
; CHECK-NEXT:    stw 6, 24(1)
; CHECK-NEXT:    stw 6, 20(1)
; CHECK-NEXT:    stw 6, 16(1)
; CHECK-NEXT:    stw 12, 44(1)
; CHECK-NEXT:    clrlwi 12, 0, 29
; CHECK-NEXT:    stw 11, 40(1)
; CHECK-NEXT:    subfic 29, 12, 32
; CHECK-NEXT:    stw 9, 32(1)
; CHECK-NEXT:    nand 9, 0, 7
; CHECK-NEXT:    lwz 11, 4(10)
; CHECK-NEXT:    clrlwi 9, 9, 27
; CHECK-NEXT:    lwz 0, 8(10)
; CHECK-NEXT:    lwz 30, 0(10)
; CHECK-NEXT:    lwz 10, 12(10)
; CHECK-NEXT:    srw 28, 0, 12
; CHECK-NEXT:    slw 0, 0, 29
; CHECK-NEXT:    slw 29, 30, 29
; CHECK-NEXT:    srw 10, 10, 12
; CHECK-NEXT:    srw 30, 30, 12
; CHECK-NEXT:    srw 12, 11, 12
; CHECK-NEXT:    slwi 11, 11, 1
; CHECK-NEXT:    slw 9, 11, 9
; CHECK-NEXT:    or 10, 0, 10
; CHECK-NEXT:    stw 10, 12(3)
; CHECK-NEXT:    or 10, 29, 12
; CHECK-NEXT:    or 9, 28, 9
; CHECK-NEXT:    stw 30, 0(3)
; CHECK-NEXT:    stw 10, 4(3)
; CHECK-NEXT:    stw 9, 8(3)
; CHECK-NEXT:    bdnz .LBB2_1
; CHECK-NEXT:  # %bb.2: # %for.end
; CHECK-NEXT:    lwz 30, 56(1) # 4-byte Folded Reload
; CHECK-NEXT:    lwz 29, 52(1) # 4-byte Folded Reload
; CHECK-NEXT:    lwz 28, 48(1) # 4-byte Folded Reload
; CHECK-NEXT:    addi 1, 1, 64
; CHECK-NEXT:    blr
entry:
  br label %for.body

for.body:                                         ; preds = %for.body, %entry
  %i.02 = phi i32 [ 0, %entry ], [ %inc, %for.body ]
  %0 = load i128, ptr %b, align 16
  %1 = load i128, ptr %c, align 16
  %shl = lshr i128 %0, %1
  store i128 %shl, ptr %a, align 16
  %inc = add nsw i32 %i.02, 1
  %exitcond = icmp eq i32 %inc, 2048
  br i1 %exitcond, label %for.end, label %for.body

for.end:                                          ; preds = %for.body
  ret void
}

attributes #0 = { nounwind }
