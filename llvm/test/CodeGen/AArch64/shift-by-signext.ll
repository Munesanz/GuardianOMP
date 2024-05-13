; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=aarch64-unknown-linux-gnu < %s | FileCheck %s

; If we have a shift by sign-extended value, we can replace sign-extension
; with zero-extension.

define i32 @t0_shl(i32 %x, i8 %shamt) nounwind {
; CHECK-LABEL: t0_shl:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sxtb w8, w1
; CHECK-NEXT:    lsl w0, w0, w8
; CHECK-NEXT:    ret
  %shamt_wide = sext i8 %shamt to i32
  %r = shl i32 %x, %shamt_wide
  ret i32 %r
}
define i32 @t1_lshr(i32 %x, i8 %shamt) nounwind {
; CHECK-LABEL: t1_lshr:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sxtb w8, w1
; CHECK-NEXT:    lsr w0, w0, w8
; CHECK-NEXT:    ret
  %shamt_wide = sext i8 %shamt to i32
  %r = lshr i32 %x, %shamt_wide
  ret i32 %r
}
define i32 @t2_ashr(i32 %x, i8 %shamt) nounwind {
; CHECK-LABEL: t2_ashr:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sxtb w8, w1
; CHECK-NEXT:    asr w0, w0, w8
; CHECK-NEXT:    ret
  %shamt_wide = sext i8 %shamt to i32
  %r = ashr i32 %x, %shamt_wide
  ret i32 %r
}

define <4 x i32> @t3_vec_shl(<4 x i32> %x, <4 x i8> %shamt) nounwind {
; CHECK-LABEL: t3_vec_shl:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ushll v1.4s, v1.4h, #0
; CHECK-NEXT:    shl v1.4s, v1.4s, #24
; CHECK-NEXT:    sshr v1.4s, v1.4s, #24
; CHECK-NEXT:    ushl v0.4s, v0.4s, v1.4s
; CHECK-NEXT:    ret
  %shamt_wide = sext <4 x i8> %shamt to <4 x i32>
  %r = shl <4 x i32> %x, %shamt_wide
  ret <4 x i32> %r
}
define <4 x i32> @t4_vec_lshr(<4 x i32> %x, <4 x i8> %shamt) nounwind {
; CHECK-LABEL: t4_vec_lshr:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ushll v1.4s, v1.4h, #0
; CHECK-NEXT:    shl v1.4s, v1.4s, #24
; CHECK-NEXT:    sshr v1.4s, v1.4s, #24
; CHECK-NEXT:    neg v1.4s, v1.4s
; CHECK-NEXT:    ushl v0.4s, v0.4s, v1.4s
; CHECK-NEXT:    ret
  %shamt_wide = sext <4 x i8> %shamt to <4 x i32>
  %r = lshr <4 x i32> %x, %shamt_wide
  ret <4 x i32> %r
}
define <4 x i32> @t5_vec_ashr(<4 x i32> %x, <4 x i8> %shamt) nounwind {
; CHECK-LABEL: t5_vec_ashr:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ushll v1.4s, v1.4h, #0
; CHECK-NEXT:    shl v1.4s, v1.4s, #24
; CHECK-NEXT:    sshr v1.4s, v1.4s, #24
; CHECK-NEXT:    neg v1.4s, v1.4s
; CHECK-NEXT:    sshl v0.4s, v0.4s, v1.4s
; CHECK-NEXT:    ret
  %shamt_wide = sext <4 x i8> %shamt to <4 x i32>
  %r = ashr <4 x i32> %x, %shamt_wide
  ret <4 x i32> %r
}

; This is not valid for funnel shifts
declare i32 @llvm.fshl.i32(i32 %a, i32 %b, i32 %c)
declare i32 @llvm.fshr.i32(i32 %a, i32 %b, i32 %c)
define i32 @n6_fshl(i32 %x, i32 %y, i8 %shamt) nounwind {
; CHECK-LABEL: n6_fshl:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $w2 killed $w2 def $x2
; CHECK-NEXT:    mvn w8, w2
; CHECK-NEXT:    lsr w9, w1, #1
; CHECK-NEXT:    lsl w10, w0, w2
; CHECK-NEXT:    lsr w8, w9, w8
; CHECK-NEXT:    orr w0, w10, w8
; CHECK-NEXT:    ret
  %shamt_wide = sext i8 %shamt to i32
  %r = call i32 @llvm.fshl.i32(i32 %x, i32 %y, i32 %shamt_wide)
  ret i32 %r
}
define i32 @n7_fshr(i32 %x, i32 %y, i8 %shamt) nounwind {
; CHECK-LABEL: n7_fshr:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $w2 killed $w2 def $x2
; CHECK-NEXT:    mvn w8, w2
; CHECK-NEXT:    lsl w9, w0, #1
; CHECK-NEXT:    lsr w10, w1, w2
; CHECK-NEXT:    lsl w8, w9, w8
; CHECK-NEXT:    orr w0, w8, w10
; CHECK-NEXT:    ret
  %shamt_wide = sext i8 %shamt to i32
  %r = call i32 @llvm.fshr.i32(i32 %x, i32 %y, i32 %shamt_wide)
  ret i32 %r
}

define i32 @n8_extrause(i32 %x, i8 %shamt, ptr %shamt_wide_store) nounwind {
; CHECK-LABEL: n8_extrause:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sxtb w8, w1
; CHECK-NEXT:    lsl w0, w0, w8
; CHECK-NEXT:    str w8, [x2]
; CHECK-NEXT:    ret
  %shamt_wide = sext i8 %shamt to i32
  store i32 %shamt_wide, ptr %shamt_wide_store, align 4
  %r = shl i32 %x, %shamt_wide
  ret i32 %r
}
