; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc --mtriple=loongarch32 --verify-machineinstrs < %s \
; RUN:   | FileCheck %s --check-prefix=LA32
; RUN: llc --mtriple=loongarch64 --verify-machineinstrs < %s \
; RUN:   | FileCheck %s --check-prefix=LA64

;; a=00112233 b=44556677
;; expected 11223344
define i32 @pick_i32_1(i32 %a, i32 %b) {
; LA32-LABEL: pick_i32_1:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a0, $a1, $a0, 1
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i32_1:
; LA64:       # %bb.0:
; LA64-NEXT:    slli.d $a0, $a0, 8
; LA64-NEXT:    bstrpick.d $a1, $a1, 31, 24
; LA64-NEXT:    or $a0, $a1, $a0
; LA64-NEXT:    ret
  %1 = lshr i32 %b, 24
  %2 = shl i32 %a, 8
  %3 = or i32 %1, %2
  ret i32 %3
}

;; a=00112233 b=44556677
;; expected 11223344
define signext i32 @pick_i32_1_sext(i32 %a, i32 %b) {
; LA32-LABEL: pick_i32_1_sext:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a0, $a1, $a0, 1
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i32_1_sext:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.w $a0, $a1, $a0, 1
; LA64-NEXT:    ret
  %1 = lshr i32 %b, 24
  %2 = shl i32 %a, 8
  %3 = or i32 %1, %2
  ret i32 %3
}

;; a=00112233 b=44556677
;; expected 22334455
define i32 @pick_i32_2(i32 %a, i32 %b) {
; LA32-LABEL: pick_i32_2:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a0, $a1, $a0, 2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i32_2:
; LA64:       # %bb.0:
; LA64-NEXT:    slli.d $a0, $a0, 16
; LA64-NEXT:    bstrpick.d $a1, $a1, 31, 16
; LA64-NEXT:    or $a0, $a1, $a0
; LA64-NEXT:    ret
  %1 = lshr i32 %b, 16
  %2 = shl i32 %a, 16
  %3 = or i32 %1, %2
  ret i32 %3
}

;; a=00112233 b=44556677
;; expected 22334455
define signext i32 @pick_i32_2_sext(i32 %a, i32 %b) {
; LA32-LABEL: pick_i32_2_sext:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a0, $a1, $a0, 2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i32_2_sext:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.w $a0, $a1, $a0, 2
; LA64-NEXT:    ret
  %1 = lshr i32 %b, 16
  %2 = shl i32 %a, 16
  %3 = or i32 %1, %2
  ret i32 %3
}

;; a=00112233 b=44556677
;; expected 33445566
define i32 @pick_i32_3(i32 %a, i32 %b) {
; LA32-LABEL: pick_i32_3:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a0, $a1, $a0, 3
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i32_3:
; LA64:       # %bb.0:
; LA64-NEXT:    slli.d $a0, $a0, 24
; LA64-NEXT:    bstrpick.d $a1, $a1, 31, 8
; LA64-NEXT:    or $a0, $a1, $a0
; LA64-NEXT:    ret
  %1 = lshr i32 %b, 8
  %2 = shl i32 %a, 24
  %3 = or i32 %1, %2
  ret i32 %3
}

;; a=00112233 b=44556677
;; expected 33445566
define signext i32 @pick_i32_3_sext(i32 %a, i32 %b) {
; LA32-LABEL: pick_i32_3_sext:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a0, $a1, $a0, 3
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i32_3_sext:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.w $a0, $a1, $a0, 3
; LA64-NEXT:    ret
  %1 = lshr i32 %b, 8
  %2 = shl i32 %a, 24
  %3 = or i32 %1, %2
  ret i32 %3
}

;; a=0011223344556677 b=8899aabbccddeeff
;; expected 1122334455667788
define i64 @pick_i64_1(i64 %a, i64 %b) {
; LA32-LABEL: pick_i64_1:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a2, $a3, $a0, 1
; LA32-NEXT:    bytepick.w $a1, $a0, $a1, 1
; LA32-NEXT:    move $a0, $a2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i64_1:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.d $a0, $a1, $a0, 1
; LA64-NEXT:    ret
  %1 = lshr i64 %b, 56
  %2 = shl i64 %a, 8
  %3 = or i64 %1, %2
  ret i64 %3
}

;; a=0011223344556677 b=8899aabbccddeeff
;; expected 2233445566778899
define i64 @pick_i64_2(i64 %a, i64 %b) {
; LA32-LABEL: pick_i64_2:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a2, $a3, $a0, 2
; LA32-NEXT:    bytepick.w $a1, $a0, $a1, 2
; LA32-NEXT:    move $a0, $a2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i64_2:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.d $a0, $a1, $a0, 2
; LA64-NEXT:    ret
  %1 = lshr i64 %b, 48
  %2 = shl i64 %a, 16
  %3 = or i64 %1, %2
  ret i64 %3
}

;; a=0011223344556677 b=8899aabbccddeeff
;; expected 33445566778899aa
define i64 @pick_i64_3(i64 %a, i64 %b) {
; LA32-LABEL: pick_i64_3:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a2, $a3, $a0, 3
; LA32-NEXT:    bytepick.w $a1, $a0, $a1, 3
; LA32-NEXT:    move $a0, $a2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i64_3:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.d $a0, $a1, $a0, 3
; LA64-NEXT:    ret
  %1 = lshr i64 %b, 40
  %2 = shl i64 %a, 24
  %3 = or i64 %1, %2
  ret i64 %3
}

;; a=0011223344556677 b=8899aabbccddeeff
;; expected 445566778899aabb
define i64 @pick_i64_4(i64 %a, i64 %b) {
; LA32-LABEL: pick_i64_4:
; LA32:       # %bb.0:
; LA32-NEXT:    move $a1, $a0
; LA32-NEXT:    move $a0, $a3
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i64_4:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.d $a0, $a1, $a0, 4
; LA64-NEXT:    ret
  %1 = lshr i64 %b, 32
  %2 = shl i64 %a, 32
  %3 = or i64 %1, %2
  ret i64 %3
}

;; a=0011223344556677 b=8899aabbccddeeff
;; expected 5566778899aabbcc
define i64 @pick_i64_5(i64 %a, i64 %b) {
; LA32-LABEL: pick_i64_5:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a2, $a2, $a3, 1
; LA32-NEXT:    bytepick.w $a1, $a3, $a0, 1
; LA32-NEXT:    move $a0, $a2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i64_5:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.d $a0, $a1, $a0, 5
; LA64-NEXT:    ret
  %1 = lshr i64 %b, 24
  %2 = shl i64 %a,40
  %3 = or i64 %1, %2
  ret i64 %3
}

;; a=0011223344556677 b=8899aabbccddeeff
;; expected 66778899aabbccdd
define i64 @pick_i64_6(i64 %a, i64 %b) {
; LA32-LABEL: pick_i64_6:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a2, $a2, $a3, 2
; LA32-NEXT:    bytepick.w $a1, $a3, $a0, 2
; LA32-NEXT:    move $a0, $a2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i64_6:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.d $a0, $a1, $a0, 6
; LA64-NEXT:    ret
  %1 = lshr i64 %b, 16
  %2 = shl i64 %a, 48
  %3 = or i64 %1, %2
  ret i64 %3
}

;; a=0011223344556677 b=8899aabbccddeeff
;; expected 778899aabbccddee
define i64 @pick_i64_7(i64 %a, i64 %b) {
; LA32-LABEL: pick_i64_7:
; LA32:       # %bb.0:
; LA32-NEXT:    bytepick.w $a2, $a2, $a3, 3
; LA32-NEXT:    bytepick.w $a1, $a3, $a0, 3
; LA32-NEXT:    move $a0, $a2
; LA32-NEXT:    ret
;
; LA64-LABEL: pick_i64_7:
; LA64:       # %bb.0:
; LA64-NEXT:    bytepick.d $a0, $a1, $a0, 7
; LA64-NEXT:    ret
  %1 = lshr i64 %b, 8
  %2 = shl i64 %a, 56
  %3 = or i64 %1, %2
  ret i64 %3
}
