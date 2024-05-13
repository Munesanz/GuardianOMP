; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown-unknown                      | FileCheck %s --check-prefix=BASE
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=slow-3ops-lea | FileCheck %s --check-prefix=SLOWLEA3

define i32 @select_unsigned_lt_10_8_13(i32 %0) {
; BASE-LABEL: select_unsigned_lt_10_8_13:
; BASE:       # %bb.0:
; BASE-NEXT:    xorl %eax, %eax
; BASE-NEXT:    cmpl $10, %edi
; BASE-NEXT:    setae %al
; BASE-NEXT:    leal 8(%rax,%rax,4), %eax
; BASE-NEXT:    retq
;
; SLOWLEA3-LABEL: select_unsigned_lt_10_8_13:
; SLOWLEA3:       # %bb.0:
; SLOWLEA3-NEXT:    xorl %eax, %eax
; SLOWLEA3-NEXT:    cmpl $10, %edi
; SLOWLEA3-NEXT:    setae %al
; SLOWLEA3-NEXT:    leal (%rax,%rax,4), %eax
; SLOWLEA3-NEXT:    addl $8, %eax
; SLOWLEA3-NEXT:    retq
  %2 = icmp ult i32 %0, 10
  %3 = select i1 %2, i32 8, i32 13
  ret i32 %3
}
