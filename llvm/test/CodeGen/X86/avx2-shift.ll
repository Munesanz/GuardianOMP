; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i686-unknown-unknown -mattr=+avx2 | FileCheck %s --check-prefixes=CHECK,X86
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+avx2 | FileCheck %s --check-prefixes=CHECK,X64

define <4 x i32> @variable_shl0(<4 x i32> %x, <4 x i32> %y) {
; CHECK-LABEL: variable_shl0:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsllvd %xmm1, %xmm0, %xmm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = shl <4 x i32> %x, %y
  ret <4 x i32> %k
}

define <8 x i32> @variable_shl1(<8 x i32> %x, <8 x i32> %y) {
; CHECK-LABEL: variable_shl1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsllvd %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = shl <8 x i32> %x, %y
  ret <8 x i32> %k
}

define <2 x i64> @variable_shl2(<2 x i64> %x, <2 x i64> %y) {
; CHECK-LABEL: variable_shl2:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsllvq %xmm1, %xmm0, %xmm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = shl <2 x i64> %x, %y
  ret <2 x i64> %k
}

define <4 x i64> @variable_shl3(<4 x i64> %x, <4 x i64> %y) {
; CHECK-LABEL: variable_shl3:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsllvq %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = shl <4 x i64> %x, %y
  ret <4 x i64> %k
}

define <4 x i32> @variable_srl0(<4 x i32> %x, <4 x i32> %y) {
; CHECK-LABEL: variable_srl0:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrlvd %xmm1, %xmm0, %xmm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = lshr <4 x i32> %x, %y
  ret <4 x i32> %k
}

define <8 x i32> @variable_srl1(<8 x i32> %x, <8 x i32> %y) {
; CHECK-LABEL: variable_srl1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrlvd %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = lshr <8 x i32> %x, %y
  ret <8 x i32> %k
}

define <2 x i64> @variable_srl2(<2 x i64> %x, <2 x i64> %y) {
; CHECK-LABEL: variable_srl2:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrlvq %xmm1, %xmm0, %xmm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = lshr <2 x i64> %x, %y
  ret <2 x i64> %k
}

define <4 x i64> @variable_srl3(<4 x i64> %x, <4 x i64> %y) {
; CHECK-LABEL: variable_srl3:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrlvq %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = lshr <4 x i64> %x, %y
  ret <4 x i64> %k
}

define <4 x i32> @variable_sra0(<4 x i32> %x, <4 x i32> %y) {
; CHECK-LABEL: variable_sra0:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsravd %xmm1, %xmm0, %xmm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = ashr <4 x i32> %x, %y
  ret <4 x i32> %k
}

define <8 x i32> @variable_sra1(<8 x i32> %x, <8 x i32> %y) {
; CHECK-LABEL: variable_sra1:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsravd %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %k = ashr <8 x i32> %x, %y
  ret <8 x i32> %k
}

;;; Shift left

define <8 x i32> @vshift00(<8 x i32> %a) nounwind readnone {
; CHECK-LABEL: vshift00:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpslld $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = shl <8 x i32> %a, <i32 2, i32 2, i32 2, i32 2, i32 2, i32 2, i32 2, i32 2>
  ret <8 x i32> %s
}

define <16 x i16> @vshift01(<16 x i16> %a) nounwind readnone {
; CHECK-LABEL: vshift01:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsllw $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = shl <16 x i16> %a, <i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2>
  ret <16 x i16> %s
}

define <4 x i64> @vshift02(<4 x i64> %a) nounwind readnone {
; CHECK-LABEL: vshift02:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsllq $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = shl <4 x i64> %a, <i64 2, i64 2, i64 2, i64 2>
  ret <4 x i64> %s
}

;;; Logical Shift right

define <8 x i32> @vshift03(<8 x i32> %a) nounwind readnone {
; CHECK-LABEL: vshift03:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrld $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = lshr <8 x i32> %a, <i32 2, i32 2, i32 2, i32 2, i32 2, i32 2, i32 2, i32 2>
  ret <8 x i32> %s
}

define <16 x i16> @vshift04(<16 x i16> %a) nounwind readnone {
; CHECK-LABEL: vshift04:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrlw $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = lshr <16 x i16> %a, <i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2>
  ret <16 x i16> %s
}

define <4 x i64> @vshift05(<4 x i64> %a) nounwind readnone {
; CHECK-LABEL: vshift05:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrlq $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = lshr <4 x i64> %a, <i64 2, i64 2, i64 2, i64 2>
  ret <4 x i64> %s
}

;;; Arithmetic Shift right

define <8 x i32> @vshift06(<8 x i32> %a) nounwind readnone {
; CHECK-LABEL: vshift06:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsrad $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = ashr <8 x i32> %a, <i32 2, i32 2, i32 2, i32 2, i32 2, i32 2, i32 2, i32 2>
  ret <8 x i32> %s
}

define <16 x i16> @vshift07(<16 x i16> %a) nounwind readnone {
; CHECK-LABEL: vshift07:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsraw $2, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %s = ashr <16 x i16> %a, <i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2, i16 2>
  ret <16 x i16> %s
}

define <4 x i32> @variable_sra0_load(<4 x i32> %x, ptr %y) {
; X86-LABEL: variable_sra0_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsravd (%eax), %xmm0, %xmm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_sra0_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsravd (%rdi), %xmm0, %xmm0
; X64-NEXT:    retq
  %y1 = load <4 x i32>, ptr %y
  %k = ashr <4 x i32> %x, %y1
  ret <4 x i32> %k
}

define <8 x i32> @variable_sra1_load(<8 x i32> %x, ptr %y) {
; X86-LABEL: variable_sra1_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsravd (%eax), %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_sra1_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsravd (%rdi), %ymm0, %ymm0
; X64-NEXT:    retq
  %y1 = load <8 x i32>, ptr %y
  %k = ashr <8 x i32> %x, %y1
  ret <8 x i32> %k
}

define <4 x i32> @variable_shl0_load(<4 x i32> %x, ptr %y) {
; X86-LABEL: variable_shl0_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsllvd (%eax), %xmm0, %xmm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_shl0_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsllvd (%rdi), %xmm0, %xmm0
; X64-NEXT:    retq
  %y1 = load <4 x i32>, ptr %y
  %k = shl <4 x i32> %x, %y1
  ret <4 x i32> %k
}

define <8 x i32> @variable_shl1_load(<8 x i32> %x, ptr %y) {
; X86-LABEL: variable_shl1_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsllvd (%eax), %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_shl1_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsllvd (%rdi), %ymm0, %ymm0
; X64-NEXT:    retq
  %y1 = load <8 x i32>, ptr %y
  %k = shl <8 x i32> %x, %y1
  ret <8 x i32> %k
}

define <2 x i64> @variable_shl2_load(<2 x i64> %x, ptr %y) {
; X86-LABEL: variable_shl2_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsllvq (%eax), %xmm0, %xmm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_shl2_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsllvq (%rdi), %xmm0, %xmm0
; X64-NEXT:    retq
  %y1 = load <2 x i64>, ptr %y
  %k = shl <2 x i64> %x, %y1
  ret <2 x i64> %k
}

define <4 x i64> @variable_shl3_load(<4 x i64> %x, ptr %y) {
; X86-LABEL: variable_shl3_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsllvq (%eax), %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_shl3_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsllvq (%rdi), %ymm0, %ymm0
; X64-NEXT:    retq
  %y1 = load <4 x i64>, ptr %y
  %k = shl <4 x i64> %x, %y1
  ret <4 x i64> %k
}

define <4 x i32> @variable_srl0_load(<4 x i32> %x, ptr %y) {
; X86-LABEL: variable_srl0_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsrlvd (%eax), %xmm0, %xmm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_srl0_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsrlvd (%rdi), %xmm0, %xmm0
; X64-NEXT:    retq
  %y1 = load <4 x i32>, ptr %y
  %k = lshr <4 x i32> %x, %y1
  ret <4 x i32> %k
}

define <8 x i32> @variable_srl1_load(<8 x i32> %x, ptr %y) {
; X86-LABEL: variable_srl1_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsrlvd (%eax), %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_srl1_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsrlvd (%rdi), %ymm0, %ymm0
; X64-NEXT:    retq
  %y1 = load <8 x i32>, ptr %y
  %k = lshr <8 x i32> %x, %y1
  ret <8 x i32> %k
}

define <2 x i64> @variable_srl2_load(<2 x i64> %x, ptr %y) {
; X86-LABEL: variable_srl2_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsrlvq (%eax), %xmm0, %xmm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_srl2_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsrlvq (%rdi), %xmm0, %xmm0
; X64-NEXT:    retq
  %y1 = load <2 x i64>, ptr %y
  %k = lshr <2 x i64> %x, %y1
  ret <2 x i64> %k
}

define <4 x i64> @variable_srl3_load(<4 x i64> %x, ptr %y) {
; X86-LABEL: variable_srl3_load:
; X86:       # %bb.0:
; X86-NEXT:    movl {{[0-9]+}}(%esp), %eax
; X86-NEXT:    vpsrlvq (%eax), %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: variable_srl3_load:
; X64:       # %bb.0:
; X64-NEXT:    vpsrlvq (%rdi), %ymm0, %ymm0
; X64-NEXT:    retq
  %y1 = load <4 x i64>, ptr %y
  %k = lshr <4 x i64> %x, %y1
  ret <4 x i64> %k
}

define <32 x i8> @shl9(<32 x i8> %A) nounwind {
; X86-LABEL: shl9:
; X86:       # %bb.0:
; X86-NEXT:    vpsllw $3, %ymm0, %ymm0
; X86-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}, %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: shl9:
; X64:       # %bb.0:
; X64-NEXT:    vpsllw $3, %ymm0, %ymm0
; X64-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; X64-NEXT:    retq
  %B = shl <32 x i8> %A, <i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3>
  ret <32 x i8> %B
}

define <32 x i8> @shr9(<32 x i8> %A) nounwind {
; X86-LABEL: shr9:
; X86:       # %bb.0:
; X86-NEXT:    vpsrlw $3, %ymm0, %ymm0
; X86-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}, %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: shr9:
; X64:       # %bb.0:
; X64-NEXT:    vpsrlw $3, %ymm0, %ymm0
; X64-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; X64-NEXT:    retq
  %B = lshr <32 x i8> %A, <i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3>
  ret <32 x i8> %B
}

define <32 x i8> @sra_v32i8_7(<32 x i8> %A) nounwind {
; CHECK-LABEL: sra_v32i8_7:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpxor %xmm1, %xmm1, %xmm1
; CHECK-NEXT:    vpcmpgtb %ymm0, %ymm1, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %B = ashr <32 x i8> %A, <i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7, i8 7>
  ret <32 x i8> %B
}

define <32 x i8> @sra_v32i8(<32 x i8> %A) nounwind {
; X86-LABEL: sra_v32i8:
; X86:       # %bb.0:
; X86-NEXT:    vpsrlw $3, %ymm0, %ymm0
; X86-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}, %ymm0, %ymm0
; X86-NEXT:    vmovdqa {{.*#+}} ymm1 = [16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16]
; X86-NEXT:    vpxor %ymm1, %ymm0, %ymm0
; X86-NEXT:    vpsubb %ymm1, %ymm0, %ymm0
; X86-NEXT:    retl
;
; X64-LABEL: sra_v32i8:
; X64:       # %bb.0:
; X64-NEXT:    vpsrlw $3, %ymm0, %ymm0
; X64-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; X64-NEXT:    vmovdqa {{.*#+}} ymm1 = [16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16]
; X64-NEXT:    vpxor %ymm1, %ymm0, %ymm0
; X64-NEXT:    vpsubb %ymm1, %ymm0, %ymm0
; X64-NEXT:    retq
  %B = ashr <32 x i8> %A, <i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3, i8 3>
  ret <32 x i8> %B
}

define <16 x i16> @sext_v16i16(<16 x i16> %a) nounwind {
; CHECK-LABEL: sext_v16i16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpsllw $8, %ymm0, %ymm0
; CHECK-NEXT:    vpsraw $8, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %b = trunc <16 x i16> %a to <16 x i8>
  %c = sext <16 x i8> %b to <16 x i16>
  ret <16 x i16> %c
}

define <8 x i32> @sext_v8i32(<8 x i32> %a) nounwind {
; CHECK-LABEL: sext_v8i32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpslld $16, %ymm0, %ymm0
; CHECK-NEXT:    vpsrad $16, %ymm0, %ymm0
; CHECK-NEXT:    ret{{[l|q]}}
  %b = trunc <8 x i32> %a to <8 x i16>
  %c = sext <8 x i16> %b to <8 x i32>
  ret <8 x i32> %c
}

define <8 x i16> @variable_shl16(<8 x i16> %lhs, <8  x i16> %rhs) {
; CHECK-LABEL: variable_shl16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpmovzxwd {{.*#+}} ymm1 = xmm1[0],zero,xmm1[1],zero,xmm1[2],zero,xmm1[3],zero,xmm1[4],zero,xmm1[5],zero,xmm1[6],zero,xmm1[7],zero
; CHECK-NEXT:    vpmovzxwd {{.*#+}} ymm0 = xmm0[0],zero,xmm0[1],zero,xmm0[2],zero,xmm0[3],zero,xmm0[4],zero,xmm0[5],zero,xmm0[6],zero,xmm0[7],zero
; CHECK-NEXT:    vpsllvd %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    vpshufb {{.*#+}} ymm0 = ymm0[0,1,4,5,8,9,12,13,u,u,u,u,u,u,u,u,16,17,20,21,24,25,28,29,u,u,u,u,u,u,u,u]
; CHECK-NEXT:    vpermq {{.*#+}} ymm0 = ymm0[0,2,2,3]
; CHECK-NEXT:    # kill: def $xmm0 killed $xmm0 killed $ymm0
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    ret{{[l|q]}}
  %res = shl <8 x i16> %lhs, %rhs
  ret <8 x i16> %res
}

define <8 x i16> @variable_ashr16(<8 x i16> %lhs, <8  x i16> %rhs) {
; CHECK-LABEL: variable_ashr16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpmovzxwd {{.*#+}} ymm1 = xmm1[0],zero,xmm1[1],zero,xmm1[2],zero,xmm1[3],zero,xmm1[4],zero,xmm1[5],zero,xmm1[6],zero,xmm1[7],zero
; CHECK-NEXT:    vpmovsxwd %xmm0, %ymm0
; CHECK-NEXT:    vpsravd %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    vextracti128 $1, %ymm0, %xmm1
; CHECK-NEXT:    vpackssdw %xmm1, %xmm0, %xmm0
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    ret{{[l|q]}}
  %res = ashr <8 x i16> %lhs, %rhs
  ret <8 x i16> %res
}

define <8 x i16> @variable_lshr16(<8 x i16> %lhs, <8  x i16> %rhs) {
; CHECK-LABEL: variable_lshr16:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vpmovzxwd {{.*#+}} ymm1 = xmm1[0],zero,xmm1[1],zero,xmm1[2],zero,xmm1[3],zero,xmm1[4],zero,xmm1[5],zero,xmm1[6],zero,xmm1[7],zero
; CHECK-NEXT:    vpmovzxwd {{.*#+}} ymm0 = xmm0[0],zero,xmm0[1],zero,xmm0[2],zero,xmm0[3],zero,xmm0[4],zero,xmm0[5],zero,xmm0[6],zero,xmm0[7],zero
; CHECK-NEXT:    vpsrlvd %ymm1, %ymm0, %ymm0
; CHECK-NEXT:    vextracti128 $1, %ymm0, %xmm1
; CHECK-NEXT:    vpackusdw %xmm1, %xmm0, %xmm0
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    ret{{[l|q]}}
  %res = lshr <8 x i16> %lhs, %rhs
  ret <8 x i16> %res
}
