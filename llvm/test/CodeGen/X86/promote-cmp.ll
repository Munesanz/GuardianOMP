; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-- -mattr=+sse2   | FileCheck %s --check-prefix=SSE2
; RUN: llc < %s -mtriple=x86_64-- -mattr=+sse4.2 | FileCheck %s --check-prefix=SSE4
; RUN: llc < %s -mtriple=x86_64-- -mattr=+avx    | FileCheck %s --check-prefix=AVX1
; RUN: llc < %s -mtriple=x86_64-- -mattr=+avx2   | FileCheck %s --check-prefix=AVX2

define <4 x i64> @PR45808(<4 x i64> %0, <4 x i64> %1) {
; SSE2-LABEL: PR45808:
; SSE2:       # %bb.0:
; SSE2-NEXT:    movdqa {{.*#+}} xmm4 = [2147483648,2147483648]
; SSE2-NEXT:    movdqa %xmm3, %xmm5
; SSE2-NEXT:    pxor %xmm4, %xmm5
; SSE2-NEXT:    movdqa %xmm1, %xmm6
; SSE2-NEXT:    pxor %xmm4, %xmm6
; SSE2-NEXT:    movdqa %xmm6, %xmm7
; SSE2-NEXT:    pcmpgtd %xmm5, %xmm7
; SSE2-NEXT:    movdqa %xmm2, %xmm8
; SSE2-NEXT:    pxor %xmm4, %xmm8
; SSE2-NEXT:    pxor %xmm0, %xmm4
; SSE2-NEXT:    movdqa %xmm4, %xmm9
; SSE2-NEXT:    pcmpgtd %xmm8, %xmm9
; SSE2-NEXT:    movdqa %xmm9, %xmm10
; SSE2-NEXT:    shufps {{.*#+}} xmm10 = xmm10[0,2],xmm7[0,2]
; SSE2-NEXT:    pcmpeqd %xmm5, %xmm6
; SSE2-NEXT:    pcmpeqd %xmm8, %xmm4
; SSE2-NEXT:    shufps {{.*#+}} xmm4 = xmm4[1,3],xmm6[1,3]
; SSE2-NEXT:    andps %xmm10, %xmm4
; SSE2-NEXT:    shufps {{.*#+}} xmm9 = xmm9[1,3],xmm7[1,3]
; SSE2-NEXT:    orps %xmm4, %xmm9
; SSE2-NEXT:    pcmpeqd %xmm4, %xmm4
; SSE2-NEXT:    pxor %xmm9, %xmm4
; SSE2-NEXT:    pxor %xmm5, %xmm5
; SSE2-NEXT:    pcmpgtd %xmm4, %xmm5
; SSE2-NEXT:    punpckldq {{.*#+}} xmm4 = xmm4[0],xmm5[0],xmm4[1],xmm5[1]
; SSE2-NEXT:    pand %xmm4, %xmm0
; SSE2-NEXT:    pandn %xmm2, %xmm4
; SSE2-NEXT:    por %xmm4, %xmm0
; SSE2-NEXT:    pshufd {{.*#+}} xmm2 = xmm9[2,1,3,3]
; SSE2-NEXT:    psllq $63, %xmm2
; SSE2-NEXT:    pshufd {{.*#+}} xmm2 = xmm2[1,1,3,3]
; SSE2-NEXT:    psrad $31, %xmm2
; SSE2-NEXT:    pand %xmm2, %xmm1
; SSE2-NEXT:    pandn %xmm3, %xmm2
; SSE2-NEXT:    por %xmm2, %xmm1
; SSE2-NEXT:    retq
;
; SSE4-LABEL: PR45808:
; SSE4:       # %bb.0:
; SSE4-NEXT:    movdqa %xmm0, %xmm4
; SSE4-NEXT:    movdqa %xmm1, %xmm0
; SSE4-NEXT:    pcmpgtq %xmm3, %xmm0
; SSE4-NEXT:    movdqa %xmm4, %xmm5
; SSE4-NEXT:    pcmpgtq %xmm2, %xmm5
; SSE4-NEXT:    pshufd {{.*#+}} xmm5 = xmm5[0,2,2,3]
; SSE4-NEXT:    pcmpeqd %xmm6, %xmm6
; SSE4-NEXT:    pxor %xmm5, %xmm6
; SSE4-NEXT:    psllq $63, %xmm0
; SSE4-NEXT:    blendvpd %xmm0, %xmm1, %xmm3
; SSE4-NEXT:    pmovsxdq %xmm6, %xmm0
; SSE4-NEXT:    blendvpd %xmm0, %xmm4, %xmm2
; SSE4-NEXT:    movapd %xmm2, %xmm0
; SSE4-NEXT:    movapd %xmm3, %xmm1
; SSE4-NEXT:    retq
;
; AVX1-LABEL: PR45808:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vextractf128 $1, %ymm1, %xmm2
; AVX1-NEXT:    vextractf128 $1, %ymm0, %xmm3
; AVX1-NEXT:    vpcmpgtq %xmm2, %xmm3, %xmm2
; AVX1-NEXT:    vpcmpgtq %xmm1, %xmm0, %xmm3
; AVX1-NEXT:    vinsertf128 $1, %xmm2, %ymm3, %ymm2
; AVX1-NEXT:    vxorpd {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm2, %ymm2
; AVX1-NEXT:    vblendvpd %ymm2, %ymm0, %ymm1, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: PR45808:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpcmpgtq %ymm1, %ymm0, %ymm2
; AVX2-NEXT:    vpxor {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm2, %ymm2
; AVX2-NEXT:    vblendvpd %ymm2, %ymm0, %ymm1, %ymm0
; AVX2-NEXT:    retq
  %3 = icmp sgt <4 x i64> %0, %1
  %4 = xor <4 x i1> %3, <i1 true, i1 true, i1 false, i1 false>
  %5 = select <4 x i1> %4, <4 x i64> %0, <4 x i64> %1
  ret <4 x i64> %5
}
