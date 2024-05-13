; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=x86_64-unknown-unknown -mattr=+sse4.1 < %s | FileCheck %s --check-prefixes=CHECK,SSE
; RUN: llc -mtriple=x86_64-unknown-unknown -mattr=+avx    < %s | FileCheck %s --check-prefixes=CHECK,AVX,AVX1
; RUN: llc -mtriple=x86_64-unknown-unknown -mattr=+avx2   < %s | FileCheck %s --check-prefixes=CHECK,AVX,AVX2
; RUN: llc -mtriple=x86_64-unknown-unknown -mattr=+avx512vl,+avx512dq,+avx512bw < %s | FileCheck %s --check-prefixes=CHECK,AVX,AVX512

define i32 @and_self(i32 %x) {
; CHECK-LABEL: and_self:
; CHECK:       # %bb.0:
; CHECK-NEXT:    movl %edi, %eax
; CHECK-NEXT:    retq
  %and = and i32 %x, %x
  ret i32 %and
}

define <4 x i32> @and_self_vec(<4 x i32> %x) {
; CHECK-LABEL: and_self_vec:
; CHECK:       # %bb.0:
; CHECK-NEXT:    retq
  %and = and <4 x i32> %x, %x
  ret <4 x i32> %and
}

;
; Verify that the DAGCombiner is able to fold a vector AND into a blend
; if one of the operands to the AND is a vector of all constants, and each
; constant element is either zero or all-ones.
;

define <4 x i32> @test1(<4 x i32> %A) {
; SSE-LABEL: test1:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0],xmm1[1,2,3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test1:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0],xmm1[1,2,3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 0, i32 0, i32 0>
  ret <4 x i32> %1
}

define <4 x i32> @test2(<4 x i32> %A) {
; SSE-LABEL: test2:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2,3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test2:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2,3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 -1, i32 0, i32 0>
  ret <4 x i32> %1
}

define <4 x i32> @test3(<4 x i32> %A) {
; SSE-LABEL: test3:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0,1],xmm0[2],xmm1[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test3:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0,1],xmm0[2],xmm1[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 0, i32 -1, i32 0>
  ret <4 x i32> %1
}

define <4 x i32> @test4(<4 x i32> %A) {
; SSE-LABEL: test4:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0,1,2],xmm0[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test4:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0,1,2],xmm0[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 0, i32 0, i32 -1>
  ret <4 x i32> %1
}

define <4 x i32> @test5(<4 x i32> %A) {
; SSE-LABEL: test5:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2],xmm1[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test5:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2],xmm1[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 0, i32 -1, i32 0>
  ret <4 x i32> %1
}

define <4 x i32> @test6(<4 x i32> %A) {
; SSE-LABEL: test6:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2],xmm0[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test6:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2],xmm0[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 -1, i32 0, i32 -1>
  ret <4 x i32> %1
}

define <4 x i32> @test7(<4 x i32> %A) {
; SSE-LABEL: test7:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0,1],xmm0[2,3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test7:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0,1],xmm0[2,3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 0, i32 -1, i32 -1>
  ret <4 x i32> %1
}

define <4 x i32> @test8(<4 x i32> %A) {
; SSE-LABEL: test8:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0],xmm1[1,2],xmm0[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test8:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0],xmm1[1,2],xmm0[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 0, i32 0, i32 -1>
  ret <4 x i32> %1
}

define <4 x i32> @test9(<4 x i32> %A) {
; SSE-LABEL: test9:
; SSE:       # %bb.0:
; SSE-NEXT:    movq {{.*#+}} xmm0 = xmm0[0],zero
; SSE-NEXT:    retq
;
; AVX-LABEL: test9:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovq {{.*#+}} xmm0 = xmm0[0],zero
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 -1, i32 0, i32 0>
  ret <4 x i32> %1
}

define <4 x i32> @test10(<4 x i32> %A) {
; SSE-LABEL: test10:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0],xmm0[1,2],xmm1[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test10:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0],xmm0[1,2],xmm1[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 -1, i32 -1, i32 0>
  ret <4 x i32> %1
}

define <4 x i32> @test11(<4 x i32> %A) {
; SSE-LABEL: test11:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0],xmm0[1,2,3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test11:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0],xmm0[1,2,3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 -1, i32 -1, i32 -1>
  ret <4 x i32> %1
}

define <4 x i32> @test12(<4 x i32> %A) {
; SSE-LABEL: test12:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0,1,2],xmm1[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test12:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0,1,2],xmm1[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 -1, i32 -1, i32 0>
  ret <4 x i32> %1
}

define <4 x i32> @test13(<4 x i32> %A) {
; SSE-LABEL: test13:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0,1],xmm1[2],xmm0[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test13:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0,1],xmm1[2],xmm0[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 -1, i32 0, i32 -1>
  ret <4 x i32> %1
}

define <4 x i32> @test14(<4 x i32> %A) {
; SSE-LABEL: test14:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2,3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test14:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2,3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 0, i32 -1, i32 -1>
  ret <4 x i32> %1
}

; X & undef must fold to 0. So lane 0 must choose from the zero vector.

define <4 x i32> @undef_lane(<4 x i32> %x) {
; SSE-LABEL: undef_lane:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm1, %xmm1
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2],xmm0[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: undef_lane:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm1, %xmm1, %xmm1
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2],xmm0[3]
; AVX-NEXT:    retq
  %r = and <4 x i32> %x, <i32 undef, i32 4294967295, i32 0, i32 4294967295>
  ret <4 x i32> %r
}

define <4 x i32> @test15(<4 x i32> %A, <4 x i32> %B) {
; SSE-LABEL: test15:
; SSE:       # %bb.0:
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2,3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test15:
; AVX:       # %bb.0:
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2,3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 0, i32 -1, i32 -1>
  %2 = and <4 x i32> %B, <i32 0, i32 -1, i32 0, i32 0>
  %3 = or <4 x i32> %1, %2
  ret <4 x i32> %3
}

define <4 x i32> @test16(<4 x i32> %A, <4 x i32> %B) {
; SSE-LABEL: test16:
; SSE:       # %bb.0:
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2],xmm1[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test16:
; AVX:       # %bb.0:
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm0[0],xmm1[1],xmm0[2],xmm1[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 -1, i32 0, i32 -1, i32 0>
  %2 = and <4 x i32> %B, <i32 0, i32 -1, i32 0, i32 -1>
  %3 = or <4 x i32> %1, %2
  ret <4 x i32> %3
}

define <4 x i32> @test17(<4 x i32> %A, <4 x i32> %B) {
; SSE-LABEL: test17:
; SSE:       # %bb.0:
; SSE-NEXT:    blendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2],xmm0[3]
; SSE-NEXT:    retq
;
; AVX-LABEL: test17:
; AVX:       # %bb.0:
; AVX-NEXT:    vblendps {{.*#+}} xmm0 = xmm1[0],xmm0[1],xmm1[2],xmm0[3]
; AVX-NEXT:    retq
  %1 = and <4 x i32> %A, <i32 0, i32 -1, i32 0, i32 -1>
  %2 = and <4 x i32> %B, <i32 -1, i32 0, i32 -1, i32 0>
  %3 = or <4 x i32> %1, %2
  ret <4 x i32> %3
}

;
; fold (and (or x, C), D) -> D if (C & D) == D
;

define <2 x i64> @and_or_v2i64(<2 x i64> %a0) {
; SSE-LABEL: and_or_v2i64:
; SSE:       # %bb.0:
; SSE-NEXT:    movaps {{.*#+}} xmm0 = [8,8]
; SSE-NEXT:    retq
;
; AVX1-LABEL: and_or_v2i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovaps {{.*#+}} xmm0 = [8,8]
; AVX1-NEXT:    retq
;
; AVX2-LABEL: and_or_v2i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovaps {{.*#+}} xmm0 = [8,8]
; AVX2-NEXT:    retq
;
; AVX512-LABEL: and_or_v2i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vmovddup {{.*#+}} xmm0 = [8,8]
; AVX512-NEXT:    # xmm0 = mem[0,0]
; AVX512-NEXT:    retq
  %1 = or <2 x i64> %a0, <i64 255, i64 255>
  %2 = and <2 x i64> %1, <i64 8, i64 8>
  ret <2 x i64> %2
}

define <4 x i32> @and_or_v4i32(<4 x i32> %a0) {
; SSE-LABEL: and_or_v4i32:
; SSE:       # %bb.0:
; SSE-NEXT:    movaps {{.*#+}} xmm0 = [3,3,3,3]
; SSE-NEXT:    retq
;
; AVX1-LABEL: and_or_v4i32:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovaps {{.*#+}} xmm0 = [3,3,3,3]
; AVX1-NEXT:    retq
;
; AVX2-LABEL: and_or_v4i32:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vbroadcastss {{.*#+}} xmm0 = [3,3,3,3]
; AVX2-NEXT:    retq
;
; AVX512-LABEL: and_or_v4i32:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vbroadcastss {{.*#+}} xmm0 = [3,3,3,3]
; AVX512-NEXT:    retq
  %1 = or <4 x i32> %a0, <i32 15, i32 15, i32 15, i32 15>
  %2 = and <4 x i32> %1, <i32 3, i32 3, i32 3, i32 3>
  ret <4 x i32> %2
}

define <8 x i16> @and_or_v8i16(<8 x i16> %a0) {
; SSE-LABEL: and_or_v8i16:
; SSE:       # %bb.0:
; SSE-NEXT:    movaps {{.*#+}} xmm0 = [15,7,3,1,14,10,2,32767]
; SSE-NEXT:    retq
;
; AVX-LABEL: and_or_v8i16:
; AVX:       # %bb.0:
; AVX-NEXT:    vmovaps {{.*#+}} xmm0 = [15,7,3,1,14,10,2,32767]
; AVX-NEXT:    retq
  %1 = or <8 x i16> %a0, <i16 255, i16 127, i16 63, i16 31, i16 15, i16 31, i16 63, i16 -1>
  %2 = and <8 x i16> %1, <i16 15, i16 7, i16 3, i16 1, i16 14, i16 10, i16 2, i16 32767>
  ret <8 x i16> %2
}

;
; Check we merge and(ext(and(x,c1)),c2) before an and gets folded to a shuffle clear mask
;

define <8 x i32> @clear_sext_and(<8 x i16> %x) {
; SSE-LABEL: clear_sext_and:
; SSE:       # %bb.0:
; SSE-NEXT:    pmovsxwd %xmm0, %xmm2
; SSE-NEXT:    pand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %xmm2
; SSE-NEXT:    pshufd {{.*#+}} xmm0 = xmm0[2,3,2,3]
; SSE-NEXT:    pmovsxwd %xmm0, %xmm1
; SSE-NEXT:    pand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %xmm1
; SSE-NEXT:    movdqa %xmm2, %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: clear_sext_and:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vpmovsxwd %xmm0, %xmm1
; AVX1-NEXT:    vpshufd {{.*#+}} xmm0 = xmm0[2,3,2,3]
; AVX1-NEXT:    vpmovsxwd %xmm0, %xmm0
; AVX1-NEXT:    vinsertf128 $1, %xmm0, %ymm1, %ymm0
; AVX1-NEXT:    vandps {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: clear_sext_and:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpmovsxwd %xmm0, %ymm0
; AVX2-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: clear_sext_and:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpmovsxwd %xmm0, %ymm0
; AVX512-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; AVX512-NEXT:    retq
  %1 = and <8 x i16> %x, <i16 -1, i16 3, i16 7, i16 15, i16 31, i16 63, i16 127, i16 -1>
  %2 = sext <8 x i16> %1 to <8 x i32>
  %3 = and <8 x i32> %2, <i32 -1, i32 0, i32 -1, i32 0, i32 0, i32 -1, i32 -1, i32 -1>
  ret <8 x i32> %3
}

define <8 x i32> @clear_zext_and(<8 x i16> %x) {
; SSE-LABEL: clear_zext_and:
; SSE:       # %bb.0:
; SSE-NEXT:    movdqa %xmm0, %xmm1
; SSE-NEXT:    pmovzxwd {{.*#+}} xmm0 = xmm0[0],zero,xmm0[1],zero,xmm0[2],zero,xmm0[3],zero
; SSE-NEXT:    punpckhwd {{.*#+}} xmm1 = xmm1[4,4,5,5,6,6,7,7]
; SSE-NEXT:    pand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %xmm1
; SSE-NEXT:    pand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: clear_zext_and:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vpunpckhwd {{.*#+}} xmm1 = xmm0[4,4,5,5,6,6,7,7]
; AVX1-NEXT:    vpmovzxwd {{.*#+}} xmm0 = xmm0[0],zero,xmm0[1],zero,xmm0[2],zero,xmm0[3],zero
; AVX1-NEXT:    vinsertf128 $1, %xmm1, %ymm0, %ymm0
; AVX1-NEXT:    vandps {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: clear_zext_and:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vpmovzxwd {{.*#+}} ymm0 = xmm0[0],zero,xmm0[1],zero,xmm0[2],zero,xmm0[3],zero,xmm0[4],zero,xmm0[5],zero,xmm0[6],zero,xmm0[7],zero
; AVX2-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: clear_zext_and:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpmovzxwd {{.*#+}} ymm0 = xmm0[0],zero,xmm0[1],zero,xmm0[2],zero,xmm0[3],zero,xmm0[4],zero,xmm0[5],zero,xmm0[6],zero,xmm0[7],zero
; AVX512-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %ymm0, %ymm0
; AVX512-NEXT:    retq
  %1 = and <8 x i16> %x, <i16 -1, i16 3, i16 7, i16 15, i16 31, i16 63, i16 127, i16 -1>
  %2 = zext <8 x i16> %1 to <8 x i32>
  %3 = and <8 x i32> %2, <i32 -1, i32 0, i32 -1, i32 0, i32 0, i32 -1, i32 -1, i32 -1>
  ret <8 x i32> %3
}

;
; known bits folding
;

define <2 x i64> @and_or_zext_v2i32(<2 x i32> %a0) {
; SSE-LABEL: and_or_zext_v2i32:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm0, %xmm0
; SSE-NEXT:    retq
;
; AVX-LABEL: and_or_zext_v2i32:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm0, %xmm0, %xmm0
; AVX-NEXT:    retq
  %1 = zext <2 x i32> %a0 to <2 x i64>
  %2 = or <2 x i64> %1, <i64 1, i64 1>
  %3 = and <2 x i64> %2, <i64 4294967296, i64 4294967296>
  ret <2 x i64> %3
}

define <4 x i32> @and_or_zext_v4i16(<4 x i16> %a0) {
; SSE-LABEL: and_or_zext_v4i16:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm0, %xmm0
; SSE-NEXT:    retq
;
; AVX-LABEL: and_or_zext_v4i16:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm0, %xmm0, %xmm0
; AVX-NEXT:    retq
  %1 = zext <4 x i16> %a0 to <4 x i32>
  %2 = or <4 x i32> %1, <i32 1, i32 1, i32 1, i32 1>
  %3 = and <4 x i32> %2, <i32 65536, i32 65536, i32 65536, i32 65536>
  ret <4 x i32> %3
}

;
; known sign bits folding
;

define <8 x i16> @ashr_mask1_v8i16(<8 x i16> %a0) {
; SSE-LABEL: ashr_mask1_v8i16:
; SSE:       # %bb.0:
; SSE-NEXT:    psrlw $15, %xmm0
; SSE-NEXT:    retq
;
; AVX-LABEL: ashr_mask1_v8i16:
; AVX:       # %bb.0:
; AVX-NEXT:    vpsrlw $15, %xmm0, %xmm0
; AVX-NEXT:    retq
  %1 = ashr <8 x i16> %a0, <i16 15, i16 15, i16 15, i16 15, i16 15, i16 15, i16 15, i16 15>
  %2 = and <8 x i16> %1, <i16 1, i16 1, i16 1, i16 1, i16 1, i16 1, i16 1, i16 1>
  ret <8 x i16> %2
}

define <4 x i32> @ashr_mask7_v4i32(<4 x i32> %a0) {
; SSE-LABEL: ashr_mask7_v4i32:
; SSE:       # %bb.0:
; SSE-NEXT:    psrad $31, %xmm0
; SSE-NEXT:    psrld $29, %xmm0
; SSE-NEXT:    retq
;
; AVX-LABEL: ashr_mask7_v4i32:
; AVX:       # %bb.0:
; AVX-NEXT:    vpsrad $31, %xmm0, %xmm0
; AVX-NEXT:    vpsrld $29, %xmm0, %xmm0
; AVX-NEXT:    retq
  %1 = ashr <4 x i32> %a0, <i32 31, i32 31, i32 31, i32 31>
  %2 = and <4 x i32> %1, <i32 7, i32 7, i32 7, i32 7>
  ret <4 x i32> %2
}

;
; SimplifyDemandedBits
;

; PR34620 - redundant PAND after vector shift of a byte vector (PSRLW)
define <16 x i8> @PR34620(<16 x i8> %a0, <16 x i8> %a1) {
; SSE-LABEL: PR34620:
; SSE:       # %bb.0:
; SSE-NEXT:    psrlw $1, %xmm0
; SSE-NEXT:    pand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %xmm0
; SSE-NEXT:    paddb %xmm1, %xmm0
; SSE-NEXT:    retq
;
; AVX-LABEL: PR34620:
; AVX:       # %bb.0:
; AVX-NEXT:    vpsrlw $1, %xmm0, %xmm0
; AVX-NEXT:    vpand {{\.?LCPI[0-9]+_[0-9]+}}(%rip), %xmm0, %xmm0
; AVX-NEXT:    vpaddb %xmm1, %xmm0, %xmm0
; AVX-NEXT:    retq
  %1 = lshr <16 x i8> %a0, <i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1>
  %2 = and <16 x i8> %1, <i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1, i8 1>
  %3 = add <16 x i8> %2, %a1
  ret <16 x i8> %3
}

;
; Simplify and with a broadcasted negated scalar
;

define <8 x i64> @neg_scalar_broadcast_v8i64_arg(i64 %a0, <8 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v8i64_arg:
; SSE:       # %bb.0:
; SSE-NEXT:    notq %rdi
; SSE-NEXT:    movq %rdi, %xmm4
; SSE-NEXT:    pshufd {{.*#+}} xmm4 = xmm4[0,1,0,1]
; SSE-NEXT:    pand %xmm4, %xmm0
; SSE-NEXT:    pand %xmm4, %xmm1
; SSE-NEXT:    pand %xmm4, %xmm2
; SSE-NEXT:    pand %xmm4, %xmm3
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v8i64_arg:
; AVX1:       # %bb.0:
; AVX1-NEXT:    notq %rdi
; AVX1-NEXT:    vmovq %rdi, %xmm2
; AVX1-NEXT:    vpshufd {{.*#+}} xmm2 = xmm2[0,1,0,1]
; AVX1-NEXT:    vinsertf128 $1, %xmm2, %ymm2, %ymm2
; AVX1-NEXT:    vandps %ymm0, %ymm2, %ymm0
; AVX1-NEXT:    vandps %ymm1, %ymm2, %ymm1
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v8i64_arg:
; AVX2:       # %bb.0:
; AVX2-NEXT:    notq %rdi
; AVX2-NEXT:    vmovq %rdi, %xmm2
; AVX2-NEXT:    vpbroadcastq %xmm2, %ymm2
; AVX2-NEXT:    vpand %ymm0, %ymm2, %ymm0
; AVX2-NEXT:    vpand %ymm1, %ymm2, %ymm1
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v8i64_arg:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastq %rdi, %zmm1
; AVX512-NEXT:    vpandnq %zmm0, %zmm1, %zmm0
; AVX512-NEXT:    retq
  %1 = xor i64 %a0, -1
  %2 = insertelement <8 x i64> undef, i64 %1, i64 0
  %3 = shufflevector <8 x i64> %2, <8 x i64> poison, <8 x i32> zeroinitializer
  %4 = and <8 x i64> %3, %a1
  ret <8 x i64> %4
}

define <8 x i64> @neg_scalar_broadcast_v8i64(i64 %a0, <2 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v8i64:
; SSE:       # %bb.0:
; SSE-NEXT:    movdqa %xmm0, %xmm2
; SSE-NEXT:    notq %rdi
; SSE-NEXT:    movq %rdi, %xmm0
; SSE-NEXT:    pshufd {{.*#+}} xmm4 = xmm0[0,1,0,1]
; SSE-NEXT:    pshufd {{.*#+}} xmm3 = xmm2[0,1,0,1]
; SSE-NEXT:    pshufd {{.*#+}} xmm1 = xmm2[2,3,2,3]
; SSE-NEXT:    pshufd {{.*#+}} xmm0 = xmm2[2,3,0,1]
; SSE-NEXT:    pand %xmm4, %xmm0
; SSE-NEXT:    pand %xmm4, %xmm1
; SSE-NEXT:    pand %xmm4, %xmm2
; SSE-NEXT:    pand %xmm4, %xmm3
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v8i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    # kill: def $xmm0 killed $xmm0 def $ymm0
; AVX1-NEXT:    vshufps {{.*#+}} xmm1 = xmm0[0,1,0,1]
; AVX1-NEXT:    vinsertf128 $1, %xmm1, %ymm0, %ymm1
; AVX1-NEXT:    vinsertf128 $1, %xmm0, %ymm0, %ymm0
; AVX1-NEXT:    vshufpd {{.*#+}} ymm0 = ymm0[1,0,3,3]
; AVX1-NEXT:    vmovq %rdi, %xmm2
; AVX1-NEXT:    vpshufd {{.*#+}} xmm2 = xmm2[0,1,0,1]
; AVX1-NEXT:    vinsertf128 $1, %xmm2, %ymm2, %ymm2
; AVX1-NEXT:    vandnpd %ymm0, %ymm2, %ymm0
; AVX1-NEXT:    vandnpd %ymm1, %ymm2, %ymm1
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v8i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    # kill: def $xmm0 killed $xmm0 def $ymm0
; AVX2-NEXT:    vpermq {{.*#+}} ymm1 = ymm0[0,1,0,0]
; AVX2-NEXT:    vpermq {{.*#+}} ymm0 = ymm0[1,0,1,1]
; AVX2-NEXT:    vmovq %rdi, %xmm2
; AVX2-NEXT:    vpbroadcastq %xmm2, %ymm2
; AVX2-NEXT:    vpandn %ymm0, %ymm2, %ymm0
; AVX2-NEXT:    vpandn %ymm1, %ymm2, %ymm1
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v8i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    # kill: def $xmm0 killed $xmm0 def $zmm0
; AVX512-NEXT:    vpbroadcastq %rdi, %zmm1
; AVX512-NEXT:    vmovdqa64 {{.*#+}} zmm2 = [1,0,1,1,0,1,0,0]
; AVX512-NEXT:    vpermq %zmm0, %zmm2, %zmm0
; AVX512-NEXT:    vpandnq %zmm0, %zmm1, %zmm0
; AVX512-NEXT:    retq
  %1 = xor i64 %a0, -1
  %2 = insertelement <8 x i64> undef, i64 %1, i64 0
  %3 = shufflevector <8 x i64> %2, <8 x i64> poison, <8 x i32> zeroinitializer
  %4 = shufflevector <2 x i64> %a1, <2 x i64> poison, <8 x i32> <i32 1, i32 0, i32 1, i32 1, i32 0, i32 1, i32 0, i32 0>
  %5 = and <8 x i64> %4, %3
  ret <8 x i64> %5
}

define <4 x i64> @neg_scalar_broadcast_v4i64_arg(i64 %a0, <4 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v4i64_arg:
; SSE:       # %bb.0:
; SSE-NEXT:    notq %rdi
; SSE-NEXT:    movq %rdi, %xmm2
; SSE-NEXT:    pshufd {{.*#+}} xmm2 = xmm2[0,1,0,1]
; SSE-NEXT:    pand %xmm2, %xmm0
; SSE-NEXT:    pand %xmm2, %xmm1
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v4i64_arg:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovq %rdi, %xmm1
; AVX1-NEXT:    vpshufd {{.*#+}} xmm1 = xmm1[0,1,0,1]
; AVX1-NEXT:    vinsertf128 $1, %xmm1, %ymm1, %ymm1
; AVX1-NEXT:    vandnps %ymm0, %ymm1, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v4i64_arg:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovq %rdi, %xmm1
; AVX2-NEXT:    vpbroadcastq %xmm1, %ymm1
; AVX2-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v4i64_arg:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastq %rdi, %ymm1
; AVX512-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX512-NEXT:    retq
  %1 = xor i64 %a0, -1
  %2 = insertelement <4 x i64> undef, i64 %1, i64 0
  %3 = shufflevector <4 x i64> %2, <4 x i64> poison, <4 x i32> zeroinitializer
  %4 = and <4 x i64> %3, %a1
  ret <4 x i64> %4
}

define <4 x i64> @neg_scalar_broadcast_v4i64(i64 %a0, <2 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v4i64:
; SSE:       # %bb.0:
; SSE-NEXT:    notq %rdi
; SSE-NEXT:    movq %rdi, %xmm1
; SSE-NEXT:    pshufd {{.*#+}} xmm2 = xmm1[0,1,0,1]
; SSE-NEXT:    pshufd {{.*#+}} xmm1 = xmm0[2,3,2,3]
; SSE-NEXT:    pshufd {{.*#+}} xmm0 = xmm0[2,3,0,1]
; SSE-NEXT:    pand %xmm2, %xmm0
; SSE-NEXT:    pand %xmm2, %xmm1
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v4i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    # kill: def $xmm0 killed $xmm0 def $ymm0
; AVX1-NEXT:    vmovq %rdi, %xmm1
; AVX1-NEXT:    vpshufd {{.*#+}} xmm1 = xmm1[0,1,0,1]
; AVX1-NEXT:    vinsertf128 $1, %xmm1, %ymm1, %ymm1
; AVX1-NEXT:    vinsertf128 $1, %xmm0, %ymm0, %ymm0
; AVX1-NEXT:    vshufpd {{.*#+}} ymm0 = ymm0[1,0,3,3]
; AVX1-NEXT:    vandnpd %ymm0, %ymm1, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v4i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    # kill: def $xmm0 killed $xmm0 def $ymm0
; AVX2-NEXT:    vmovq %rdi, %xmm1
; AVX2-NEXT:    vpbroadcastq %xmm1, %ymm1
; AVX2-NEXT:    vpermq {{.*#+}} ymm0 = ymm0[1,0,1,1]
; AVX2-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v4i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    # kill: def $xmm0 killed $xmm0 def $ymm0
; AVX512-NEXT:    vpbroadcastq %rdi, %ymm1
; AVX512-NEXT:    vpermq {{.*#+}} ymm0 = ymm0[1,0,1,1]
; AVX512-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX512-NEXT:    retq
  %1 = xor i64 %a0, -1
  %2 = insertelement <4 x i64> undef, i64 %1, i64 0
  %3 = shufflevector <4 x i64> %2, <4 x i64> poison, <4 x i32> zeroinitializer
  %4 = shufflevector <2 x i64> %a1, <2 x i64> poison, <4 x i32> <i32 1, i32 0, i32 1, i32 1>
  %5 = and <4 x i64> %4, %3
  ret <4 x i64> %5
}

define <2 x i64> @neg_scalar_broadcast_v2i64(i64 %a0, <2 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v2i64:
; SSE:       # %bb.0:
; SSE-NEXT:    movq %rdi, %xmm1
; SSE-NEXT:    pshufd {{.*#+}} xmm1 = xmm1[0,1,0,1]
; SSE-NEXT:    pandn %xmm0, %xmm1
; SSE-NEXT:    movdqa %xmm1, %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v2i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovq %rdi, %xmm1
; AVX1-NEXT:    vpshufd {{.*#+}} xmm1 = xmm1[0,1,0,1]
; AVX1-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v2i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovq %rdi, %xmm1
; AVX2-NEXT:    vpbroadcastq %xmm1, %xmm1
; AVX2-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v2i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastq %rdi, %xmm1
; AVX512-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX512-NEXT:    retq
  %1 = xor i64 %a0, -1
  %2 = insertelement <2 x i64> undef, i64 %1, i64 0
  %3 = shufflevector <2 x i64> %2, <2 x i64> poison, <2 x i32> zeroinitializer
  %4 = and <2 x i64> %3, %a1
  ret <2 x i64> %4
}

define <2 x i64> @casted_neg_scalar_broadcast_v2i64(<2 x i32> %a0, <2 x i64> %a1) {
; SSE-LABEL: casted_neg_scalar_broadcast_v2i64:
; SSE:       # %bb.0:
; SSE-NEXT:    pshufd {{.*#+}} xmm0 = xmm0[0,1,0,1]
; SSE-NEXT:    pandn %xmm1, %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: casted_neg_scalar_broadcast_v2i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vshufps {{.*#+}} xmm0 = xmm0[0,1,0,1]
; AVX1-NEXT:    vandnps %xmm1, %xmm0, %xmm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: casted_neg_scalar_broadcast_v2i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovddup {{.*#+}} xmm0 = xmm0[0,0]
; AVX2-NEXT:    vandnps %xmm1, %xmm0, %xmm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: casted_neg_scalar_broadcast_v2i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vmovddup {{.*#+}} xmm0 = xmm0[0,0]
; AVX512-NEXT:    vandnps %xmm1, %xmm0, %xmm0
; AVX512-NEXT:    retq
  %1 = xor <2 x i32> %a0, <i32 -1, i32 -1>
  %2 = bitcast <2 x i32> %1 to i64
  %3 = insertelement <2 x i64> undef, i64 %2, i64 0
  %4 = shufflevector <2 x i64> %3, <2 x i64> poison, <2 x i32> zeroinitializer
  %5 = and <2 x i64> %4, %a1
  ret <2 x i64> %5
}

define <8 x i32> @neg_scalar_broadcast_v8i32(i32 %a0, <8 x i32> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v8i32:
; SSE:       # %bb.0:
; SSE-NEXT:    notl %edi
; SSE-NEXT:    movd %edi, %xmm2
; SSE-NEXT:    pshufd {{.*#+}} xmm2 = xmm2[0,0,0,0]
; SSE-NEXT:    pand %xmm2, %xmm0
; SSE-NEXT:    pand %xmm2, %xmm1
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v8i32:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovd %edi, %xmm1
; AVX1-NEXT:    vpshufd {{.*#+}} xmm1 = xmm1[0,0,0,0]
; AVX1-NEXT:    vinsertf128 $1, %xmm1, %ymm1, %ymm1
; AVX1-NEXT:    vandnps %ymm0, %ymm1, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v8i32:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovd %edi, %xmm1
; AVX2-NEXT:    vpbroadcastd %xmm1, %ymm1
; AVX2-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v8i32:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastd %edi, %ymm1
; AVX512-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX512-NEXT:    retq
  %1 = xor i32 %a0, -1
  %2 = insertelement <8 x i32> undef, i32 %1, i64 0
  %3 = shufflevector <8 x i32> %2, <8 x i32> poison, <8 x i32> zeroinitializer
  %4 = and <8 x i32> %3, %a1
  ret <8 x i32> %4
}

define <8 x i16> @neg_scalar_broadcast_v8i16(i16 %a0, <8 x i16> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v8i16:
; SSE:       # %bb.0:
; SSE-NEXT:    movd %edi, %xmm1
; SSE-NEXT:    pshuflw {{.*#+}} xmm1 = xmm1[0,0,0,0,4,5,6,7]
; SSE-NEXT:    pshufd {{.*#+}} xmm1 = xmm1[0,0,0,0]
; SSE-NEXT:    pandn %xmm0, %xmm1
; SSE-NEXT:    movdqa %xmm1, %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v8i16:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovd %edi, %xmm1
; AVX1-NEXT:    vpshuflw {{.*#+}} xmm1 = xmm1[0,0,0,0,4,5,6,7]
; AVX1-NEXT:    vpshufd {{.*#+}} xmm1 = xmm1[0,0,0,0]
; AVX1-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v8i16:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovd %edi, %xmm1
; AVX2-NEXT:    vpbroadcastw %xmm1, %xmm1
; AVX2-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v8i16:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastw %edi, %xmm1
; AVX512-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX512-NEXT:    retq
  %1 = xor i16 %a0, -1
  %2 = insertelement <8 x i16> undef, i16 %1, i64 0
  %3 = shufflevector <8 x i16> %2, <8 x i16> poison, <8 x i32> zeroinitializer
  %4 = and <8 x i16> %3, %a1
  ret <8 x i16> %4
}

define <16 x i8> @neg_scalar_broadcast_v16i8(i8 %a0, <16 x i8> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v16i8:
; SSE:       # %bb.0:
; SSE-NEXT:    movd %edi, %xmm1
; SSE-NEXT:    pxor %xmm2, %xmm2
; SSE-NEXT:    pshufb %xmm2, %xmm1
; SSE-NEXT:    pandn %xmm0, %xmm1
; SSE-NEXT:    movdqa %xmm1, %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v16i8:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovd %edi, %xmm1
; AVX1-NEXT:    vpxor %xmm2, %xmm2, %xmm2
; AVX1-NEXT:    vpshufb %xmm2, %xmm1, %xmm1
; AVX1-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v16i8:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovd %edi, %xmm1
; AVX2-NEXT:    vpbroadcastb %xmm1, %xmm1
; AVX2-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v16i8:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastb %edi, %xmm1
; AVX512-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX512-NEXT:    retq
  %1 = xor i8 %a0, -1
  %2 = insertelement <16 x i8> undef, i8 %1, i64 0
  %3 = shufflevector <16 x i8> %2, <16 x i8> poison, <16 x i32> zeroinitializer
  %4 = and <16 x i8> %3, %a1
  ret <16 x i8> %4
}

define <64 x i8> @neg_scalar_broadcast_v64i8(i8 %a0, <64 x i8> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v64i8:
; SSE:       # %bb.0:
; SSE-NEXT:    notb %dil
; SSE-NEXT:    movzbl %dil, %eax
; SSE-NEXT:    movd %eax, %xmm4
; SSE-NEXT:    pxor %xmm5, %xmm5
; SSE-NEXT:    pshufb %xmm5, %xmm4
; SSE-NEXT:    pand %xmm4, %xmm0
; SSE-NEXT:    pand %xmm4, %xmm1
; SSE-NEXT:    pand %xmm4, %xmm2
; SSE-NEXT:    pand %xmm4, %xmm3
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v64i8:
; AVX1:       # %bb.0:
; AVX1-NEXT:    notb %dil
; AVX1-NEXT:    vmovd %edi, %xmm2
; AVX1-NEXT:    vpxor %xmm3, %xmm3, %xmm3
; AVX1-NEXT:    vpshufb %xmm3, %xmm2, %xmm2
; AVX1-NEXT:    vinsertf128 $1, %xmm2, %ymm2, %ymm2
; AVX1-NEXT:    vandps %ymm0, %ymm2, %ymm0
; AVX1-NEXT:    vandps %ymm1, %ymm2, %ymm1
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v64i8:
; AVX2:       # %bb.0:
; AVX2-NEXT:    notb %dil
; AVX2-NEXT:    vmovd %edi, %xmm2
; AVX2-NEXT:    vpbroadcastb %xmm2, %ymm2
; AVX2-NEXT:    vpand %ymm0, %ymm2, %ymm0
; AVX2-NEXT:    vpand %ymm1, %ymm2, %ymm1
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v64i8:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastb %edi, %zmm1
; AVX512-NEXT:    vpandnq %zmm0, %zmm1, %zmm0
; AVX512-NEXT:    retq
  %1 = xor i8 %a0, -1
  %2 = insertelement <64 x i8> undef, i8 %1, i64 0
  %3 = shufflevector <64 x i8> %2, <64 x i8> poison, <64 x i32> zeroinitializer
  %4 = and <64 x i8> %3, %a1
  ret <64 x i8> %4
}

define <8 x i64> @neg_scalar_broadcast_v64i8_v8i64(i8 %a0, <8 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v64i8_v8i64:
; SSE:       # %bb.0:
; SSE-NEXT:    notb %dil
; SSE-NEXT:    movzbl %dil, %eax
; SSE-NEXT:    movd %eax, %xmm4
; SSE-NEXT:    pxor %xmm5, %xmm5
; SSE-NEXT:    pshufb %xmm5, %xmm4
; SSE-NEXT:    pand %xmm4, %xmm0
; SSE-NEXT:    pand %xmm4, %xmm1
; SSE-NEXT:    pand %xmm4, %xmm2
; SSE-NEXT:    pand %xmm4, %xmm3
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v64i8_v8i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    notb %dil
; AVX1-NEXT:    vmovd %edi, %xmm2
; AVX1-NEXT:    vpxor %xmm3, %xmm3, %xmm3
; AVX1-NEXT:    vpshufb %xmm3, %xmm2, %xmm2
; AVX1-NEXT:    vinsertf128 $1, %xmm2, %ymm2, %ymm2
; AVX1-NEXT:    vandps %ymm0, %ymm2, %ymm0
; AVX1-NEXT:    vandps %ymm1, %ymm2, %ymm1
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v64i8_v8i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    notb %dil
; AVX2-NEXT:    vmovd %edi, %xmm2
; AVX2-NEXT:    vpbroadcastb %xmm2, %ymm2
; AVX2-NEXT:    vpand %ymm0, %ymm2, %ymm0
; AVX2-NEXT:    vpand %ymm1, %ymm2, %ymm1
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v64i8_v8i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastb %edi, %zmm1
; AVX512-NEXT:    vpandnq %zmm0, %zmm1, %zmm0
; AVX512-NEXT:    retq
  %1 = xor i8 %a0, -1
  %2 = insertelement <64 x i8> undef, i8 %1, i64 0
  %3 = shufflevector <64 x i8> %2, <64 x i8> poison, <64 x i32> zeroinitializer
  %4 = bitcast <64 x i8> %3 to <8 x i64>
  %5 = and <8 x i64> %4, %a1
  ret <8 x i64> %5
}

define <4 x i64> @neg_scalar_broadcast_v32i8_v4i64(i8 %a0, <4 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v32i8_v4i64:
; SSE:       # %bb.0:
; SSE-NEXT:    notb %dil
; SSE-NEXT:    movzbl %dil, %eax
; SSE-NEXT:    movd %eax, %xmm2
; SSE-NEXT:    pxor %xmm3, %xmm3
; SSE-NEXT:    pshufb %xmm3, %xmm2
; SSE-NEXT:    pand %xmm2, %xmm0
; SSE-NEXT:    pand %xmm2, %xmm1
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v32i8_v4i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovd %edi, %xmm1
; AVX1-NEXT:    vpxor %xmm2, %xmm2, %xmm2
; AVX1-NEXT:    vpshufb %xmm2, %xmm1, %xmm1
; AVX1-NEXT:    vinsertf128 $1, %xmm1, %ymm1, %ymm1
; AVX1-NEXT:    vandnps %ymm0, %ymm1, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v32i8_v4i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovd %edi, %xmm1
; AVX2-NEXT:    vpbroadcastb %xmm1, %ymm1
; AVX2-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v32i8_v4i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastb %edi, %ymm1
; AVX512-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX512-NEXT:    retq
  %1 = xor i8 %a0, -1
  %2 = insertelement <32 x i8> undef, i8 %1, i64 0
  %3 = shufflevector <32 x i8> %2, <32 x i8> poison, <32 x i32> zeroinitializer
  %4 = bitcast <32 x i8> %3 to <4 x i64>
  %5 = and <4 x i64> %4, %a1
  ret <4 x i64> %5
}

define <2 x i64> @neg_scalar_broadcast_v16i8_v2i64(i8 %a0, <2 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v16i8_v2i64:
; SSE:       # %bb.0:
; SSE-NEXT:    movd %edi, %xmm1
; SSE-NEXT:    pxor %xmm2, %xmm2
; SSE-NEXT:    pshufb %xmm2, %xmm1
; SSE-NEXT:    pandn %xmm0, %xmm1
; SSE-NEXT:    movdqa %xmm1, %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v16i8_v2i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovd %edi, %xmm1
; AVX1-NEXT:    vpxor %xmm2, %xmm2, %xmm2
; AVX1-NEXT:    vpshufb %xmm2, %xmm1, %xmm1
; AVX1-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v16i8_v2i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovd %edi, %xmm1
; AVX2-NEXT:    vpbroadcastb %xmm1, %xmm1
; AVX2-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v16i8_v2i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastb %edi, %xmm1
; AVX512-NEXT:    vpandn %xmm0, %xmm1, %xmm0
; AVX512-NEXT:    retq
  %1 = xor i8 %a0, -1
  %2 = insertelement <16 x i8> undef, i8 %1, i64 0
  %3 = shufflevector <16 x i8> %2, <16 x i8> poison, <16 x i32> zeroinitializer
  %4 = bitcast <16 x i8> %3 to <2 x i64>
  %5 = and <2 x i64> %4, %a1
  ret <2 x i64> %5
}

define <4 x i64> @neg_scalar_broadcast_v8i32_v4i64(i32 %a0, <4 x i64> %a1) {
; SSE-LABEL: neg_scalar_broadcast_v8i32_v4i64:
; SSE:       # %bb.0:
; SSE-NEXT:    notl %edi
; SSE-NEXT:    movd %edi, %xmm2
; SSE-NEXT:    pshufd {{.*#+}} xmm2 = xmm2[0,0,0,0]
; SSE-NEXT:    pand %xmm2, %xmm0
; SSE-NEXT:    pand %xmm2, %xmm1
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_v8i32_v4i64:
; AVX1:       # %bb.0:
; AVX1-NEXT:    vmovd %edi, %xmm1
; AVX1-NEXT:    vpshufd {{.*#+}} xmm1 = xmm1[0,0,0,0]
; AVX1-NEXT:    vinsertf128 $1, %xmm1, %ymm1, %ymm1
; AVX1-NEXT:    vandnps %ymm0, %ymm1, %ymm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_v8i32_v4i64:
; AVX2:       # %bb.0:
; AVX2-NEXT:    vmovd %edi, %xmm1
; AVX2-NEXT:    vpbroadcastd %xmm1, %ymm1
; AVX2-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_v8i32_v4i64:
; AVX512:       # %bb.0:
; AVX512-NEXT:    vpbroadcastd %edi, %ymm1
; AVX512-NEXT:    vpandn %ymm0, %ymm1, %ymm0
; AVX512-NEXT:    retq
  %1 = xor i32 %a0, -1
  %2 = insertelement <8 x i32> undef, i32 %1, i64 0
  %3 = shufflevector <8 x i32> %2, <8 x i32> poison, <8 x i32> zeroinitializer
  %4 = bitcast <8 x i32> %3 to <4 x i64>
  %5 = and <4 x i64> %4, %a1
  ret <4 x i64> %5
}

define <4 x i32> @neg_scalar_broadcast_two_uses(i32 %a0, <4 x i32> %a1, ptr %a2) {
; SSE-LABEL: neg_scalar_broadcast_two_uses:
; SSE:       # %bb.0:
; SSE-NEXT:    notl %edi
; SSE-NEXT:    movd %edi, %xmm1
; SSE-NEXT:    pshufd {{.*#+}} xmm1 = xmm1[0,0,0,0]
; SSE-NEXT:    movdqa %xmm1, (%rsi)
; SSE-NEXT:    pand %xmm1, %xmm0
; SSE-NEXT:    retq
;
; AVX1-LABEL: neg_scalar_broadcast_two_uses:
; AVX1:       # %bb.0:
; AVX1-NEXT:    notl %edi
; AVX1-NEXT:    vmovd %edi, %xmm1
; AVX1-NEXT:    vpshufd {{.*#+}} xmm1 = xmm1[0,0,0,0]
; AVX1-NEXT:    vmovdqa %xmm1, (%rsi)
; AVX1-NEXT:    vpand %xmm0, %xmm1, %xmm0
; AVX1-NEXT:    retq
;
; AVX2-LABEL: neg_scalar_broadcast_two_uses:
; AVX2:       # %bb.0:
; AVX2-NEXT:    notl %edi
; AVX2-NEXT:    vmovd %edi, %xmm1
; AVX2-NEXT:    vpbroadcastd %xmm1, %xmm1
; AVX2-NEXT:    vmovdqa %xmm1, (%rsi)
; AVX2-NEXT:    vpand %xmm0, %xmm1, %xmm0
; AVX2-NEXT:    retq
;
; AVX512-LABEL: neg_scalar_broadcast_two_uses:
; AVX512:       # %bb.0:
; AVX512-NEXT:    notl %edi
; AVX512-NEXT:    vpbroadcastd %edi, %xmm1
; AVX512-NEXT:    vmovdqa %xmm1, (%rsi)
; AVX512-NEXT:    vpand %xmm0, %xmm1, %xmm0
; AVX512-NEXT:    retq
  %1 = xor i32 %a0, -1
  %2 = insertelement <4 x i32> undef, i32 %1, i64 0
  %3 = shufflevector <4 x i32> %2, <4 x i32> poison, <4 x i32> zeroinitializer
  store <4 x i32> %3, ptr %a2, align 16
  %4 = and <4 x i32> %3, %a1
  ret <4 x i32> %4
}

define <2 x i64> @andnp_xx(<2 x i64> %v0) nounwind {
; SSE-LABEL: andnp_xx:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm0, %xmm0
; SSE-NEXT:    retq
;
; AVX-LABEL: andnp_xx:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm0, %xmm0, %xmm0
; AVX-NEXT:    retq
  %x = xor <2 x i64> %v0, <i64 -1, i64 -1>
  %y = and <2 x i64> %v0, %x
  ret <2 x i64> %y
}

define <2 x i64> @andnp_xx_2(<2 x i64> %v0) nounwind {
; SSE-LABEL: andnp_xx_2:
; SSE:       # %bb.0:
; SSE-NEXT:    xorps %xmm0, %xmm0
; SSE-NEXT:    retq
;
; AVX-LABEL: andnp_xx_2:
; AVX:       # %bb.0:
; AVX-NEXT:    vxorps %xmm0, %xmm0, %xmm0
; AVX-NEXT:    retq
  %x = xor <2 x i64> %v0, <i64 -1, i64 -1>
  %y = and <2 x i64> %x, %v0
  ret <2 x i64> %y
}

define i64 @andn_xx(i64 %v0) nounwind {
; CHECK-LABEL: andn_xx:
; CHECK:       # %bb.0:
; CHECK-NEXT:    xorl %eax, %eax
; CHECK-NEXT:    retq
  %x = xor i64 %v0, -1
  %y = and i64 %v0, %x
  ret i64 %y
}

define i64 @andn_xx_2(i64 %v0) nounwind {
; CHECK-LABEL: andn_xx_2:
; CHECK:       # %bb.0:
; CHECK-NEXT:    xorl %eax, %eax
; CHECK-NEXT:    retq
  %x = xor i64 %v0, -1
  %y = and i64 %x, %v0
  ret i64 %y
}
