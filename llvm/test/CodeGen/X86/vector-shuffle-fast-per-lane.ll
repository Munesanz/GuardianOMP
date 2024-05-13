; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown -mattr=+avx2 | FileCheck %s --check-prefixes=SLOW
; RUN: llc < %s -mtriple=x86_64-unknown -mattr=+avx512f | FileCheck %s --check-prefixes=SLOW
; RUN: llc < %s -mtriple=x86_64-unknown -mattr=+avx2,+fast-variable-perlane-shuffle | FileCheck %s --check-prefixes=FAST
; RUN: llc < %s -mtriple=x86_64-unknown -mattr=+avx512f,+fast-variable-perlane-shuffle | FileCheck %s --check-prefixes=FAST
;
; RUN: llc < %s -mtriple=x86_64-unknown -mcpu=znver1 | FileCheck %s --check-prefixes=FAST
; RUN: llc < %s -mtriple=x86_64-unknown -mcpu=znver2 | FileCheck %s --check-prefixes=FAST
; RUN: llc < %s -mtriple=x86_64-unknown -mcpu=znver3 | FileCheck %s --check-prefixes=FAST
; RUN: llc < %s -mtriple=x86_64-unknown -mcpu=znver4 | FileCheck %s --check-prefixes=FAST
; RUN: llc < %s -mtriple=x86_64-unknown -mcpu=haswell | FileCheck %s --check-prefixes=FAST
; RUN: llc < %s -mtriple=x86_64-unknown -mcpu=skx | FileCheck %s --check-prefixes=FAST

define <32 x i8> @PR44795(<32 x i8> %a0) {
; SLOW-LABEL: PR44795:
; SLOW:       # %bb.0:
; SLOW-NEXT:    vpshuflw {{.*#+}} ymm0 = ymm0[0,0,2,2,4,5,6,7,8,8,10,10,12,13,14,15]
; SLOW-NEXT:    vpshufhw {{.*#+}} ymm0 = ymm0[0,1,2,3,4,4,6,6,8,9,10,11,12,12,14,14]
; SLOW-NEXT:    retq
;
; FAST-LABEL: PR44795:
; FAST:       # %bb.0:
; FAST-NEXT:    vpshufb {{.*#+}} ymm0 = ymm0[0,1,0,1,4,5,4,5,8,9,8,9,12,13,12,13,16,17,16,17,20,21,20,21,24,25,24,25,28,29,28,29]
; FAST-NEXT:    retq
  %r = shufflevector <32 x i8> %a0, <32 x i8> poison, <32 x i32> <i32 0, i32 1, i32 0, i32 1, i32 4, i32 5, i32 4, i32 5, i32 8, i32 9, i32 8, i32 9, i32 12, i32 13, i32 12, i32 13, i32 16, i32 17, i32 16, i32 17, i32 20, i32 21, i32 20, i32 21, i32 24, i32 25, i32 24, i32 25, i32 28, i32 29, i32 28, i32 29>
  ret <32 x i8> %r
}
