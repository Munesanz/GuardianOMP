; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 2
; RUN: opt -aa-pipeline=basic-aa -passes=attributor -attributor-manifest-internal -S < %s | FileCheck %s --check-prefixes=CHECK,TUNIT

declare float @llvm.round.f32(float)
declare ppc_fp128 @llvm.round.ppcf128(ppc_fp128)

define float @ret_round(float %arg0) {
; CHECK-LABEL: define float @ret_round
; CHECK-SAME: (float [[ARG0:%.*]]) #[[ATTR1:[0-9]+]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2:[0-9]+]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_noinf(float nofpclass(inf) %arg0) {
; CHECK-LABEL: define float @ret_round_noinf
; CHECK-SAME: (float nofpclass(inf) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopinf(float nofpclass(pinf) %arg0) {
; CHECK-LABEL: define float @ret_round_nopinf
; CHECK-SAME: (float nofpclass(pinf) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_noninf(float nofpclass(ninf) %arg0) {
; CHECK-LABEL: define float @ret_round_noninf
; CHECK-SAME: (float nofpclass(ninf) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nonan(float nofpclass(nan) %arg0) {
; CHECK-LABEL: define float @ret_round_nonan
; CHECK-SAME: (float nofpclass(nan) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_noqnan(float nofpclass(qnan) %arg0) {
; CHECK-LABEL: define float @ret_round_noqnan
; CHECK-SAME: (float nofpclass(qnan) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nosnan(float nofpclass(snan) %arg0) {
; CHECK-LABEL: define float @ret_round_nosnan
; CHECK-SAME: (float nofpclass(snan) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nozero(float nofpclass(zero) %arg0) {
; CHECK-LABEL: define float @ret_round_nozero
; CHECK-SAME: (float nofpclass(zero) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopzero(float nofpclass(pzero) %arg0) {
; CHECK-LABEL: define float @ret_round_nopzero
; CHECK-SAME: (float nofpclass(pzero) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nonzero(float nofpclass(nzero) %arg0) {
; CHECK-LABEL: define float @ret_round_nonzero
; CHECK-SAME: (float nofpclass(nzero) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nonorm(float nofpclass(norm) %arg0) {
; CHECK-LABEL: define float @ret_round_nonorm
; CHECK-SAME: (float nofpclass(norm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nonnorm(float nofpclass(nnorm) %arg0) {
; CHECK-LABEL: define float @ret_round_nonnorm
; CHECK-SAME: (float nofpclass(nnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopnorm(float nofpclass(pnorm) %arg0) {
; CHECK-LABEL: define float @ret_round_nopnorm
; CHECK-SAME: (float nofpclass(pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nonsub(float nofpclass(nsub) %arg0) {
; CHECK-LABEL: define float @ret_round_nonsub
; CHECK-SAME: (float nofpclass(nsub) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopsub(float nofpclass(psub) %arg0) {
; CHECK-LABEL: define float @ret_round_nopsub
; CHECK-SAME: (float nofpclass(psub) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nonorm_nosub(float nofpclass(norm sub) %arg0) {
; CHECK-LABEL: define float @ret_round_nonorm_nosub
; CHECK-SAME: (float nofpclass(sub norm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopnorm_nopsub(float nofpclass(pnorm psub) %arg0) {
; CHECK-LABEL: define float @ret_round_nopnorm_nopsub
; CHECK-SAME: (float nofpclass(psub pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nonnorm_nonsub(float nofpclass(nnorm nsub) %arg0) {
; CHECK-LABEL: define float @ret_round_nonnorm_nonsub
; CHECK-SAME: (float nofpclass(nsub nnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopnorm_nonsub(float nofpclass(pnorm nsub) %arg0) {
; CHECK-LABEL: define float @ret_round_nopnorm_nonsub
; CHECK-SAME: (float nofpclass(nsub pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define ppc_fp128 @ret_round_ppcf128(ppc_fp128 %arg0) {
; CHECK-LABEL: define ppc_fp128 @ret_round_ppcf128
; CHECK-SAME: (ppc_fp128 [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret ppc_fp128 [[CALL]]
;
  %call = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 %arg0)
  ret ppc_fp128 %call
}

define ppc_fp128 @ret_round_noinf_ppcf128(ppc_fp128 nofpclass(inf) %arg0) {
; CHECK-LABEL: define ppc_fp128 @ret_round_noinf_ppcf128
; CHECK-SAME: (ppc_fp128 nofpclass(inf) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret ppc_fp128 [[CALL]]
;
  %call = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 %arg0)
  ret ppc_fp128 %call
}

define ppc_fp128 @ret_round_nopinf_ppcf128(ppc_fp128 nofpclass(pinf) %arg0) {
; CHECK-LABEL: define ppc_fp128 @ret_round_nopinf_ppcf128
; CHECK-SAME: (ppc_fp128 nofpclass(pinf) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret ppc_fp128 [[CALL]]
;
  %call = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 %arg0)
  ret ppc_fp128 %call
}

define ppc_fp128 @ret_round_noninf_ppcf128(ppc_fp128 nofpclass(ninf) %arg0) {
; CHECK-LABEL: define ppc_fp128 @ret_round_noninf_ppcf128
; CHECK-SAME: (ppc_fp128 nofpclass(ninf) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret ppc_fp128 [[CALL]]
;
  %call = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 %arg0)
  ret ppc_fp128 %call
}

define ppc_fp128 @ret_round_nonan_ppcf128(ppc_fp128 nofpclass(nan) %arg0) {
; CHECK-LABEL: define ppc_fp128 @ret_round_nonan_ppcf128
; CHECK-SAME: (ppc_fp128 nofpclass(nan) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret ppc_fp128 [[CALL]]
;
  %call = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 %arg0)
  ret ppc_fp128 %call
}

define float @ret_round_noneg(float nofpclass(ninf nsub nnorm) %arg0) {
; CHECK-LABEL: define float @ret_round_noneg
; CHECK-SAME: (float nofpclass(ninf nsub nnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_noneg_nonegzero(float nofpclass(ninf nsub nnorm nzero) %arg0) {
; CHECK-LABEL: define float @ret_round_noneg_nonegzero
; CHECK-SAME: (float nofpclass(ninf nzero nsub nnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_noneg_nonegzero_nonan(float nofpclass(ninf nsub nnorm nzero nan) %arg0) {
; CHECK-LABEL: define float @ret_round_noneg_nonegzero_nonan
; CHECK-SAME: (float nofpclass(nan ninf nzero nsub nnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_noneg_nozero(float nofpclass(ninf nsub nnorm zero) %arg0) {
; CHECK-LABEL: define float @ret_round_noneg_nozero
; CHECK-SAME: (float nofpclass(ninf zero nsub nnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_noneg_nozero_nonan(float nofpclass(ninf nsub nnorm zero nan) %arg0) {
; CHECK-LABEL: define float @ret_round_noneg_nozero_nonan
; CHECK-SAME: (float nofpclass(nan ninf zero nsub nnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopos(float nofpclass(pinf psub pnorm) %arg0) {
; CHECK-LABEL: define float @ret_round_nopos
; CHECK-SAME: (float nofpclass(pinf psub pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopos_nopzero(float nofpclass(pinf psub pnorm pzero) %arg0) {
; CHECK-LABEL: define float @ret_round_nopos_nopzero
; CHECK-SAME: (float nofpclass(pinf pzero psub pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopos_nopzero_nonan(float nofpclass(pinf psub pnorm pzero nan) %arg0) {
; CHECK-LABEL: define float @ret_round_nopos_nopzero_nonan
; CHECK-SAME: (float nofpclass(nan pinf pzero psub pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopos_nozero(float nofpclass(pinf psub pnorm zero) %arg0) {
; CHECK-LABEL: define float @ret_round_nopos_nozero
; CHECK-SAME: (float nofpclass(pinf zero psub pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

define float @ret_round_nopos_nozero_nonan(float nofpclass(pinf psub pnorm zero nan) %arg0) {
; CHECK-LABEL: define float @ret_round_nopos_nozero_nonan
; CHECK-SAME: (float nofpclass(nan pinf zero psub pnorm) [[ARG0:%.*]]) #[[ATTR1]] {
; CHECK-NEXT:    [[CALL:%.*]] = call float @llvm.round.f32(float [[ARG0]]) #[[ATTR2]]
; CHECK-NEXT:    ret float [[CALL]]
;
  %call = call float @llvm.round.f32(float %arg0)
  ret float %call
}

;; NOTE: These prefixes are unused and the list is autogenerated. Do not add tests below this line:
; TUNIT: {{.*}}
