; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 2
; RUN: opt < %s -S -passes=instsimplify | FileCheck %s

; largest unsigned i15 = 2^15 - 1 = 32767
; largest half (max exponent = 15 -> 2^15 * (1 + 1023/1024) = 65504

define i1 @isKnownNeverInfinity_uitofp(i15 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_uitofp
; CHECK-SAME: (i15 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %f = uitofp i15 %x to half
  %r = fcmp une half %f, 0xH7c00
  ret i1 %r
}

; negative test

define i1 @isNotKnownNeverInfinity_uitofp(i16 %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_uitofp
; CHECK-SAME: (i16 [[X:%.*]]) {
; CHECK-NEXT:    [[F:%.*]] = uitofp i16 [[X]] to half
; CHECK-NEXT:    [[R:%.*]] = fcmp une half [[F]], 0xH7C00
; CHECK-NEXT:    ret i1 [[R]]
;
  %f = uitofp i16 %x to half
  %r = fcmp une half %f, 0xH7c00
  ret i1 %r
}

define i1 @isKnownNeverNegativeInfinity_uitofp(i15 %x) {
; CHECK-LABEL: define i1 @isKnownNeverNegativeInfinity_uitofp
; CHECK-SAME: (i15 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 false
;
  %f = uitofp i15 %x to half
  %r = fcmp oeq half %f, 0xHfc00
  ret i1 %r
}

; uitofp can't be negative, so this still works.

define i1 @isNotKnownNeverNegativeInfinity_uitofp(i16 %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverNegativeInfinity_uitofp
; CHECK-SAME: (i16 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 false
;
  %f = uitofp i16 %x to half
  %r = fcmp oeq half %f, 0xHfc00
  ret i1 %r
}

; largest magnitude signed i16 = 2^15 - 1 = 32767 --> -32768
; largest half (max exponent = 15 -> 2^15 * (1 + 1023/1024) = 65504

define i1 @isKnownNeverInfinity_sitofp(i16 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_sitofp
; CHECK-SAME: (i16 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %f = sitofp i16 %x to half
  %r = fcmp une half %f, 0xH7c00
  ret i1 %r
}

; negative test

define i1 @isNotKnownNeverInfinity_sitofp(i17 %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_sitofp
; CHECK-SAME: (i17 [[X:%.*]]) {
; CHECK-NEXT:    [[F:%.*]] = sitofp i17 [[X]] to half
; CHECK-NEXT:    [[R:%.*]] = fcmp une half [[F]], 0xH7C00
; CHECK-NEXT:    ret i1 [[R]]
;
  %f = sitofp i17 %x to half
  %r = fcmp une half %f, 0xH7c00
  ret i1 %r
}

define i1 @isKnownNeverNegativeInfinity_sitofp(i16 %x) {
; CHECK-LABEL: define i1 @isKnownNeverNegativeInfinity_sitofp
; CHECK-SAME: (i16 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 false
;
  %f = sitofp i16 %x to half
  %r = fcmp oeq half %f, 0xHfc00
  ret i1 %r
}

; negative test

define i1 @isNotKnownNeverNegativeInfinity_sitofp(i17 %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverNegativeInfinity_sitofp
; CHECK-SAME: (i17 [[X:%.*]]) {
; CHECK-NEXT:    [[F:%.*]] = sitofp i17 [[X]] to half
; CHECK-NEXT:    [[R:%.*]] = fcmp oeq half [[F]], 0xHFC00
; CHECK-NEXT:    ret i1 [[R]]
;
  %f = sitofp i17 %x to half
  %r = fcmp oeq half %f, 0xHfc00
  ret i1 %r
}

define i1 @isKnownNeverInfinity_fpext(float %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_fpext
; CHECK-SAME: (float [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf float %x, 1.0
  %e = fpext float %a to double
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_fpext_sitofp(i16 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_fpext_sitofp
; CHECK-SAME: (i16 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 false
;
  %f = sitofp i16 %x to half
  %e = fpext half %f to double
  %r = fcmp oeq double %e, 0xfff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_fptrunc(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_fptrunc
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = fptrunc double [[A]] to float
; CHECK-NEXT:    [[R:%.*]] = fcmp une float [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf double %x, 1.0
  %e = fptrunc double %a to float
  %r = fcmp une float %e, 0x7FF0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_fptrunc(double %unknown) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_fptrunc
; CHECK-SAME: (double [[UNKNOWN:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = fptrunc double [[UNKNOWN]] to float
; CHECK-NEXT:    [[R:%.*]] = fcmp une float [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = fptrunc double %unknown to float
  %r = fcmp une float %e, 0x7FF0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_canonicalize(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_canonicalize
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.canonicalize.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_canonicalize(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_canonicalize
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.canonicalize.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.canonicalize.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_fabs(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_fabs
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.fabs.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_fabs(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_fabs
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.fabs.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.fabs.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_fneg(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_fneg
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = fneg double %a
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_fneg(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_fneg
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = fneg double [[X]]
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = fneg double %x
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_copysign(double %x, double %sign) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_copysign
; CHECK-SAME: (double [[X:%.*]], double [[SIGN:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.copysign.f64(double %a, double %sign)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_copysign(double %x, double %sign) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_copysign
; CHECK-SAME: (double [[X:%.*]], double [[SIGN:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.copysign.f64(double [[X]], double [[SIGN]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.copysign.f64(double %x, double %sign)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_arithmetic_fence(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_arithmetic_fence
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.arithmetic.fence.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_arithmetic_fence(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_arithmetic_fence
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.arithmetic.fence.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.arithmetic.fence.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_floor(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_floor
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.floor.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_floor(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_floor
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.floor.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.floor.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_ceil(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_ceil
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.ceil.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_ceil(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_ceil
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.ceil.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.ceil.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_trunc(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_trunc
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.trunc.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_trunc(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_trunc
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.trunc.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.trunc.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_rint(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_rint
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.rint.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_rint(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_rint
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.rint.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.rint.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_nearbyint(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_nearbyint
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.nearbyint.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_nearbyint(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_nearbyint
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.nearbyint.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.nearbyint.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_round(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_round
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.round.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_round(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_round
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.round.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.round.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_roundeven(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_roundeven
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.roundeven.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_roundeven(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_roundeven
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.roundeven.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.roundeven.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_fptrunc_round(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_fptrunc_round
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call float @llvm.fptrunc.round.f32.f64(double [[A]], metadata !"round.downward")
; CHECK-NEXT:    [[R:%.*]] = fcmp une float [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf double %x, 1.0
  %e = call float @llvm.fptrunc.round.f32.f64(double %a, metadata !"round.downward")
  %r = fcmp une float %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_floor_ppcf128(ppc_fp128 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_floor_ppcf128
; CHECK-SAME: (ppc_fp128 [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf ppc_fp128 [[X]], [[X]]
; CHECK-NEXT:    [[E:%.*]] = call ppc_fp128 @llvm.floor.ppcf128(ppc_fp128 [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une ppc_fp128 [[E]], 0xM7FF00000000000000000000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf ppc_fp128 %x, %x
  %e = call ppc_fp128 @llvm.floor.ppcf128(ppc_fp128 %a)
  %r = fcmp une ppc_fp128 %e, 0xM7FF00000000000000000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_ceil_ppcf128(ppc_fp128 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_ceil_ppcf128
; CHECK-SAME: (ppc_fp128 [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf ppc_fp128 [[X]], [[X]]
; CHECK-NEXT:    [[E:%.*]] = call ppc_fp128 @llvm.ceil.ppcf128(ppc_fp128 [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une ppc_fp128 [[E]], 0xM7FF00000000000000000000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf ppc_fp128 %x, %x
  %e = call ppc_fp128 @llvm.ceil.ppcf128(ppc_fp128 %a)
  %r = fcmp une ppc_fp128 %e, 0xM7FF00000000000000000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_rint_ppcf128(ppc_fp128 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_rint_ppcf128
; CHECK-SAME: (ppc_fp128 [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf ppc_fp128 [[X]], [[X]]
; CHECK-NEXT:    [[E:%.*]] = call ppc_fp128 @llvm.rint.ppcf128(ppc_fp128 [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une ppc_fp128 [[E]], 0xM7FF00000000000000000000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf ppc_fp128 %x, %x
  %e = call ppc_fp128 @llvm.rint.ppcf128(ppc_fp128 %a)
  %r = fcmp une ppc_fp128 %e, 0xM7FF00000000000000000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_nearbyint_ppcf128(ppc_fp128 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_nearbyint_ppcf128
; CHECK-SAME: (ppc_fp128 [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf ppc_fp128 [[X]], [[X]]
; CHECK-NEXT:    [[E:%.*]] = call ppc_fp128 @llvm.nearbyint.ppcf128(ppc_fp128 [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une ppc_fp128 [[E]], 0xM7FF00000000000000000000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf ppc_fp128 %x, %x
  %e = call ppc_fp128 @llvm.nearbyint.ppcf128(ppc_fp128 %a)
  %r = fcmp une ppc_fp128 %e, 0xM7FF00000000000000000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_round_ppcf128(ppc_fp128 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_round_ppcf128
; CHECK-SAME: (ppc_fp128 [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf ppc_fp128 [[X]], [[X]]
; CHECK-NEXT:    [[E:%.*]] = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une ppc_fp128 [[E]], 0xM7FF00000000000000000000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf ppc_fp128 %x, %x
  %e = call ppc_fp128 @llvm.round.ppcf128(ppc_fp128 %a)
  %r = fcmp une ppc_fp128 %e, 0xM7FF00000000000000000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_roundeven_ppcf128(ppc_fp128 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_roundeven_ppcf128
; CHECK-SAME: (ppc_fp128 [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf ppc_fp128 [[X]], [[X]]
; CHECK-NEXT:    [[E:%.*]] = call ppc_fp128 @llvm.roundeven.ppcf128(ppc_fp128 [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une ppc_fp128 [[E]], 0xM7FF00000000000000000000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf ppc_fp128 %x, %x
  %e = call ppc_fp128 @llvm.roundeven.ppcf128(ppc_fp128 %a)
  %r = fcmp une ppc_fp128 %e, 0xM7FF00000000000000000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_trunc_ppcf128(ppc_fp128 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_trunc_ppcf128
; CHECK-SAME: (ppc_fp128 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf ppc_fp128 %x, %x
  %e = call ppc_fp128 @llvm.trunc.ppcf128(ppc_fp128 %a)
  %r = fcmp une ppc_fp128 %e, 0xM7FF00000000000000000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_ceil_x86_fp80(x86_fp80 %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_ceil_x86_fp80
; CHECK-SAME: (x86_fp80 [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf x86_fp80 %x, %x
  %e = call x86_fp80 @llvm.ceil.f80(x86_fp80 %a)
  %r = fcmp une x86_fp80 %e, 0xK7FFF8000000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_minnum(double %x, double %y) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_minnum
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %ninf.x = fadd ninf double %x, 1.0
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.minnum.f64(double %ninf.x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_minnum_lhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_minnum_lhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_Y:%.*]] = fadd ninf double [[Y]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.minnum.f64(double [[X]], double [[NINF_Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.minnum.f64(double %x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_minnum_rhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_minnum_rhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.minnum.f64(double [[NINF_X]], double [[Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %op = call double @llvm.minnum.f64(double %ninf.x, double %y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isKnownNeverInfinity_maxnum(double %x, double %y) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_maxnum
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %ninf.x = fadd ninf double %x, 1.0
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.maxnum.f64(double %ninf.x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_maxnum_lhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_maxnum_lhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_Y:%.*]] = fadd ninf double [[Y]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.maxnum.f64(double [[X]], double [[NINF_Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.maxnum.f64(double %x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_maxnum_rhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_maxnum_rhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.maxnum.f64(double [[NINF_X]], double [[Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %op = call double @llvm.maxnum.f64(double %ninf.x, double %y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isKnownNeverInfinity_minimum(double %x, double %y) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_minimum
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %ninf.x = fadd ninf double %x, 1.0
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.minimum.f64(double %ninf.x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_minimum_lhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_minimum_lhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_Y:%.*]] = fadd ninf double [[Y]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.minimum.f64(double [[X]], double [[NINF_Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.minimum.f64(double %x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_minimum_rhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_minimum_rhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.minimum.f64(double [[NINF_X]], double [[Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %op = call double @llvm.minimum.f64(double %ninf.x, double %y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isKnownNeverInfinity_maximum(double %x, double %y) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_maximum
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %ninf.x = fadd ninf double %x, 1.0
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.maximum.f64(double %ninf.x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_maximum_lhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_maximum_lhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_Y:%.*]] = fadd ninf double [[Y]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.maximum.f64(double [[X]], double [[NINF_Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.maximum.f64(double %x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_maximum_rhs(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_maximum_rhs
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.maximum.f64(double [[NINF_X]], double [[Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %op = call double @llvm.maximum.f64(double %ninf.x, double %y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isKnownNeverInfinity_sqrt(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_sqrt
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.sqrt.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_sqrt(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_sqrt
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.sqrt.f64(double [[X]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %e = call double @llvm.sqrt.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

; No source check required
define i1 @isKnownNeverInfinity_sin(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_sin
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %e = call double @llvm.sin.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

; No source check required
define i1 @isKnownNeverInfinity_cos(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_cos
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    ret i1 true
;
  %e = call double @llvm.cos.f64(double %x)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_log(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_log
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_CLAMP_ZERO:%.*]] = call double @llvm.maxnum.f64(double [[X]], double 0.000000e+00)
; CHECK-NEXT:    [[A:%.*]] = fadd ninf double [[X_CLAMP_ZERO]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %x.clamp.zero = call double @llvm.maxnum.f64(double %x, double 0.0)
  %a = fadd ninf double %x.clamp.zero, 1.0
  %e = call double @llvm.log.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_log_maybe_negative(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_log_maybe_negative
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_NOT_INF:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log.f64(double [[X_NOT_INF]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;

  %x.not.inf = fadd ninf double %x, 1.0
  %e = call double @llvm.log.f64(double %x.not.inf)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_log_maybe_inf(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_log_maybe_inf
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_CLAMP_ZERO:%.*]] = call double @llvm.maxnum.f64(double [[X]], double 0.000000e+00)
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log.f64(double [[X_CLAMP_ZERO]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %x.clamp.zero = call double @llvm.maxnum.f64(double %x, double 0.0)
  %e = call double @llvm.log.f64(double %x.clamp.zero)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverNegInfinity_log_maybe_0(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverNegInfinity_log_maybe_0
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = call ninf double @llvm.sqrt.f64(double [[X]])
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0xFFF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = call ninf double @llvm.sqrt.f64(double %x) ; could be 0.0
  %e = call double @llvm.log.f64(double %a) ; log(0.0) --> -inf
  %r = fcmp une double %e, 0xfff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_log10(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_log10
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_CLAMP_ZERO:%.*]] = call double @llvm.maxnum.f64(double [[X]], double 0.000000e+00)
; CHECK-NEXT:    [[A:%.*]] = fadd ninf double [[X_CLAMP_ZERO]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log10.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %x.clamp.zero = call double @llvm.maxnum.f64(double %x, double 0.0)
  %a = fadd ninf double %x.clamp.zero, 1.0
  %e = call double @llvm.log10.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_log10_maybe_negative(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_log10_maybe_negative
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_NOT_INF:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log10.f64(double [[X_NOT_INF]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;

  %x.not.inf = fadd ninf double %x, 1.0
  %e = call double @llvm.log10.f64(double %x.not.inf)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_log10_maybe_inf(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_log10_maybe_inf
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_CLAMP_ZERO:%.*]] = call double @llvm.maxnum.f64(double [[X]], double 0.000000e+00)
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log10.f64(double [[X_CLAMP_ZERO]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %x.clamp.zero = call double @llvm.maxnum.f64(double %x, double 0.0)
  %e = call double @llvm.log10.f64(double %x.clamp.zero)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverNegInfinity_log10_maybe_0(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverNegInfinity_log10_maybe_0
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = call ninf double @llvm.sqrt.f64(double [[X]])
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log10.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0xFFF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = call ninf double @llvm.sqrt.f64(double %x) ; could be 0.0
  %e = call double @llvm.log10.f64(double %a) ; log(0.0) --> -inf
  %r = fcmp une double %e, 0xfff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverInfinity_log2(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverInfinity_log2
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_CLAMP_ZERO:%.*]] = call double @llvm.maxnum.f64(double [[X]], double 0.000000e+00)
; CHECK-NEXT:    [[A:%.*]] = fadd ninf double [[X_CLAMP_ZERO]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log2.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %x.clamp.zero = call double @llvm.maxnum.f64(double %x, double 0.0)
  %a = fadd ninf double %x.clamp.zero, 1.0
  %e = call double @llvm.log2.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_log2_maybe_negative(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_log2_maybe_negative
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_NOT_INF:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log2.f64(double [[X_NOT_INF]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;

  %x.not.inf = fadd ninf double %x, 1.0
  %e = call double @llvm.log2.f64(double %x.not.inf)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_log2_maybe_inf(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_log2_maybe_inf
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[X_CLAMP_ZERO:%.*]] = call double @llvm.maxnum.f64(double [[X]], double 0.000000e+00)
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log2.f64(double [[X_CLAMP_ZERO]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %x.clamp.zero = call double @llvm.maxnum.f64(double %x, double 0.0)
  %e = call double @llvm.log2.f64(double %x.clamp.zero)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isKnownNeverNegInfinity_log2_maybe_0(double %x) {
; CHECK-LABEL: define i1 @isKnownNeverNegInfinity_log2_maybe_0
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = call ninf double @llvm.sqrt.f64(double [[X]])
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.log2.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0xFFF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = call ninf double @llvm.sqrt.f64(double %x) ; could be 0.0
  %e = call double @llvm.log2.f64(double %a) ; log(0.0) --> -inf
  %r = fcmp une double %e, 0xfff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_pow(double %x, double %y) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_pow
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[NINF_Y:%.*]] = fadd ninf double [[Y]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.pow.f64(double [[NINF_X]], double [[NINF_Y]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %ninf.y = fadd ninf double %y, 1.0
  %op = call double @llvm.pow.f64(double %ninf.x, double %ninf.y)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_powi(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_powi
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.powi.f64.i32(double [[NINF_X]], i32 2)
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %op = call double @llvm.powi.f64.i32(double %ninf.x, i32 2)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_exp(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_exp
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.exp.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.exp.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_exp2(double %x) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_exp2
; CHECK-SAME: (double [[X:%.*]]) {
; CHECK-NEXT:    [[A:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[E:%.*]] = call double @llvm.exp2.f64(double [[A]])
; CHECK-NEXT:    [[R:%.*]] = fcmp une double [[E]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[R]]
;
  %a = fadd ninf double %x, 1.0
  %e = call double @llvm.exp2.f64(double %a)
  %r = fcmp une double %e, 0x7ff0000000000000
  ret i1 %r
}

define i1 @isNotKnownNeverInfinity_fma(double %x, double %y, double %z) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_fma
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]], double [[Z:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[NINF_Y:%.*]] = fadd ninf double [[Y]], 1.000000e+00
; CHECK-NEXT:    [[NINF_Z:%.*]] = fadd ninf double [[Z]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.fma.f64(double [[NINF_X]], double [[NINF_Y]], double [[NINF_Z]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %ninf.y = fadd ninf double %y, 1.0
  %ninf.z = fadd ninf double %z, 1.0
  %op = call double @llvm.fma.f64(double %ninf.x, double %ninf.y, double %ninf.z)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

define i1 @isNotKnownNeverInfinity_fmuladd(double %x, double %y, double %z) {
; CHECK-LABEL: define i1 @isNotKnownNeverInfinity_fmuladd
; CHECK-SAME: (double [[X:%.*]], double [[Y:%.*]], double [[Z:%.*]]) {
; CHECK-NEXT:    [[NINF_X:%.*]] = fadd ninf double [[X]], 1.000000e+00
; CHECK-NEXT:    [[NINF_Y:%.*]] = fadd ninf double [[Y]], 1.000000e+00
; CHECK-NEXT:    [[NINF_Z:%.*]] = fadd ninf double [[Z]], 1.000000e+00
; CHECK-NEXT:    [[OP:%.*]] = call double @llvm.fmuladd.f64(double [[NINF_X]], double [[NINF_Y]], double [[NINF_Z]])
; CHECK-NEXT:    [[CMP:%.*]] = fcmp une double [[OP]], 0x7FF0000000000000
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %ninf.x = fadd ninf double %x, 1.0
  %ninf.y = fadd ninf double %y, 1.0
  %ninf.z = fadd ninf double %z, 1.0
  %op = call double @llvm.fmuladd.f64(double %ninf.x, double %ninf.y, double %ninf.z)
  %cmp = fcmp une double %op, 0x7ff0000000000000
  ret i1 %cmp
}

declare double @llvm.arithmetic.fence.f64(double)
declare double @llvm.canonicalize.f64(double)
declare double @llvm.ceil.f64(double)
declare double @llvm.copysign.f64(double, double)
declare double @llvm.cos.f64(double)
declare double @llvm.exp2.f64(double)
declare double @llvm.exp.f64(double)
declare double @llvm.fabs.f64(double)
declare double @llvm.floor.f64(double)
declare double @llvm.fma.f64(double, double, double)
declare double @llvm.fmuladd.f64(double, double, double)
declare double @llvm.log10.f64(double)
declare double @llvm.log2.f64(double)
declare double @llvm.log.f64(double)
declare double @llvm.maximum.f64(double, double)
declare double @llvm.maxnum.f64(double, double)
declare double @llvm.minimum.f64(double, double)
declare double @llvm.minnum.f64(double, double)
declare double @llvm.nearbyint.f64(double)
declare double @llvm.pow.f64(double, double)
declare double @llvm.powi.f64.i32(double, i32)
declare double @llvm.rint.f64(double)
declare double @llvm.roundeven.f64(double)
declare double @llvm.round.f64(double)
declare double @llvm.sin.f64(double)
declare double @llvm.sqrt.f64(double)
declare double @llvm.trunc.f64(double)
declare float @llvm.fptrunc.round.f32.f64(double, metadata)
declare ppc_fp128 @llvm.ceil.ppcf128(ppc_fp128)
declare ppc_fp128 @llvm.floor.ppcf128(ppc_fp128)
declare ppc_fp128 @llvm.nearbyint.ppcf128(ppc_fp128)
declare ppc_fp128 @llvm.rint.ppcf128(ppc_fp128)
declare ppc_fp128 @llvm.roundeven.ppcf128(ppc_fp128)
declare ppc_fp128 @llvm.round.ppcf128(ppc_fp128)
declare ppc_fp128 @llvm.trunc.ppcf128(ppc_fp128)
declare x86_fp80 @llvm.ceil.f80(x86_fp80)
