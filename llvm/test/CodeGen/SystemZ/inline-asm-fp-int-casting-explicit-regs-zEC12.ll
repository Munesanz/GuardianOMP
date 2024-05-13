; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 2
; RUN: llc -mtriple=s390x-linux-gnu -mcpu=zEC12 < %s | FileCheck %s
;
; Test inline assembly where the operand is bitcasted.

define signext i32 @int_and_f(i32 signext %cc_dep1) {
; CHECK-LABEL: int_and_f:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    risbhg %r0, %r2, 0, 159, 32
; CHECK-NEXT:    ldgr %f1, %r0
; CHECK-NEXT:    # kill: def $f1s killed $f1s killed $f1d
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    # kill: def $f1s killed $f1s def $f1d
; CHECK-NEXT:    lgdr %r0, %f1
; CHECK-NEXT:    risblg %r0, %r0, 0, 159, 32
; CHECK-NEXT:    lgfr %r2, %r0
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call i32 asm sideeffect "", "={f1},0"(i32 %cc_dep1)
  ret i32 %0
}

define i64 @long_and_f(i64 %cc_dep1) {
; CHECK-LABEL: long_and_f:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    ldgr %f2, %r2
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    lgdr %r2, %f2
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call i64 asm sideeffect "", "={f2},0"(i64 %cc_dep1)
  ret i64 %0
}

define void @__int128_and_f(ptr noalias nocapture writeonly sret(i128) align 8 %agg.result, ptr %0) {
; CHECK-LABEL: __int128_and_f:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    ld %f1, 0(%r3)
; CHECK-NEXT:    ld %f3, 8(%r3)
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    std %f1, 0(%r2)
; CHECK-NEXT:    std %f3, 8(%r2)
; CHECK-NEXT:    br %r14
entry:
  %cc_dep1 = load i128, ptr %0, align 8
  %1 = tail call i128 asm sideeffect "", "={f1},0"(i128 %cc_dep1)
  store i128 %1, ptr %agg.result, align 8
  ret void
}

define float @float_and_r(float %cc_dep1) {
; CHECK-LABEL: float_and_r:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    # kill: def $f0s killed $f0s def $f0d
; CHECK-NEXT:    lgdr %r0, %f0
; CHECK-NEXT:    risblg %r2, %r0, 0, 159, 32
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    risbhg %r0, %r2, 0, 159, 32
; CHECK-NEXT:    ldgr %f0, %r0
; CHECK-NEXT:    # kill: def $f0s killed $f0s killed $f0d
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call float asm sideeffect "", "={r2},0"(float %cc_dep1)
  ret float %0
}

define double @double_and_r(double %cc_dep1) {
; CHECK-LABEL: double_and_r:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lgdr %r3, %f0
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    ldgr %f0, %r3
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call double asm sideeffect "", "={r3},0"(double %cc_dep1)
  ret double %0
}

define void @longdouble_and_r(ptr noalias nocapture writeonly sret(fp128) align 8 %agg.result, ptr %0) {
; CHECK-LABEL: longdouble_and_r:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    lg %r5, 8(%r3)
; CHECK-NEXT:    lg %r4, 0(%r3)
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    stg %r5, 8(%r2)
; CHECK-NEXT:    stg %r4, 0(%r2)
; CHECK-NEXT:    br %r14
entry:
  %cc_dep1 = load fp128, ptr %0, align 8
  %1 = tail call fp128 asm sideeffect "", "={r4},0"(fp128 %cc_dep1)
  store fp128 %1, ptr %agg.result, align 8
  ret void
}

define <2 x i16> @vec32_and_r(<2 x i16> %cc_dep1) {
; CHECK-LABEL: vec32_and_r:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    # kill: def $r3l killed $r3l def $r3d
; CHECK-NEXT:    # kill: def $r2l killed $r2l def $r2d
; CHECK-NEXT:    risbgn %r3, %r2, 32, 47, 16
; CHECK-NEXT:    # kill: def $r3l killed $r3l killed $r3d
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    srlk %r2, %r3, 16
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call <2 x i16> asm sideeffect "", "={r3},0"(<2 x i16> %cc_dep1)
  ret <2 x i16> %0
}

define <2 x i32> @vec64_and_r(<2 x i32> %cc_dep1) {
; CHECK-LABEL: vec64_and_r:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    # kill: def $r2l killed $r2l def $r2d
; CHECK-NEXT:    sllg %r5, %r2, 32
; CHECK-NEXT:    lr %r5, %r3
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    lgr %r3, %r5
; CHECK-NEXT:    srlg %r2, %r5, 32
; CHECK-NEXT:    # kill: def $r2l killed $r2l killed $r2d
; CHECK-NEXT:    # kill: def $r3l killed $r3l killed $r3d
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call <2 x i32> asm sideeffect "", "={r5},0"(<2 x i32> %cc_dep1)
  ret <2 x i32> %0
}

define <2 x i16> @vec32_and_f(<2 x i16> %cc_dep1) {
; CHECK-LABEL: vec32_and_f:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    # kill: def $r3l killed $r3l def $r3d
; CHECK-NEXT:    # kill: def $r2l killed $r2l def $r2d
; CHECK-NEXT:    risbgn %r3, %r2, 32, 47, 16
; CHECK-NEXT:    risbhg %r0, %r3, 0, 159, 32
; CHECK-NEXT:    ldgr %f3, %r0
; CHECK-NEXT:    # kill: def $f3s killed $f3s killed $f3d
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    # kill: def $f3s killed $f3s def $f3d
; CHECK-NEXT:    lgdr %r0, %f3
; CHECK-NEXT:    risblg %r3, %r0, 0, 159, 32
; CHECK-NEXT:    srlk %r2, %r3, 16
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call <2 x i16> asm sideeffect "", "={f3},0"(<2 x i16> %cc_dep1)
  ret <2 x i16> %0
}

define <2 x i32> @vec64_and_f(<2 x i32> %cc_dep1) {
; CHECK-LABEL: vec64_and_f:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    # kill: def $r2l killed $r2l def $r2d
; CHECK-NEXT:    sllg %r0, %r2, 32
; CHECK-NEXT:    lr %r0, %r3
; CHECK-NEXT:    ldgr %f4, %r0
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    lgdr %r3, %f4
; CHECK-NEXT:    srlg %r2, %r3, 32
; CHECK-NEXT:    # kill: def $r2l killed $r2l killed $r2d
; CHECK-NEXT:    # kill: def $r3l killed $r3l killed $r3d
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call <2 x i32> asm sideeffect "", "={f4},0"(<2 x i32> %cc_dep1)
  ret <2 x i32> %0
}

define <4 x i32> @vec128_and_f(<4 x i32> %cc_dep1) {
; CHECK-LABEL: vec128_and_f:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    aghi %r15, -176
; CHECK-NEXT:    .cfi_def_cfa_offset 336
; CHECK-NEXT:    # kill: def $r4l killed $r4l def $r4d
; CHECK-NEXT:    sllg %r0, %r4, 32
; CHECK-NEXT:    lr %r0, %r5
; CHECK-NEXT:    # kill: def $r2l killed $r2l def $r2d
; CHECK-NEXT:    stg %r0, 168(%r15)
; CHECK-NEXT:    sllg %r0, %r2, 32
; CHECK-NEXT:    lr %r0, %r3
; CHECK-NEXT:    stg %r0, 160(%r15)
; CHECK-NEXT:    ld %f0, 160(%r15)
; CHECK-NEXT:    ld %f2, 168(%r15)
; CHECK-NEXT:    #APP
; CHECK-NEXT:    #NO_APP
; CHECK-NEXT:    lgdr %r3, %f0
; CHECK-NEXT:    lgdr %r5, %f2
; CHECK-NEXT:    srlg %r2, %r3, 32
; CHECK-NEXT:    srlg %r4, %r5, 32
; CHECK-NEXT:    # kill: def $r2l killed $r2l killed $r2d
; CHECK-NEXT:    # kill: def $r3l killed $r3l killed $r3d
; CHECK-NEXT:    # kill: def $r4l killed $r4l killed $r4d
; CHECK-NEXT:    # kill: def $r5l killed $r5l killed $r5d
; CHECK-NEXT:    aghi %r15, 176
; CHECK-NEXT:    br %r14
entry:
  %0 = tail call <4 x i32> asm sideeffect "", "={f0},0"(<4 x i32> %cc_dep1)
  ret <4 x i32> %0
}

