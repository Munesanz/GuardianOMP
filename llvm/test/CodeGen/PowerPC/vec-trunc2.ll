; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -verify-machineinstrs -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:     -mattr=+vsx -ppc-asm-full-reg-names -ppc-vsr-nums-as-vr < %s | \
; RUN: FileCheck %s
; RUN: llc -verify-machineinstrs -mtriple=powerpc64-unknown-linux-gnu \
; RUN:     -mattr=+vsx -ppc-asm-full-reg-names -ppc-vsr-nums-as-vr < %s | \
; RUN: FileCheck %s --check-prefix=CHECK-BE

define dso_local <8 x i8> @test8x32(i32 %i1, i32 %i2, i32 %i3, i32 %i4, i32 %i5, i32 %i6, i32 %i7, i32 %i8) {
; CHECK-LABEL: test8x32:
; CHECK:       # %bb.0:
; CHECK-NEXT:    addis r11, r2, .LCPI0_0@toc@ha
; CHECK-NEXT:    rldimi r3, r4, 32, 0
; CHECK-NEXT:    rldimi r5, r6, 32, 0
; CHECK-NEXT:    mtfprd f0, r3
; CHECK-NEXT:    addi r3, r11, .LCPI0_0@toc@l
; CHECK-NEXT:    rldimi r7, r8, 32, 0
; CHECK-NEXT:    rldimi r9, r10, 32, 0
; CHECK-NEXT:    lxvd2x vs3, 0, r3
; CHECK-NEXT:    mtfprd f1, r5
; CHECK-NEXT:    mtfprd f2, r7
; CHECK-NEXT:    mtfprd f4, r9
; CHECK-NEXT:    xxmrghd v2, vs1, vs0
; CHECK-NEXT:    xxswapd v4, vs3
; CHECK-NEXT:    xxmrghd v3, vs4, vs2
; CHECK-NEXT:    vperm v2, v3, v2, v4
; CHECK-NEXT:    blr
;
; CHECK-BE-LABEL: test8x32:
; CHECK-BE:       # %bb.0:
; CHECK-BE-NEXT:    stw r10, -80(r1)
; CHECK-BE-NEXT:    stw r9, -96(r1)
; CHECK-BE-NEXT:    stw r8, -112(r1)
; CHECK-BE-NEXT:    stw r7, -128(r1)
; CHECK-BE-NEXT:    stw r6, -16(r1)
; CHECK-BE-NEXT:    stw r5, -32(r1)
; CHECK-BE-NEXT:    stw r4, -48(r1)
; CHECK-BE-NEXT:    stw r3, -64(r1)
; CHECK-BE-NEXT:    addi r3, r1, -80
; CHECK-BE-NEXT:    lxvw4x vs0, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -96
; CHECK-BE-NEXT:    lxvw4x vs1, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -112
; CHECK-BE-NEXT:    lxvw4x vs2, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -128
; CHECK-BE-NEXT:    lxvw4x vs3, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -16
; CHECK-BE-NEXT:    lxvw4x vs4, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -32
; CHECK-BE-NEXT:    lxvw4x vs5, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -48
; CHECK-BE-NEXT:    lxvw4x vs6, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -64
; CHECK-BE-NEXT:    lxvw4x vs7, 0, r3
; CHECK-BE-NEXT:    addis r3, r2, .LCPI0_0@toc@ha
; CHECK-BE-NEXT:    xxmrghw vs0, vs1, vs0
; CHECK-BE-NEXT:    xxmrghw vs1, vs3, vs2
; CHECK-BE-NEXT:    xxmrghw vs2, vs5, vs4
; CHECK-BE-NEXT:    addi r3, r3, .LCPI0_0@toc@l
; CHECK-BE-NEXT:    xxmrghd v3, vs1, vs0
; CHECK-BE-NEXT:    lxvw4x v2, 0, r3
; CHECK-BE-NEXT:    xxmrghw vs3, vs7, vs6
; CHECK-BE-NEXT:    xxmrghd v4, vs3, vs2
; CHECK-BE-NEXT:    vperm v2, v4, v3, v2
; CHECK-BE-NEXT:    blr
%v10 = insertelement <8 x i32> undef, i32 %i1, i32 0
%v11 = insertelement <8 x i32> %v10, i32 %i2, i32 1
%v12 = insertelement <8 x i32> %v11, i32 %i3, i32 2
%v13 = insertelement <8 x i32> %v12, i32 %i4, i32 3
%v14 = insertelement <8 x i32> %v13, i32 %i5, i32 4
%v15 = insertelement <8 x i32> %v14, i32 %i6, i32 5
%v16 = insertelement <8 x i32> %v15, i32 %i7, i32 6
%v17 = insertelement <8 x i32> %v16, i32 %i8, i32 7
%v2 = trunc <8 x i32> %v17 to <8 x i8>
ret <8 x i8> %v2
}

define dso_local <4 x i16> @test4x64(i64 %i1, i64 %i2, i64 %i3, i64 %i4) {
; CHECK-LABEL: test4x64:
; CHECK:       # %bb.0:
; CHECK-NEXT:    addis r7, r2, .LCPI1_0@toc@ha
; CHECK-NEXT:    mtfprd f0, r5
; CHECK-NEXT:    addi r5, r7, .LCPI1_0@toc@l
; CHECK-NEXT:    mtfprd f1, r6
; CHECK-NEXT:    lxvd2x vs3, 0, r5
; CHECK-NEXT:    mtfprd f2, r3
; CHECK-NEXT:    mtfprd f4, r4
; CHECK-NEXT:    xxmrghd v2, vs1, vs0
; CHECK-NEXT:    xxmrghd v3, vs4, vs2
; CHECK-NEXT:    xxswapd v4, vs3
; CHECK-NEXT:    vperm v2, v2, v3, v4
; CHECK-NEXT:    blr
;
; CHECK-BE-LABEL: test4x64:
; CHECK-BE:       # %bb.0:
; CHECK-BE-NEXT:    std r6, -8(r1)
; CHECK-BE-NEXT:    std r5, -16(r1)
; CHECK-BE-NEXT:    std r4, -24(r1)
; CHECK-BE-NEXT:    std r3, -32(r1)
; CHECK-BE-NEXT:    addi r3, r1, -32
; CHECK-BE-NEXT:    addis r4, r2, .LCPI1_0@toc@ha
; CHECK-BE-NEXT:    addi r7, r1, -16
; CHECK-BE-NEXT:    lxvd2x v3, 0, r3
; CHECK-BE-NEXT:    addi r3, r4, .LCPI1_0@toc@l
; CHECK-BE-NEXT:    lxvd2x v2, 0, r7
; CHECK-BE-NEXT:    lxvw4x v4, 0, r3
; CHECK-BE-NEXT:    vperm v2, v3, v2, v4
; CHECK-BE-NEXT:    blr
%v10 = insertelement <4 x i64> undef, i64 %i1, i32 0
%v11 = insertelement <4 x i64> %v10, i64 %i2, i32 1
%v12 = insertelement <4 x i64> %v11, i64 %i3, i32 2
%v13 = insertelement <4 x i64> %v12, i64 %i4, i32 3
%v2 = trunc <4 x i64> %v13 to <4 x i16>
ret <4 x i16> %v2
}

define dso_local <8 x i16> @test8x24(i32 %i1, i32 %i2, i32 %i3, i32 %i4, i32 %i5, i32 %i6, i32 %i7, i32 %i8) {
; CHECK-LABEL: test8x24:
; CHECK:       # %bb.0:
; CHECK-NEXT:    mtvsrd v2, r3
; CHECK-NEXT:    mtvsrd v3, r4
; CHECK-NEXT:    mtvsrd v4, r5
; CHECK-NEXT:    mtvsrd v5, r6
; CHECK-NEXT:    mtvsrd v0, r7
; CHECK-NEXT:    mtvsrd v1, r8
; CHECK-NEXT:    vmrghh v2, v3, v2
; CHECK-NEXT:    mtvsrd v3, r9
; CHECK-NEXT:    vmrghh v4, v5, v4
; CHECK-NEXT:    mtvsrd v5, r10
; CHECK-NEXT:    vmrghh v0, v1, v0
; CHECK-NEXT:    vmrghh v3, v5, v3
; CHECK-NEXT:    xxmrglw vs0, v4, v2
; CHECK-NEXT:    xxmrglw vs1, v3, v0
; CHECK-NEXT:    xxmrgld v2, vs1, vs0
; CHECK-NEXT:    blr
;
; CHECK-BE-LABEL: test8x24:
; CHECK-BE:       # %bb.0:
; CHECK-BE-NEXT:    sth r10, -16(r1)
; CHECK-BE-NEXT:    sth r9, -32(r1)
; CHECK-BE-NEXT:    sth r8, -48(r1)
; CHECK-BE-NEXT:    sth r7, -64(r1)
; CHECK-BE-NEXT:    sth r6, -80(r1)
; CHECK-BE-NEXT:    sth r5, -96(r1)
; CHECK-BE-NEXT:    sth r4, -112(r1)
; CHECK-BE-NEXT:    sth r3, -128(r1)
; CHECK-BE-NEXT:    addi r3, r1, -16
; CHECK-BE-NEXT:    lxvw4x v2, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -32
; CHECK-BE-NEXT:    lxvw4x v3, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -48
; CHECK-BE-NEXT:    lxvw4x v4, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -64
; CHECK-BE-NEXT:    lxvw4x v5, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -80
; CHECK-BE-NEXT:    lxvw4x v0, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -96
; CHECK-BE-NEXT:    lxvw4x v1, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -112
; CHECK-BE-NEXT:    lxvw4x v6, 0, r3
; CHECK-BE-NEXT:    addi r3, r1, -128
; CHECK-BE-NEXT:    lxvw4x v7, 0, r3
; CHECK-BE-NEXT:    vmrghh v2, v3, v2
; CHECK-BE-NEXT:    vmrghh v3, v5, v4
; CHECK-BE-NEXT:    vmrghh v4, v1, v0
; CHECK-BE-NEXT:    xxmrghw vs0, v3, v2
; CHECK-BE-NEXT:    vmrghh v5, v7, v6
; CHECK-BE-NEXT:    xxmrghw vs1, v5, v4
; CHECK-BE-NEXT:    xxmrghd v2, vs1, vs0
; CHECK-BE-NEXT:    blr
%i11 = trunc i32 %i1 to i24
%i21 = trunc i32 %i2 to i24
%i31 = trunc i32 %i3 to i24
%i41 = trunc i32 %i4 to i24
%i51 = trunc i32 %i5 to i24
%i61 = trunc i32 %i6 to i24
%i71 = trunc i32 %i7 to i24
%i81 = trunc i32 %i8 to i24
%v10 = insertelement <8 x i24> undef, i24 %i11, i32 0
%v11 = insertelement <8 x i24> %v10, i24 %i21, i32 1
%v12 = insertelement <8 x i24> %v11, i24 %i31, i32 2
%v13 = insertelement <8 x i24> %v12, i24 %i41, i32 3
%v14 = insertelement <8 x i24> %v13, i24 %i51, i32 4
%v15 = insertelement <8 x i24> %v14, i24 %i61, i32 5
%v16 = insertelement <8 x i24> %v15, i24 %i71, i32 6
%v17 = insertelement <8 x i24> %v16, i24 %i81, i32 7
%v2 = trunc <8 x i24> %v17 to <8 x i16>
ret <8 x i16> %v2
}
