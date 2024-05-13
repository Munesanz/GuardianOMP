; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -force-streaming-compatible-sve < %s | FileCheck %s

target triple = "aarch64-unknown-linux-gnu"

define <8 x i16> @load_zext_v8i8i16(ptr %ap)  #0 {
; CHECK-LABEL: load_zext_v8i8i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    ld1b { z0.h }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %a = load <8 x i8>, ptr %ap
  %val = zext <8 x i8> %a to <8 x i16>
  ret <8 x i16> %val
}

define <4 x i32> @load_zext_v4i16i32(ptr %ap)  #0 {
; CHECK-LABEL: load_zext_v4i16i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    ld1h { z0.s }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %a = load <4 x i16>, ptr %ap
  %val = zext <4 x i16> %a to <4 x i32>
  ret <4 x i32> %val
}

define <2 x i64> @load_zext_v2i32i64(ptr %ap) #0 {
; CHECK-LABEL: load_zext_v2i32i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    ld1w { z0.d }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %a = load <2 x i32>, ptr %ap
  %val = zext <2 x i32> %a to <2 x i64>
  ret <2 x i64> %val
}

define <2 x i256> @load_zext_v2i64i256(ptr %ap) #0 {
; CHECK-LABEL: load_zext_v2i64i256:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov z0.d, #0 // =0x0
; CHECK-NEXT:    ldr q1, [x0]
; CHECK-NEXT:    mov z2.d, z0.d[1]
; CHECK-NEXT:    fmov x2, d0
; CHECK-NEXT:    fmov x3, d2
; CHECK-NEXT:    mov x1, xzr
; CHECK-NEXT:    mov z0.d, z1.d[1]
; CHECK-NEXT:    fmov x0, d1
; CHECK-NEXT:    fmov x4, d0
; CHECK-NEXT:    mov x5, xzr
; CHECK-NEXT:    mov x6, x2
; CHECK-NEXT:    mov x7, x3
; CHECK-NEXT:    ret
  %a = load <2 x i64>, ptr %ap
  %val = zext <2 x i64> %a to <2 x i256>
  ret <2 x i256> %val
}

define <16 x i32> @load_sext_v16i8i32(ptr %ap)  #0 {
; CHECK-LABEL: load_sext_v16i8i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #4 // =0x4
; CHECK-NEXT:    mov w9, #8 // =0x8
; CHECK-NEXT:    mov w10, #12 // =0xc
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    ld1sb { z1.s }, p0/z, [x0, x8]
; CHECK-NEXT:    ld1sb { z2.s }, p0/z, [x0, x9]
; CHECK-NEXT:    ld1sb { z3.s }, p0/z, [x0, x10]
; CHECK-NEXT:    ld1sb { z0.s }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    // kill: def $q1 killed $q1 killed $z1
; CHECK-NEXT:    // kill: def $q2 killed $q2 killed $z2
; CHECK-NEXT:    // kill: def $q3 killed $q3 killed $z3
; CHECK-NEXT:    ret
  %a = load <16 x i8>, ptr %ap
  %val = sext <16 x i8> %a to <16 x i32>
  ret <16 x i32> %val
}

define <8 x i32> @load_sext_v8i16i32(ptr %ap)  #0 {
; CHECK-LABEL: load_sext_v8i16i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov x8, #4 // =0x4
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    ld1sh { z1.s }, p0/z, [x0, x8, lsl #1]
; CHECK-NEXT:    ld1sh { z0.s }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    // kill: def $q1 killed $q1 killed $z1
; CHECK-NEXT:    ret
  %a = load <8 x i16>, ptr %ap
  %val = sext <8 x i16> %a to <8 x i32>
  ret <8 x i32> %val
}

define <4 x i256> @load_sext_v4i32i256(ptr %ap) #0 {
; CHECK-LABEL: load_sext_v4i32i256:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0]
; CHECK-NEXT:    sunpklo z1.d, z0.s
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    fmov x9, d1
; CHECK-NEXT:    sunpklo z0.d, z0.s
; CHECK-NEXT:    fmov x11, d0
; CHECK-NEXT:    mov z0.d, z0.d[1]
; CHECK-NEXT:    asr x10, x9, #63
; CHECK-NEXT:    asr x12, x11, #63
; CHECK-NEXT:    stp x9, x10, [x8]
; CHECK-NEXT:    fmov x9, d0
; CHECK-NEXT:    mov z0.d, z1.d[1]
; CHECK-NEXT:    stp x11, x12, [x8, #64]
; CHECK-NEXT:    fmov x11, d0
; CHECK-NEXT:    stp x10, x10, [x8, #16]
; CHECK-NEXT:    stp x12, x12, [x8, #80]
; CHECK-NEXT:    asr x10, x9, #63
; CHECK-NEXT:    asr x12, x11, #63
; CHECK-NEXT:    stp x10, x10, [x8, #112]
; CHECK-NEXT:    stp x9, x10, [x8, #96]
; CHECK-NEXT:    stp x12, x12, [x8, #48]
; CHECK-NEXT:    stp x11, x12, [x8, #32]
; CHECK-NEXT:    ret
  %a = load <4 x i32>, ptr %ap
  %val = sext <4 x i32> %a to <4 x i256>
  ret <4 x i256> %val
}

define <2 x i256> @load_sext_v2i64i256(ptr %ap) #0 {
; CHECK-LABEL: load_sext_v2i64i256:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0]
; CHECK-NEXT:    fmov x8, d0
; CHECK-NEXT:    mov z0.d, z0.d[1]
; CHECK-NEXT:    fmov x10, d0
; CHECK-NEXT:    asr x9, x8, #63
; CHECK-NEXT:    asr x11, x10, #63
; CHECK-NEXT:    stp x8, x9, [sp, #-32]!
; CHECK-NEXT:    .cfi_def_cfa_offset 32
; CHECK-NEXT:    mov z0.d, x9
; CHECK-NEXT:    stp x10, x11, [sp, #16]
; CHECK-NEXT:    mov z1.d, z0.d[1]
; CHECK-NEXT:    fmov x2, d0
; CHECK-NEXT:    mov z0.d, x11
; CHECK-NEXT:    fmov x3, d1
; CHECK-NEXT:    ldp q1, q3, [sp], #32
; CHECK-NEXT:    mov z2.d, z0.d[1]
; CHECK-NEXT:    fmov x6, d0
; CHECK-NEXT:    mov z0.d, z1.d[1]
; CHECK-NEXT:    fmov x0, d1
; CHECK-NEXT:    mov z1.d, z3.d[1]
; CHECK-NEXT:    fmov x7, d2
; CHECK-NEXT:    fmov x4, d3
; CHECK-NEXT:    fmov x1, d0
; CHECK-NEXT:    fmov x5, d1
; CHECK-NEXT:    ret
  %a = load <2 x i64>, ptr %ap
  %val = sext <2 x i64> %a to <2 x i256>
  ret <2 x i256> %val
}

define <16 x i64> @load_zext_v16i16i64(ptr %ap)  #0 {
; CHECK-LABEL: load_zext_v16i16i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov x8, #2 // =0x2
; CHECK-NEXT:    mov x9, #4 // =0x4
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    mov x10, #6 // =0x6
; CHECK-NEXT:    mov x11, #8 // =0x8
; CHECK-NEXT:    mov x12, #10 // =0xa
; CHECK-NEXT:    ld1h { z1.d }, p0/z, [x0, x8, lsl #1]
; CHECK-NEXT:    mov x8, #12 // =0xc
; CHECK-NEXT:    ld1h { z2.d }, p0/z, [x0, x9, lsl #1]
; CHECK-NEXT:    mov x9, #14 // =0xe
; CHECK-NEXT:    ld1h { z3.d }, p0/z, [x0, x10, lsl #1]
; CHECK-NEXT:    ld1h { z4.d }, p0/z, [x0, x11, lsl #1]
; CHECK-NEXT:    ld1h { z5.d }, p0/z, [x0, x12, lsl #1]
; CHECK-NEXT:    ld1h { z6.d }, p0/z, [x0, x8, lsl #1]
; CHECK-NEXT:    ld1h { z7.d }, p0/z, [x0, x9, lsl #1]
; CHECK-NEXT:    ld1h { z0.d }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    // kill: def $q1 killed $q1 killed $z1
; CHECK-NEXT:    // kill: def $q2 killed $q2 killed $z2
; CHECK-NEXT:    // kill: def $q3 killed $q3 killed $z3
; CHECK-NEXT:    // kill: def $q4 killed $q4 killed $z4
; CHECK-NEXT:    // kill: def $q5 killed $q5 killed $z5
; CHECK-NEXT:    // kill: def $q6 killed $q6 killed $z6
; CHECK-NEXT:    // kill: def $q7 killed $q7 killed $z7
; CHECK-NEXT:    ret
  %a = load <16 x i16>, ptr %ap
  %val = zext <16 x i16> %a to <16 x i64>
  ret <16 x i64> %val
}

attributes #0 = { "target-features"="+sve" }
