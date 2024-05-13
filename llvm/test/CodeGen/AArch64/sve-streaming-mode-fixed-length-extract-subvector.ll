; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -force-streaming-compatible-sve < %s | FileCheck %s

target triple = "aarch64-unknown-linux-gnu"

; i1

define <4 x i1> @extract_subvector_v8i1(<8 x i1> %op) #0 {
; CHECK-LABEL: extract_subvector_v8i1:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub sp, sp, #16
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    mov z1.b, z0.b[7]
; CHECK-NEXT:    mov z2.b, z0.b[6]
; CHECK-NEXT:    fmov w8, s1
; CHECK-NEXT:    mov z1.b, z0.b[5]
; CHECK-NEXT:    mov z0.b, z0.b[4]
; CHECK-NEXT:    fmov w9, s2
; CHECK-NEXT:    fmov w10, s1
; CHECK-NEXT:    fmov w11, s0
; CHECK-NEXT:    strh w8, [sp, #14]
; CHECK-NEXT:    strh w9, [sp, #12]
; CHECK-NEXT:    strh w10, [sp, #10]
; CHECK-NEXT:    strh w11, [sp, #8]
; CHECK-NEXT:    ldr d0, [sp, #8]
; CHECK-NEXT:    add sp, sp, #16
; CHECK-NEXT:    ret
  %ret = call <4 x i1> @llvm.vector.extract.v4i1.v8i1(<8 x i1> %op, i64 4)
  ret <4 x i1> %ret
}

; i8

define <4 x i8> @extract_subvector_v8i8(<8 x i8> %op) #0 {
; CHECK-LABEL: extract_subvector_v8i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub sp, sp, #16
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    mov z1.b, z0.b[7]
; CHECK-NEXT:    mov z2.b, z0.b[6]
; CHECK-NEXT:    fmov w8, s1
; CHECK-NEXT:    mov z1.b, z0.b[5]
; CHECK-NEXT:    mov z0.b, z0.b[4]
; CHECK-NEXT:    fmov w9, s2
; CHECK-NEXT:    fmov w10, s1
; CHECK-NEXT:    fmov w11, s0
; CHECK-NEXT:    strh w8, [sp, #14]
; CHECK-NEXT:    strh w9, [sp, #12]
; CHECK-NEXT:    strh w10, [sp, #10]
; CHECK-NEXT:    strh w11, [sp, #8]
; CHECK-NEXT:    ldr d0, [sp, #8]
; CHECK-NEXT:    add sp, sp, #16
; CHECK-NEXT:    ret
  %ret = call <4 x i8> @llvm.vector.extract.v4i8.v8i8(<8 x i8> %op, i64 4)
  ret <4 x i8> %ret
}

define <8 x i8> @extract_subvector_v16i8(<16 x i8> %op) #0 {
; CHECK-LABEL: extract_subvector_v16i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <8 x i8> @llvm.vector.extract.v8i8.v16i8(<16 x i8> %op, i64 8)
  ret <8 x i8> %ret
}

define void @extract_subvector_v32i8(ptr %a, ptr %b) #0 {
; CHECK-LABEL: extract_subvector_v32i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    str q0, [x1]
; CHECK-NEXT:    ret
  %op = load <32 x i8>, ptr %a
  %ret = call <16 x i8> @llvm.vector.extract.v16i8.v32i8(<32 x i8> %op, i64 16)
  store <16 x i8> %ret, ptr %b
  ret void
}

; i16

define <2 x i16> @extract_subvector_v4i16(<4 x i16> %op) #0 {
; CHECK-LABEL: extract_subvector_v4i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    uunpklo z0.s, z0.h
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <2 x i16> @llvm.vector.extract.v2i16.v4i16(<4 x i16> %op, i64 2)
  ret <2 x i16> %ret
}

define <4 x i16> @extract_subvector_v8i16(<8 x i16> %op) #0 {
; CHECK-LABEL: extract_subvector_v8i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <4 x i16> @llvm.vector.extract.v4i16.v8i16(<8 x i16> %op, i64 4)
  ret <4 x i16> %ret
}

define void @extract_subvector_v16i16(ptr %a, ptr %b) #0 {
; CHECK-LABEL: extract_subvector_v16i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    str q0, [x1]
; CHECK-NEXT:    ret
  %op = load <16 x i16>, ptr %a
  %ret = call <8 x i16> @llvm.vector.extract.v8i16.v16i16(<16 x i16> %op, i64 8)
  store <8 x i16> %ret, ptr %b
  ret void
}

; i32

define <1 x i32> @extract_subvector_v2i32(<2 x i32> %op) #0 {
; CHECK-LABEL: extract_subvector_v2i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    mov z0.s, z0.s[1]
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <1 x i32> @llvm.vector.extract.v1i32.v2i32(<2 x i32> %op, i64 1)
  ret <1 x i32> %ret
}

define <2 x i32> @extract_subvector_v4i32(<4 x i32> %op) #0 {
; CHECK-LABEL: extract_subvector_v4i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <2 x i32> @llvm.vector.extract.v2i32.v4i32(<4 x i32> %op, i64 2)
  ret <2 x i32> %ret
}

define void @extract_subvector_v8i32(ptr %a, ptr %b) #0 {
; CHECK-LABEL: extract_subvector_v8i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    str q0, [x1]
; CHECK-NEXT:    ret
  %op = load <8 x i32>, ptr %a
  %ret = call <4 x i32> @llvm.vector.extract.v4i32.v8i32(<8 x i32> %op, i64 4)
  store <4 x i32> %ret, ptr %b
  ret void
}

; i64

define <1 x i64> @extract_subvector_v2i64(<2 x i64> %op) #0 {
; CHECK-LABEL: extract_subvector_v2i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <1 x i64> @llvm.vector.extract.v1i64.v2i64(<2 x i64> %op, i64 1)
  ret <1 x i64> %ret
}

define void @extract_subvector_v4i64(ptr %a, ptr %b) #0 {
; CHECK-LABEL: extract_subvector_v4i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    str q0, [x1]
; CHECK-NEXT:    ret
  %op = load <4 x i64>, ptr %a
  %ret = call <2 x i64> @llvm.vector.extract.v2i64.v4i64(<4 x i64> %op, i64 2)
  store <2 x i64> %ret, ptr %b
  ret void
}

; f16

define <2 x half> @extract_subvector_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: extract_subvector_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub sp, sp, #16
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    mov z1.h, z0.h[3]
; CHECK-NEXT:    mov z0.h, z0.h[2]
; CHECK-NEXT:    str h1, [sp, #10]
; CHECK-NEXT:    str h0, [sp, #8]
; CHECK-NEXT:    ldr d0, [sp, #8]
; CHECK-NEXT:    add sp, sp, #16
; CHECK-NEXT:    ret
  %ret = call <2 x half> @llvm.vector.extract.v2f16.v4f16(<4 x half> %op, i64 2)
  ret <2 x half> %ret
}

define <4 x half> @extract_subvector_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: extract_subvector_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <4 x half> @llvm.vector.extract.v4f16.v8f16(<8 x half> %op, i64 4)
  ret <4 x half> %ret
}

define void @extract_subvector_v16f16(ptr %a, ptr %b) #0 {
; CHECK-LABEL: extract_subvector_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    str q0, [x1]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %ret = call <8 x half> @llvm.vector.extract.v8f16.v16f16(<16 x half> %op, i64 8)
  store <8 x half> %ret, ptr %b
  ret void
}

; f32

define <1 x float> @extract_subvector_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: extract_subvector_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    mov z0.s, z0.s[1]
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <1 x float> @llvm.vector.extract.v1f32.v2f32(<2 x float> %op, i64 1)
  ret <1 x float> %ret
}

define <2 x float> @extract_subvector_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: extract_subvector_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <2 x float> @llvm.vector.extract.v2f32.v4f32(<4 x float> %op, i64 2)
  ret <2 x float> %ret
}

define void @extract_subvector_v8f32(ptr %a, ptr %b) #0 {
; CHECK-LABEL: extract_subvector_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    str q0, [x1]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %ret = call <4 x float> @llvm.vector.extract.v4f32.v8f32(<8 x float> %op, i64 4)
  store <4 x float> %ret, ptr %b
  ret void
}

; f64

define <1 x double> @extract_subvector_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: extract_subvector_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %ret = call <1 x double> @llvm.vector.extract.v1f64.v2f64(<2 x double> %op, i64 1)
  ret <1 x double> %ret
}

define void @extract_subvector_v4f64(ptr %a, ptr %b) #0 {
; CHECK-LABEL: extract_subvector_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    str q0, [x1]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %ret = call <2 x double> @llvm.vector.extract.v2f64.v4f64(<4 x double> %op, i64 2)
  store <2 x double> %ret, ptr %b
  ret void
}

declare <4 x i1> @llvm.vector.extract.v4i1.v8i1(<8 x i1>, i64)

declare <4 x i8> @llvm.vector.extract.v4i8.v8i8(<8 x i8>, i64)
declare <8 x i8> @llvm.vector.extract.v8i8.v16i8(<16 x i8>, i64)
declare <16 x i8> @llvm.vector.extract.v16i8.v32i8(<32 x i8>, i64)
declare <32 x i8> @llvm.vector.extract.v32i8.v64i8(<64 x i8>, i64)

declare <2 x i16> @llvm.vector.extract.v2i16.v4i16(<4 x i16>, i64)
declare <4 x i16> @llvm.vector.extract.v4i16.v8i16(<8 x i16>, i64)
declare <8 x i16> @llvm.vector.extract.v8i16.v16i16(<16 x i16>, i64)
declare <16 x i16> @llvm.vector.extract.v16i16.v32i16(<32 x i16>, i64)

declare <1 x i32> @llvm.vector.extract.v1i32.v2i32(<2 x i32>, i64)
declare <2 x i32> @llvm.vector.extract.v2i32.v4i32(<4 x i32>, i64)
declare <4 x i32> @llvm.vector.extract.v4i32.v8i32(<8 x i32>, i64)
declare <8 x i32> @llvm.vector.extract.v8i32.v16i32(<16 x i32>, i64)

declare <1 x i64> @llvm.vector.extract.v1i64.v2i64(<2 x i64>, i64)
declare <2 x i64> @llvm.vector.extract.v2i64.v4i64(<4 x i64>, i64)
declare <4 x i64> @llvm.vector.extract.v4i64.v8i64(<8 x i64>, i64)

declare <2 x half> @llvm.vector.extract.v2f16.v4f16(<4 x half>, i64)
declare <4 x half> @llvm.vector.extract.v4f16.v8f16(<8 x half>, i64)
declare <8 x half> @llvm.vector.extract.v8f16.v16f16(<16 x half>, i64)
declare <16 x half> @llvm.vector.extract.v16f16.v32f16(<32 x half>, i64)

declare <1 x float> @llvm.vector.extract.v1f32.v2f32(<2 x float>, i64)
declare <2 x float> @llvm.vector.extract.v2f32.v4f32(<4 x float>, i64)
declare <4 x float> @llvm.vector.extract.v4f32.v8f32(<8 x float>, i64)
declare <8 x float> @llvm.vector.extract.v8f32.v16f32(<16 x float>, i64)

declare <1 x double> @llvm.vector.extract.v1f64.v2f64(<2 x double>, i64)
declare <2 x double> @llvm.vector.extract.v2f64.v4f64(<4 x double>, i64)
declare <4 x double> @llvm.vector.extract.v4f64.v8f64(<8 x double>, i64)

attributes #0 = { "target-features"="+sve" }
