; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -force-streaming-compatible-sve < %s | FileCheck %s

target triple = "aarch64-unknown-linux-gnu"

;
; CEIL -> FRINTP
;

define <2 x half> @frintp_v2f16(<2 x half> %op) #0 {
; CHECK-LABEL: frintp_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintp z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x half> @llvm.ceil.v2f16(<2 x half> %op)
  ret <2 x half> %res
}

define <4 x half> @frintp_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: frintp_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintp z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x half> @llvm.ceil.v4f16(<4 x half> %op)
  ret <4 x half> %res
}

define <8 x half> @frintp_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: frintp_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintp z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <8 x half> @llvm.ceil.v8f16(<8 x half> %op)
  ret <8 x half> %res
}

define void @frintp_v16f16(ptr %a) #0 {
; CHECK-LABEL: frintp_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintp z0.h, p0/m, z0.h
; CHECK-NEXT:    frintp z1.h, p0/m, z1.h
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %res = call <16 x half> @llvm.ceil.v16f16(<16 x half> %op)
  store <16 x half> %res, ptr %a
  ret void
}

define <2 x float> @frintp_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: frintp_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    frintp z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x float> @llvm.ceil.v2f32(<2 x float> %op)
  ret <2 x float> %res
}

define <4 x float> @frintp_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: frintp_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintp z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x float> @llvm.ceil.v4f32(<4 x float> %op)
  ret <4 x float> %res
}

define void @frintp_v8f32(ptr %a) #0 {
; CHECK-LABEL: frintp_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintp z0.s, p0/m, z0.s
; CHECK-NEXT:    frintp z1.s, p0/m, z1.s
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %res = call <8 x float> @llvm.ceil.v8f32(<8 x float> %op)
  store <8 x float> %res, ptr %a
  ret void
}

define <1 x double> @frintp_v1f64(<1 x double> %op) #0 {
; CHECK-LABEL: frintp_v1f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    frintp d0, d0
; CHECK-NEXT:    ret
  %res = call <1 x double> @llvm.ceil.v1f64(<1 x double> %op)
  ret <1 x double> %res
}

define <2 x double> @frintp_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: frintp_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintp z0.d, p0/m, z0.d
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x double> @llvm.ceil.v2f64(<2 x double> %op)
  ret <2 x double> %res
}

define void @frintp_v4f64(ptr %a) #0 {
; CHECK-LABEL: frintp_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintp z0.d, p0/m, z0.d
; CHECK-NEXT:    frintp z1.d, p0/m, z1.d
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %res = call <4 x double> @llvm.ceil.v4f64(<4 x double> %op)
  store <4 x double> %res, ptr %a
  ret void
}

;
; FLOOR -> FRINTM
;

define <2 x half> @frintm_v2f16(<2 x half> %op) #0 {
; CHECK-LABEL: frintm_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintm z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x half> @llvm.floor.v2f16(<2 x half> %op)
  ret <2 x half> %res
}

define <4 x half> @frintm_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: frintm_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintm z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x half> @llvm.floor.v4f16(<4 x half> %op)
  ret <4 x half> %res
}

define <8 x half> @frintm_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: frintm_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintm z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <8 x half> @llvm.floor.v8f16(<8 x half> %op)
  ret <8 x half> %res
}

define void @frintm_v16f16(ptr %a) #0 {
; CHECK-LABEL: frintm_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintm z0.h, p0/m, z0.h
; CHECK-NEXT:    frintm z1.h, p0/m, z1.h
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %res = call <16 x half> @llvm.floor.v16f16(<16 x half> %op)
  store <16 x half> %res, ptr %a
  ret void
}

define <2 x float> @frintm_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: frintm_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    frintm z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x float> @llvm.floor.v2f32(<2 x float> %op)
  ret <2 x float> %res
}

define <4 x float> @frintm_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: frintm_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintm z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x float> @llvm.floor.v4f32(<4 x float> %op)
  ret <4 x float> %res
}

define void @frintm_v8f32(ptr %a) #0 {
; CHECK-LABEL: frintm_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintm z0.s, p0/m, z0.s
; CHECK-NEXT:    frintm z1.s, p0/m, z1.s
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %res = call <8 x float> @llvm.floor.v8f32(<8 x float> %op)
  store <8 x float> %res, ptr %a
  ret void
}

define <1 x double> @frintm_v1f64(<1 x double> %op) #0 {
; CHECK-LABEL: frintm_v1f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    frintm d0, d0
; CHECK-NEXT:    ret
  %res = call <1 x double> @llvm.floor.v1f64(<1 x double> %op)
  ret <1 x double> %res
}

define <2 x double> @frintm_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: frintm_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintm z0.d, p0/m, z0.d
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x double> @llvm.floor.v2f64(<2 x double> %op)
  ret <2 x double> %res
}

define void @frintm_v4f64(ptr %a) #0 {
; CHECK-LABEL: frintm_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintm z0.d, p0/m, z0.d
; CHECK-NEXT:    frintm z1.d, p0/m, z1.d
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %res = call <4 x double> @llvm.floor.v4f64(<4 x double> %op)
  store <4 x double> %res, ptr %a
  ret void
}

;
; FNEARBYINT -> FRINTI
;

define <2 x half> @frinti_v2f16(<2 x half> %op) #0 {
; CHECK-LABEL: frinti_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frinti z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x half> @llvm.nearbyint.v2f16(<2 x half> %op)
  ret <2 x half> %res
}

define <4 x half> @frinti_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: frinti_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frinti z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x half> @llvm.nearbyint.v4f16(<4 x half> %op)
  ret <4 x half> %res
}

define <8 x half> @frinti_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: frinti_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frinti z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <8 x half> @llvm.nearbyint.v8f16(<8 x half> %op)
  ret <8 x half> %res
}

define void @frinti_v16f16(ptr %a) #0 {
; CHECK-LABEL: frinti_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frinti z0.h, p0/m, z0.h
; CHECK-NEXT:    frinti z1.h, p0/m, z1.h
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %res = call <16 x half> @llvm.nearbyint.v16f16(<16 x half> %op)
  store <16 x half> %res, ptr %a
  ret void
}

define <2 x float> @frinti_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: frinti_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    frinti z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x float> @llvm.nearbyint.v2f32(<2 x float> %op)
  ret <2 x float> %res
}

define <4 x float> @frinti_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: frinti_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frinti z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x float> @llvm.nearbyint.v4f32(<4 x float> %op)
  ret <4 x float> %res
}

define void @frinti_v8f32(ptr %a) #0 {
; CHECK-LABEL: frinti_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frinti z0.s, p0/m, z0.s
; CHECK-NEXT:    frinti z1.s, p0/m, z1.s
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %res = call <8 x float> @llvm.nearbyint.v8f32(<8 x float> %op)
  store <8 x float> %res, ptr %a
  ret void
}

define <1 x double> @frinti_v1f64(<1 x double> %op) #0 {
; CHECK-LABEL: frinti_v1f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    frinti d0, d0
; CHECK-NEXT:    ret
  %res = call <1 x double> @llvm.nearbyint.v1f64(<1 x double> %op)
  ret <1 x double> %res
}

define <2 x double> @frinti_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: frinti_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frinti z0.d, p0/m, z0.d
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x double> @llvm.nearbyint.v2f64(<2 x double> %op)
  ret <2 x double> %res
}

define void @frinti_v4f64(ptr %a) #0 {
; CHECK-LABEL: frinti_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frinti z0.d, p0/m, z0.d
; CHECK-NEXT:    frinti z1.d, p0/m, z1.d
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %res = call <4 x double> @llvm.nearbyint.v4f64(<4 x double> %op)
  store <4 x double> %res, ptr %a
  ret void
}

;
; RINT -> FRINTX
;

define <2 x half> @frintx_v2f16(<2 x half> %op) #0 {
; CHECK-LABEL: frintx_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintx z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x half> @llvm.rint.v2f16(<2 x half> %op)
  ret <2 x half> %res
}

define <4 x half> @frintx_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: frintx_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintx z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x half> @llvm.rint.v4f16(<4 x half> %op)
  ret <4 x half> %res
}

define <8 x half> @frintx_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: frintx_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintx z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <8 x half> @llvm.rint.v8f16(<8 x half> %op)
  ret <8 x half> %res
}

define void @frintx_v16f16(ptr %a) #0 {
; CHECK-LABEL: frintx_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintx z0.h, p0/m, z0.h
; CHECK-NEXT:    frintx z1.h, p0/m, z1.h
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %res = call <16 x half> @llvm.rint.v16f16(<16 x half> %op)
  store <16 x half> %res, ptr %a
  ret void
}

define <2 x float> @frintx_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: frintx_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    frintx z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x float> @llvm.rint.v2f32(<2 x float> %op)
  ret <2 x float> %res
}

define <4 x float> @frintx_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: frintx_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintx z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x float> @llvm.rint.v4f32(<4 x float> %op)
  ret <4 x float> %res
}

define void @frintx_v8f32(ptr %a) #0 {
; CHECK-LABEL: frintx_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintx z0.s, p0/m, z0.s
; CHECK-NEXT:    frintx z1.s, p0/m, z1.s
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %res = call <8 x float> @llvm.rint.v8f32(<8 x float> %op)
  store <8 x float> %res, ptr %a
  ret void
}

define <1 x double> @frintx_v1f64(<1 x double> %op) #0 {
; CHECK-LABEL: frintx_v1f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    frintx d0, d0
; CHECK-NEXT:    ret
  %res = call <1 x double> @llvm.rint.v1f64(<1 x double> %op)
  ret <1 x double> %res
}

define <2 x double> @frintx_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: frintx_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintx z0.d, p0/m, z0.d
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x double> @llvm.rint.v2f64(<2 x double> %op)
  ret <2 x double> %res
}

define void @frintx_v4f64(ptr %a) #0 {
; CHECK-LABEL: frintx_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintx z0.d, p0/m, z0.d
; CHECK-NEXT:    frintx z1.d, p0/m, z1.d
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %res = call <4 x double> @llvm.rint.v4f64(<4 x double> %op)
  store <4 x double> %res, ptr %a
  ret void
}

;
; ROUND -> FRINTA
;

define <2 x half> @frinta_v2f16(<2 x half> %op) #0 {
; CHECK-LABEL: frinta_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frinta z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x half> @llvm.round.v2f16(<2 x half> %op)
  ret <2 x half> %res
}

define <4 x half> @frinta_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: frinta_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frinta z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x half> @llvm.round.v4f16(<4 x half> %op)
  ret <4 x half> %res
}

define <8 x half> @frinta_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: frinta_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frinta z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <8 x half> @llvm.round.v8f16(<8 x half> %op)
  ret <8 x half> %res
}

define void @frinta_v16f16(ptr %a) #0 {
; CHECK-LABEL: frinta_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frinta z0.h, p0/m, z0.h
; CHECK-NEXT:    frinta z1.h, p0/m, z1.h
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %res = call <16 x half> @llvm.round.v16f16(<16 x half> %op)
  store <16 x half> %res, ptr %a
  ret void
}

define <2 x float> @frinta_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: frinta_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    frinta z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x float> @llvm.round.v2f32(<2 x float> %op)
  ret <2 x float> %res
}

define <4 x float> @frinta_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: frinta_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frinta z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x float> @llvm.round.v4f32(<4 x float> %op)
  ret <4 x float> %res
}

define void @frinta_v8f32(ptr %a) #0 {
; CHECK-LABEL: frinta_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frinta z0.s, p0/m, z0.s
; CHECK-NEXT:    frinta z1.s, p0/m, z1.s
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %res = call <8 x float> @llvm.round.v8f32(<8 x float> %op)
  store <8 x float> %res, ptr %a
  ret void
}

define <1 x double> @frinta_v1f64(<1 x double> %op) #0 {
; CHECK-LABEL: frinta_v1f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    frinta d0, d0
; CHECK-NEXT:    ret
  %res = call <1 x double> @llvm.round.v1f64(<1 x double> %op)
  ret <1 x double> %res
}

define <2 x double> @frinta_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: frinta_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frinta z0.d, p0/m, z0.d
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x double> @llvm.round.v2f64(<2 x double> %op)
  ret <2 x double> %res
}

define void @frinta_v4f64(ptr %a) #0 {
; CHECK-LABEL: frinta_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frinta z0.d, p0/m, z0.d
; CHECK-NEXT:    frinta z1.d, p0/m, z1.d
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %res = call <4 x double> @llvm.round.v4f64(<4 x double> %op)
  store <4 x double> %res, ptr %a
  ret void
}

;
; ROUNDEVEN -> FRINTN
;

define <2 x half> @frintn_v2f16(<2 x half> %op) #0 {
; CHECK-LABEL: frintn_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintn z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x half> @llvm.roundeven.v2f16(<2 x half> %op)
  ret <2 x half> %res
}

define <4 x half> @frintn_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: frintn_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintn z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x half> @llvm.roundeven.v4f16(<4 x half> %op)
  ret <4 x half> %res
}

define <8 x half> @frintn_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: frintn_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintn z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <8 x half> @llvm.roundeven.v8f16(<8 x half> %op)
  ret <8 x half> %res
}

define void @frintn_v16f16(ptr %a) #0 {
; CHECK-LABEL: frintn_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintn z0.h, p0/m, z0.h
; CHECK-NEXT:    frintn z1.h, p0/m, z1.h
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %res = call <16 x half> @llvm.roundeven.v16f16(<16 x half> %op)
  store <16 x half> %res, ptr %a
  ret void
}

define <2 x float> @frintn_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: frintn_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    frintn z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x float> @llvm.roundeven.v2f32(<2 x float> %op)
  ret <2 x float> %res
}

define <4 x float> @frintn_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: frintn_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintn z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x float> @llvm.roundeven.v4f32(<4 x float> %op)
  ret <4 x float> %res
}

define void @frintn_v8f32(ptr %a) #0 {
; CHECK-LABEL: frintn_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintn z0.s, p0/m, z0.s
; CHECK-NEXT:    frintn z1.s, p0/m, z1.s
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %res = call <8 x float> @llvm.roundeven.v8f32(<8 x float> %op)
  store <8 x float> %res, ptr %a
  ret void
}

define <1 x double> @frintn_v1f64(<1 x double> %op) #0 {
; CHECK-LABEL: frintn_v1f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    frintn d0, d0
; CHECK-NEXT:    ret
  %res = call <1 x double> @llvm.roundeven.v1f64(<1 x double> %op)
  ret <1 x double> %res
}

define <2 x double> @frintn_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: frintn_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintn z0.d, p0/m, z0.d
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x double> @llvm.roundeven.v2f64(<2 x double> %op)
  ret <2 x double> %res
}

define void @frintn_v4f64(ptr %a) #0 {
; CHECK-LABEL: frintn_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintn z0.d, p0/m, z0.d
; CHECK-NEXT:    frintn z1.d, p0/m, z1.d
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %res = call <4 x double> @llvm.roundeven.v4f64(<4 x double> %op)
  store <4 x double> %res, ptr %a
  ret void
}

;
; TRUNC -> FRINTZ
;

define <2 x half> @frintz_v2f16(<2 x half> %op) #0 {
; CHECK-LABEL: frintz_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintz z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x half> @llvm.trunc.v2f16(<2 x half> %op)
  ret <2 x half> %res
}

define <4 x half> @frintz_v4f16(<4 x half> %op) #0 {
; CHECK-LABEL: frintz_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    frintz z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x half> @llvm.trunc.v4f16(<4 x half> %op)
  ret <4 x half> %res
}

define <8 x half> @frintz_v8f16(<8 x half> %op) #0 {
; CHECK-LABEL: frintz_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintz z0.h, p0/m, z0.h
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <8 x half> @llvm.trunc.v8f16(<8 x half> %op)
  ret <8 x half> %res
}

define void @frintz_v16f16(ptr %a) #0 {
; CHECK-LABEL: frintz_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    frintz z0.h, p0/m, z0.h
; CHECK-NEXT:    frintz z1.h, p0/m, z1.h
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <16 x half>, ptr %a
  %res = call <16 x half> @llvm.trunc.v16f16(<16 x half> %op)
  store <16 x half> %res, ptr %a
  ret void
}

define <2 x float> @frintz_v2f32(<2 x float> %op) #0 {
; CHECK-LABEL: frintz_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    frintz z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x float> @llvm.trunc.v2f32(<2 x float> %op)
  ret <2 x float> %res
}

define <4 x float> @frintz_v4f32(<4 x float> %op) #0 {
; CHECK-LABEL: frintz_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintz z0.s, p0/m, z0.s
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <4 x float> @llvm.trunc.v4f32(<4 x float> %op)
  ret <4 x float> %res
}

define void @frintz_v8f32(ptr %a) #0 {
; CHECK-LABEL: frintz_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    frintz z0.s, p0/m, z0.s
; CHECK-NEXT:    frintz z1.s, p0/m, z1.s
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <8 x float>, ptr %a
  %res = call <8 x float> @llvm.trunc.v8f32(<8 x float> %op)
  store <8 x float> %res, ptr %a
  ret void
}

define <1 x double> @frintz_v1f64(<1 x double> %op) #0 {
; CHECK-LABEL: frintz_v1f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    frintz d0, d0
; CHECK-NEXT:    ret
  %res = call <1 x double> @llvm.trunc.v1f64(<1 x double> %op)
  ret <1 x double> %res
}

define <2 x double> @frintz_v2f64(<2 x double> %op) #0 {
; CHECK-LABEL: frintz_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintz z0.d, p0/m, z0.d
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %res = call <2 x double> @llvm.trunc.v2f64(<2 x double> %op)
  ret <2 x double> %res
}

define void @frintz_v4f64(ptr %a) #0 {
; CHECK-LABEL: frintz_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    frintz z0.d, p0/m, z0.d
; CHECK-NEXT:    frintz z1.d, p0/m, z1.d
; CHECK-NEXT:    stp q0, q1, [x0]
; CHECK-NEXT:    ret
  %op = load <4 x double>, ptr %a
  %res = call <4 x double> @llvm.trunc.v4f64(<4 x double> %op)
  store <4 x double> %res, ptr %a
  ret void
}

attributes #0 = { "target-features"="+sve" }

declare <2 x half> @llvm.ceil.v2f16(<2 x half>)
declare <4 x half> @llvm.ceil.v4f16(<4 x half>)
declare <8 x half> @llvm.ceil.v8f16(<8 x half>)
declare <16 x half> @llvm.ceil.v16f16(<16 x half>)
declare <32 x half> @llvm.ceil.v32f16(<32 x half>)
declare <64 x half> @llvm.ceil.v64f16(<64 x half>)
declare <128 x half> @llvm.ceil.v128f16(<128 x half>)
declare <2 x float> @llvm.ceil.v2f32(<2 x float>)
declare <4 x float> @llvm.ceil.v4f32(<4 x float>)
declare <8 x float> @llvm.ceil.v8f32(<8 x float>)
declare <16 x float> @llvm.ceil.v16f32(<16 x float>)
declare <32 x float> @llvm.ceil.v32f32(<32 x float>)
declare <64 x float> @llvm.ceil.v64f32(<64 x float>)
declare <1 x double> @llvm.ceil.v1f64(<1 x double>)
declare <2 x double> @llvm.ceil.v2f64(<2 x double>)
declare <4 x double> @llvm.ceil.v4f64(<4 x double>)
declare <8 x double> @llvm.ceil.v8f64(<8 x double>)
declare <16 x double> @llvm.ceil.v16f64(<16 x double>)
declare <32 x double> @llvm.ceil.v32f64(<32 x double>)

declare <2 x half> @llvm.floor.v2f16(<2 x half>)
declare <4 x half> @llvm.floor.v4f16(<4 x half>)
declare <8 x half> @llvm.floor.v8f16(<8 x half>)
declare <16 x half> @llvm.floor.v16f16(<16 x half>)
declare <32 x half> @llvm.floor.v32f16(<32 x half>)
declare <64 x half> @llvm.floor.v64f16(<64 x half>)
declare <128 x half> @llvm.floor.v128f16(<128 x half>)
declare <2 x float> @llvm.floor.v2f32(<2 x float>)
declare <4 x float> @llvm.floor.v4f32(<4 x float>)
declare <8 x float> @llvm.floor.v8f32(<8 x float>)
declare <16 x float> @llvm.floor.v16f32(<16 x float>)
declare <32 x float> @llvm.floor.v32f32(<32 x float>)
declare <64 x float> @llvm.floor.v64f32(<64 x float>)
declare <1 x double> @llvm.floor.v1f64(<1 x double>)
declare <2 x double> @llvm.floor.v2f64(<2 x double>)
declare <4 x double> @llvm.floor.v4f64(<4 x double>)
declare <8 x double> @llvm.floor.v8f64(<8 x double>)
declare <16 x double> @llvm.floor.v16f64(<16 x double>)
declare <32 x double> @llvm.floor.v32f64(<32 x double>)

declare <2 x half> @llvm.nearbyint.v2f16(<2 x half>)
declare <4 x half> @llvm.nearbyint.v4f16(<4 x half>)
declare <8 x half> @llvm.nearbyint.v8f16(<8 x half>)
declare <16 x half> @llvm.nearbyint.v16f16(<16 x half>)
declare <32 x half> @llvm.nearbyint.v32f16(<32 x half>)
declare <64 x half> @llvm.nearbyint.v64f16(<64 x half>)
declare <128 x half> @llvm.nearbyint.v128f16(<128 x half>)
declare <2 x float> @llvm.nearbyint.v2f32(<2 x float>)
declare <4 x float> @llvm.nearbyint.v4f32(<4 x float>)
declare <8 x float> @llvm.nearbyint.v8f32(<8 x float>)
declare <16 x float> @llvm.nearbyint.v16f32(<16 x float>)
declare <32 x float> @llvm.nearbyint.v32f32(<32 x float>)
declare <64 x float> @llvm.nearbyint.v64f32(<64 x float>)
declare <1 x double> @llvm.nearbyint.v1f64(<1 x double>)
declare <2 x double> @llvm.nearbyint.v2f64(<2 x double>)
declare <4 x double> @llvm.nearbyint.v4f64(<4 x double>)
declare <8 x double> @llvm.nearbyint.v8f64(<8 x double>)
declare <16 x double> @llvm.nearbyint.v16f64(<16 x double>)
declare <32 x double> @llvm.nearbyint.v32f64(<32 x double>)

declare <2 x half> @llvm.rint.v2f16(<2 x half>)
declare <4 x half> @llvm.rint.v4f16(<4 x half>)
declare <8 x half> @llvm.rint.v8f16(<8 x half>)
declare <16 x half> @llvm.rint.v16f16(<16 x half>)
declare <32 x half> @llvm.rint.v32f16(<32 x half>)
declare <64 x half> @llvm.rint.v64f16(<64 x half>)
declare <128 x half> @llvm.rint.v128f16(<128 x half>)
declare <2 x float> @llvm.rint.v2f32(<2 x float>)
declare <4 x float> @llvm.rint.v4f32(<4 x float>)
declare <8 x float> @llvm.rint.v8f32(<8 x float>)
declare <16 x float> @llvm.rint.v16f32(<16 x float>)
declare <32 x float> @llvm.rint.v32f32(<32 x float>)
declare <64 x float> @llvm.rint.v64f32(<64 x float>)
declare <1 x double> @llvm.rint.v1f64(<1 x double>)
declare <2 x double> @llvm.rint.v2f64(<2 x double>)
declare <4 x double> @llvm.rint.v4f64(<4 x double>)
declare <8 x double> @llvm.rint.v8f64(<8 x double>)
declare <16 x double> @llvm.rint.v16f64(<16 x double>)
declare <32 x double> @llvm.rint.v32f64(<32 x double>)

declare <2 x half> @llvm.round.v2f16(<2 x half>)
declare <4 x half> @llvm.round.v4f16(<4 x half>)
declare <8 x half> @llvm.round.v8f16(<8 x half>)
declare <16 x half> @llvm.round.v16f16(<16 x half>)
declare <32 x half> @llvm.round.v32f16(<32 x half>)
declare <64 x half> @llvm.round.v64f16(<64 x half>)
declare <128 x half> @llvm.round.v128f16(<128 x half>)
declare <2 x float> @llvm.round.v2f32(<2 x float>)
declare <4 x float> @llvm.round.v4f32(<4 x float>)
declare <8 x float> @llvm.round.v8f32(<8 x float>)
declare <16 x float> @llvm.round.v16f32(<16 x float>)
declare <32 x float> @llvm.round.v32f32(<32 x float>)
declare <64 x float> @llvm.round.v64f32(<64 x float>)
declare <1 x double> @llvm.round.v1f64(<1 x double>)
declare <2 x double> @llvm.round.v2f64(<2 x double>)
declare <4 x double> @llvm.round.v4f64(<4 x double>)
declare <8 x double> @llvm.round.v8f64(<8 x double>)
declare <16 x double> @llvm.round.v16f64(<16 x double>)
declare <32 x double> @llvm.round.v32f64(<32 x double>)

declare <2 x half> @llvm.roundeven.v2f16(<2 x half>)
declare <4 x half> @llvm.roundeven.v4f16(<4 x half>)
declare <8 x half> @llvm.roundeven.v8f16(<8 x half>)
declare <16 x half> @llvm.roundeven.v16f16(<16 x half>)
declare <32 x half> @llvm.roundeven.v32f16(<32 x half>)
declare <64 x half> @llvm.roundeven.v64f16(<64 x half>)
declare <128 x half> @llvm.roundeven.v128f16(<128 x half>)
declare <2 x float> @llvm.roundeven.v2f32(<2 x float>)
declare <4 x float> @llvm.roundeven.v4f32(<4 x float>)
declare <8 x float> @llvm.roundeven.v8f32(<8 x float>)
declare <16 x float> @llvm.roundeven.v16f32(<16 x float>)
declare <32 x float> @llvm.roundeven.v32f32(<32 x float>)
declare <64 x float> @llvm.roundeven.v64f32(<64 x float>)
declare <1 x double> @llvm.roundeven.v1f64(<1 x double>)
declare <2 x double> @llvm.roundeven.v2f64(<2 x double>)
declare <4 x double> @llvm.roundeven.v4f64(<4 x double>)
declare <8 x double> @llvm.roundeven.v8f64(<8 x double>)
declare <16 x double> @llvm.roundeven.v16f64(<16 x double>)
declare <32 x double> @llvm.roundeven.v32f64(<32 x double>)

declare <2 x half> @llvm.trunc.v2f16(<2 x half>)
declare <4 x half> @llvm.trunc.v4f16(<4 x half>)
declare <8 x half> @llvm.trunc.v8f16(<8 x half>)
declare <16 x half> @llvm.trunc.v16f16(<16 x half>)
declare <32 x half> @llvm.trunc.v32f16(<32 x half>)
declare <64 x half> @llvm.trunc.v64f16(<64 x half>)
declare <128 x half> @llvm.trunc.v128f16(<128 x half>)
declare <2 x float> @llvm.trunc.v2f32(<2 x float>)
declare <4 x float> @llvm.trunc.v4f32(<4 x float>)
declare <8 x float> @llvm.trunc.v8f32(<8 x float>)
declare <16 x float> @llvm.trunc.v16f32(<16 x float>)
declare <32 x float> @llvm.trunc.v32f32(<32 x float>)
declare <64 x float> @llvm.trunc.v64f32(<64 x float>)
declare <1 x double> @llvm.trunc.v1f64(<1 x double>)
declare <2 x double> @llvm.trunc.v2f64(<2 x double>)
declare <4 x double> @llvm.trunc.v4f64(<4 x double>)
declare <8 x double> @llvm.trunc.v8f64(<8 x double>)
declare <16 x double> @llvm.trunc.v16f64(<16 x double>)
declare <32 x double> @llvm.trunc.v32f64(<32 x double>)
