; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=arm64-eabi < %s | FileCheck %s

define float @fma32(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fma32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmadd s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %0 = tail call float @llvm.fma.f32(float %a, float %b, float %c)
  ret float %0
}

define float @fnma32(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fnma32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmadd s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %0 = tail call float @llvm.fma.f32(float %a, float %b, float %c)
  %mul = fmul float %0, -1.000000e+00
  ret float %mul
}

define float @fms32(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fms32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %mul = fmul float %b, -1.000000e+00
  %0 = tail call float @llvm.fma.f32(float %a, float %mul, float %c)
  ret float %0
}

define float @fms32_com(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fms32_com:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub s0, s1, s0, s2
; CHECK-NEXT:    ret
entry:
  %mul = fmul float %b, -1.000000e+00
  %0 = tail call float @llvm.fma.f32(float %mul, float %a, float %c)
  ret float %0
}

define float @fnms32(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fnms32:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmsub s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %mul = fmul float %c, -1.000000e+00
  %0 = tail call float @llvm.fma.f32(float %a, float %b, float %mul)
  ret float %0
}

define double @fma64(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fma64:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmadd d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %0 = tail call double @llvm.fma.f64(double %a, double %b, double %c)
  ret double %0
}

define double @fnma64(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fnma64:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmadd d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %0 = tail call double @llvm.fma.f64(double %a, double %b, double %c)
  %mul = fmul double %0, -1.000000e+00
  ret double %mul
}

define double @fms64(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fms64:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %mul = fneg double %b
  %0 = tail call double @llvm.fma.f64(double %a, double %mul, double %c)
  ret double %0
}

define double @fms64_com(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fms64_com:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub d0, d1, d0, d2
; CHECK-NEXT:    ret
entry:
  %mul = fneg double %b
  %0 = tail call double @llvm.fma.f64(double %mul, double %a, double %c)
  ret double %0
}

define double @fnms64(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fnms64:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmsub d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %mul = fneg double %c
  %0 = tail call double @llvm.fma.f64(double %a, double %b, double %mul)
  ret double %0
}

define float @fma32_strict(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fma32_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmadd s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %0 = tail call float @llvm.experimental.constrained.fma.f32(float %a, float %b, float %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret float %0
}

define float @fnma32_strict(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fnma32_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmadd s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %0 = tail call float @llvm.experimental.constrained.fma.f32(float %a, float %b, float %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  %neg = fneg float %0
  ret float %neg
}

define float @fms32_strict(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fms32_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %neg = fneg float %b
  %0 = tail call float @llvm.experimental.constrained.fma.f32(float %a, float %neg, float %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret float %0
}

define float @fms32_com_strict(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fms32_com_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %neg = fneg float %b
  %0 = tail call float @llvm.experimental.constrained.fma.f32(float %neg, float %a, float %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret float %0
}

define float @fnms32_strict(float %a, float %b, float %c) nounwind readnone ssp {
; CHECK-LABEL: fnms32_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmsub s0, s0, s1, s2
; CHECK-NEXT:    ret
entry:
  %neg = fneg float %c
  %0 = tail call float @llvm.experimental.constrained.fma.f32(float %a, float %b, float %neg, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret float %0
}

define double @fma64_strict(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fma64_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmadd d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %0 = tail call double @llvm.experimental.constrained.fma.f64(double %a, double %b, double %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret double %0
}

define double @fnma64_strict(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fnma64_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmadd d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %0 = tail call double @llvm.experimental.constrained.fma.f64(double %a, double %b, double %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  %neg = fneg double %0
  ret double %neg
}

define double @fms64_strict(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fms64_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %neg = fneg double %b
  %0 = tail call double @llvm.experimental.constrained.fma.f64(double %a, double %neg, double %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret double %0
}

define double @fms64_com_strict(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fms64_com_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fmsub d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %neg = fneg double %b
  %0 = tail call double @llvm.experimental.constrained.fma.f64(double %neg, double %a, double %c, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret double %0
}

define double @fnms64_strict(double %a, double %b, double %c) nounwind readnone ssp {
; CHECK-LABEL: fnms64_strict:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    fnmsub d0, d0, d1, d2
; CHECK-NEXT:    ret
entry:
  %neg = fneg double %c
  %0 = tail call double @llvm.experimental.constrained.fma.f64(double %a, double %b, double %neg, metadata !"round.tonearest", metadata !"fpexcept.strict") #0
  ret double %0
}

; This would crash while trying getNegatedExpression().

define float @negated_constant(float %x) {
; CHECK-LABEL: negated_constant:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #-1037565952
; CHECK-NEXT:    fmov s1, w8
; CHECK-NEXT:    mov w8, #1109917696
; CHECK-NEXT:    fmul s1, s0, s1
; CHECK-NEXT:    fmov s2, w8
; CHECK-NEXT:    fmadd s0, s0, s2, s1
; CHECK-NEXT:    ret
  %m = fmul float %x, 42.0
  %fma = call nsz float @llvm.fma.f32(float %x, float -42.0, float %m)
  %nfma = fneg float %fma
  ret float %nfma
}

attributes #0 = { strictfp }

declare float @llvm.fma.f32(float, float, float) nounwind readnone
declare double @llvm.fma.f64(double, double, double) nounwind readnone
declare float @llvm.experimental.constrained.fma.f32(float, float, float, metadata, metadata)
declare double @llvm.experimental.constrained.fma.f64(double, double, double, metadata, metadata)
