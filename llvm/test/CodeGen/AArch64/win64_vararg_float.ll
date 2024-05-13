; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=aarch64-windows -verify-machineinstrs | FileCheck %s --check-prefixes=DAGISEL
; RUN: llc < %s -mtriple=aarch64-windows -verify-machineinstrs -O0 -fast-isel | FileCheck %s --check-prefixes=O0,FASTISEL
; RUN: llc < %s -mtriple=aarch64-windows -verify-machineinstrs -O0 -global-isel | FileCheck %s --check-prefixes=O0,GISEL

define void @float_va_fn(float %a, i32 %b, ...) nounwind {
; DAGISEL-LABEL: float_va_fn:
; DAGISEL:       // %bb.0: // %entry
; DAGISEL-NEXT:    str x30, [sp, #-64]! // 8-byte Folded Spill
; DAGISEL-NEXT:    add x8, sp, #16
; DAGISEL-NEXT:    fmov s0, w0
; DAGISEL-NEXT:    add x0, sp, #16
; DAGISEL-NEXT:    stp x3, x4, [sp, #24]
; DAGISEL-NEXT:    stp x5, x6, [sp, #40]
; DAGISEL-NEXT:    stp x8, x2, [sp, #8]
; DAGISEL-NEXT:    str x7, [sp, #56]
; DAGISEL-NEXT:    bl f_va_list
; DAGISEL-NEXT:    ldr x30, [sp], #64 // 8-byte Folded Reload
; DAGISEL-NEXT:    ret
;
; O0-LABEL: float_va_fn:
; O0:       // %bb.0: // %entry
; O0-NEXT:    sub sp, sp, #80
; O0-NEXT:    str x30, [sp, #16] // 8-byte Folded Spill
; O0-NEXT:    str x7, [sp, #72]
; O0-NEXT:    str x6, [sp, #64]
; O0-NEXT:    str x5, [sp, #56]
; O0-NEXT:    str x4, [sp, #48]
; O0-NEXT:    str x3, [sp, #40]
; O0-NEXT:    str x2, [sp, #32]
; O0-NEXT:    fmov s0, w0
; O0-NEXT:    add x8, sp, #32
; O0-NEXT:    str x8, [sp, #8]
; O0-NEXT:    ldr x0, [sp, #8]
; O0-NEXT:    bl f_va_list
; O0-NEXT:    ldr x30, [sp, #16] // 8-byte Folded Reload
; O0-NEXT:    add sp, sp, #80
; O0-NEXT:    ret
entry:
  %ap = alloca ptr, align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %ap)
  call void @llvm.va_start(ptr nonnull %ap)
  %0 = load ptr, ptr %ap, align 8
  call void @f_va_list(float %a, ptr %0)
  call void @llvm.va_end(ptr nonnull %ap)
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %ap)
  ret void
}

declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture)
declare void @llvm.va_start(ptr)
declare void @f_va_list(float, ptr)
declare void @llvm.va_end(ptr)
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture)

define void @double_va_fn(double %a, i32 %b, ...) nounwind {
; DAGISEL-LABEL: double_va_fn:
; DAGISEL:       // %bb.0: // %entry
; DAGISEL-NEXT:    str x30, [sp, #-64]! // 8-byte Folded Spill
; DAGISEL-NEXT:    add x8, sp, #16
; DAGISEL-NEXT:    fmov d0, x0
; DAGISEL-NEXT:    add x0, sp, #16
; DAGISEL-NEXT:    stp x3, x4, [sp, #24]
; DAGISEL-NEXT:    stp x5, x6, [sp, #40]
; DAGISEL-NEXT:    stp x8, x2, [sp, #8]
; DAGISEL-NEXT:    str x7, [sp, #56]
; DAGISEL-NEXT:    bl d_va_list
; DAGISEL-NEXT:    ldr x30, [sp], #64 // 8-byte Folded Reload
; DAGISEL-NEXT:    ret
;
; O0-LABEL: double_va_fn:
; O0:       // %bb.0: // %entry
; O0-NEXT:    sub sp, sp, #80
; O0-NEXT:    str x30, [sp, #16] // 8-byte Folded Spill
; O0-NEXT:    str x7, [sp, #72]
; O0-NEXT:    str x6, [sp, #64]
; O0-NEXT:    str x5, [sp, #56]
; O0-NEXT:    str x4, [sp, #48]
; O0-NEXT:    str x3, [sp, #40]
; O0-NEXT:    str x2, [sp, #32]
; O0-NEXT:    fmov d0, x0
; O0-NEXT:    add x8, sp, #32
; O0-NEXT:    str x8, [sp, #8]
; O0-NEXT:    ldr x0, [sp, #8]
; O0-NEXT:    bl d_va_list
; O0-NEXT:    ldr x30, [sp, #16] // 8-byte Folded Reload
; O0-NEXT:    add sp, sp, #80
; O0-NEXT:    ret
entry:
  %ap = alloca ptr, align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %ap)
  call void @llvm.va_start(ptr nonnull %ap)
  %0 = load ptr, ptr %ap, align 8
  call void @d_va_list(double %a, ptr %0)
  call void @llvm.va_end(ptr nonnull %ap)
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %ap)
  ret void
}

declare void @d_va_list(double, ptr)

define void @call_f_va() nounwind {
; DAGISEL-LABEL: call_f_va:
; DAGISEL:       // %bb.0: // %entry
; DAGISEL-NEXT:    mov w0, #1065353216
; DAGISEL-NEXT:    mov w1, #2
; DAGISEL-NEXT:    mov x2, #4613937818241073152
; DAGISEL-NEXT:    mov w3, #4
; DAGISEL-NEXT:    b other_f_va_fn
;
; FASTISEL-LABEL: call_f_va:
; FASTISEL:       // %bb.0: // %entry
; FASTISEL-NEXT:    mov w0, #1065353216
; FASTISEL-NEXT:    mov w1, #2
; FASTISEL-NEXT:    mov x2, #4613937818241073152
; FASTISEL-NEXT:    mov w3, #4
; FASTISEL-NEXT:    b other_f_va_fn
;
; GISEL-LABEL: call_f_va:
; GISEL:       // %bb.0: // %entry
; GISEL-NEXT:    fmov s0, #1.00000000
; GISEL-NEXT:    fmov w0, s0
; GISEL-NEXT:    mov w1, #2
; GISEL-NEXT:    fmov d0, #3.00000000
; GISEL-NEXT:    fmov x2, d0
; GISEL-NEXT:    mov w3, #4
; GISEL-NEXT:    b other_f_va_fn
entry:
  tail call void (float, i32, ...) @other_f_va_fn(float 1.000000e+00, i32 2, double 3.000000e+00, i32 4)
  ret void
}

declare void @other_f_va_fn(float, i32, ...)

define void @call_d_va() nounwind {
; DAGISEL-LABEL: call_d_va:
; DAGISEL:       // %bb.0: // %entry
; DAGISEL-NEXT:    mov x0, #4607182418800017408
; DAGISEL-NEXT:    mov w1, #2
; DAGISEL-NEXT:    mov x2, #4613937818241073152
; DAGISEL-NEXT:    mov w3, #4
; DAGISEL-NEXT:    b other_d_va_fn
;
; FASTISEL-LABEL: call_d_va:
; FASTISEL:       // %bb.0: // %entry
; FASTISEL-NEXT:    mov x0, #4607182418800017408
; FASTISEL-NEXT:    mov w1, #2
; FASTISEL-NEXT:    mov x2, #4613937818241073152
; FASTISEL-NEXT:    mov w3, #4
; FASTISEL-NEXT:    b other_d_va_fn
;
; GISEL-LABEL: call_d_va:
; GISEL:       // %bb.0: // %entry
; GISEL-NEXT:    fmov d0, #1.00000000
; GISEL-NEXT:    fmov x0, d0
; GISEL-NEXT:    mov w1, #2
; GISEL-NEXT:    fmov d0, #3.00000000
; GISEL-NEXT:    fmov x2, d0
; GISEL-NEXT:    mov w3, #4
; GISEL-NEXT:    b other_d_va_fn
entry:
  tail call void (double, i32, ...) @other_d_va_fn(double 1.000000e+00, i32 2, double 3.000000e+00, i32 4)
  ret void
}

declare void @other_d_va_fn(double, i32, ...)

define void @call_d_non_va() nounwind {
; DAGISEL-LABEL: call_d_non_va:
; DAGISEL:       // %bb.0: // %entry
; DAGISEL-NEXT:    fmov d0, #1.00000000
; DAGISEL-NEXT:    fmov d1, #3.00000000
; DAGISEL-NEXT:    mov w0, #2
; DAGISEL-NEXT:    mov w1, #4
; DAGISEL-NEXT:    b other_d_non_va_fn
;
; O0-LABEL: call_d_non_va:
; O0:       // %bb.0: // %entry
; O0-NEXT:    fmov d0, #1.00000000
; O0-NEXT:    mov w0, #2
; O0-NEXT:    fmov d1, #3.00000000
; O0-NEXT:    mov w1, #4
; O0-NEXT:    b other_d_non_va_fn
entry:
  tail call void (double, i32, double, i32) @other_d_non_va_fn(double 1.000000e+00, i32 2, double 3.000000e+00, i32 4)
  ret void
}

declare void @other_d_non_va_fn(double, i32, double, i32)
