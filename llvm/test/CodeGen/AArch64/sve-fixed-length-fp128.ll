; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s | FileCheck %s

target triple = "aarch64-unknown-linux-gnu"

; Ensure we don't attempt to combine into an extending fp128 load.
define void @fcvt_v4f64_v4f128(ptr %a, ptr %b) vscale_range(2,0) #0 {
; CHECK-LABEL: fcvt_v4f64_v4f128:
; CHECK:       // %bb.0:
; CHECK-NEXT:    str x29, [sp, #-32]! // 8-byte Folded Spill
; CHECK-NEXT:    stp x30, x19, [sp, #16] // 16-byte Folded Spill
; CHECK-NEXT:    addvl sp, sp, #-2
; CHECK-NEXT:    sub sp, sp, #48
; CHECK-NEXT:    ptrue p0.d, vl4
; CHECK-NEXT:    add x8, sp, #48
; CHECK-NEXT:    ld1d { z0.d }, p0/z, [x0]
; CHECK-NEXT:    mov x19, x1
; CHECK-NEXT:    str z0, [x8, #1, mul vl] // 16-byte Folded Spill
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #16
; CHECK-NEXT:    str z0, [x8] // 16-byte Folded Spill
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    bl __extenddftf2
; CHECK-NEXT:    add x8, sp, #48
; CHECK-NEXT:    str q0, [sp, #32] // 16-byte Folded Spill
; CHECK-NEXT:    ldr z1, [x8] // 16-byte Folded Reload
; CHECK-NEXT:    mov d1, v1.d[1]
; CHECK-NEXT:    fmov d0, d1
; CHECK-NEXT:    bl __extenddftf2
; CHECK-NEXT:    add x8, sp, #48
; CHECK-NEXT:    str q0, [sp, #16] // 16-byte Folded Spill
; CHECK-NEXT:    ldr z0, [x8, #1, mul vl] // 16-byte Folded Reload
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    bl __extenddftf2
; CHECK-NEXT:    add x8, sp, #48
; CHECK-NEXT:    str q0, [sp] // 16-byte Folded Spill
; CHECK-NEXT:    ldr z1, [x8, #1, mul vl] // 16-byte Folded Reload
; CHECK-NEXT:    mov d1, v1.d[1]
; CHECK-NEXT:    fmov d0, d1
; CHECK-NEXT:    bl __extenddftf2
; CHECK-NEXT:    ldr q1, [sp] // 16-byte Folded Reload
; CHECK-NEXT:    ldr q2, [sp, #16] // 16-byte Folded Reload
; CHECK-NEXT:    stp q1, q0, [x19]
; CHECK-NEXT:    ldr q0, [sp, #32] // 16-byte Folded Reload
; CHECK-NEXT:    stp q0, q2, [x19, #32]
; CHECK-NEXT:    addvl sp, sp, #2
; CHECK-NEXT:    add sp, sp, #48
; CHECK-NEXT:    ldp x30, x19, [sp, #16] // 16-byte Folded Reload
; CHECK-NEXT:    ldr x29, [sp], #32 // 8-byte Folded Reload
; CHECK-NEXT:    ret
  %op1 = load <4 x double>, ptr %a
  %res = fpext <4 x double> %op1 to <4 x fp128>
  store <4 x fp128> %res, ptr %b
  ret void
}

; Ensure we don't attempt to combine into a truncating fp128 store.
define void @fcvt_v4f128_v4f64(ptr %a, ptr %b) vscale_range(2,0) #0 {
; CHECK-LABEL: fcvt_v4f128_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    str x29, [sp, #-32]! // 8-byte Folded Spill
; CHECK-NEXT:    stp x30, x19, [sp, #16] // 16-byte Folded Spill
; CHECK-NEXT:    addvl sp, sp, #-2
; CHECK-NEXT:    sub sp, sp, #128
; CHECK-NEXT:    ldr q1, [x0, #64]
; CHECK-NEXT:    mov x19, x1
; CHECK-NEXT:    ldr q0, [x0, #80]
; CHECK-NEXT:    stp q0, q1, [sp, #96] // 32-byte Folded Spill
; CHECK-NEXT:    ldr q1, [x0, #96]
; CHECK-NEXT:    ldr q0, [x0, #112]
; CHECK-NEXT:    stp q0, q1, [sp, #64] // 32-byte Folded Spill
; CHECK-NEXT:    ldr q1, [x0]
; CHECK-NEXT:    ldr q0, [x0, #16]
; CHECK-NEXT:    stp q0, q1, [sp, #32] // 32-byte Folded Spill
; CHECK-NEXT:    ldr q0, [x0, #32]
; CHECK-NEXT:    str q0, [sp, #16] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [x0, #48]
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    str q0, [sp] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [sp, #16] // 16-byte Folded Reload
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    ldr q1, [sp] // 16-byte Folded Reload
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    add x8, sp, #128
; CHECK-NEXT:    mov v0.d[1], v1.d[0]
; CHECK-NEXT:    str z0, [x8, #1, mul vl] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [sp, #32] // 16-byte Folded Reload
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    str q0, [sp, #32] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [sp, #48] // 16-byte Folded Reload
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    ldr q1, [sp, #32] // 16-byte Folded Reload
; CHECK-NEXT:    add x8, sp, #128
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    mov v0.d[1], v1.d[0]
; CHECK-NEXT:    ldr z1, [x8, #1, mul vl] // 16-byte Folded Reload
; CHECK-NEXT:    splice z0.d, p0, z0.d, z1.d
; CHECK-NEXT:    str z0, [x8, #1, mul vl] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [sp, #64] // 16-byte Folded Reload
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    str q0, [sp, #64] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [sp, #80] // 16-byte Folded Reload
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    ldr q1, [sp, #64] // 16-byte Folded Reload
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    add x8, sp, #128
; CHECK-NEXT:    mov v0.d[1], v1.d[0]
; CHECK-NEXT:    str z0, [x8] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [sp, #96] // 16-byte Folded Reload
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    str q0, [sp, #96] // 16-byte Folded Spill
; CHECK-NEXT:    ldr q0, [sp, #112] // 16-byte Folded Reload
; CHECK-NEXT:    bl __trunctfdf2
; CHECK-NEXT:    ldr q1, [sp, #96] // 16-byte Folded Reload
; CHECK-NEXT:    add x9, sp, #128
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    mov x8, #4
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    mov v0.d[1], v1.d[0]
; CHECK-NEXT:    ldr z1, [x9] // 16-byte Folded Reload
; CHECK-NEXT:    splice z0.d, p0, z0.d, z1.d
; CHECK-NEXT:    ptrue p0.d, vl4
; CHECK-NEXT:    st1d { z0.d }, p0, [x19, x8, lsl #3]
; CHECK-NEXT:    add x8, sp, #128
; CHECK-NEXT:    ldr z0, [x8, #1, mul vl] // 16-byte Folded Reload
; CHECK-NEXT:    st1d { z0.d }, p0, [x19]
; CHECK-NEXT:    addvl sp, sp, #2
; CHECK-NEXT:    add sp, sp, #128
; CHECK-NEXT:    ldp x30, x19, [sp, #16] // 16-byte Folded Reload
; CHECK-NEXT:    ldr x29, [sp], #32 // 8-byte Folded Reload
; CHECK-NEXT:    ret
  %op1 = load <8 x fp128>, ptr %a
  %res = fptrunc <8 x fp128> %op1 to <8 x double>
  store <8 x double> %res, ptr %b
  ret void
}

attributes #0 = { nounwind "target-features"="+sve" }
