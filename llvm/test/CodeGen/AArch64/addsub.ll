; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -verify-machineinstrs < %s -mtriple=aarch64-linux-gnu -verify-machineinstrs | FileCheck %s

; Note that this should be refactored (for efficiency if nothing else)
; when the PCS is implemented so we don't have to worry about the
; loads and stores.

@var_i32 = global i32 42
@var2_i32 = global i32 43
@var_i64 = global i64 0

; Add pure 12-bit immediates:
define void @add_small() {
; CHECK-LABEL: add_small:
; CHECK:       // %bb.0:
; CHECK-NEXT:    adrp x8, :got:var_i32
; CHECK-NEXT:    adrp x9, :got:var_i64
; CHECK-NEXT:    ldr x8, [x8, :got_lo12:var_i32]
; CHECK-NEXT:    ldr x9, [x9, :got_lo12:var_i64]
; CHECK-NEXT:    ldr w10, [x8]
; CHECK-NEXT:    ldr x11, [x9]
; CHECK-NEXT:    add w10, w10, #4095
; CHECK-NEXT:    add x11, x11, #52
; CHECK-NEXT:    str w10, [x8]
; CHECK-NEXT:    str x11, [x9]
; CHECK-NEXT:    ret

  %val32 = load i32, ptr @var_i32
  %newval32 = add i32 %val32, 4095
  store i32 %newval32, ptr @var_i32

  %val64 = load i64, ptr @var_i64
  %newval64 = add i64 %val64, 52
  store i64 %newval64, ptr @var_i64

  ret void
}

; Make sure we grab the imm variant when the register operand
; can be implicitly zero-extend.
; We used to generate something horrible like this:
; wA = ldrb
; xB = ldimm 12
; xC = add xB, wA, uxtb
; whereas this can be achieved with:
; wA = ldrb
; xC = add xA, #12 ; <- xA implicitly zero extend wA.
define void @add_small_imm(ptr %p, ptr %q, i32 %b, ptr %addr) {
; CHECK-LABEL: add_small_imm:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    ldrb w8, [x0]
; CHECK-NEXT:    add w9, w8, w2
; CHECK-NEXT:    add x8, x8, #12
; CHECK-NEXT:    str w9, [x3]
; CHECK-NEXT:    str x8, [x1]
; CHECK-NEXT:    ret
entry:

  %t = load i8, ptr %p
  %promoted = zext i8 %t to i64
  %zextt = zext i8 %t to i32
  %add = add nuw i32 %zextt, %b

  %add2 = add nuw i64 %promoted, 12
  store i32 %add, ptr %addr

  store i64 %add2, ptr %q
  ret void
}

; Add 12-bit immediates, shifted left by 12 bits
define void @add_med() {
; CHECK-LABEL: add_med:
; CHECK:       // %bb.0:
; CHECK-NEXT:    adrp x8, :got:var_i32
; CHECK-NEXT:    adrp x9, :got:var_i64
; CHECK-NEXT:    ldr x8, [x8, :got_lo12:var_i32]
; CHECK-NEXT:    ldr x9, [x9, :got_lo12:var_i64]
; CHECK-NEXT:    ldr w10, [x8]
; CHECK-NEXT:    ldr x11, [x9]
; CHECK-NEXT:    add w10, w10, #3567, lsl #12 // =14610432
; CHECK-NEXT:    add x11, x11, #4095, lsl #12 // =16773120
; CHECK-NEXT:    str w10, [x8]
; CHECK-NEXT:    str x11, [x9]
; CHECK-NEXT:    ret

  %val32 = load i32, ptr @var_i32
  %newval32 = add i32 %val32, 14610432 ; =0xdef000
  store i32 %newval32, ptr @var_i32

  %val64 = load i64, ptr @var_i64
  %newval64 = add i64 %val64, 16773120 ; =0xfff000
  store i64 %newval64, ptr @var_i64

  ret void
}

; Subtract 12-bit immediates
define void @sub_small() {
; CHECK-LABEL: sub_small:
; CHECK:       // %bb.0:
; CHECK-NEXT:    adrp x8, :got:var_i32
; CHECK-NEXT:    adrp x9, :got:var_i64
; CHECK-NEXT:    ldr x8, [x8, :got_lo12:var_i32]
; CHECK-NEXT:    ldr x9, [x9, :got_lo12:var_i64]
; CHECK-NEXT:    ldr w10, [x8]
; CHECK-NEXT:    ldr x11, [x9]
; CHECK-NEXT:    sub w10, w10, #4095
; CHECK-NEXT:    sub x11, x11, #52
; CHECK-NEXT:    str w10, [x8]
; CHECK-NEXT:    str x11, [x9]
; CHECK-NEXT:    ret

  %val32 = load i32, ptr @var_i32
  %newval32 = sub i32 %val32, 4095
  store i32 %newval32, ptr @var_i32

  %val64 = load i64, ptr @var_i64
  %newval64 = sub i64 %val64, 52
  store i64 %newval64, ptr @var_i64

  ret void
}

; Subtract 12-bit immediates, shifted left by 12 bits
define void @sub_med() {
; CHECK-LABEL: sub_med:
; CHECK:       // %bb.0:
; CHECK-NEXT:    adrp x8, :got:var_i32
; CHECK-NEXT:    adrp x9, :got:var_i64
; CHECK-NEXT:    ldr x8, [x8, :got_lo12:var_i32]
; CHECK-NEXT:    ldr x9, [x9, :got_lo12:var_i64]
; CHECK-NEXT:    ldr w10, [x8]
; CHECK-NEXT:    ldr x11, [x9]
; CHECK-NEXT:    sub w10, w10, #3567, lsl #12 // =14610432
; CHECK-NEXT:    sub x11, x11, #4095, lsl #12 // =16773120
; CHECK-NEXT:    str w10, [x8]
; CHECK-NEXT:    str x11, [x9]
; CHECK-NEXT:    ret

  %val32 = load i32, ptr @var_i32
  %newval32 = sub i32 %val32, 14610432 ; =0xdef000
  store i32 %newval32, ptr @var_i32

  %val64 = load i64, ptr @var_i64
  %newval64 = sub i64 %val64, 16773120 ; =0xfff000
  store i64 %newval64, ptr @var_i64

  ret void
}

define i64 @add_two_parts_imm_i64(i64 %a) {
; CHECK-LABEL: add_two_parts_imm_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add x8, x0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    add x0, x8, #1365
; CHECK-NEXT:    ret
  %b = add i64 %a, 11183445
  ret i64 %b
}

define i32 @add_two_parts_imm_i32(i32 %a) {
; CHECK-LABEL: add_two_parts_imm_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add w8, w0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    add w0, w8, #1365
; CHECK-NEXT:    ret
  %b = add i32 %a, 11183445
  ret i32 %b
}

define i64 @add_two_parts_imm_i64_neg(i64 %a) {
; CHECK-LABEL: add_two_parts_imm_i64_neg:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub x8, x0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    sub x0, x8, #1365
; CHECK-NEXT:    ret
  %b = add i64 %a, -11183445
  ret i64 %b
}

define i32 @add_two_parts_imm_i32_neg(i32 %a) {
; CHECK-LABEL: add_two_parts_imm_i32_neg:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    sub w0, w8, #1365
; CHECK-NEXT:    ret
  %b = add i32 %a, -11183445
  ret i32 %b
}

define i64 @sub_two_parts_imm_i64(i64 %a) {
; CHECK-LABEL: sub_two_parts_imm_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub x8, x0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    sub x0, x8, #1365
; CHECK-NEXT:    ret
  %b = sub i64 %a, 11183445
  ret i64 %b
}

define i32 @sub_two_parts_imm_i32(i32 %a) {
; CHECK-LABEL: sub_two_parts_imm_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    sub w0, w8, #1365
; CHECK-NEXT:    ret
  %b = sub i32 %a, 11183445
  ret i32 %b
}

define i64 @sub_two_parts_imm_i64_neg(i64 %a) {
; CHECK-LABEL: sub_two_parts_imm_i64_neg:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add x8, x0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    add x0, x8, #1365
; CHECK-NEXT:    ret
  %b = sub i64 %a, -11183445
  ret i64 %b
}

define i32 @sub_two_parts_imm_i32_neg(i32 %a) {
; CHECK-LABEL: sub_two_parts_imm_i32_neg:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add w8, w0, #2730, lsl #12 // =11182080
; CHECK-NEXT:    add w0, w8, #1365
; CHECK-NEXT:    ret
  %b = sub i32 %a, -11183445
  ret i32 %b
}

define i32 @add_27962026(i32 %a) {
; CHECK-LABEL: add_27962026:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #43690
; CHECK-NEXT:    movk w8, #426, lsl #16
; CHECK-NEXT:    add w0, w0, w8
; CHECK-NEXT:    ret
  %b = add i32 %a, 27962026
  ret i32 %b
}

define i32 @add_65534(i32 %a) {
; CHECK-LABEL: add_65534:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #65534
; CHECK-NEXT:    add w0, w0, w8
; CHECK-NEXT:    ret
  %b = add i32 %a, 65534
  ret i32 %b
}

declare i32 @foox(i32)

define void @add_in_loop(i32 %0) {
; CHECK-LABEL: add_in_loop:
; CHECK:       // %bb.0:
; CHECK-NEXT:    stp x30, x19, [sp, #-16]! // 16-byte Folded Spill
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    .cfi_offset w19, -8
; CHECK-NEXT:    .cfi_offset w30, -16
; CHECK-NEXT:    mov w19, #43690
; CHECK-NEXT:    movk w19, #170, lsl #16
; CHECK-NEXT:  .LBB15_1: // =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    add w0, w0, w19
; CHECK-NEXT:    bl foox
; CHECK-NEXT:    b .LBB15_1
  br label %2
2:
  %3 = phi i32 [ %0, %1 ], [ %5, %2 ]
  %4 = add nsw i32 %3, 11184810
  %5 = tail call i32 @foox(i32 %4) #2
  br label %2
}

define void @testing() {
; CHECK-LABEL: testing:
; CHECK:       // %bb.0:
; CHECK-NEXT:    adrp x8, :got:var_i32
; CHECK-NEXT:    ldr x8, [x8, :got_lo12:var_i32]
; CHECK-NEXT:    ldr w9, [x8]
; CHECK-NEXT:    cmp w9, #4095
; CHECK-NEXT:    b.ne .LBB16_6
; CHECK-NEXT:  // %bb.1: // %test2
; CHECK-NEXT:    adrp x10, :got:var2_i32
; CHECK-NEXT:    add w11, w9, #1
; CHECK-NEXT:    ldr x10, [x10, :got_lo12:var2_i32]
; CHECK-NEXT:    str w11, [x8]
; CHECK-NEXT:    ldr w10, [x10]
; CHECK-NEXT:    cmp w10, #3567, lsl #12 // =14610432
; CHECK-NEXT:    b.lo .LBB16_6
; CHECK-NEXT:  // %bb.2: // %test3
; CHECK-NEXT:    add w11, w9, #2
; CHECK-NEXT:    cmp w9, #123
; CHECK-NEXT:    str w11, [x8]
; CHECK-NEXT:    b.lt .LBB16_6
; CHECK-NEXT:  // %bb.3: // %test4
; CHECK-NEXT:    add w11, w9, #3
; CHECK-NEXT:    cmp w10, #321
; CHECK-NEXT:    str w11, [x8]
; CHECK-NEXT:    b.gt .LBB16_6
; CHECK-NEXT:  // %bb.4: // %test5
; CHECK-NEXT:    add w11, w9, #4
; CHECK-NEXT:    cmn w10, #443
; CHECK-NEXT:    str w11, [x8]
; CHECK-NEXT:    b.ge .LBB16_6
; CHECK-NEXT:  // %bb.5: // %test6
; CHECK-NEXT:    add w9, w9, #5
; CHECK-NEXT:    str w9, [x8]
; CHECK-NEXT:  .LBB16_6: // %common.ret
; CHECK-NEXT:    ret
  %val = load i32, ptr @var_i32
  %val2 = load i32, ptr @var2_i32

  %cmp_pos_small = icmp ne i32 %val, 4095
  br i1 %cmp_pos_small, label %ret, label %test2

test2:
  %newval2 = add i32 %val, 1
  store i32 %newval2, ptr @var_i32
  %cmp_pos_big = icmp ult i32 %val2, 14610432
  br i1 %cmp_pos_big, label %ret, label %test3

test3:
  %newval3 = add i32 %val, 2
  store i32 %newval3, ptr @var_i32
  %cmp_pos_slt = icmp slt i32 %val, 123
  br i1 %cmp_pos_slt, label %ret, label %test4

test4:
  %newval4 = add i32 %val, 3
  store i32 %newval4, ptr @var_i32
  %cmp_pos_sgt = icmp sgt i32 %val2, 321
  br i1 %cmp_pos_sgt, label %ret, label %test5

test5:
  %newval5 = add i32 %val, 4
  store i32 %newval5, ptr @var_i32
  %cmp_neg_uge = icmp sgt i32 %val2, -444
  br i1 %cmp_neg_uge, label %ret, label %test6

test6:
  %newval6 = add i32 %val, 5
  store i32 %newval6, ptr @var_i32
  ret void

ret:
  ret void
}

declare {i32, i1} @llvm.sadd.with.overflow.i32(i32 %a, i32 %b)

define i1 @sadd_add(i32 %a, i32 %b, ptr %p) {
; CHECK-LABEL: sadd_add:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mvn w8, w0
; CHECK-NEXT:    adds w8, w8, w1
; CHECK-NEXT:    cset w0, vs
; CHECK-NEXT:    add w8, w8, #1
; CHECK-NEXT:    str w8, [x2]
; CHECK-NEXT:    ret
  %nota = xor i32 %a, -1
  %a0 = call {i32, i1} @llvm.sadd.with.overflow.i32(i32 %nota, i32 %b)
  %e0 = extractvalue {i32, i1} %a0, 0
  %e1 = extractvalue {i32, i1} %a0, 1
  %res = add i32 %e0, 1
  store i32 %res, ptr %p
  ret i1 %e1
}

declare {i8, i1} @llvm.uadd.with.overflow.i8(i8 %a, i8 %b)

define i1 @uadd_add(i8 %a, i8 %b, ptr %p) {
; CHECK-LABEL: uadd_add:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #255
; CHECK-NEXT:    bic w8, w8, w0
; CHECK-NEXT:    add w8, w8, w1, uxtb
; CHECK-NEXT:    lsr w0, w8, #8
; CHECK-NEXT:    add w8, w8, #1
; CHECK-NEXT:    strb w8, [x2]
; CHECK-NEXT:    ret
  %nota = xor i8 %a, -1
  %a0 = call {i8, i1} @llvm.uadd.with.overflow.i8(i8 %nota, i8 %b)
  %e0 = extractvalue {i8, i1} %a0, 0
  %e1 = extractvalue {i8, i1} %a0, 1
  %res = add i8 %e0, 1
  store i8 %res, ptr %p
  ret i1 %e1
}

; This is a unique edge case that will generate the following MIR
;   MOVi32imm -1000000
;   SUBREG_TO_REG 0, killed %1, %subreg.sub_32
; When using a 64-bit unsigned for the "-1000000" immediate, the code
; must make sure to zero out the top 32 bits since SUBREG_TO_REG is
; zero extending the value
define i64 @addl_0x80000000(i64 %a) {
; CHECK-LABEL: addl_0x80000000:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #48576
; CHECK-NEXT:    movk w8, #65520, lsl #16
; CHECK-NEXT:    add x0, x0, x8
; CHECK-NEXT:    ret
  %b = add i64 %a, 4293967296
  ret i64 %b
}

; ADDS and SUBS Optimizations
; Checks with all types first, then checks that only EQ and NE optimize
define i1 @eq_i(i32 %0) {
; CHECK-LABEL: eq_i:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmp w8, #273
; CHECK-NEXT:    cset w0, eq
; CHECK-NEXT:    ret
  %2 = icmp eq i32 %0, 1118481
  ret i1 %2
}

define i1 @eq_l(i64 %0) {
; CHECK-LABEL: eq_l:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub x8, x0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmp x8, #273
; CHECK-NEXT:    cset w0, eq
; CHECK-NEXT:    ret
  %2 = icmp eq i64 %0, 1118481
  ret i1 %2
}

define i1 @ne_i(i32 %0) {
; CHECK-LABEL: ne_i:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmp w8, #273
; CHECK-NEXT:    cset w0, ne
; CHECK-NEXT:    ret
  %2 = icmp ne i32 %0, 1118481
  ret i1 %2
}

define i1 @ne_l(i64 %0) {
; CHECK-LABEL: ne_l:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub x8, x0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmp x8, #273
; CHECK-NEXT:    cset w0, ne
; CHECK-NEXT:    ret
  %2 = icmp ne i64 %0, 1118481
  ret i1 %2
}

define i1 @eq_in(i32 %0) {
; CHECK-LABEL: eq_in:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add w8, w0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmn w8, #273
; CHECK-NEXT:    cset w0, eq
; CHECK-NEXT:    ret
  %2 = icmp eq i32 %0, -1118481
  ret i1 %2
}

define i1 @eq_ln(i64 %0) {
; CHECK-LABEL: eq_ln:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add x8, x0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmn x8, #273
; CHECK-NEXT:    cset w0, eq
; CHECK-NEXT:    ret
  %2 = icmp eq i64 %0, -1118481
  ret i1 %2
}

define i1 @ne_in(i32 %0) {
; CHECK-LABEL: ne_in:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add w8, w0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmn w8, #273
; CHECK-NEXT:    cset w0, ne
; CHECK-NEXT:    ret
  %2 = icmp ne i32 %0, -1118481
  ret i1 %2
}

define i1 @ne_ln(i64 %0) {
; CHECK-LABEL: ne_ln:
; CHECK:       // %bb.0:
; CHECK-NEXT:    add x8, x0, #273, lsl #12 // =1118208
; CHECK-NEXT:    cmn x8, #273
; CHECK-NEXT:    cset w0, ne
; CHECK-NEXT:    ret
  %2 = icmp ne i64 %0, -1118481
  ret i1 %2
}

define i1 @reject_eq(i32 %0) {
; CHECK-LABEL: reject_eq:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #51712
; CHECK-NEXT:    movk w8, #15258, lsl #16
; CHECK-NEXT:    cmp w0, w8
; CHECK-NEXT:    cset w0, eq
; CHECK-NEXT:    ret
  %2 = icmp eq i32 %0, 1000000000
  ret i1 %2
}

define i1 @reject_non_eqne_csinc(i32 %0) {
; CHECK-LABEL: reject_non_eqne_csinc:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #4369
; CHECK-NEXT:    movk w8, #17, lsl #16
; CHECK-NEXT:    cmp w0, w8
; CHECK-NEXT:    cset w0, lo
; CHECK-NEXT:    ret
  %2 = icmp ult i32 %0, 1118481
  ret i1 %2
}

define i32 @accept_csel(i32 %0) {
; CHECK-LABEL: accept_csel:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w9, w0, #273, lsl #12 // =1118208
; CHECK-NEXT:    mov w8, #17
; CHECK-NEXT:    cmp w9, #273
; CHECK-NEXT:    mov w9, #11
; CHECK-NEXT:    csel w0, w9, w8, eq
; CHECK-NEXT:    ret
  %2 = icmp eq i32 %0, 1118481
  %3 = select i1 %2, i32 11, i32 17
  ret i32 %3
}

define i32 @reject_non_eqne_csel(i32 %0) {
; CHECK-LABEL: reject_non_eqne_csel:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #4369
; CHECK-NEXT:    mov w9, #11
; CHECK-NEXT:    movk w8, #17, lsl #16
; CHECK-NEXT:    cmp w0, w8
; CHECK-NEXT:    mov w8, #17
; CHECK-NEXT:    csel w0, w9, w8, lo
; CHECK-NEXT:    ret
  %2 = icmp ult i32 %0, 1118481
  %3 = select i1 %2, i32 11, i32 17
  ret i32 %3
}

declare void @fooy()

define void @accept_branch(i32 %0) {
; CHECK-LABEL: accept_branch:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w0, #291, lsl #12 // =1191936
; CHECK-NEXT:    cmp w8, #1110
; CHECK-NEXT:    b.eq .LBB32_2
; CHECK-NEXT:  // %bb.1:
; CHECK-NEXT:    ret
; CHECK-NEXT:  .LBB32_2:
; CHECK-NEXT:    b fooy
  %2 = icmp ne i32 %0, 1193046
  br i1 %2, label %4, label %3
3:                                                ; preds = %1
  tail call void @fooy()
  br label %4
4:                                                ; preds = %3, %1
  ret void
}

define void @reject_non_eqne_branch(i32 %0) {
; CHECK-LABEL: reject_non_eqne_branch:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #13398
; CHECK-NEXT:    movk w8, #18, lsl #16
; CHECK-NEXT:    cmp w0, w8
; CHECK-NEXT:    b.le .LBB33_2
; CHECK-NEXT:  // %bb.1:
; CHECK-NEXT:    ret
; CHECK-NEXT:  .LBB33_2:
; CHECK-NEXT:    b fooy
  %2 = icmp sgt i32 %0, 1193046
  br i1 %2, label %4, label %3
3:                                                ; preds = %1
  tail call void @fooy()
  br label %4
4:                                                ; preds = %3, %1
  ret void
}

define i32 @reject_multiple_usages(i32 %0) {
; CHECK-LABEL: reject_multiple_usages:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #4369
; CHECK-NEXT:    mov w9, #3
; CHECK-NEXT:    movk w8, #17, lsl #16
; CHECK-NEXT:    mov w10, #17
; CHECK-NEXT:    cmp w0, w8
; CHECK-NEXT:    mov w8, #9
; CHECK-NEXT:    mov w11, #12
; CHECK-NEXT:    csel w8, w8, w9, eq
; CHECK-NEXT:    csel w9, w11, w10, hi
; CHECK-NEXT:    add w8, w8, w9
; CHECK-NEXT:    mov w9, #53312
; CHECK-NEXT:    movk w9, #2, lsl #16
; CHECK-NEXT:    cmp w0, w9
; CHECK-NEXT:    mov w9, #26304
; CHECK-NEXT:    movk w9, #1433, lsl #16
; CHECK-NEXT:    csel w0, w8, w9, hi
; CHECK-NEXT:    ret
  %2 = icmp eq i32 %0, 1118481
  %3 = icmp ugt i32 %0, 1118481
  %4 = select i1 %2, i32 9, i32 3
  %5 = select i1 %3, i32 12, i32 17
  %6 = add i32 %4, %5
  %7 = icmp ugt i32 %0, 184384
  %8 = select i1 %7, i32 %6, i32 93939392
  ret i32 %8
}

; Unique case found in ClangBuiltLinux where the DstReg is not Virtual and
; caused an assertion failure
define dso_local i32 @neigh_periodic_work_tbl_1() {
; CHECK-LABEL: neigh_periodic_work_tbl_1:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    adrp x8, neigh_periodic_work_tbl_1
; CHECK-NEXT:    add x8, x8, :lo12:neigh_periodic_work_tbl_1
; CHECK-NEXT:    add x8, x8, #18, lsl #12 // =73728
; CHECK-NEXT:    cmn x8, #1272
; CHECK-NEXT:    b.pl .LBB35_2
; CHECK-NEXT:  .LBB35_1: // %for.cond
; CHECK-NEXT:    // =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    b .LBB35_1
; CHECK-NEXT:  .LBB35_2: // %if.end
; CHECK-NEXT:    ret
entry:
  br i1 icmp slt (i64 add (i64 ptrtoint (ptr @neigh_periodic_work_tbl_1 to i64), i64 75000), i64 0), label %for.cond, label %if.end
for.cond:                                         ; preds = %entry, %for.cond
  br label %for.cond
if.end:                                           ; preds = %entry
  ret i32 undef
}

@jiffies = dso_local local_unnamed_addr global i32 0, align 4
@primary_crng = dso_local local_unnamed_addr global i32 0, align 4
@input_pool = dso_local global i32 0, align 4
declare dso_local i32 @crng_reseed(...) local_unnamed_addr
; Function Attrs: nounwind uwtable
define dso_local i32 @_extract_crng_crng() {
; CHECK-LABEL: _extract_crng_crng:
; CHECK:       // %bb.0: // %entry
; CHECK-NEXT:    str x30, [sp, #-16]! // 8-byte Folded Spill
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    .cfi_offset w30, -16
; CHECK-NEXT:    adrp x8, _extract_crng_crng
; CHECK-NEXT:    add x8, x8, :lo12:_extract_crng_crng
; CHECK-NEXT:    tbnz x8, #63, .LBB36_2
; CHECK-NEXT:  // %bb.1: // %lor.lhs.false
; CHECK-NEXT:    adrp x9, jiffies
; CHECK-NEXT:    ldrsw x9, [x9, :lo12:jiffies]
; CHECK-NEXT:    sub x8, x8, x9
; CHECK-NEXT:    add x8, x8, #18, lsl #12 // =73728
; CHECK-NEXT:    cmn x8, #1272
; CHECK-NEXT:    b.pl .LBB36_3
; CHECK-NEXT:  .LBB36_2: // %if.then
; CHECK-NEXT:    adrp x8, primary_crng
; CHECK-NEXT:    adrp x9, input_pool
; CHECK-NEXT:    add x9, x9, :lo12:input_pool
; CHECK-NEXT:    ldr w8, [x8, :lo12:primary_crng]
; CHECK-NEXT:    cmp w8, #0
; CHECK-NEXT:    csel x0, xzr, x9, eq
; CHECK-NEXT:    bl crng_reseed
; CHECK-NEXT:  .LBB36_3: // %if.end
; CHECK-NEXT:    ldr x30, [sp], #16 // 8-byte Folded Reload
; CHECK-NEXT:    ret
entry:
  br i1 icmp slt (ptr @_extract_crng_crng, ptr null), label %if.then, label %lor.lhs.false
lor.lhs.false:                                    ; preds = %entry
  %0 = load i32, ptr @jiffies, align 4
  %idx.ext = sext i32 %0 to i64
  %idx.neg = sub nsw i64 0, %idx.ext
  %add.ptr = getelementptr i8, ptr getelementptr (i8, ptr @_extract_crng_crng, i64 75000), i64 %idx.neg
  %cmp = icmp slt ptr %add.ptr, null
  br i1 %cmp, label %if.then, label %if.end
if.then:                                          ; preds = %lor.lhs.false, %entry
  %1 = load i32, ptr @primary_crng, align 4
  %tobool.not = icmp eq i32 %1, 0
  %cond = select i1 %tobool.not, ptr null, ptr @input_pool
  %call = tail call i32 @crng_reseed(ptr noundef %cond)
  br label %if.end
if.end:                                           ; preds = %if.then, %lor.lhs.false
  ret i32 undef
}

; ((X << C) - Y) + Z --> (Z - Y) + (X << C)
define i32 @commute_subop0(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w2, w1
; CHECK-NEXT:    add w0, w8, w0, lsl #3
; CHECK-NEXT:    ret
  %shl = shl i32 %x, 3
  %sub = sub i32 %shl, %y
  %add = add i32 %sub, %z
  ret i32 %add
}

; ((X >> C) - Y) + Z --> (Z - Y) + (X >> C)
define i32 @commute_subop0_lshr(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0_lshr:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w2, w1
; CHECK-NEXT:    add w0, w8, w0, lsr #3
; CHECK-NEXT:    ret
  %lshr = lshr i32 %x, 3
  %sub = sub i32 %lshr, %y
  %add = add i32 %sub, %z
  ret i32 %add
}

; ((X >> C) - Y) + Z --> (Z - Y) + (X >> C)
define i32 @commute_subop0_ashr(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0_ashr:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w2, w1
; CHECK-NEXT:    add w0, w8, w0, asr #3
; CHECK-NEXT:    ret
  %ashr = ashr i32 %x, 3
  %sub = sub i32 %ashr, %y
  %add = add i32 %sub, %z
  ret i32 %add
}

; ((sext X) - Y) + Z --> (Z - Y) + (sext X)
define i64 @commute_subop0_sext(i32 %x, i64 %y, i64 %z) {
; CHECK-LABEL: commute_subop0_sext:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub x8, x2, x1
; CHECK-NEXT:    add x0, x8, w0, sxtw
; CHECK-NEXT:    ret
  %sext = sext i32 %x to i64
  %sub = sub i64 %sext, %y
  %add = add i64 %sub, %z
  ret i64 %add
}

; ((sext_inreg X) - Y) + Z --> (Z - Y) + (sext_inreg X)
define i64 @commute_subop0_sext_inreg(i64 %x, i64 %y, i64 %z) {
; CHECK-LABEL: commute_subop0_sext_inreg:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub x8, x2, x1
; CHECK-NEXT:    add x0, x8, w0, sxth
; CHECK-NEXT:    ret
  %shl = shl i64 %x, 48
  %ashr = ashr i64 %shl, 48
  %sub = sub i64 %ashr, %y
  %add = add i64 %sub, %z
  ret i64 %add
}

; ((zext X) - Y) + Z --> (Z - Y) + (zext X)
define i32 @commute_subop0_zext(i16 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0_zext:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w2, w1
; CHECK-NEXT:    add w0, w8, w0, uxth
; CHECK-NEXT:    ret
  %zext = zext i16 %x to i32
  %sub = sub i32 %zext, %y
  %add = add i32 %sub, %z
  ret i32 %add
}


; ((anyext X) - Y) + Z --> (Z - Y) + (anyext X)
define i8 @commute_subop0_anyext(i16 %a, i16 %b, i32 %c) {
; CHECK-LABEL: commute_subop0_anyext:
; CHECK:       // %bb.0:
; CHECK-NEXT:    mov w8, #111
; CHECK-NEXT:    sub w9, w2, w1
; CHECK-NEXT:    madd w8, w0, w8, w9
; CHECK-NEXT:    lsl w8, w8, #3
; CHECK-NEXT:    sub w0, w8, #1776
; CHECK-NEXT:    ret
  %aa = mul i16 %a, 111
  %bb = add i16 %b, 222
  %a_32 = zext i16 %aa to i32
  %b_32 = zext i16 %bb to i32
  %sub = sub i32 %a_32, %b_32
  %add = add i32 %sub, %c
  %trunc = trunc i32 %add to i8
  %r = shl i8 %trunc, 3
  ret i8 %r
}

; ((X and C) - Y) + Z --> (Z - Y) + (X and C)
define i32 @commute_subop0_and(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0_and:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w2, w1
; CHECK-NEXT:    add w0, w8, w0, uxtb
; CHECK-NEXT:    ret
  %and = and i32 %x, 255
  %sub = sub i32 %and, %y
  %add = add i32 %sub, %z
  ret i32 %add
}

; Z + ((X << C) - Y) --> (Z - Y) + (X << C)
define i32 @commute_subop0_cadd(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0_cadd:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w2, w1
; CHECK-NEXT:    add w0, w8, w0, lsl #3
; CHECK-NEXT:    ret
  %shl = shl i32 %x, 3
  %sub = sub i32 %shl, %y
  %add = add i32 %z, %sub
  ret i32 %add
}

; Y + ((X << C) - X) --> (Y - X) + (X << C)
define i32 @commute_subop0_mul(i32 %x, i32 %y) {
; CHECK-LABEL: commute_subop0_mul:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub w8, w1, w0
; CHECK-NEXT:    add w0, w8, w0, lsl #3
; CHECK-NEXT:    ret
  %mul = mul i32 %x, 7
  %add = add i32 %mul, %y
  ret i32 %add
}

; negative case for ((X << C) - Y) + Z --> (Z - Y) + (X << C)
; Y can't be constant to avoid dead loop
define i32 @commute_subop0_zconst(i32 %x, i32 %y) {
; CHECK-LABEL: commute_subop0_zconst:
; CHECK:       // %bb.0:
; CHECK-NEXT:    lsl w8, w0, #3
; CHECK-NEXT:    sub w8, w8, w1
; CHECK-NEXT:    add w0, w8, #1
; CHECK-NEXT:    ret
  %shl = shl i32 %x, 3
  %sub = sub i32 %shl, %y
  %add = add i32 %sub, 1
  ret i32 %add
}

; negative case for ((X << C) - Y) + Z --> (Z - Y) + (X << C)
; Y can't be shift C also to avoid dead loop
define i32 @commute_subop0_zshiftc_oneuse(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0_zshiftc_oneuse:
; CHECK:       // %bb.0:
; CHECK-NEXT:    lsl w8, w0, #3
; CHECK-NEXT:    sub w8, w8, w1
; CHECK-NEXT:    add w0, w8, w2, lsl #2
; CHECK-NEXT:    ret
  %xshl = shl i32 %x, 3
  %sub = sub i32 %xshl, %y
  %zshl = shl i32 %z, 2
  %add = add i32 %sub, %zshl
  ret i32 %add
}

define i32 @commute_subop0_zshiftc(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: commute_subop0_zshiftc:
; CHECK:       // %bb.0:
; CHECK-NEXT:    lsl w8, w2, #2
; CHECK-NEXT:    sub w9, w8, w1
; CHECK-NEXT:    add w9, w9, w0, lsl #3
; CHECK-NEXT:    eor w0, w8, w9
; CHECK-NEXT:    ret
  %xshl = shl i32 %x, 3
  %sub = sub i32 %xshl, %y
  %zshl = shl i32 %z, 2
  %add = add i32 %sub, %zshl
  %r = xor i32 %zshl, %add
  ret i32 %r
}
