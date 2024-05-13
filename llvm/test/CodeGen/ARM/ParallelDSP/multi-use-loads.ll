; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -O3 -mtriple=armv8m.main-none-none-eabi -mattr=+dsp < %s | FileCheck %s --check-prefixes=CHECK-LE
; RUN: llc -O3 -mtriple=armv8m.maineb-none-none-eabi -mattr=+dsp < %s | FileCheck %s --check-prefixes=CHECK-BE

define i32 @add_user(i32 %arg, ptr nocapture readnone %arg1, ptr nocapture readonly %arg2, ptr nocapture readonly %arg3) {
; CHECK-LE-LABEL: add_user:
; CHECK-LE:       @ %bb.0: @ %entry
; CHECK-LE-NEXT:    .save {r4, lr}
; CHECK-LE-NEXT:    push {r4, lr}
; CHECK-LE-NEXT:    cmp r0, #1
; CHECK-LE-NEXT:    blt .LBB0_4
; CHECK-LE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-LE-NEXT:    sub.w lr, r3, #2
; CHECK-LE-NEXT:    subs r2, #2
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:  .LBB0_2: @ %for.body
; CHECK-LE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-LE-NEXT:    ldr r3, [lr, #2]!
; CHECK-LE-NEXT:    subs r0, #1
; CHECK-LE-NEXT:    ldr r4, [r2, #2]!
; CHECK-LE-NEXT:    sxtah r1, r1, r3
; CHECK-LE-NEXT:    smlad r12, r4, r3, r12
; CHECK-LE-NEXT:    bne .LBB0_2
; CHECK-LE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
; CHECK-LE-NEXT:  .LBB0_4:
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
;
; CHECK-BE-LABEL: add_user:
; CHECK-BE:       @ %bb.0: @ %entry
; CHECK-BE-NEXT:    .save {r4, r5, r7, lr}
; CHECK-BE-NEXT:    push {r4, r5, r7, lr}
; CHECK-BE-NEXT:    cmp r0, #1
; CHECK-BE-NEXT:    blt .LBB0_4
; CHECK-BE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-BE-NEXT:    subs r3, #2
; CHECK-BE-NEXT:    subs r2, #2
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:  .LBB0_2: @ %for.body
; CHECK-BE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-BE-NEXT:    ldrsh lr, [r3, #2]!
; CHECK-BE-NEXT:    subs r0, #1
; CHECK-BE-NEXT:    ldrsh r4, [r2, #2]!
; CHECK-BE-NEXT:    add r1, lr
; CHECK-BE-NEXT:    ldrsh.w r5, [r2, #2]
; CHECK-BE-NEXT:    smlabb r12, r4, lr, r12
; CHECK-BE-NEXT:    ldrsh.w r4, [r3, #2]
; CHECK-BE-NEXT:    smlabb r12, r5, r4, r12
; CHECK-BE-NEXT:    bne .LBB0_2
; CHECK-BE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
; CHECK-BE-NEXT:  .LBB0_4:
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
entry:
  %cmp24 = icmp sgt i32 %arg, 0
  br i1 %cmp24, label %for.body.preheader, label %for.cond.cleanup

for.body.preheader:
  %.pre = load i16, ptr %arg3, align 2
  %.pre27 = load i16, ptr %arg2, align 2
  br label %for.body

for.cond.cleanup:
  %mac1.0.lcssa = phi i32 [ 0, %entry ], [ %add11, %for.body ]
  %count.final = phi i32 [ 0, %entry ], [ %count.next, %for.body ]
  %res = add i32 %mac1.0.lcssa, %count.final
  ret i32 %res

for.body:
  %mac1.026 = phi i32 [ %add11, %for.body ], [ 0, %for.body.preheader ]
  %i.025 = phi i32 [ %add, %for.body ], [ 0, %for.body.preheader ]
  %count = phi i32 [ %count.next, %for.body ], [ 0, %for.body.preheader ]
  %arrayidx = getelementptr inbounds i16, ptr %arg3, i32 %i.025
  %0 = load i16, ptr %arrayidx, align 2
  %add = add nuw nsw i32 %i.025, 1
  %arrayidx1 = getelementptr inbounds i16, ptr %arg3, i32 %add
  %1 = load i16, ptr %arrayidx1, align 2
  %arrayidx3 = getelementptr inbounds i16, ptr %arg2, i32 %i.025
  %2 = load i16, ptr %arrayidx3, align 2
  %conv = sext i16 %2 to i32
  %conv4 = sext i16 %0 to i32
  %count.next = add i32 %conv4, %count
  %mul = mul nsw i32 %conv, %conv4
  %arrayidx6 = getelementptr inbounds i16, ptr %arg2, i32 %add
  %3 = load i16, ptr %arrayidx6, align 2
  %conv7 = sext i16 %3 to i32
  %conv8 = sext i16 %1 to i32
  %mul9 = mul nsw i32 %conv7, %conv8
  %add10 = add i32 %mul, %mac1.026
  %add11 = add i32 %mul9, %add10
  %exitcond = icmp ne i32 %add, %arg
  br i1 %exitcond, label %for.body, label %for.cond.cleanup
}

define i32 @mul_bottom_user(i32 %arg, ptr nocapture readnone %arg1, ptr nocapture readonly %arg2, ptr nocapture readonly %arg3) {
; CHECK-LE-LABEL: mul_bottom_user:
; CHECK-LE:       @ %bb.0: @ %entry
; CHECK-LE-NEXT:    .save {r4, lr}
; CHECK-LE-NEXT:    push {r4, lr}
; CHECK-LE-NEXT:    cmp r0, #1
; CHECK-LE-NEXT:    blt .LBB1_4
; CHECK-LE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-LE-NEXT:    sub.w lr, r3, #2
; CHECK-LE-NEXT:    subs r2, #2
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:  .LBB1_2: @ %for.body
; CHECK-LE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-LE-NEXT:    ldr r3, [lr, #2]!
; CHECK-LE-NEXT:    subs r0, #1
; CHECK-LE-NEXT:    ldr r4, [r2, #2]!
; CHECK-LE-NEXT:    smlad r12, r4, r3, r12
; CHECK-LE-NEXT:    sxth r3, r3
; CHECK-LE-NEXT:    mul r1, r3, r1
; CHECK-LE-NEXT:    bne .LBB1_2
; CHECK-LE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
; CHECK-LE-NEXT:  .LBB1_4:
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
;
; CHECK-BE-LABEL: mul_bottom_user:
; CHECK-BE:       @ %bb.0: @ %entry
; CHECK-BE-NEXT:    .save {r4, r5, r7, lr}
; CHECK-BE-NEXT:    push {r4, r5, r7, lr}
; CHECK-BE-NEXT:    cmp r0, #1
; CHECK-BE-NEXT:    blt .LBB1_4
; CHECK-BE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-BE-NEXT:    subs r3, #2
; CHECK-BE-NEXT:    subs r2, #2
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:  .LBB1_2: @ %for.body
; CHECK-BE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-BE-NEXT:    ldrsh lr, [r3, #2]!
; CHECK-BE-NEXT:    subs r0, #1
; CHECK-BE-NEXT:    ldrsh r4, [r2, #2]!
; CHECK-BE-NEXT:    ldrsh.w r5, [r2, #2]
; CHECK-BE-NEXT:    mul r1, lr, r1
; CHECK-BE-NEXT:    smlabb r12, r4, lr, r12
; CHECK-BE-NEXT:    ldrsh.w r4, [r3, #2]
; CHECK-BE-NEXT:    smlabb r12, r5, r4, r12
; CHECK-BE-NEXT:    bne .LBB1_2
; CHECK-BE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
; CHECK-BE-NEXT:  .LBB1_4:
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
entry:
  %cmp24 = icmp sgt i32 %arg, 0
  br i1 %cmp24, label %for.body.preheader, label %for.cond.cleanup

for.body.preheader:
  %.pre = load i16, ptr %arg3, align 2
  %.pre27 = load i16, ptr %arg2, align 2
  br label %for.body

for.cond.cleanup:
  %mac1.0.lcssa = phi i32 [ 0, %entry ], [ %add11, %for.body ]
  %count.final = phi i32 [ 0, %entry ], [ %count.next, %for.body ]
  %res = add i32 %mac1.0.lcssa, %count.final
  ret i32 %res

for.body:
  %mac1.026 = phi i32 [ %add11, %for.body ], [ 0, %for.body.preheader ]
  %i.025 = phi i32 [ %add, %for.body ], [ 0, %for.body.preheader ]
  %count = phi i32 [ %count.next, %for.body ], [ 0, %for.body.preheader ]
  %arrayidx = getelementptr inbounds i16, ptr %arg3, i32 %i.025
  %0 = load i16, ptr %arrayidx, align 2
  %add = add nuw nsw i32 %i.025, 1
  %arrayidx1 = getelementptr inbounds i16, ptr %arg3, i32 %add
  %1 = load i16, ptr %arrayidx1, align 2
  %arrayidx3 = getelementptr inbounds i16, ptr %arg2, i32 %i.025
  %2 = load i16, ptr %arrayidx3, align 2
  %conv = sext i16 %2 to i32
  %conv4 = sext i16 %0 to i32
  %mul = mul nsw i32 %conv, %conv4
  %arrayidx6 = getelementptr inbounds i16, ptr %arg2, i32 %add
  %3 = load i16, ptr %arrayidx6, align 2
  %conv7 = sext i16 %3 to i32
  %conv8 = sext i16 %1 to i32
  %mul9 = mul nsw i32 %conv7, %conv8
  %add10 = add i32 %mul, %mac1.026
  %add11 = add i32 %mul9, %add10
  %count.next = mul i32 %conv4, %count
  %exitcond = icmp ne i32 %add, %arg
  br i1 %exitcond, label %for.body, label %for.cond.cleanup
}

define i32 @mul_top_user(i32 %arg, ptr nocapture readnone %arg1, ptr nocapture readonly %arg2, ptr nocapture readonly %arg3) {
; CHECK-LE-LABEL: mul_top_user:
; CHECK-LE:       @ %bb.0: @ %entry
; CHECK-LE-NEXT:    .save {r4, lr}
; CHECK-LE-NEXT:    push {r4, lr}
; CHECK-LE-NEXT:    cmp r0, #1
; CHECK-LE-NEXT:    blt .LBB2_4
; CHECK-LE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-LE-NEXT:    subs r3, #2
; CHECK-LE-NEXT:    subs r2, #2
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:  .LBB2_2: @ %for.body
; CHECK-LE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-LE-NEXT:    ldr lr, [r3, #2]!
; CHECK-LE-NEXT:    subs r0, #1
; CHECK-LE-NEXT:    ldr r4, [r2, #2]!
; CHECK-LE-NEXT:    smlad r12, r4, lr, r12
; CHECK-LE-NEXT:    asr.w r4, r4, #16
; CHECK-LE-NEXT:    mul r1, r4, r1
; CHECK-LE-NEXT:    bne .LBB2_2
; CHECK-LE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
; CHECK-LE-NEXT:  .LBB2_4:
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
;
; CHECK-BE-LABEL: mul_top_user:
; CHECK-BE:       @ %bb.0: @ %entry
; CHECK-BE-NEXT:    .save {r4, lr}
; CHECK-BE-NEXT:    push {r4, lr}
; CHECK-BE-NEXT:    cmp r0, #1
; CHECK-BE-NEXT:    blt .LBB2_4
; CHECK-BE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-BE-NEXT:    subs r3, #2
; CHECK-BE-NEXT:    subs r2, #2
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:  .LBB2_2: @ %for.body
; CHECK-BE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-BE-NEXT:    ldrsh lr, [r3, #2]!
; CHECK-BE-NEXT:    subs r0, #1
; CHECK-BE-NEXT:    ldrsh r4, [r2, #2]!
; CHECK-BE-NEXT:    smlabb r12, r4, lr, r12
; CHECK-BE-NEXT:    ldrsh.w r4, [r2, #2]
; CHECK-BE-NEXT:    ldrsh.w lr, [r3, #2]
; CHECK-BE-NEXT:    mul r1, r4, r1
; CHECK-BE-NEXT:    smlabb r12, r4, lr, r12
; CHECK-BE-NEXT:    bne .LBB2_2
; CHECK-BE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, pc}
; CHECK-BE-NEXT:  .LBB2_4:
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, pc}
entry:
  %cmp24 = icmp sgt i32 %arg, 0
  br i1 %cmp24, label %for.body.preheader, label %for.cond.cleanup

for.body.preheader:
  %.pre = load i16, ptr %arg3, align 2
  %.pre27 = load i16, ptr %arg2, align 2
  br label %for.body

for.cond.cleanup:
  %mac1.0.lcssa = phi i32 [ 0, %entry ], [ %add11, %for.body ]
  %count.final = phi i32 [ 0, %entry ], [ %count.next, %for.body ]
  %res = add i32 %mac1.0.lcssa, %count.final
  ret i32 %res

for.body:
  %mac1.026 = phi i32 [ %add11, %for.body ], [ 0, %for.body.preheader ]
  %i.025 = phi i32 [ %add, %for.body ], [ 0, %for.body.preheader ]
  %count = phi i32 [ %count.next, %for.body ], [ 0, %for.body.preheader ]
  %arrayidx = getelementptr inbounds i16, ptr %arg3, i32 %i.025
  %0 = load i16, ptr %arrayidx, align 2
  %add = add nuw nsw i32 %i.025, 1
  %arrayidx1 = getelementptr inbounds i16, ptr %arg3, i32 %add
  %1 = load i16, ptr %arrayidx1, align 2
  %arrayidx3 = getelementptr inbounds i16, ptr %arg2, i32 %i.025
  %2 = load i16, ptr %arrayidx3, align 2
  %conv = sext i16 %2 to i32
  %conv4 = sext i16 %0 to i32
  %mul = mul nsw i32 %conv, %conv4
  %arrayidx6 = getelementptr inbounds i16, ptr %arg2, i32 %add
  %3 = load i16, ptr %arrayidx6, align 2
  %conv7 = sext i16 %3 to i32
  %conv8 = sext i16 %1 to i32
  %mul9 = mul nsw i32 %conv7, %conv8
  %add10 = add i32 %mul, %mac1.026
  %add11 = add i32 %mul9, %add10
  %count.next = mul i32 %conv7, %count
  %exitcond = icmp ne i32 %add, %arg
  br i1 %exitcond, label %for.body, label %for.cond.cleanup
}

define i32 @and_user(i32 %arg, ptr nocapture readnone %arg1, ptr nocapture readonly %arg2, ptr nocapture readonly %arg3) {
; CHECK-LE-LABEL: and_user:
; CHECK-LE:       @ %bb.0: @ %entry
; CHECK-LE-NEXT:    .save {r4, lr}
; CHECK-LE-NEXT:    push {r4, lr}
; CHECK-LE-NEXT:    cmp r0, #1
; CHECK-LE-NEXT:    blt .LBB3_4
; CHECK-LE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-LE-NEXT:    sub.w lr, r3, #2
; CHECK-LE-NEXT:    subs r2, #2
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:  .LBB3_2: @ %for.body
; CHECK-LE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-LE-NEXT:    ldr r3, [lr, #2]!
; CHECK-LE-NEXT:    subs r0, #1
; CHECK-LE-NEXT:    ldr r4, [r2, #2]!
; CHECK-LE-NEXT:    smlad r12, r4, r3, r12
; CHECK-LE-NEXT:    uxth r3, r3
; CHECK-LE-NEXT:    mul r1, r3, r1
; CHECK-LE-NEXT:    bne .LBB3_2
; CHECK-LE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
; CHECK-LE-NEXT:  .LBB3_4:
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    movs r1, #0
; CHECK-LE-NEXT:    add.w r0, r12, r1
; CHECK-LE-NEXT:    pop {r4, pc}
;
; CHECK-BE-LABEL: and_user:
; CHECK-BE:       @ %bb.0: @ %entry
; CHECK-BE-NEXT:    .save {r4, r5, r7, lr}
; CHECK-BE-NEXT:    push {r4, r5, r7, lr}
; CHECK-BE-NEXT:    cmp r0, #1
; CHECK-BE-NEXT:    blt .LBB3_4
; CHECK-BE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-BE-NEXT:    subs r3, #2
; CHECK-BE-NEXT:    subs r2, #2
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:  .LBB3_2: @ %for.body
; CHECK-BE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-BE-NEXT:    ldrh lr, [r3, #2]!
; CHECK-BE-NEXT:    subs r0, #1
; CHECK-BE-NEXT:    ldrsh r4, [r2, #2]!
; CHECK-BE-NEXT:    ldrsh.w r5, [r2, #2]
; CHECK-BE-NEXT:    mul r1, lr, r1
; CHECK-BE-NEXT:    smlabb r12, r4, lr, r12
; CHECK-BE-NEXT:    ldrsh.w r4, [r3, #2]
; CHECK-BE-NEXT:    smlabb r12, r5, r4, r12
; CHECK-BE-NEXT:    bne .LBB3_2
; CHECK-BE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
; CHECK-BE-NEXT:  .LBB3_4:
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    movs r1, #0
; CHECK-BE-NEXT:    add.w r0, r12, r1
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
entry:
  %cmp24 = icmp sgt i32 %arg, 0
  br i1 %cmp24, label %for.body.preheader, label %for.cond.cleanup

for.body.preheader:
  %.pre = load i16, ptr %arg3, align 2
  %.pre27 = load i16, ptr %arg2, align 2
  br label %for.body

for.cond.cleanup:
  %mac1.0.lcssa = phi i32 [ 0, %entry ], [ %add11, %for.body ]
  %count.final = phi i32 [ 0, %entry ], [ %count.next, %for.body ]
  %res = add i32 %mac1.0.lcssa, %count.final
  ret i32 %res

for.body:
  %mac1.026 = phi i32 [ %add11, %for.body ], [ 0, %for.body.preheader ]
  %i.025 = phi i32 [ %add, %for.body ], [ 0, %for.body.preheader ]
  %count = phi i32 [ %count.next, %for.body ], [ 0, %for.body.preheader ]
  %arrayidx = getelementptr inbounds i16, ptr %arg3, i32 %i.025
  %0 = load i16, ptr %arrayidx, align 2
  %add = add nuw nsw i32 %i.025, 1
  %arrayidx1 = getelementptr inbounds i16, ptr %arg3, i32 %add
  %arrayidx3 = getelementptr inbounds i16, ptr %arg2, i32 %i.025
  %arrayidx6 = getelementptr inbounds i16, ptr %arg2, i32 %add
  %1 = load i16, ptr %arrayidx1, align 2
  %2 = load i16, ptr %arrayidx3, align 2
  %conv = sext i16 %2 to i32
  %conv4 = sext i16 %0 to i32
  %bottom = and i32 %conv4, 65535
  %mul = mul nsw i32 %conv, %conv4
  %3 = load i16, ptr %arrayidx6, align 2
  %conv7 = sext i16 %3 to i32
  %conv8 = sext i16 %1 to i32
  %mul9 = mul nsw i32 %conv7, %conv8
  %add10 = add i32 %mul, %mac1.026
  %add11 = add i32 %mul9, %add10
  %count.next = mul i32 %bottom, %count
  %exitcond = icmp ne i32 %add, %arg
  br i1 %exitcond, label %for.body, label %for.cond.cleanup
}

define i32 @multi_uses(i32 %arg, ptr nocapture readnone %arg1, ptr nocapture readonly %arg2, ptr nocapture readonly %arg3) {
; CHECK-LE-LABEL: multi_uses:
; CHECK-LE:       @ %bb.0: @ %entry
; CHECK-LE-NEXT:    .save {r4, lr}
; CHECK-LE-NEXT:    push {r4, lr}
; CHECK-LE-NEXT:    cmp r0, #1
; CHECK-LE-NEXT:    blt .LBB4_4
; CHECK-LE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-LE-NEXT:    subs r3, #2
; CHECK-LE-NEXT:    subs r2, #2
; CHECK-LE-NEXT:    mov.w lr, #0
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:  .LBB4_2: @ %for.body
; CHECK-LE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-LE-NEXT:    ldr r1, [r3, #2]!
; CHECK-LE-NEXT:    subs r0, #1
; CHECK-LE-NEXT:    ldr r4, [r2, #2]!
; CHECK-LE-NEXT:    smlad lr, r4, r1, lr
; CHECK-LE-NEXT:    eor.w r4, r1, r12
; CHECK-LE-NEXT:    mul r1, r4, r1
; CHECK-LE-NEXT:    lsl.w r12, r1, #16
; CHECK-LE-NEXT:    bne .LBB4_2
; CHECK-LE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-LE-NEXT:    add.w r0, lr, r12
; CHECK-LE-NEXT:    pop {r4, pc}
; CHECK-LE-NEXT:  .LBB4_4:
; CHECK-LE-NEXT:    mov.w lr, #0
; CHECK-LE-NEXT:    mov.w r12, #0
; CHECK-LE-NEXT:    add.w r0, lr, r12
; CHECK-LE-NEXT:    pop {r4, pc}
;
; CHECK-BE-LABEL: multi_uses:
; CHECK-BE:       @ %bb.0: @ %entry
; CHECK-BE-NEXT:    .save {r4, r5, r7, lr}
; CHECK-BE-NEXT:    push {r4, r5, r7, lr}
; CHECK-BE-NEXT:    cmp r0, #1
; CHECK-BE-NEXT:    blt .LBB4_4
; CHECK-BE-NEXT:  @ %bb.1: @ %for.body.preheader
; CHECK-BE-NEXT:    subs r3, #2
; CHECK-BE-NEXT:    subs r2, #2
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    mov.w lr, #0
; CHECK-BE-NEXT:  .LBB4_2: @ %for.body
; CHECK-BE-NEXT:    @ =>This Inner Loop Header: Depth=1
; CHECK-BE-NEXT:    ldrsh r4, [r2, #2]!
; CHECK-BE-NEXT:    subs r0, #1
; CHECK-BE-NEXT:    ldrsh r1, [r3, #2]!
; CHECK-BE-NEXT:    ldrsh.w r5, [r2, #2]
; CHECK-BE-NEXT:    smlabb r12, r4, r1, r12
; CHECK-BE-NEXT:    ldrsh.w r4, [r3, #2]
; CHECK-BE-NEXT:    smlabb r12, r5, r4, r12
; CHECK-BE-NEXT:    eor.w r5, r1, lr
; CHECK-BE-NEXT:    mul r1, r5, r1
; CHECK-BE-NEXT:    lsl.w lr, r1, #16
; CHECK-BE-NEXT:    bne .LBB4_2
; CHECK-BE-NEXT:  @ %bb.3: @ %for.cond.cleanup
; CHECK-BE-NEXT:    add.w r0, r12, lr
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
; CHECK-BE-NEXT:  .LBB4_4:
; CHECK-BE-NEXT:    mov.w r12, #0
; CHECK-BE-NEXT:    mov.w lr, #0
; CHECK-BE-NEXT:    add.w r0, r12, lr
; CHECK-BE-NEXT:    pop {r4, r5, r7, pc}
entry:
  %cmp24 = icmp sgt i32 %arg, 0
  br i1 %cmp24, label %for.body.preheader, label %for.cond.cleanup

for.body.preheader:
  %.pre = load i16, ptr %arg3, align 2
  %.pre27 = load i16, ptr %arg2, align 2
  br label %for.body

for.cond.cleanup:
  %mac1.0.lcssa = phi i32 [ 0, %entry ], [ %add11, %for.body ]
  %count.final = phi i32 [ 0, %entry ], [ %count.next, %for.body ]
  %res = add i32 %mac1.0.lcssa, %count.final
  ret i32 %res

for.body:
  %mac1.026 = phi i32 [ %add11, %for.body ], [ 0, %for.body.preheader ]
  %i.025 = phi i32 [ %add, %for.body ], [ 0, %for.body.preheader ]
  %count = phi i32 [ %count.next, %for.body ], [ 0, %for.body.preheader ]
  %arrayidx = getelementptr inbounds i16, ptr %arg3, i32 %i.025
  %0 = load i16, ptr %arrayidx, align 2
  %add = add nuw nsw i32 %i.025, 1
  %arrayidx1 = getelementptr inbounds i16, ptr %arg3, i32 %add
  %arrayidx3 = getelementptr inbounds i16, ptr %arg2, i32 %i.025
  %arrayidx6 = getelementptr inbounds i16, ptr %arg2, i32 %add
  %1 = load i16, ptr %arrayidx1, align 2
  %2 = load i16, ptr %arrayidx3, align 2
  %conv = sext i16 %2 to i32
  %conv4 = sext i16 %0 to i32
  %bottom = and i32 %conv4, 65535
  %mul = mul nsw i32 %conv, %conv4
  %3 = load i16, ptr %arrayidx6, align 2
  %conv7 = sext i16 %3 to i32
  %conv8 = sext i16 %1 to i32
  %mul9 = mul nsw i32 %conv7, %conv8
  %add10 = add i32 %mul, %mac1.026
  %shl = shl i32 %conv4, 16
  %add11 = add i32 %mul9, %add10
  %xor = xor i32 %bottom, %count
  %count.next = mul i32 %xor, %shl
  %exitcond = icmp ne i32 %add, %arg
  br i1 %exitcond, label %for.body, label %for.cond.cleanup
}
