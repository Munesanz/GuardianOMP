; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=wasm32 -wasm-keep-registers %s -o - | FileCheck %s

target datalayout = "e-m:e-p:32:32-p10:8:8-p20:8:8-i64:64-n32:64-S128-ni:1:10:20"

define hidden void @one_dim(ptr nocapture noundef readonly %arg, ptr nocapture noundef readonly %arg1, ptr nocapture noundef writeonly %arg2) {
; CHECK-LABEL: one_dim:
; CHECK:         .functype one_dim (i32, i32, i32) -> ()
; CHECK-NEXT:    .local i32, i32, i32
; CHECK-NEXT:  # %bb.0: # %bb
; CHECK-NEXT:    i32.const $push22=, 0
; CHECK-NEXT:    local.set 3, $pop22
; CHECK-NEXT:  .LBB0_1: # %bb4
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    loop # label0:
; CHECK-NEXT:    local.get $push27=, 2
; CHECK-NEXT:    local.get $push24=, 1
; CHECK-NEXT:    local.get $push23=, 3
; CHECK-NEXT:    i32.add $push21=, $pop24, $pop23
; CHECK-NEXT:    local.tee $push20=, 4, $pop21
; CHECK-NEXT:    i32.load16_s $push1=, 0($pop20)
; CHECK-NEXT:    local.get $push26=, 0
; CHECK-NEXT:    local.get $push25=, 3
; CHECK-NEXT:    i32.add $push19=, $pop26, $pop25
; CHECK-NEXT:    local.tee $push18=, 5, $pop19
; CHECK-NEXT:    i32.load16_s $push0=, 0($pop18)
; CHECK-NEXT:    i32.add $push2=, $pop1, $pop0
; CHECK-NEXT:    i32.store 0($pop27), $pop2
; CHECK-NEXT:    local.get $push28=, 2
; CHECK-NEXT:    i32.const $push17=, 4
; CHECK-NEXT:    i32.add $push8=, $pop28, $pop17
; CHECK-NEXT:    local.get $push29=, 4
; CHECK-NEXT:    i32.const $push16=, 2
; CHECK-NEXT:    i32.add $push5=, $pop29, $pop16
; CHECK-NEXT:    i32.load16_s $push6=, 0($pop5)
; CHECK-NEXT:    local.get $push30=, 5
; CHECK-NEXT:    i32.const $push15=, 2
; CHECK-NEXT:    i32.add $push3=, $pop30, $pop15
; CHECK-NEXT:    i32.load16_s $push4=, 0($pop3)
; CHECK-NEXT:    i32.add $push7=, $pop6, $pop4
; CHECK-NEXT:    i32.store 0($pop8), $pop7
; CHECK-NEXT:    local.get $push32=, 2
; CHECK-NEXT:    i32.const $push14=, 8
; CHECK-NEXT:    i32.add $push31=, $pop32, $pop14
; CHECK-NEXT:    local.set 2, $pop31
; CHECK-NEXT:    local.get $push33=, 3
; CHECK-NEXT:    i32.const $push13=, 4
; CHECK-NEXT:    i32.add $push12=, $pop33, $pop13
; CHECK-NEXT:    local.tee $push11=, 3, $pop12
; CHECK-NEXT:    i32.const $push10=, 20000
; CHECK-NEXT:    i32.ne $push9=, $pop11, $pop10
; CHECK-NEXT:    br_if 0, $pop9 # 0: up to label0
; CHECK-NEXT:  # %bb.2: # %bb3
; CHECK-NEXT:    end_loop
; CHECK-NEXT:    # fallthrough-return
bb:
  br label %bb4

bb3:                                              ; preds = %bb4
  ret void

bb4:                                              ; preds = %bb4, %bb
  %i = phi i32 [ 0, %bb ], [ %i22, %bb4 ]
  %i5 = getelementptr inbounds i16, ptr %arg, i32 %i
  %i6 = load i16, ptr %i5, align 2
  %i7 = sext i16 %i6 to i32
  %i8 = getelementptr inbounds i16, ptr %arg1, i32 %i
  %i9 = load i16, ptr %i8, align 2
  %i10 = sext i16 %i9 to i32
  %i11 = add nsw i32 %i10, %i7
  %i12 = getelementptr inbounds i32, ptr %arg2, i32 %i
  store i32 %i11, ptr %i12, align 4
  %i13 = or i32 %i, 1
  %i14 = getelementptr inbounds i16, ptr %arg, i32 %i13
  %i15 = load i16, ptr %i14, align 2
  %i16 = sext i16 %i15 to i32
  %i17 = getelementptr inbounds i16, ptr %arg1, i32 %i13
  %i18 = load i16, ptr %i17, align 2
  %i19 = sext i16 %i18 to i32
  %i20 = add nsw i32 %i19, %i16
  %i21 = getelementptr inbounds i32, ptr %arg2, i32 %i13
  store i32 %i20, ptr %i21, align 4
  %i22 = add nuw nsw i32 %i, 2
  %i23 = icmp eq i32 %i22, 10000
  br i1 %i23, label %bb3, label %bb4
}

define hidden void @one_dim_no_inbound_loads(ptr nocapture noundef readonly %arg, ptr nocapture noundef readonly %arg1, ptr nocapture noundef writeonly %arg2) {
; CHECK-LABEL: one_dim_no_inbound_loads:
; CHECK:         .functype one_dim_no_inbound_loads (i32, i32, i32) -> ()
; CHECK-NEXT:    .local i32, i32, i32
; CHECK-NEXT:  # %bb.0: # %bb
; CHECK-NEXT:    i32.const $push22=, 0
; CHECK-NEXT:    local.set 3, $pop22
; CHECK-NEXT:  .LBB1_1: # %bb4
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    loop # label1:
; CHECK-NEXT:    local.get $push27=, 2
; CHECK-NEXT:    local.get $push24=, 1
; CHECK-NEXT:    local.get $push23=, 3
; CHECK-NEXT:    i32.add $push21=, $pop24, $pop23
; CHECK-NEXT:    local.tee $push20=, 4, $pop21
; CHECK-NEXT:    i32.load16_s $push1=, 0($pop20)
; CHECK-NEXT:    local.get $push26=, 0
; CHECK-NEXT:    local.get $push25=, 3
; CHECK-NEXT:    i32.add $push19=, $pop26, $pop25
; CHECK-NEXT:    local.tee $push18=, 5, $pop19
; CHECK-NEXT:    i32.load16_s $push0=, 0($pop18)
; CHECK-NEXT:    i32.add $push2=, $pop1, $pop0
; CHECK-NEXT:    i32.store 0($pop27), $pop2
; CHECK-NEXT:    local.get $push28=, 2
; CHECK-NEXT:    i32.const $push17=, 4
; CHECK-NEXT:    i32.add $push8=, $pop28, $pop17
; CHECK-NEXT:    local.get $push29=, 4
; CHECK-NEXT:    i32.const $push16=, 2
; CHECK-NEXT:    i32.add $push5=, $pop29, $pop16
; CHECK-NEXT:    i32.load16_s $push6=, 0($pop5)
; CHECK-NEXT:    local.get $push30=, 5
; CHECK-NEXT:    i32.const $push15=, 2
; CHECK-NEXT:    i32.add $push3=, $pop30, $pop15
; CHECK-NEXT:    i32.load16_s $push4=, 0($pop3)
; CHECK-NEXT:    i32.add $push7=, $pop6, $pop4
; CHECK-NEXT:    i32.store 0($pop8), $pop7
; CHECK-NEXT:    local.get $push32=, 2
; CHECK-NEXT:    i32.const $push14=, 8
; CHECK-NEXT:    i32.add $push31=, $pop32, $pop14
; CHECK-NEXT:    local.set 2, $pop31
; CHECK-NEXT:    local.get $push33=, 3
; CHECK-NEXT:    i32.const $push13=, 4
; CHECK-NEXT:    i32.add $push12=, $pop33, $pop13
; CHECK-NEXT:    local.tee $push11=, 3, $pop12
; CHECK-NEXT:    i32.const $push10=, 20000
; CHECK-NEXT:    i32.ne $push9=, $pop11, $pop10
; CHECK-NEXT:    br_if 0, $pop9 # 0: up to label1
; CHECK-NEXT:  # %bb.2: # %bb3
; CHECK-NEXT:    end_loop
; CHECK-NEXT:    # fallthrough-return
bb:
  br label %bb4

bb3:                                              ; preds = %bb4
  ret void

bb4:                                              ; preds = %bb4, %bb
  %i = phi i32 [ 0, %bb ], [ %i22, %bb4 ]
  %i5 = getelementptr i16, ptr %arg, i32 %i
  %i6 = load i16, ptr %i5, align 2
  %i7 = sext i16 %i6 to i32
  %i8 = getelementptr i16, ptr %arg1, i32 %i
  %i9 = load i16, ptr %i8, align 2
  %i10 = sext i16 %i9 to i32
  %i11 = add nsw i32 %i10, %i7
  %i12 = getelementptr inbounds i32, ptr %arg2, i32 %i
  store i32 %i11, ptr %i12, align 4
  %i13 = or i32 %i, 1
  %i14 = getelementptr i16, ptr %arg, i32 %i13
  %i15 = load i16, ptr %i14, align 2
  %i16 = sext i16 %i15 to i32
  %i17 = getelementptr i16, ptr %arg1, i32 %i13
  %i18 = load i16, ptr %i17, align 2
  %i19 = sext i16 %i18 to i32
  %i20 = add nsw i32 %i19, %i16
  %i21 = getelementptr inbounds i32, ptr %arg2, i32 %i13
  store i32 %i20, ptr %i21, align 4
  %i22 = add nuw nsw i32 %i, 2
  %i23 = icmp eq i32 %i22, 10000
  br i1 %i23, label %bb3, label %bb4
}

define hidden void @two_dims(ptr nocapture noundef readonly %arg, ptr nocapture noundef readonly %arg1, ptr nocapture noundef %arg2) {
; CHECK-LABEL: two_dims:
; CHECK:         .functype two_dims (i32, i32, i32) -> ()
; CHECK-NEXT:    .local i32, i32, i32, i32, i32, i32, i32, i32
; CHECK-NEXT:  # %bb.0: # %bb
; CHECK-NEXT:    i32.const $push48=, 0
; CHECK-NEXT:    local.set 3, $pop48
; CHECK-NEXT:  .LBB2_1: # %bb3
; CHECK-NEXT:    # =>This Loop Header: Depth=1
; CHECK-NEXT:    # Child Loop BB2_2 Depth 2
; CHECK-NEXT:    loop # label2:
; CHECK-NEXT:    local.get $push50=, 2
; CHECK-NEXT:    local.get $push49=, 3
; CHECK-NEXT:    i32.const $push29=, 2
; CHECK-NEXT:    i32.shl $push28=, $pop49, $pop29
; CHECK-NEXT:    local.tee $push27=, 4, $pop28
; CHECK-NEXT:    i32.add $push26=, $pop50, $pop27
; CHECK-NEXT:    local.tee $push25=, 5, $pop26
; CHECK-NEXT:    i32.load $push51=, 0($pop25)
; CHECK-NEXT:    local.set 6, $pop51
; CHECK-NEXT:    local.get $push53=, 1
; CHECK-NEXT:    local.get $push52=, 4
; CHECK-NEXT:    i32.add $push0=, $pop53, $pop52
; CHECK-NEXT:    i32.load $push54=, 0($pop0)
; CHECK-NEXT:    local.set 7, $pop54
; CHECK-NEXT:    local.get $push56=, 0
; CHECK-NEXT:    local.get $push55=, 4
; CHECK-NEXT:    i32.add $push1=, $pop56, $pop55
; CHECK-NEXT:    i32.load $push57=, 0($pop1)
; CHECK-NEXT:    local.set 8, $pop57
; CHECK-NEXT:    i32.const $push58=, 0
; CHECK-NEXT:    local.set 4, $pop58
; CHECK-NEXT:  .LBB2_2: # %bb14
; CHECK-NEXT:    # Parent Loop BB2_1 Depth=1
; CHECK-NEXT:    # => This Inner Loop Header: Depth=2
; CHECK-NEXT:    loop # label3:
; CHECK-NEXT:    local.get $push60=, 7
; CHECK-NEXT:    local.get $push59=, 4
; CHECK-NEXT:    i32.add $push43=, $pop60, $pop59
; CHECK-NEXT:    local.tee $push42=, 9, $pop43
; CHECK-NEXT:    i32.const $push41=, 6
; CHECK-NEXT:    i32.add $push20=, $pop42, $pop41
; CHECK-NEXT:    i32.load16_s $push21=, 0($pop20)
; CHECK-NEXT:    local.get $push62=, 8
; CHECK-NEXT:    local.get $push61=, 4
; CHECK-NEXT:    i32.add $push40=, $pop62, $pop61
; CHECK-NEXT:    local.tee $push39=, 10, $pop40
; CHECK-NEXT:    i32.const $push38=, 6
; CHECK-NEXT:    i32.add $push18=, $pop39, $pop38
; CHECK-NEXT:    i32.load16_s $push19=, 0($pop18)
; CHECK-NEXT:    i32.add $push22=, $pop21, $pop19
; CHECK-NEXT:    local.get $push63=, 9
; CHECK-NEXT:    i32.const $push37=, 4
; CHECK-NEXT:    i32.add $push14=, $pop63, $pop37
; CHECK-NEXT:    i32.load16_s $push15=, 0($pop14)
; CHECK-NEXT:    local.get $push64=, 10
; CHECK-NEXT:    i32.const $push36=, 4
; CHECK-NEXT:    i32.add $push12=, $pop64, $pop36
; CHECK-NEXT:    i32.load16_s $push13=, 0($pop12)
; CHECK-NEXT:    i32.add $push16=, $pop15, $pop13
; CHECK-NEXT:    local.get $push65=, 9
; CHECK-NEXT:    i32.const $push35=, 2
; CHECK-NEXT:    i32.add $push8=, $pop65, $pop35
; CHECK-NEXT:    i32.load16_s $push9=, 0($pop8)
; CHECK-NEXT:    local.get $push66=, 10
; CHECK-NEXT:    i32.const $push34=, 2
; CHECK-NEXT:    i32.add $push6=, $pop66, $pop34
; CHECK-NEXT:    i32.load16_s $push7=, 0($pop6)
; CHECK-NEXT:    i32.add $push10=, $pop9, $pop7
; CHECK-NEXT:    local.get $push67=, 9
; CHECK-NEXT:    i32.load16_s $push3=, 0($pop67)
; CHECK-NEXT:    local.get $push68=, 10
; CHECK-NEXT:    i32.load16_s $push2=, 0($pop68)
; CHECK-NEXT:    i32.add $push4=, $pop3, $pop2
; CHECK-NEXT:    local.get $push69=, 6
; CHECK-NEXT:    i32.add $push5=, $pop4, $pop69
; CHECK-NEXT:    i32.add $push11=, $pop10, $pop5
; CHECK-NEXT:    i32.add $push17=, $pop16, $pop11
; CHECK-NEXT:    i32.add $push70=, $pop22, $pop17
; CHECK-NEXT:    local.set 6, $pop70
; CHECK-NEXT:    local.get $push71=, 4
; CHECK-NEXT:    i32.const $push33=, 8
; CHECK-NEXT:    i32.add $push32=, $pop71, $pop33
; CHECK-NEXT:    local.tee $push31=, 4, $pop32
; CHECK-NEXT:    i32.const $push30=, 20000
; CHECK-NEXT:    i32.ne $push23=, $pop31, $pop30
; CHECK-NEXT:    br_if 0, $pop23 # 0: up to label3
; CHECK-NEXT:  # %bb.3: # %bb11
; CHECK-NEXT:    # in Loop: Header=BB2_1 Depth=1
; CHECK-NEXT:    end_loop
; CHECK-NEXT:    local.get $push73=, 5
; CHECK-NEXT:    local.get $push72=, 6
; CHECK-NEXT:    i32.store 0($pop73), $pop72
; CHECK-NEXT:    local.get $push74=, 3
; CHECK-NEXT:    i32.const $push47=, 1
; CHECK-NEXT:    i32.add $push46=, $pop74, $pop47
; CHECK-NEXT:    local.tee $push45=, 3, $pop46
; CHECK-NEXT:    i32.const $push44=, 10000
; CHECK-NEXT:    i32.ne $push24=, $pop45, $pop44
; CHECK-NEXT:    br_if 0, $pop24 # 0: up to label2
; CHECK-NEXT:  # %bb.4: # %bb10
; CHECK-NEXT:    end_loop
; CHECK-NEXT:    # fallthrough-return
bb:
  br label %bb3

bb3:                                              ; preds = %bb11, %bb
  %i = phi i32 [ 0, %bb ], [ %i12, %bb11 ]
  %i4 = getelementptr inbounds ptr, ptr %arg, i32 %i
  %i5 = load ptr, ptr %i4, align 4
  %i6 = getelementptr inbounds ptr, ptr %arg1, i32 %i
  %i7 = load ptr, ptr %i6, align 4
  %i8 = getelementptr inbounds i32, ptr %arg2, i32 %i
  %i9 = load i32, ptr %i8, align 4
  br label %bb14

bb10:                                             ; preds = %bb11
  ret void

bb11:                                             ; preds = %bb14
  store i32 %i51, ptr %i8, align 4
  %i12 = add nuw nsw i32 %i, 1
  %i13 = icmp eq i32 %i12, 10000
  br i1 %i13, label %bb10, label %bb3

bb14:                                             ; preds = %bb14, %bb3
  %i15 = phi i32 [ 0, %bb3 ], [ %i52, %bb14 ]
  %i16 = phi i32 [ %i9, %bb3 ], [ %i51, %bb14 ]
  %i17 = getelementptr inbounds i16, ptr %i5, i32 %i15
  %i18 = load i16, ptr %i17, align 2
  %i19 = sext i16 %i18 to i32
  %i20 = getelementptr inbounds i16, ptr %i7, i32 %i15
  %i21 = load i16, ptr %i20, align 2
  %i22 = sext i16 %i21 to i32
  %i23 = add nsw i32 %i22, %i19
  %i24 = add nsw i32 %i23, %i16
  %i25 = or i32 %i15, 1
  %i26 = getelementptr inbounds i16, ptr %i5, i32 %i25
  %i27 = load i16, ptr %i26, align 2
  %i28 = sext i16 %i27 to i32
  %i29 = getelementptr inbounds i16, ptr %i7, i32 %i25
  %i30 = load i16, ptr %i29, align 2
  %i31 = sext i16 %i30 to i32
  %i32 = add nsw i32 %i31, %i28
  %i33 = add nsw i32 %i32, %i24
  %i34 = or i32 %i15, 2
  %i35 = getelementptr inbounds i16, ptr %i5, i32 %i34
  %i36 = load i16, ptr %i35, align 2
  %i37 = sext i16 %i36 to i32
  %i38 = getelementptr inbounds i16, ptr %i7, i32 %i34
  %i39 = load i16, ptr %i38, align 2
  %i40 = sext i16 %i39 to i32
  %i41 = add nsw i32 %i40, %i37
  %i42 = add nsw i32 %i41, %i33
  %i43 = or i32 %i15, 3
  %i44 = getelementptr inbounds i16, ptr %i5, i32 %i43
  %i45 = load i16, ptr %i44, align 2
  %i46 = sext i16 %i45 to i32
  %i47 = getelementptr inbounds i16, ptr %i7, i32 %i43
  %i48 = load i16, ptr %i47, align 2
  %i49 = sext i16 %i48 to i32
  %i50 = add nsw i32 %i49, %i46
  %i51 = add nsw i32 %i50, %i42
  %i52 = add nuw nsw i32 %i15, 4
  %i53 = icmp eq i32 %i52, 10000
  br i1 %i53, label %bb11, label %bb14
}

define hidden void @runtime(ptr nocapture noundef readonly %arg, ptr nocapture noundef readonly %arg1, ptr nocapture noundef writeonly %arg2, i32 noundef %arg3) {
; CHECK-LABEL: runtime:
; CHECK:         .functype runtime (i32, i32, i32, i32) -> ()
; CHECK-NEXT:    .local i32, i32, i32, i32, i32
; CHECK-NEXT:  # %bb.0: # %bb
; CHECK-NEXT:    block
; CHECK-NEXT:    local.get $push32=, 3
; CHECK-NEXT:    i32.eqz $push64=, $pop32
; CHECK-NEXT:    br_if 0, $pop64 # 0: down to label4
; CHECK-NEXT:  # %bb.1: # %bb4
; CHECK-NEXT:    local.get $push34=, 3
; CHECK-NEXT:    i32.const $push0=, 1
; CHECK-NEXT:    i32.and $push33=, $pop34, $pop0
; CHECK-NEXT:    local.set 4, $pop33
; CHECK-NEXT:    i32.const $push35=, 0
; CHECK-NEXT:    local.set 5, $pop35
; CHECK-NEXT:    block
; CHECK-NEXT:    local.get $push36=, 3
; CHECK-NEXT:    i32.const $push20=, 1
; CHECK-NEXT:    i32.eq $push1=, $pop36, $pop20
; CHECK-NEXT:    br_if 0, $pop1 # 0: down to label5
; CHECK-NEXT:  # %bb.2: # %bb7
; CHECK-NEXT:    local.get $push38=, 3
; CHECK-NEXT:    i32.const $push2=, -2
; CHECK-NEXT:    i32.and $push37=, $pop38, $pop2
; CHECK-NEXT:    local.set 6, $pop37
; CHECK-NEXT:    i32.const $push39=, 0
; CHECK-NEXT:    local.set 5, $pop39
; CHECK-NEXT:    local.get $push40=, 0
; CHECK-NEXT:    local.set 3, $pop40
; CHECK-NEXT:    local.get $push41=, 1
; CHECK-NEXT:    local.set 7, $pop41
; CHECK-NEXT:    local.get $push42=, 2
; CHECK-NEXT:    local.set 8, $pop42
; CHECK-NEXT:  .LBB3_3: # %bb20
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    loop # label6:
; CHECK-NEXT:    local.get $push45=, 8
; CHECK-NEXT:    local.get $push43=, 3
; CHECK-NEXT:    f32.load $push4=, 0($pop43)
; CHECK-NEXT:    local.get $push44=, 7
; CHECK-NEXT:    f32.load $push3=, 0($pop44)
; CHECK-NEXT:    f32.add $push5=, $pop4, $pop3
; CHECK-NEXT:    f32.store 0($pop45), $pop5
; CHECK-NEXT:    local.get $push46=, 8
; CHECK-NEXT:    i32.const $push29=, 4
; CHECK-NEXT:    i32.add $push11=, $pop46, $pop29
; CHECK-NEXT:    local.get $push47=, 3
; CHECK-NEXT:    i32.const $push28=, 4
; CHECK-NEXT:    i32.add $push8=, $pop47, $pop28
; CHECK-NEXT:    f32.load $push9=, 0($pop8)
; CHECK-NEXT:    local.get $push48=, 7
; CHECK-NEXT:    i32.const $push27=, 4
; CHECK-NEXT:    i32.add $push6=, $pop48, $pop27
; CHECK-NEXT:    f32.load $push7=, 0($pop6)
; CHECK-NEXT:    f32.add $push10=, $pop9, $pop7
; CHECK-NEXT:    f32.store 0($pop11), $pop10
; CHECK-NEXT:    local.get $push50=, 3
; CHECK-NEXT:    i32.const $push26=, 8
; CHECK-NEXT:    i32.add $push49=, $pop50, $pop26
; CHECK-NEXT:    local.set 3, $pop49
; CHECK-NEXT:    local.get $push52=, 7
; CHECK-NEXT:    i32.const $push25=, 8
; CHECK-NEXT:    i32.add $push51=, $pop52, $pop25
; CHECK-NEXT:    local.set 7, $pop51
; CHECK-NEXT:    local.get $push54=, 8
; CHECK-NEXT:    i32.const $push24=, 8
; CHECK-NEXT:    i32.add $push53=, $pop54, $pop24
; CHECK-NEXT:    local.set 8, $pop53
; CHECK-NEXT:    local.get $push56=, 6
; CHECK-NEXT:    local.get $push55=, 5
; CHECK-NEXT:    i32.const $push23=, 2
; CHECK-NEXT:    i32.add $push22=, $pop55, $pop23
; CHECK-NEXT:    local.tee $push21=, 5, $pop22
; CHECK-NEXT:    i32.ne $push12=, $pop56, $pop21
; CHECK-NEXT:    br_if 0, $pop12 # 0: up to label6
; CHECK-NEXT:  .LBB3_4: # %bb9
; CHECK-NEXT:    end_loop
; CHECK-NEXT:    end_block # label5:
; CHECK-NEXT:    local.get $push57=, 4
; CHECK-NEXT:    i32.eqz $push65=, $pop57
; CHECK-NEXT:    br_if 0, $pop65 # 0: down to label4
; CHECK-NEXT:  # %bb.5: # %bb12
; CHECK-NEXT:    local.get $push59=, 2
; CHECK-NEXT:    local.get $push58=, 5
; CHECK-NEXT:    i32.const $push13=, 2
; CHECK-NEXT:    i32.shl $push31=, $pop58, $pop13
; CHECK-NEXT:    local.tee $push30=, 3, $pop31
; CHECK-NEXT:    i32.add $push19=, $pop59, $pop30
; CHECK-NEXT:    local.get $push61=, 0
; CHECK-NEXT:    local.get $push60=, 3
; CHECK-NEXT:    i32.add $push16=, $pop61, $pop60
; CHECK-NEXT:    f32.load $push17=, 0($pop16)
; CHECK-NEXT:    local.get $push63=, 1
; CHECK-NEXT:    local.get $push62=, 3
; CHECK-NEXT:    i32.add $push14=, $pop63, $pop62
; CHECK-NEXT:    f32.load $push15=, 0($pop14)
; CHECK-NEXT:    f32.add $push18=, $pop17, $pop15
; CHECK-NEXT:    f32.store 0($pop19), $pop18
; CHECK-NEXT:  .LBB3_6: # %bb19
; CHECK-NEXT:    end_block # label4:
; CHECK-NEXT:    # fallthrough-return
bb:
  %i = icmp eq i32 %arg3, 0
  br i1 %i, label %bb19, label %bb4

bb4:                                              ; preds = %bb
  %i5 = and i32 %arg3, 1
  %i6 = icmp eq i32 %arg3, 1
  br i1 %i6, label %bb9, label %bb7

bb7:                                              ; preds = %bb4
  %i8 = and i32 %arg3, -2
  br label %bb20

bb9:                                              ; preds = %bb20, %bb4
  %i10 = phi i32 [ 0, %bb4 ], [ %i36, %bb20 ]
  %i11 = icmp eq i32 %i5, 0
  br i1 %i11, label %bb19, label %bb12

bb12:                                             ; preds = %bb9
  %i13 = getelementptr inbounds float, ptr %arg, i32 %i10
  %i14 = load float, ptr %i13, align 4
  %i15 = getelementptr inbounds float, ptr %arg1, i32 %i10
  %i16 = load float, ptr %i15, align 4
  %i17 = fadd float %i14, %i16
  %i18 = getelementptr inbounds float, ptr %arg2, i32 %i10
  store float %i17, ptr %i18, align 4
  br label %bb19

bb19:                                             ; preds = %bb12, %bb9, %bb
  ret void

bb20:                                             ; preds = %bb20, %bb7
  %i21 = phi i32 [ 0, %bb7 ], [ %i36, %bb20 ]
  %i22 = phi i32 [ 0, %bb7 ], [ %i37, %bb20 ]
  %i23 = getelementptr inbounds float, ptr %arg, i32 %i21
  %i24 = load float, ptr %i23, align 4
  %i25 = getelementptr inbounds float, ptr %arg1, i32 %i21
  %i26 = load float, ptr %i25, align 4
  %i27 = fadd float %i24, %i26
  %i28 = getelementptr inbounds float, ptr %arg2, i32 %i21
  store float %i27, ptr %i28, align 4
  %i29 = or i32 %i21, 1
  %i30 = getelementptr inbounds float, ptr %arg, i32 %i29
  %i31 = load float, ptr %i30, align 4
  %i32 = getelementptr inbounds float, ptr %arg1, i32 %i29
  %i33 = load float, ptr %i32, align 4
  %i34 = fadd float %i31, %i33
  %i35 = getelementptr inbounds float, ptr %arg2, i32 %i29
  store float %i34, ptr %i35, align 4
  %i36 = add nuw i32 %i21, 2
  %i37 = add i32 %i22, 2
  %i38 = icmp eq i32 %i37, %i8
  br i1 %i38, label %bb9, label %bb20
}
