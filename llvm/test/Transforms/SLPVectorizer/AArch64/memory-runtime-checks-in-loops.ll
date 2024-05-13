; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=slp-vectorizer  -mtriple=arm64-apple-ios -S %s | FileCheck %s
; RUN: opt -aa-pipeline='basic-aa,scoped-noalias-aa' -passes=slp-vectorizer -mtriple=arm64-apple-darwin -S %s | FileCheck %s

define void @loop1(ptr %A, ptr %B, i64 %N) {
; CHECK-LABEL: @loop1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i64 [ 0, [[ENTRY:%.*]] ], [ [[IV_NEXT:%.*]], [[LOOP]] ]
; CHECK-NEXT:    [[B_GEP_0:%.*]] = getelementptr inbounds i32, ptr [[B:%.*]], i64 [[IV]]
; CHECK-NEXT:    [[B_0:%.*]] = load i32, ptr [[B_GEP_0]], align 4
; CHECK-NEXT:    [[A_GEP_0:%.*]] = getelementptr inbounds i32, ptr [[A:%.*]], i64 [[IV]]
; CHECK-NEXT:    [[A_0:%.*]] = load i32, ptr [[A_GEP_0]], align 4
; CHECK-NEXT:    [[ADD_0:%.*]] = add i32 [[A_0]], 20
; CHECK-NEXT:    [[XOR_0:%.*]] = xor i32 [[ADD_0]], [[B_0]]
; CHECK-NEXT:    store i32 [[XOR_0]], ptr [[A_GEP_0]], align 4
; CHECK-NEXT:    [[IV_1:%.*]] = or i64 [[IV]], 1
; CHECK-NEXT:    [[B_GEP_1:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[IV_1]]
; CHECK-NEXT:    [[B_1:%.*]] = load i32, ptr [[B_GEP_1]], align 4
; CHECK-NEXT:    [[A_GEP_1:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[IV_1]]
; CHECK-NEXT:    [[A_1:%.*]] = load i32, ptr [[A_GEP_1]], align 4
; CHECK-NEXT:    [[ADD_1:%.*]] = add i32 [[A_1]], 20
; CHECK-NEXT:    [[XOR_1:%.*]] = xor i32 [[ADD_1]], [[B_1]]
; CHECK-NEXT:    store i32 [[XOR_1]], ptr [[A_GEP_1]], align 4
; CHECK-NEXT:    [[IV_2:%.*]] = or i64 [[IV]], 2
; CHECK-NEXT:    [[B_GEP_2:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[IV_2]]
; CHECK-NEXT:    [[B_2:%.*]] = load i32, ptr [[B_GEP_2]], align 4
; CHECK-NEXT:    [[A_GEP_2:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[IV_2]]
; CHECK-NEXT:    [[A_2:%.*]] = load i32, ptr [[A_GEP_2]], align 4
; CHECK-NEXT:    [[ADD_2:%.*]] = add i32 [[A_2]], 20
; CHECK-NEXT:    [[XOR_2:%.*]] = xor i32 [[ADD_2]], [[B_2]]
; CHECK-NEXT:    store i32 [[XOR_2]], ptr [[A_GEP_2]], align 4
; CHECK-NEXT:    [[IV_3:%.*]] = or i64 [[IV]], 3
; CHECK-NEXT:    [[B_GEP_3:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[IV_3]]
; CHECK-NEXT:    [[B_3:%.*]] = load i32, ptr [[B_GEP_3]], align 4
; CHECK-NEXT:    [[A_GEP_3:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[IV_3]]
; CHECK-NEXT:    [[A_3:%.*]] = load i32, ptr [[A_GEP_3]], align 4
; CHECK-NEXT:    [[ADD_3:%.*]] = add i32 [[A_3]], 20
; CHECK-NEXT:    [[XOR_3:%.*]] = xor i32 [[ADD_3]], [[B_3]]
; CHECK-NEXT:    store i32 [[XOR_3]], ptr [[A_GEP_3]], align 4
; CHECK-NEXT:    [[IV_NEXT]] = add nuw nsw i64 [[IV]], 16
; CHECK-NEXT:    [[COND:%.*]] = icmp ult i64 [[IV_NEXT]], [[N:%.*]]
; CHECK-NEXT:    br i1 [[COND]], label [[LOOP]], label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
;
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %B.gep.0 = getelementptr inbounds i32, ptr %B, i64 %iv
  %B.0 = load i32, ptr %B.gep.0, align 4
  %A.gep.0 = getelementptr inbounds i32, ptr %A, i64 %iv
  %A.0 = load i32, ptr %A.gep.0, align 4
  %add.0 = add i32  %A.0, 20
  %xor.0 = xor i32 %add.0, %B.0
  store i32 %xor.0, ptr %A.gep.0, align 4
  %iv.1 = or i64 %iv, 1
  %B.gep.1 = getelementptr inbounds i32, ptr %B, i64 %iv.1
  %B.1 = load i32, ptr %B.gep.1, align 4
  %A.gep.1 = getelementptr inbounds i32, ptr %A, i64 %iv.1
  %A.1 = load i32, ptr %A.gep.1, align 4
  %add.1 = add i32  %A.1, 20
  %xor.1 = xor i32 %add.1, %B.1
  store i32 %xor.1, ptr %A.gep.1, align 4
  %iv.2 = or i64 %iv, 2
  %B.gep.2 = getelementptr inbounds i32, ptr %B, i64 %iv.2
  %B.2 = load i32, ptr %B.gep.2, align 4
  %A.gep.2 = getelementptr inbounds i32, ptr %A, i64 %iv.2
  %A.2 = load i32, ptr %A.gep.2, align 4
  %add.2 = add i32  %A.2, 20
  %xor.2 = xor i32 %add.2, %B.2
  store i32 %xor.2, ptr %A.gep.2, align 4
  %iv.3 = or i64 %iv, 3
  %B.gep.3 = getelementptr inbounds i32, ptr %B, i64 %iv.3
  %B.3 = load i32, ptr %B.gep.3, align 4
  %A.gep.3 = getelementptr inbounds i32, ptr %A, i64 %iv.3
  %A.3 = load i32, ptr %A.gep.3, align 4
  %add.3 = add i32  %A.3, 20
  %xor.3 = xor i32 %add.3, %B.3
  store i32 %xor.3, ptr %A.gep.3, align 4
  %iv.next = add nuw nsw i64 %iv, 16
  %cond = icmp ult i64 %iv.next, %N
  br i1 %cond, label %loop, label %exit

exit:
  ret void
}

define void @loop_iv_update_at_start(ptr %src, ptr %dst) #0 {
; CHECK-LABEL: @loop_iv_update_at_start(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i32 [ 0, [[ENTRY:%.*]] ], [ [[IV_NEXT:%.*]], [[LOOP]] ]
; CHECK-NEXT:    [[IV_NEXT]] = add i32 [[IV]], 1
; CHECK-NEXT:    [[COND:%.*]] = icmp ult i32 [[IV]], 2000
; CHECK-NEXT:    [[SRC_0:%.*]] = load float, ptr [[SRC:%.*]], align 8
; CHECK-NEXT:    [[ADD_0:%.*]] = fadd float [[SRC_0]], 1.000000e+00
; CHECK-NEXT:    [[MUL_0:%.*]] = fmul float [[ADD_0]], [[SRC_0]]
; CHECK-NEXT:    store float [[MUL_0]], ptr [[DST:%.*]], align 8
; CHECK-NEXT:    [[SRC_GEP_1:%.*]] = getelementptr inbounds float, ptr [[SRC]], i64 1
; CHECK-NEXT:    [[SRC_1:%.*]] = load float, ptr [[SRC_GEP_1]], align 8
; CHECK-NEXT:    [[ADD_1:%.*]] = fadd float [[SRC_1]], 1.000000e+00
; CHECK-NEXT:    [[MUL_1:%.*]] = fmul float [[ADD_1]], [[SRC_1]]
; CHECK-NEXT:    [[DST_GEP_1:%.*]] = getelementptr inbounds float, ptr [[DST]], i64 1
; CHECK-NEXT:    store float [[MUL_1]], ptr [[DST_GEP_1]], align 8
; CHECK-NEXT:    [[SRC_GEP_2:%.*]] = getelementptr inbounds float, ptr [[SRC]], i64 2
; CHECK-NEXT:    [[SRC_2:%.*]] = load float, ptr [[SRC_GEP_2]], align 8
; CHECK-NEXT:    [[ADD_2:%.*]] = fadd float [[SRC_2]], 1.000000e+00
; CHECK-NEXT:    [[MUL_2:%.*]] = fmul float [[ADD_2]], [[SRC_2]]
; CHECK-NEXT:    [[DST_GEP_2:%.*]] = getelementptr inbounds float, ptr [[DST]], i64 2
; CHECK-NEXT:    store float [[MUL_2]], ptr [[DST_GEP_2]], align 8
; CHECK-NEXT:    [[SRC_GEP_3:%.*]] = getelementptr inbounds float, ptr [[SRC]], i64 3
; CHECK-NEXT:    [[SRC_3:%.*]] = load float, ptr [[SRC_GEP_3]], align 8
; CHECK-NEXT:    [[ADD_3:%.*]] = fadd float [[SRC_3]], 1.000000e+00
; CHECK-NEXT:    [[MUL_3:%.*]] = fmul float [[ADD_3]], [[SRC_3]]
; CHECK-NEXT:    [[DST_GEP_3:%.*]] = getelementptr inbounds float, ptr [[DST]], i64 3
; CHECK-NEXT:    store float [[MUL_3]], ptr [[DST_GEP_3]], align 8
; CHECK-NEXT:    [[SRC_GEP_4:%.*]] = getelementptr inbounds float, ptr [[SRC]], i64 4
; CHECK-NEXT:    [[SRC_4:%.*]] = load float, ptr [[SRC_GEP_4]], align 8
; CHECK-NEXT:    [[ADD_4:%.*]] = fadd float [[SRC_4]], 1.000000e+00
; CHECK-NEXT:    [[MUL_4:%.*]] = fmul float [[ADD_4]], [[SRC_4]]
; CHECK-NEXT:    [[DST_GEP_4:%.*]] = getelementptr inbounds float, ptr [[DST]], i64 4
; CHECK-NEXT:    store float [[MUL_4]], ptr [[DST_GEP_4]], align 8
; CHECK-NEXT:    br i1 [[COND]], label [[LOOP]], label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
;
entry:
  br label %loop

loop:
  %iv = phi i32 [ 0, %entry ], [ %iv.next, %loop ]
  %iv.next = add i32 %iv, 1
  %cond = icmp ult i32 %iv, 2000

  %src.0 = load float, ptr %src, align 8
  %add.0 = fadd float %src.0, 1.0
  %mul.0 = fmul float %add.0, %src.0
  store float %mul.0, ptr %dst, align 8

  %src.gep.1 = getelementptr inbounds float, ptr %src, i64 1
  %src.1 = load float, ptr %src.gep.1, align 8
  %add.1 = fadd float %src.1, 1.0
  %mul.1 = fmul float %add.1, %src.1
  %dst.gep.1 = getelementptr inbounds float, ptr %dst, i64 1
  store float %mul.1, ptr %dst.gep.1, align 8
  %src.gep.2 = getelementptr inbounds float, ptr %src, i64 2
  %src.2 = load float, ptr %src.gep.2, align 8
  %add.2 = fadd float %src.2, 1.0
  %mul.2 = fmul float %add.2, %src.2
  %dst.gep.2 = getelementptr inbounds float, ptr %dst, i64 2
  store float %mul.2, ptr %dst.gep.2, align 8
  %src.gep.3 = getelementptr inbounds float, ptr %src, i64 3
  %src.3 = load float, ptr %src.gep.3, align 8
  %add.3 = fadd float %src.3, 1.0
  %mul.3 = fmul float %add.3, %src.3
  %dst.gep.3 = getelementptr inbounds float, ptr %dst, i64 3
  store float %mul.3, ptr %dst.gep.3, align 8
  %src.gep.4 = getelementptr inbounds float, ptr %src, i64 4
  %src.4 = load float, ptr %src.gep.4, align 8
  %add.4 = fadd float %src.4, 1.0
  %mul.4 = fmul float %add.4, %src.4
  %dst.gep.4 = getelementptr inbounds float, ptr %dst, i64 4
  store float %mul.4, ptr %dst.gep.4, align 8
  br i1 %cond, label %loop, label %exit

exit:
  ret void
}

; Similar to @loop1, but a load is used in a phi in the same basic block.
define i32 @value_used_in_phi(ptr %A, ptr %B, i64 %N) {
; CHECK-LABEL: @value_used_in_phi(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i64 [ 0, [[ENTRY:%.*]] ], [ [[IV_NEXT:%.*]], [[LOOP]] ]
; CHECK-NEXT:    [[P:%.*]] = phi i32 [ 0, [[ENTRY]] ], [ [[A_3:%.*]], [[LOOP]] ]
; CHECK-NEXT:    [[B_GEP_0:%.*]] = getelementptr inbounds i32, ptr [[B:%.*]], i64 [[IV]]
; CHECK-NEXT:    [[B_0:%.*]] = load i32, ptr [[B_GEP_0]], align 4
; CHECK-NEXT:    [[A_GEP_0:%.*]] = getelementptr inbounds i32, ptr [[A:%.*]], i64 [[IV]]
; CHECK-NEXT:    [[A_0:%.*]] = load i32, ptr [[A_GEP_0]], align 4
; CHECK-NEXT:    [[ADD_0:%.*]] = add i32 [[A_0]], 20
; CHECK-NEXT:    [[XOR_0:%.*]] = xor i32 [[ADD_0]], [[B_0]]
; CHECK-NEXT:    store i32 [[XOR_0]], ptr [[A_GEP_0]], align 4
; CHECK-NEXT:    [[IV_1:%.*]] = or i64 [[IV]], 1
; CHECK-NEXT:    [[B_GEP_1:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[IV_1]]
; CHECK-NEXT:    [[B_1:%.*]] = load i32, ptr [[B_GEP_1]], align 4
; CHECK-NEXT:    [[A_GEP_1:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[IV_1]]
; CHECK-NEXT:    [[A_1:%.*]] = load i32, ptr [[A_GEP_1]], align 4
; CHECK-NEXT:    [[ADD_1:%.*]] = add i32 [[A_1]], 20
; CHECK-NEXT:    [[XOR_1:%.*]] = xor i32 [[ADD_1]], [[B_1]]
; CHECK-NEXT:    store i32 [[XOR_1]], ptr [[A_GEP_1]], align 4
; CHECK-NEXT:    [[IV_2:%.*]] = or i64 [[IV]], 2
; CHECK-NEXT:    [[B_GEP_2:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[IV_2]]
; CHECK-NEXT:    [[B_2:%.*]] = load i32, ptr [[B_GEP_2]], align 4
; CHECK-NEXT:    [[A_GEP_2:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[IV_2]]
; CHECK-NEXT:    [[A_2:%.*]] = load i32, ptr [[A_GEP_2]], align 4
; CHECK-NEXT:    [[ADD_2:%.*]] = add i32 [[A_2]], 20
; CHECK-NEXT:    [[XOR_2:%.*]] = xor i32 [[ADD_2]], [[B_2]]
; CHECK-NEXT:    store i32 [[XOR_2]], ptr [[A_GEP_2]], align 4
; CHECK-NEXT:    [[IV_3:%.*]] = or i64 [[IV]], 3
; CHECK-NEXT:    [[B_GEP_3:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[IV_3]]
; CHECK-NEXT:    [[B_3:%.*]] = load i32, ptr [[B_GEP_3]], align 4
; CHECK-NEXT:    [[A_GEP_3:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[IV_3]]
; CHECK-NEXT:    [[A_3]] = load i32, ptr [[A_GEP_3]], align 4
; CHECK-NEXT:    [[ADD_3:%.*]] = add i32 [[A_3]], 20
; CHECK-NEXT:    [[XOR_3:%.*]] = xor i32 [[ADD_3]], [[B_3]]
; CHECK-NEXT:    store i32 [[XOR_3]], ptr [[A_GEP_3]], align 4
; CHECK-NEXT:    [[IV_NEXT]] = add nuw nsw i64 [[IV]], 16
; CHECK-NEXT:    [[COND:%.*]] = icmp ult i64 [[IV_NEXT]], [[N:%.*]]
; CHECK-NEXT:    br i1 [[COND]], label [[LOOP]], label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret i32 [[P]]
;
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %p = phi i32 [ 0, %entry ], [ %A.3, %loop ]
  %B.gep.0 = getelementptr inbounds i32, ptr %B, i64 %iv
  %B.0 = load i32, ptr %B.gep.0, align 4
  %A.gep.0 = getelementptr inbounds i32, ptr %A, i64 %iv
  %A.0 = load i32, ptr %A.gep.0, align 4
  %add.0 = add i32  %A.0, 20
  %xor.0 = xor i32 %add.0, %B.0
  store i32 %xor.0, ptr %A.gep.0, align 4
  %iv.1 = or i64 %iv, 1
  %B.gep.1 = getelementptr inbounds i32, ptr %B, i64 %iv.1
  %B.1 = load i32, ptr %B.gep.1, align 4
  %A.gep.1 = getelementptr inbounds i32, ptr %A, i64 %iv.1
  %A.1 = load i32, ptr %A.gep.1, align 4
  %add.1 = add i32  %A.1, 20
  %xor.1 = xor i32 %add.1, %B.1
  store i32 %xor.1, ptr %A.gep.1, align 4
  %iv.2 = or i64 %iv, 2
  %B.gep.2 = getelementptr inbounds i32, ptr %B, i64 %iv.2
  %B.2 = load i32, ptr %B.gep.2, align 4
  %A.gep.2 = getelementptr inbounds i32, ptr %A, i64 %iv.2
  %A.2 = load i32, ptr %A.gep.2, align 4
  %add.2 = add i32  %A.2, 20
  %xor.2 = xor i32 %add.2, %B.2
  store i32 %xor.2, ptr %A.gep.2, align 4
  %iv.3 = or i64 %iv, 3
  %B.gep.3 = getelementptr inbounds i32, ptr %B, i64 %iv.3
  %B.3 = load i32, ptr %B.gep.3, align 4
  %A.gep.3 = getelementptr inbounds i32, ptr %A, i64 %iv.3
  %A.3 = load i32, ptr %A.gep.3, align 4
  %add.3 = add i32  %A.3, 20
  %xor.3 = xor i32 %add.3, %B.3
  store i32 %xor.3, ptr %A.gep.3, align 4
  %iv.next = add nuw nsw i64 %iv, 16
  %cond = icmp ult i64 %iv.next, %N
  br i1 %cond, label %loop, label %exit

exit:
  ret i32 %p
}


