; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -mtriple aarch64-linux-gnu -mattr=+sve -passes=loop-vectorize,dce,instcombine -S \
; RUN:   -prefer-predicate-over-epilogue=scalar-epilogue < %s | FileCheck %s

; Ensure that we can vectorize loops such as:
;   int *ptr = c;
;   for (long long i = 0; i < n; i++) {
;     int X1 = *ptr++;
;     int X2 = *ptr++;
;     a[i] = X1 + 1;
;     b[i] = X2 + 1;
;   }
; with scalable vectors, including unrolling. The test below makes sure
; that we can use gather instructions with the correct offsets, taking
; vscale into account.

define void @widen_ptr_phi_unrolled(ptr noalias nocapture %a, ptr noalias nocapture %b, ptr nocapture readonly %c, i64 %n) #0 {
; CHECK-LABEL: @widen_ptr_phi_unrolled(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP1:%.*]] = shl nuw nsw i64 [[TMP0]], 3
; CHECK-NEXT:    [[MIN_ITERS_CHECK:%.*]] = icmp ugt i64 [[TMP1]], [[N:%.*]]
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK]], label [[SCALAR_PH:%.*]], label [[VECTOR_PH:%.*]]
; CHECK:       vector.ph:
; CHECK-NEXT:    [[TMP2:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP3:%.*]] = shl nuw nsw i64 [[TMP2]], 3
; CHECK-NEXT:    [[N_MOD_VF:%.*]] = urem i64 [[N]], [[TMP3]]
; CHECK-NEXT:    [[N_VEC:%.*]] = sub i64 [[N]], [[N_MOD_VF]]
; CHECK-NEXT:    [[TMP4:%.*]] = shl i64 [[N_VEC]], 3
; CHECK-NEXT:    [[IND_END:%.*]] = getelementptr i8, ptr [[C:%.*]], i64 [[TMP4]]
; CHECK-NEXT:    br label [[VECTOR_BODY:%.*]]
; CHECK:       vector.body:
; CHECK-NEXT:    [[POINTER_PHI:%.*]] = phi ptr [ [[C]], [[VECTOR_PH]] ], [ [[PTR_IND:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[INDEX:%.*]] = phi i64 [ 0, [[VECTOR_PH]] ], [ [[INDEX_NEXT:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP5:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP6:%.*]] = shl nuw nsw i64 [[TMP5]], 2
; CHECK-NEXT:    [[TMP7:%.*]] = shl nuw nsw i64 [[TMP5]], 6
; CHECK-NEXT:    [[TMP8:%.*]] = call <vscale x 4 x i64> @llvm.experimental.stepvector.nxv4i64()
; CHECK-NEXT:    [[VECTOR_GEP:%.*]] = shl <vscale x 4 x i64> [[TMP8]], shufflevector (<vscale x 4 x i64> insertelement (<vscale x 4 x i64> poison, i64 3, i64 0), <vscale x 4 x i64> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP9:%.*]] = getelementptr i8, ptr [[POINTER_PHI]], <vscale x 4 x i64> [[VECTOR_GEP]]
; CHECK-NEXT:    [[DOTSPLATINSERT2:%.*]] = insertelement <vscale x 4 x i64> poison, i64 [[TMP6]], i64 0
; CHECK-NEXT:    [[DOTSPLAT3:%.*]] = shufflevector <vscale x 4 x i64> [[DOTSPLATINSERT2]], <vscale x 4 x i64> poison, <vscale x 4 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP10:%.*]] = call <vscale x 4 x i64> @llvm.experimental.stepvector.nxv4i64()
; CHECK-NEXT:    [[TMP11:%.*]] = add <vscale x 4 x i64> [[DOTSPLAT3]], [[TMP10]]
; CHECK-NEXT:    [[VECTOR_GEP4:%.*]] = shl <vscale x 4 x i64> [[TMP11]], shufflevector (<vscale x 4 x i64> insertelement (<vscale x 4 x i64> poison, i64 3, i64 0), <vscale x 4 x i64> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP12:%.*]] = getelementptr i8, ptr [[POINTER_PHI]], <vscale x 4 x i64> [[VECTOR_GEP4]]
; CHECK-NEXT:    [[TMP13:%.*]] = getelementptr inbounds i32, <vscale x 4 x ptr> [[TMP9]], i64 1
; CHECK-NEXT:    [[TMP14:%.*]] = getelementptr inbounds i32, <vscale x 4 x ptr> [[TMP12]], i64 1
; CHECK-NEXT:    [[WIDE_MASKED_GATHER:%.*]] = call <vscale x 4 x i32> @llvm.masked.gather.nxv4i32.nxv4p0(<vscale x 4 x ptr> [[TMP9]], i32 4, <vscale x 4 x i1> shufflevector (<vscale x 4 x i1> insertelement (<vscale x 4 x i1> poison, i1 true, i64 0), <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer), <vscale x 4 x i32> poison)
; CHECK-NEXT:    [[WIDE_MASKED_GATHER5:%.*]] = call <vscale x 4 x i32> @llvm.masked.gather.nxv4i32.nxv4p0(<vscale x 4 x ptr> [[TMP12]], i32 4, <vscale x 4 x i1> shufflevector (<vscale x 4 x i1> insertelement (<vscale x 4 x i1> poison, i1 true, i64 0), <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer), <vscale x 4 x i32> poison)
; CHECK-NEXT:    [[WIDE_MASKED_GATHER6:%.*]] = call <vscale x 4 x i32> @llvm.masked.gather.nxv4i32.nxv4p0(<vscale x 4 x ptr> [[TMP13]], i32 4, <vscale x 4 x i1> shufflevector (<vscale x 4 x i1> insertelement (<vscale x 4 x i1> poison, i1 true, i64 0), <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer), <vscale x 4 x i32> poison)
; CHECK-NEXT:    [[WIDE_MASKED_GATHER7:%.*]] = call <vscale x 4 x i32> @llvm.masked.gather.nxv4i32.nxv4p0(<vscale x 4 x ptr> [[TMP14]], i32 4, <vscale x 4 x i1> shufflevector (<vscale x 4 x i1> insertelement (<vscale x 4 x i1> poison, i1 true, i64 0), <vscale x 4 x i1> poison, <vscale x 4 x i32> zeroinitializer), <vscale x 4 x i32> poison)
; CHECK-NEXT:    [[TMP15:%.*]] = add nsw <vscale x 4 x i32> [[WIDE_MASKED_GATHER]], shufflevector (<vscale x 4 x i32> insertelement (<vscale x 4 x i32> poison, i32 1, i64 0), <vscale x 4 x i32> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP16:%.*]] = add nsw <vscale x 4 x i32> [[WIDE_MASKED_GATHER5]], shufflevector (<vscale x 4 x i32> insertelement (<vscale x 4 x i32> poison, i32 1, i64 0), <vscale x 4 x i32> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP17:%.*]] = getelementptr inbounds i32, ptr [[A:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    store <vscale x 4 x i32> [[TMP15]], ptr [[TMP17]], align 4
; CHECK-NEXT:    [[TMP18:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP19:%.*]] = shl nuw nsw i64 [[TMP18]], 2
; CHECK-NEXT:    [[TMP20:%.*]] = getelementptr inbounds i32, ptr [[TMP17]], i64 [[TMP19]]
; CHECK-NEXT:    store <vscale x 4 x i32> [[TMP16]], ptr [[TMP20]], align 4
; CHECK-NEXT:    [[TMP21:%.*]] = add nsw <vscale x 4 x i32> [[WIDE_MASKED_GATHER6]], shufflevector (<vscale x 4 x i32> insertelement (<vscale x 4 x i32> poison, i32 1, i64 0), <vscale x 4 x i32> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP22:%.*]] = add nsw <vscale x 4 x i32> [[WIDE_MASKED_GATHER7]], shufflevector (<vscale x 4 x i32> insertelement (<vscale x 4 x i32> poison, i32 1, i64 0), <vscale x 4 x i32> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP23:%.*]] = getelementptr inbounds i32, ptr [[B:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    store <vscale x 4 x i32> [[TMP21]], ptr [[TMP23]], align 4
; CHECK-NEXT:    [[TMP24:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP25:%.*]] = shl nuw nsw i64 [[TMP24]], 2
; CHECK-NEXT:    [[TMP26:%.*]] = getelementptr inbounds i32, ptr [[TMP23]], i64 [[TMP25]]
; CHECK-NEXT:    store <vscale x 4 x i32> [[TMP22]], ptr [[TMP26]], align 4
; CHECK-NEXT:    [[TMP27:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP28:%.*]] = shl nuw nsw i64 [[TMP27]], 3
; CHECK-NEXT:    [[INDEX_NEXT]] = add nuw i64 [[INDEX]], [[TMP28]]
; CHECK-NEXT:    [[PTR_IND]] = getelementptr i8, ptr [[POINTER_PHI]], i64 [[TMP7]]
; CHECK-NEXT:    [[TMP29:%.*]] = icmp eq i64 [[INDEX_NEXT]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[TMP29]], label [[MIDDLE_BLOCK:%.*]], label [[VECTOR_BODY]], !llvm.loop [[LOOP0:![0-9]+]]
; CHECK:       middle.block:
; CHECK-NEXT:    [[CMP_N:%.*]] = icmp eq i64 [[N_MOD_VF]], 0
; CHECK-NEXT:    br i1 [[CMP_N]], label [[FOR_EXIT:%.*]], label [[SCALAR_PH]]
; CHECK:       scalar.ph:
; CHECK-NEXT:    [[BC_RESUME_VAL:%.*]] = phi ptr [ [[IND_END]], [[MIDDLE_BLOCK]] ], [ [[C]], [[ENTRY:%.*]] ]
; CHECK-NEXT:    [[BC_RESUME_VAL1:%.*]] = phi i64 [ [[N_VEC]], [[MIDDLE_BLOCK]] ], [ 0, [[ENTRY]] ]
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[PTR_014:%.*]] = phi ptr [ [[INCDEC_PTR1:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[I_013:%.*]] = phi i64 [ [[INC:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL1]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[INCDEC_PTR:%.*]] = getelementptr inbounds i32, ptr [[PTR_014]], i64 1
; CHECK-NEXT:    [[TMP30:%.*]] = load i32, ptr [[PTR_014]], align 4
; CHECK-NEXT:    [[INCDEC_PTR1]] = getelementptr inbounds i32, ptr [[PTR_014]], i64 2
; CHECK-NEXT:    [[TMP31:%.*]] = load i32, ptr [[INCDEC_PTR]], align 4
; CHECK-NEXT:    [[ADD:%.*]] = add nsw i32 [[TMP30]], 1
; CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[I_013]]
; CHECK-NEXT:    store i32 [[ADD]], ptr [[ARRAYIDX]], align 4
; CHECK-NEXT:    [[ADD2:%.*]] = add nsw i32 [[TMP31]], 1
; CHECK-NEXT:    [[ARRAYIDX3:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[I_013]]
; CHECK-NEXT:    store i32 [[ADD2]], ptr [[ARRAYIDX3]], align 4
; CHECK-NEXT:    [[INC]] = add nuw nsw i64 [[I_013]], 1
; CHECK-NEXT:    [[EXITCOND_NOT:%.*]] = icmp eq i64 [[INC]], [[N]]
; CHECK-NEXT:    br i1 [[EXITCOND_NOT]], label [[FOR_EXIT]], label [[FOR_BODY]], !llvm.loop [[LOOP4:![0-9]+]]
; CHECK:       for.exit:
; CHECK-NEXT:    ret void
;
entry:
  br label %for.body

for.body:                                         ; preds = %entry, %for.body
  %ptr.014 = phi ptr [ %incdec.ptr1, %for.body ], [ %c, %entry ]
  %i.013 = phi i64 [ %inc, %for.body ], [ 0, %entry ]
  %incdec.ptr = getelementptr inbounds i32, ptr %ptr.014, i64 1
  %0 = load i32, ptr %ptr.014, align 4
  %incdec.ptr1 = getelementptr inbounds i32, ptr %ptr.014, i64 2
  %1 = load i32, ptr %incdec.ptr, align 4
  %add = add nsw i32 %0, 1
  %arrayidx = getelementptr inbounds i32, ptr %a, i64 %i.013
  store i32 %add, ptr %arrayidx, align 4
  %add2 = add nsw i32 %1, 1
  %arrayidx3 = getelementptr inbounds i32, ptr %b, i64 %i.013
  store i32 %add2, ptr %arrayidx3, align 4
  %inc = add nuw nsw i64 %i.013, 1
  %exitcond.not = icmp eq i64 %inc, %n
  br i1 %exitcond.not, label %for.exit, label %for.body, !llvm.loop !0

for.exit:                                 ; preds = %for.body
  ret void
}


; Ensure we can vectorise loops without interleaving, e.g.:
;   int *D = dst;
;   int *S = src;
;   for (long long i = 0; i < n; i++) {
;     *D = *S * 2;
;     D++;
;     S++;
;   }
; This takes us down a different codepath to the test above, where
; here we treat the PHIs as being uniform.

define void @widen_2ptrs_phi_unrolled(ptr noalias nocapture %dst, ptr noalias nocapture readonly %src, i64 %n) #0 {
; CHECK-LABEL: @widen_2ptrs_phi_unrolled(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP1:%.*]] = shl nuw nsw i64 [[TMP0]], 3
; CHECK-NEXT:    [[MIN_ITERS_CHECK:%.*]] = icmp ugt i64 [[TMP1]], [[N:%.*]]
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK]], label [[SCALAR_PH:%.*]], label [[VECTOR_PH:%.*]]
; CHECK:       vector.ph:
; CHECK-NEXT:    [[TMP2:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP3:%.*]] = shl nuw nsw i64 [[TMP2]], 3
; CHECK-NEXT:    [[N_MOD_VF:%.*]] = urem i64 [[N]], [[TMP3]]
; CHECK-NEXT:    [[N_VEC:%.*]] = sub i64 [[N]], [[N_MOD_VF]]
; CHECK-NEXT:    [[TMP4:%.*]] = shl i64 [[N_VEC]], 2
; CHECK-NEXT:    [[IND_END:%.*]] = getelementptr i8, ptr [[SRC:%.*]], i64 [[TMP4]]
; CHECK-NEXT:    [[TMP5:%.*]] = shl i64 [[N_VEC]], 2
; CHECK-NEXT:    [[IND_END2:%.*]] = getelementptr i8, ptr [[DST:%.*]], i64 [[TMP5]]
; CHECK-NEXT:    br label [[VECTOR_BODY:%.*]]
; CHECK:       vector.body:
; CHECK-NEXT:    [[INDEX:%.*]] = phi i64 [ 0, [[VECTOR_PH]] ], [ [[INDEX_NEXT:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP6:%.*]] = shl i64 [[INDEX]], 2
; CHECK-NEXT:    [[NEXT_GEP:%.*]] = getelementptr i8, ptr [[SRC]], i64 [[TMP6]]
; CHECK-NEXT:    [[TMP7:%.*]] = shl i64 [[INDEX]], 2
; CHECK-NEXT:    [[NEXT_GEP5:%.*]] = getelementptr i8, ptr [[DST]], i64 [[TMP7]]
; CHECK-NEXT:    [[WIDE_LOAD:%.*]] = load <vscale x 4 x i32>, ptr [[NEXT_GEP]], align 4
; CHECK-NEXT:    [[TMP8:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP9:%.*]] = shl nuw nsw i64 [[TMP8]], 2
; CHECK-NEXT:    [[TMP10:%.*]] = getelementptr i32, ptr [[NEXT_GEP]], i64 [[TMP9]]
; CHECK-NEXT:    [[WIDE_LOAD7:%.*]] = load <vscale x 4 x i32>, ptr [[TMP10]], align 4
; CHECK-NEXT:    [[TMP11:%.*]] = shl nsw <vscale x 4 x i32> [[WIDE_LOAD]], shufflevector (<vscale x 4 x i32> insertelement (<vscale x 4 x i32> poison, i32 1, i64 0), <vscale x 4 x i32> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP12:%.*]] = shl nsw <vscale x 4 x i32> [[WIDE_LOAD7]], shufflevector (<vscale x 4 x i32> insertelement (<vscale x 4 x i32> poison, i32 1, i64 0), <vscale x 4 x i32> poison, <vscale x 4 x i32> zeroinitializer)
; CHECK-NEXT:    store <vscale x 4 x i32> [[TMP11]], ptr [[NEXT_GEP5]], align 4
; CHECK-NEXT:    [[TMP13:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP14:%.*]] = shl nuw nsw i64 [[TMP13]], 2
; CHECK-NEXT:    [[TMP15:%.*]] = getelementptr i32, ptr [[NEXT_GEP5]], i64 [[TMP14]]
; CHECK-NEXT:    store <vscale x 4 x i32> [[TMP12]], ptr [[TMP15]], align 4
; CHECK-NEXT:    [[TMP16:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP17:%.*]] = shl nuw nsw i64 [[TMP16]], 3
; CHECK-NEXT:    [[INDEX_NEXT]] = add nuw i64 [[INDEX]], [[TMP17]]
; CHECK-NEXT:    [[TMP18:%.*]] = icmp eq i64 [[INDEX_NEXT]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[TMP18]], label [[MIDDLE_BLOCK:%.*]], label [[VECTOR_BODY]], !llvm.loop [[LOOP5:![0-9]+]]
; CHECK:       middle.block:
; CHECK-NEXT:    [[CMP_N:%.*]] = icmp eq i64 [[N_MOD_VF]], 0
; CHECK-NEXT:    br i1 [[CMP_N]], label [[FOR_COND_CLEANUP:%.*]], label [[SCALAR_PH]]
; CHECK:       scalar.ph:
; CHECK-NEXT:    [[BC_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC]], [[MIDDLE_BLOCK]] ], [ 0, [[ENTRY:%.*]] ]
; CHECK-NEXT:    [[BC_RESUME_VAL1:%.*]] = phi ptr [ [[IND_END]], [[MIDDLE_BLOCK]] ], [ [[SRC]], [[ENTRY]] ]
; CHECK-NEXT:    [[BC_RESUME_VAL3:%.*]] = phi ptr [ [[IND_END2]], [[MIDDLE_BLOCK]] ], [ [[DST]], [[ENTRY]] ]
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[I_011:%.*]] = phi i64 [ [[INC:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[S_010:%.*]] = phi ptr [ [[INCDEC_PTR1:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL1]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[D_09:%.*]] = phi ptr [ [[INCDEC_PTR:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL3]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[TMP19:%.*]] = load i32, ptr [[S_010]], align 4
; CHECK-NEXT:    [[MUL:%.*]] = shl nsw i32 [[TMP19]], 1
; CHECK-NEXT:    store i32 [[MUL]], ptr [[D_09]], align 4
; CHECK-NEXT:    [[INCDEC_PTR]] = getelementptr inbounds i32, ptr [[D_09]], i64 1
; CHECK-NEXT:    [[INCDEC_PTR1]] = getelementptr inbounds i32, ptr [[S_010]], i64 1
; CHECK-NEXT:    [[INC]] = add nuw nsw i64 [[I_011]], 1
; CHECK-NEXT:    [[EXITCOND_NOT:%.*]] = icmp eq i64 [[INC]], [[N]]
; CHECK-NEXT:    br i1 [[EXITCOND_NOT]], label [[FOR_COND_CLEANUP]], label [[FOR_BODY]], !llvm.loop [[LOOP6:![0-9]+]]
; CHECK:       for.cond.cleanup:
; CHECK-NEXT:    ret void
;
entry:
  br label %for.body

for.body:                                         ; preds = %entry, %for.body
  %i.011 = phi i64 [ %inc, %for.body ], [ 0, %entry ]
  %S.010 = phi ptr [ %incdec.ptr1, %for.body ], [ %src, %entry ]
  %D.09 = phi ptr [ %incdec.ptr, %for.body ], [ %dst, %entry ]
  %0 = load i32, ptr %S.010, align 4
  %mul = shl nsw i32 %0, 1
  store i32 %mul, ptr %D.09, align 4
  %incdec.ptr = getelementptr inbounds i32, ptr %D.09, i64 1
  %incdec.ptr1 = getelementptr inbounds i32, ptr %S.010, i64 1
  %inc = add nuw nsw i64 %i.011, 1
  %exitcond.not = icmp eq i64 %inc, %n
  br i1 %exitcond.not, label %for.cond.cleanup, label %for.body, !llvm.loop !0

for.cond.cleanup:                                 ; preds = %for.body
  ret void
}


;
; Check multiple pointer induction variables where only one is recognized as
; uniform and remains uniform after vectorization. The other pointer induction
; variable is not recognized as uniform and is not uniform after vectorization
; because it is stored to memory.
;

define i32 @pointer_iv_mixed(ptr noalias %a, ptr noalias %b, i64 %n) #0 {
; CHECK-LABEL: @pointer_iv_mixed(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SMAX:%.*]] = call i64 @llvm.smax.i64(i64 [[N:%.*]], i64 1)
; CHECK-NEXT:    [[TMP0:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP1:%.*]] = shl nuw nsw i64 [[TMP0]], 1
; CHECK-NEXT:    [[MIN_ITERS_CHECK:%.*]] = icmp ult i64 [[SMAX]], [[TMP1]]
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK]], label [[SCALAR_PH:%.*]], label [[VECTOR_PH:%.*]]
; CHECK:       vector.ph:
; CHECK-NEXT:    [[TMP2:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP3:%.*]] = shl nuw nsw i64 [[TMP2]], 1
; CHECK-NEXT:    [[N_MOD_VF:%.*]] = urem i64 [[SMAX]], [[TMP3]]
; CHECK-NEXT:    [[N_VEC:%.*]] = sub nsw i64 [[SMAX]], [[N_MOD_VF]]
; CHECK-NEXT:    [[TMP4:%.*]] = shl i64 [[N_VEC]], 2
; CHECK-NEXT:    [[IND_END:%.*]] = getelementptr i8, ptr [[A:%.*]], i64 [[TMP4]]
; CHECK-NEXT:    [[TMP5:%.*]] = shl i64 [[N_VEC]], 3
; CHECK-NEXT:    [[IND_END2:%.*]] = getelementptr i8, ptr [[B:%.*]], i64 [[TMP5]]
; CHECK-NEXT:    br label [[VECTOR_BODY:%.*]]
; CHECK:       vector.body:
; CHECK-NEXT:    [[POINTER_PHI:%.*]] = phi ptr [ [[A]], [[VECTOR_PH]] ], [ [[PTR_IND:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[INDEX:%.*]] = phi i64 [ 0, [[VECTOR_PH]] ], [ [[INDEX_NEXT:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[VEC_PHI:%.*]] = phi <vscale x 2 x i32> [ zeroinitializer, [[VECTOR_PH]] ], [ [[TMP12:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP6:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP7:%.*]] = shl nuw nsw i64 [[TMP6]], 3
; CHECK-NEXT:    [[TMP8:%.*]] = call <vscale x 2 x i64> @llvm.experimental.stepvector.nxv2i64()
; CHECK-NEXT:    [[VECTOR_GEP:%.*]] = shl <vscale x 2 x i64> [[TMP8]], shufflevector (<vscale x 2 x i64> insertelement (<vscale x 2 x i64> poison, i64 2, i64 0), <vscale x 2 x i64> poison, <vscale x 2 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP9:%.*]] = getelementptr i8, ptr [[POINTER_PHI]], <vscale x 2 x i64> [[VECTOR_GEP]]
; CHECK-NEXT:    [[TMP10:%.*]] = shl i64 [[INDEX]], 3
; CHECK-NEXT:    [[NEXT_GEP:%.*]] = getelementptr i8, ptr [[B]], i64 [[TMP10]]
; CHECK-NEXT:    [[TMP11:%.*]] = extractelement <vscale x 2 x ptr> [[TMP9]], i64 0
; CHECK-NEXT:    [[WIDE_LOAD:%.*]] = load <vscale x 2 x i32>, ptr [[TMP11]], align 8
; CHECK-NEXT:    [[TMP12]] = add <vscale x 2 x i32> [[WIDE_LOAD]], [[VEC_PHI]]
; CHECK-NEXT:    store <vscale x 2 x ptr> [[TMP9]], ptr [[NEXT_GEP]], align 8
; CHECK-NEXT:    [[TMP13:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP14:%.*]] = shl nuw nsw i64 [[TMP13]], 1
; CHECK-NEXT:    [[INDEX_NEXT]] = add nuw i64 [[INDEX]], [[TMP14]]
; CHECK-NEXT:    [[PTR_IND]] = getelementptr i8, ptr [[POINTER_PHI]], i64 [[TMP7]]
; CHECK-NEXT:    [[TMP15:%.*]] = icmp eq i64 [[INDEX_NEXT]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[TMP15]], label [[MIDDLE_BLOCK:%.*]], label [[VECTOR_BODY]], !llvm.loop [[LOOP7:![0-9]+]]
; CHECK:       middle.block:
; CHECK-NEXT:    [[TMP16:%.*]] = call i32 @llvm.vector.reduce.add.nxv2i32(<vscale x 2 x i32> [[TMP12]])
; CHECK-NEXT:    [[CMP_N:%.*]] = icmp eq i64 [[N_MOD_VF]], 0
; CHECK-NEXT:    br i1 [[CMP_N]], label [[FOR_END:%.*]], label [[SCALAR_PH]]
; CHECK:       scalar.ph:
; CHECK-NEXT:    [[BC_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC]], [[MIDDLE_BLOCK]] ], [ 0, [[ENTRY:%.*]] ]
; CHECK-NEXT:    [[BC_RESUME_VAL1:%.*]] = phi ptr [ [[IND_END]], [[MIDDLE_BLOCK]] ], [ [[A]], [[ENTRY]] ]
; CHECK-NEXT:    [[BC_RESUME_VAL3:%.*]] = phi ptr [ [[IND_END2]], [[MIDDLE_BLOCK]] ], [ [[B]], [[ENTRY]] ]
; CHECK-NEXT:    [[BC_MERGE_RDX:%.*]] = phi i32 [ [[TMP16]], [[MIDDLE_BLOCK]] ], [ 0, [[ENTRY]] ]
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[I:%.*]] = phi i64 [ [[I_NEXT:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[P:%.*]] = phi ptr [ [[VAR3:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL1]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[Q:%.*]] = phi ptr [ [[VAR4:%.*]], [[FOR_BODY]] ], [ [[BC_RESUME_VAL3]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[VAR0:%.*]] = phi i32 [ [[VAR2:%.*]], [[FOR_BODY]] ], [ [[BC_MERGE_RDX]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[VAR1:%.*]] = load i32, ptr [[P]], align 8
; CHECK-NEXT:    [[VAR2]] = add i32 [[VAR1]], [[VAR0]]
; CHECK-NEXT:    store ptr [[P]], ptr [[Q]], align 8
; CHECK-NEXT:    [[VAR3]] = getelementptr inbounds i32, ptr [[P]], i64 1
; CHECK-NEXT:    [[VAR4]] = getelementptr inbounds ptr, ptr [[Q]], i64 1
; CHECK-NEXT:    [[I_NEXT]] = add nuw nsw i64 [[I]], 1
; CHECK-NEXT:    [[COND:%.*]] = icmp slt i64 [[I_NEXT]], [[N]]
; CHECK-NEXT:    br i1 [[COND]], label [[FOR_BODY]], label [[FOR_END]], !llvm.loop [[LOOP8:![0-9]+]]
; CHECK:       for.end:
; CHECK-NEXT:    [[VAR5:%.*]] = phi i32 [ [[VAR2]], [[FOR_BODY]] ], [ [[TMP16]], [[MIDDLE_BLOCK]] ]
; CHECK-NEXT:    ret i32 [[VAR5]]
;
entry:
  br label %for.body

for.body:
  %i = phi i64 [ %i.next, %for.body ], [ 0, %entry ]
  %p = phi ptr [ %var3, %for.body ], [ %a, %entry ]
  %q = phi ptr [ %var4, %for.body ], [ %b, %entry ]
  %var0 = phi i32 [ %var2, %for.body ], [ 0, %entry ]
  %var1 = load i32, ptr %p, align 8
  %var2 = add i32 %var1, %var0
  store ptr %p, ptr %q, align 8
  %var3 = getelementptr inbounds i32, ptr %p, i32 1
  %var4 = getelementptr inbounds ptr, ptr %q, i32 1
  %i.next = add nuw nsw i64 %i, 1
  %cond = icmp slt i64 %i.next, %n
  br i1 %cond, label %for.body, label %for.end, !llvm.loop !6

for.end:
  %var5 = phi i32 [ %var2, %for.body ]
  ret i32 %var5
}

define void @phi_used_in_vector_compare_and_scalar_indvar_update_and_store(ptr %ptr) #0 {
; CHECK-LABEL: @phi_used_in_vector_compare_and_scalar_indvar_update_and_store(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 false, label [[SCALAR_PH:%.*]], label [[VECTOR_PH:%.*]]
; CHECK:       vector.ph:
; CHECK-NEXT:    [[TMP0:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP1:%.*]] = shl nuw nsw i64 [[TMP0]], 1
; CHECK-NEXT:    [[N_MOD_VF:%.*]] = urem i64 1024, [[TMP1]]
; CHECK-NEXT:    [[N_VEC:%.*]] = sub nuw nsw i64 1024, [[N_MOD_VF]]
; CHECK-NEXT:    [[TMP2:%.*]] = shl nuw nsw i64 [[N_VEC]], 1
; CHECK-NEXT:    [[IND_END:%.*]] = getelementptr i8, ptr [[PTR:%.*]], i64 [[TMP2]]
; CHECK-NEXT:    br label [[VECTOR_BODY:%.*]]
; CHECK:       vector.body:
; CHECK-NEXT:    [[POINTER_PHI:%.*]] = phi ptr [ [[PTR]], [[VECTOR_PH]] ], [ [[PTR_IND:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[INDEX:%.*]] = phi i64 [ 0, [[VECTOR_PH]] ], [ [[INDEX_NEXT:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP3:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP4:%.*]] = shl nuw nsw i64 [[TMP3]], 2
; CHECK-NEXT:    [[TMP5:%.*]] = call <vscale x 2 x i64> @llvm.experimental.stepvector.nxv2i64()
; CHECK-NEXT:    [[VECTOR_GEP:%.*]] = shl <vscale x 2 x i64> [[TMP5]], shufflevector (<vscale x 2 x i64> insertelement (<vscale x 2 x i64> poison, i64 1, i64 0), <vscale x 2 x i64> poison, <vscale x 2 x i32> zeroinitializer)
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr i8, ptr [[POINTER_PHI]], <vscale x 2 x i64> [[VECTOR_GEP]]
; CHECK-NEXT:    [[TMP7:%.*]] = icmp ne <vscale x 2 x ptr> [[TMP6]], zeroinitializer
; CHECK-NEXT:    [[TMP8:%.*]] = extractelement <vscale x 2 x ptr> [[TMP6]], i64 0
; CHECK-NEXT:    call void @llvm.masked.store.nxv2i16.p0(<vscale x 2 x i16> zeroinitializer, ptr [[TMP8]], i32 2, <vscale x 2 x i1> [[TMP7]])
; CHECK-NEXT:    [[TMP9:%.*]] = call i64 @llvm.vscale.i64()
; CHECK-NEXT:    [[TMP10:%.*]] = shl nuw nsw i64 [[TMP9]], 1
; CHECK-NEXT:    [[INDEX_NEXT]] = add nuw i64 [[INDEX]], [[TMP10]]
; CHECK-NEXT:    [[PTR_IND]] = getelementptr i8, ptr [[POINTER_PHI]], i64 [[TMP4]]
; CHECK-NEXT:    [[TMP11:%.*]] = icmp eq i64 [[INDEX_NEXT]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[TMP11]], label [[MIDDLE_BLOCK:%.*]], label [[VECTOR_BODY]], !llvm.loop [[LOOP9:![0-9]+]]
; CHECK:       middle.block:
; CHECK-NEXT:    [[CMP_N:%.*]] = icmp eq i64 [[N_MOD_VF]], 0
; CHECK-NEXT:    br i1 [[CMP_N]], label [[FOR_END:%.*]], label [[SCALAR_PH]]
; CHECK:       scalar.ph:
; CHECK-NEXT:    [[BC_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC]], [[MIDDLE_BLOCK]] ], [ 0, [[ENTRY:%.*]] ]
; CHECK-NEXT:    [[BC_RESUME_VAL1:%.*]] = phi ptr [ [[IND_END]], [[MIDDLE_BLOCK]] ], [ [[PTR]], [[ENTRY]] ]
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[IV:%.*]] = phi i64 [ [[INC:%.*]], [[IF_END:%.*]] ], [ [[BC_RESUME_VAL]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[IV_PTR:%.*]] = phi ptr [ [[INCDEC_IV_PTR:%.*]], [[IF_END]] ], [ [[BC_RESUME_VAL1]], [[SCALAR_PH]] ]
; CHECK-NEXT:    [[CMP_I_NOT:%.*]] = icmp eq ptr [[IV_PTR]], null
; CHECK-NEXT:    br i1 [[CMP_I_NOT]], label [[IF_END]], label [[IF_END_SINK_SPLIT:%.*]]
; CHECK:       if.end.sink.split:
; CHECK-NEXT:    store i16 0, ptr [[IV_PTR]], align 2
; CHECK-NEXT:    br label [[IF_END]]
; CHECK:       if.end:
; CHECK-NEXT:    [[INCDEC_IV_PTR]] = getelementptr inbounds i16, ptr [[IV_PTR]], i64 1
; CHECK-NEXT:    [[INC]] = add nuw nsw i64 [[IV]], 1
; CHECK-NEXT:    [[EXITCOND_NOT:%.*]] = icmp ult i64 [[IV]], 1023
; CHECK-NEXT:    br i1 [[EXITCOND_NOT]], label [[FOR_BODY]], label [[FOR_END]], !llvm.loop [[LOOP10:![0-9]+]]
; CHECK:       for.end:
; CHECK-NEXT:    ret void
;
entry:
  br label %for.body

for.body:                                      ; preds = %if.end, %entry
  %iv = phi i64 [ %inc, %if.end ], [ 0, %entry ]
  %iv.ptr = phi ptr [ %incdec.iv.ptr, %if.end ], [ %ptr, %entry ]
  %cmp.i = icmp ne ptr %iv.ptr, null
  br i1 %cmp.i, label %if.end.sink.split, label %if.end

if.end.sink.split:                             ; preds = %for.body
  store i16 0, ptr %iv.ptr, align 2
  br label %if.end

if.end:                                        ; preds = %if.end.sink.split, %for.body
  %incdec.iv.ptr = getelementptr inbounds i16, ptr %iv.ptr, i64 1
  %inc = add nuw nsw i64 %iv, 1
  %exitcond.not = icmp ult i64 %inc, 1024
  br i1 %exitcond.not, label %for.body, label %for.end, !llvm.loop !6

for.end:                            ; preds = %if.end, %for.end
  %iv.ptr.1.lcssa = phi ptr [ %incdec.iv.ptr, %if.end ]
  ret void
}

attributes #0 = { vscale_range(1, 16) }

!0 = distinct !{!0, !1, !2, !3, !4, !5}
!1 = !{!"llvm.loop.mustprogress"}
!2 = !{!"llvm.loop.vectorize.width", i32 4}
!3 = !{!"llvm.loop.vectorize.scalable.enable", i1 true}
!4 = !{!"llvm.loop.vectorize.enable", i1 true}
!5 = !{!"llvm.loop.interleave.count", i32 2}
!6 = distinct !{!6, !1, !7, !3, !4, !8}
!7 = !{!"llvm.loop.vectorize.width", i32 2}
!8 = !{!"llvm.loop.interleave.count", i32 1}