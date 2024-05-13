; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes 'loop-reduce' -scalar-evolution-max-arith-depth=2 -S < %s | FileCheck --check-prefixes=DEFAULT %s
; RUN: opt -loop-reduce -scalar-evolution-max-arith-depth=2 -S < %s | FileCheck --check-prefixes=LIMIT %s

; This test should just compile cleanly without assertions.

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128-ni:1-p2:32:8:8:32-ni:2"

define void @test(i32 %A, i32 %B, i32 %C) {
; DEFAULT-LABEL: @test(
; DEFAULT-NEXT:  entry:
; DEFAULT-NEXT:    [[TMP0:%.*]] = mul i32 [[C:%.*]], -3
; DEFAULT-NEXT:    br label [[OUTER_LOOP:%.*]]
; DEFAULT:       outer_loop:
; DEFAULT-NEXT:    [[PHI2:%.*]] = phi i32 [ [[A:%.*]], [[ENTRY:%.*]] ], [ 204, [[OUTER_TAIL:%.*]] ]
; DEFAULT-NEXT:    [[PHI3:%.*]] = phi i32 [ [[A]], [[ENTRY]] ], [ 243, [[OUTER_TAIL]] ]
; DEFAULT-NEXT:    [[PHI4:%.*]] = phi i32 [ [[B:%.*]], [[ENTRY]] ], [ [[I35:%.*]], [[OUTER_TAIL]] ]
; DEFAULT-NEXT:    br label [[GUARD:%.*]]
; DEFAULT:       guard:
; DEFAULT-NEXT:    [[LCMP_MOD:%.*]] = icmp eq i32 [[C]], 0
; DEFAULT-NEXT:    br i1 [[LCMP_MOD]], label [[OUTER_TAIL]], label [[PREHEADER:%.*]]
; DEFAULT:       preheader:
; DEFAULT-NEXT:    [[I15:%.*]] = shl i32 [[B]], 1
; DEFAULT-NEXT:    [[TMP1:%.*]] = mul i32 [[PHI2]], -1
; DEFAULT-NEXT:    [[TMP2:%.*]] = mul i32 [[TMP1]], -1
; DEFAULT-NEXT:    [[TMP3:%.*]] = sub i32 [[PHI4]], [[TMP2]]
; DEFAULT-NEXT:    [[TMP4:%.*]] = add i32 [[B]], [[PHI4]]
; DEFAULT-NEXT:    [[TMP5:%.*]] = sub i32 [[TMP4]], [[TMP2]]
; DEFAULT-NEXT:    [[TMP6:%.*]] = sub i32 14, [[TMP5]]
; DEFAULT-NEXT:    [[TMP7:%.*]] = add i32 [[TMP0]], [[PHI2]]
; DEFAULT-NEXT:    br label [[INNER_LOOP:%.*]]
; DEFAULT:       inner_loop:
; DEFAULT-NEXT:    [[LSR_IV3:%.*]] = phi i32 [ [[LSR_IV_NEXT4:%.*]], [[INNER_LOOP]] ], [ [[TMP6]], [[PREHEADER]] ]
; DEFAULT-NEXT:    [[LSR_IV1:%.*]] = phi i32 [ [[LSR_IV_NEXT2:%.*]], [[INNER_LOOP]] ], [ [[TMP5]], [[PREHEADER]] ]
; DEFAULT-NEXT:    [[LSR_IV:%.*]] = phi i32 [ [[LSR_IV_NEXT:%.*]], [[INNER_LOOP]] ], [ [[TMP3]], [[PREHEADER]] ]
; DEFAULT-NEXT:    [[PHI5:%.*]] = phi i32 [ [[PHI3]], [[PREHEADER]] ], [ [[I30:%.*]], [[INNER_LOOP]] ]
; DEFAULT-NEXT:    [[PHI6:%.*]] = phi i32 [ [[PHI2]], [[PREHEADER]] ], [ [[I33:%.*]], [[INNER_LOOP]] ]
; DEFAULT-NEXT:    [[ITER:%.*]] = phi i32 [ [[C]], [[PREHEADER]] ], [ [[ITER_SUB:%.*]], [[INNER_LOOP]] ]
; DEFAULT-NEXT:    [[I17:%.*]] = sub i32 [[PHI4]], [[PHI6]]
; DEFAULT-NEXT:    [[I18:%.*]] = sub i32 14, [[PHI5]]
; DEFAULT-NEXT:    [[I19:%.*]] = mul i32 [[I18]], [[C]]
; DEFAULT-NEXT:    [[FACTOR_PROL:%.*]] = shl i32 [[PHI5]], 1
; DEFAULT-NEXT:    [[TMP8:%.*]] = add i32 [[LSR_IV1]], [[I19]]
; DEFAULT-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], [[FACTOR_PROL]]
; DEFAULT-NEXT:    [[TMP10:%.*]] = shl i32 [[TMP9]], 1
; DEFAULT-NEXT:    [[TMP11:%.*]] = add i32 [[LSR_IV]], [[TMP10]]
; DEFAULT-NEXT:    [[TMP12:%.*]] = sub i32 [[LSR_IV3]], [[I19]]
; DEFAULT-NEXT:    [[TMP13:%.*]] = sub i32 [[TMP12]], [[FACTOR_PROL]]
; DEFAULT-NEXT:    [[TMP14:%.*]] = mul i32 [[C]], [[TMP13]]
; DEFAULT-NEXT:    [[TMP15:%.*]] = add i32 [[LSR_IV1]], [[I19]]
; DEFAULT-NEXT:    [[TMP16:%.*]] = add i32 [[TMP15]], [[FACTOR_PROL]]
; DEFAULT-NEXT:    [[TMP17:%.*]] = shl i32 [[TMP16]], 1
; DEFAULT-NEXT:    [[TMP18:%.*]] = add i32 [[TMP14]], [[TMP17]]
; DEFAULT-NEXT:    [[TMP19:%.*]] = add i32 [[LSR_IV]], [[TMP18]]
; DEFAULT-NEXT:    [[I29:%.*]] = mul i32 [[TMP11]], [[C]]
; DEFAULT-NEXT:    [[FACTOR_2_PROL:%.*]] = shl i32 [[TMP19]], 1
; DEFAULT-NEXT:    [[I30]] = add i32 [[I17]], [[FACTOR_2_PROL]]
; DEFAULT-NEXT:    [[I33]] = add i32 [[PHI6]], -3
; DEFAULT-NEXT:    [[ITER_SUB]] = add i32 [[ITER]], -1
; DEFAULT-NEXT:    [[LSR_IV_NEXT]] = add i32 [[LSR_IV]], 3
; DEFAULT-NEXT:    [[LSR_IV_NEXT2]] = add i32 [[LSR_IV1]], 3
; DEFAULT-NEXT:    [[LSR_IV_NEXT4]] = add i32 [[LSR_IV3]], -3
; DEFAULT-NEXT:    [[ITER_CMP:%.*]] = icmp eq i32 [[ITER_SUB]], 0
; DEFAULT-NEXT:    br i1 [[ITER_CMP]], label [[OUTER_TAIL_LOOPEXIT:%.*]], label [[INNER_LOOP]]
; DEFAULT:       outer_tail.loopexit:
; DEFAULT-NEXT:    br label [[OUTER_TAIL]]
; DEFAULT:       outer_tail:
; DEFAULT-NEXT:    [[PHI7:%.*]] = phi i32 [ [[PHI2]], [[GUARD]] ], [ [[TMP7]], [[OUTER_TAIL_LOOPEXIT]] ]
; DEFAULT-NEXT:    [[I35]] = sub i32 [[A]], [[PHI7]]
; DEFAULT-NEXT:    [[CMP:%.*]] = icmp sgt i32 [[I35]], 9876
; DEFAULT-NEXT:    br i1 [[CMP]], label [[EXIT:%.*]], label [[OUTER_LOOP]]
; DEFAULT:       exit:
; DEFAULT-NEXT:    ret void
;
; LIMIT-LABEL: @test(
; LIMIT-NEXT:  entry:
; LIMIT-NEXT:    [[TMP0:%.*]] = mul i32 [[C:%.*]], -3
; LIMIT-NEXT:    br label [[OUTER_LOOP:%.*]]
; LIMIT:       outer_loop:
; LIMIT-NEXT:    [[PHI2:%.*]] = phi i32 [ [[A:%.*]], [[ENTRY:%.*]] ], [ 204, [[OUTER_TAIL:%.*]] ]
; LIMIT-NEXT:    [[PHI3:%.*]] = phi i32 [ [[A]], [[ENTRY]] ], [ 243, [[OUTER_TAIL]] ]
; LIMIT-NEXT:    [[PHI4:%.*]] = phi i32 [ [[B:%.*]], [[ENTRY]] ], [ [[I35:%.*]], [[OUTER_TAIL]] ]
; LIMIT-NEXT:    br label [[GUARD:%.*]]
; LIMIT:       guard:
; LIMIT-NEXT:    [[LCMP_MOD:%.*]] = icmp eq i32 [[C]], 0
; LIMIT-NEXT:    br i1 [[LCMP_MOD]], label [[OUTER_TAIL]], label [[PREHEADER:%.*]]
; LIMIT:       preheader:
; LIMIT-NEXT:    [[I15:%.*]] = shl i32 [[B]], 1
; LIMIT-NEXT:    [[TMP1:%.*]] = mul i32 [[PHI2]], -1
; LIMIT-NEXT:    [[TMP2:%.*]] = mul i32 [[TMP1]], -1
; LIMIT-NEXT:    [[TMP3:%.*]] = sub i32 [[PHI4]], [[TMP2]]
; LIMIT-NEXT:    [[TMP4:%.*]] = add i32 [[B]], [[PHI4]]
; LIMIT-NEXT:    [[TMP5:%.*]] = sub i32 [[TMP4]], [[TMP2]]
; LIMIT-NEXT:    [[TMP6:%.*]] = sub i32 14, [[TMP5]]
; LIMIT-NEXT:    [[TMP7:%.*]] = add i32 [[TMP0]], [[PHI2]]
; LIMIT-NEXT:    br label [[INNER_LOOP:%.*]]
; LIMIT:       inner_loop:
; LIMIT-NEXT:    [[LSR_IV3:%.*]] = phi i32 [ [[LSR_IV_NEXT4:%.*]], [[INNER_LOOP]] ], [ [[TMP6]], [[PREHEADER]] ]
; LIMIT-NEXT:    [[LSR_IV1:%.*]] = phi i32 [ [[LSR_IV_NEXT2:%.*]], [[INNER_LOOP]] ], [ [[TMP5]], [[PREHEADER]] ]
; LIMIT-NEXT:    [[LSR_IV:%.*]] = phi i32 [ [[LSR_IV_NEXT:%.*]], [[INNER_LOOP]] ], [ [[TMP3]], [[PREHEADER]] ]
; LIMIT-NEXT:    [[PHI5:%.*]] = phi i32 [ [[PHI3]], [[PREHEADER]] ], [ [[I30:%.*]], [[INNER_LOOP]] ]
; LIMIT-NEXT:    [[PHI6:%.*]] = phi i32 [ [[PHI2]], [[PREHEADER]] ], [ [[I33:%.*]], [[INNER_LOOP]] ]
; LIMIT-NEXT:    [[ITER:%.*]] = phi i32 [ [[C]], [[PREHEADER]] ], [ [[ITER_SUB:%.*]], [[INNER_LOOP]] ]
; LIMIT-NEXT:    [[I17:%.*]] = sub i32 [[PHI4]], [[PHI6]]
; LIMIT-NEXT:    [[I18:%.*]] = sub i32 14, [[PHI5]]
; LIMIT-NEXT:    [[I19:%.*]] = mul i32 [[I18]], [[C]]
; LIMIT-NEXT:    [[FACTOR_PROL:%.*]] = shl i32 [[PHI5]], 1
; LIMIT-NEXT:    [[TMP8:%.*]] = add i32 [[LSR_IV1]], [[I19]]
; LIMIT-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], [[FACTOR_PROL]]
; LIMIT-NEXT:    [[TMP10:%.*]] = shl i32 [[TMP9]], 1
; LIMIT-NEXT:    [[TMP11:%.*]] = add i32 [[LSR_IV]], [[TMP10]]
; LIMIT-NEXT:    [[TMP12:%.*]] = sub i32 [[LSR_IV3]], [[I19]]
; LIMIT-NEXT:    [[TMP13:%.*]] = sub i32 [[TMP12]], [[FACTOR_PROL]]
; LIMIT-NEXT:    [[TMP14:%.*]] = mul i32 [[C]], [[TMP13]]
; LIMIT-NEXT:    [[TMP15:%.*]] = add i32 [[LSR_IV1]], [[I19]]
; LIMIT-NEXT:    [[TMP16:%.*]] = add i32 [[TMP15]], [[FACTOR_PROL]]
; LIMIT-NEXT:    [[TMP17:%.*]] = shl i32 [[TMP16]], 1
; LIMIT-NEXT:    [[TMP18:%.*]] = add i32 [[TMP14]], [[TMP17]]
; LIMIT-NEXT:    [[TMP19:%.*]] = add i32 [[LSR_IV]], [[TMP18]]
; LIMIT-NEXT:    [[I29:%.*]] = mul i32 [[TMP11]], [[C]]
; LIMIT-NEXT:    [[FACTOR_2_PROL:%.*]] = shl i32 [[TMP19]], 1
; LIMIT-NEXT:    [[I30]] = add i32 [[I17]], [[FACTOR_2_PROL]]
; LIMIT-NEXT:    [[I33]] = add i32 [[PHI6]], -3
; LIMIT-NEXT:    [[ITER_SUB]] = add i32 [[ITER]], -1
; LIMIT-NEXT:    [[LSR_IV_NEXT]] = add i32 [[LSR_IV]], 3
; LIMIT-NEXT:    [[LSR_IV_NEXT2]] = add i32 [[LSR_IV1]], 3
; LIMIT-NEXT:    [[LSR_IV_NEXT4]] = add i32 [[LSR_IV3]], -3
; LIMIT-NEXT:    [[ITER_CMP:%.*]] = icmp eq i32 [[ITER_SUB]], 0
; LIMIT-NEXT:    br i1 [[ITER_CMP]], label [[OUTER_TAIL_LOOPEXIT:%.*]], label [[INNER_LOOP]]
; LIMIT:       outer_tail.loopexit:
; LIMIT-NEXT:    br label [[OUTER_TAIL]]
; LIMIT:       outer_tail:
; LIMIT-NEXT:    [[PHI7:%.*]] = phi i32 [ [[PHI2]], [[GUARD]] ], [ [[TMP7]], [[OUTER_TAIL_LOOPEXIT]] ]
; LIMIT-NEXT:    [[I35]] = sub i32 [[A]], [[PHI7]]
; LIMIT-NEXT:    [[CMP:%.*]] = icmp sgt i32 [[I35]], 9876
; LIMIT-NEXT:    br i1 [[CMP]], label [[EXIT:%.*]], label [[OUTER_LOOP]]
; LIMIT:       exit:
; LIMIT-NEXT:    ret void
;
entry:
  br label %outer_loop

outer_loop:
  %phi2 = phi i32 [ %A, %entry ], [ 204, %outer_tail ]
  %phi3 = phi i32 [ %A, %entry ], [ 243, %outer_tail ]
  %phi4 = phi i32 [ %B, %entry ], [ %i35, %outer_tail ]
  br label %guard

guard:
  %lcmp.mod = icmp eq i32 %C, 0
  br i1 %lcmp.mod, label %outer_tail, label %preheader

preheader:
  %i15 = shl i32 %B, 1
  br label %inner_loop

inner_loop:
  %phi5 = phi i32 [ %phi3, %preheader ], [ %i30, %inner_loop ]
  %phi6 = phi i32 [ %phi2, %preheader ], [ %i33, %inner_loop ]
  %iter = phi i32 [ %C, %preheader ], [ %iter.sub, %inner_loop ]
  %i17 = sub i32 %phi4, %phi6
  %i18 = sub i32 14, %phi5
  %i19 = mul i32 %i18, %C
  %factor.prol = shl i32 %phi5, 1
  %i20 = add i32 %i17, %factor.prol
  %i21 = add i32 %i20, %B
  %i22 = add i32 %i21, %i19
  %i23 = sub i32 14, %i22
  %i24 = mul i32 %i23, %C
  %factor.1.prol = shl i32 %i22, 1
  %i25 = add i32 %i17, %factor.1.prol
  %i27 = add i32 %i25, %i24
  %i29 = mul i32 %i25, %C
  %factor.2.prol = shl i32 %i27, 1
  %i30 = add i32 %i17, %factor.2.prol
  %i33 = add nsw i32 %phi6, -3
  %iter.sub = add i32 %iter, -1
  %iter.cmp = icmp eq i32 %iter.sub, 0
  br i1 %iter.cmp, label %outer_tail, label %inner_loop

outer_tail:
  %phi7 = phi i32 [ %phi2, %guard ], [ %i33, %inner_loop ]
  %i35 = sub i32 %A, %phi7
  %cmp = icmp sgt i32 %i35, 9876
  br i1 %cmp, label %exit, label %outer_loop

exit:
  ret void

}
