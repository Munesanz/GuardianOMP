; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instcombine -S | FileCheck %s

define i1 @is_pow2or0_negate_op(i32 %x) {
; CHECK-LABEL: @is_pow2or0_negate_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0:![0-9]+]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[TMP1]], 2
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  %cmp = icmp eq i32 %and, %x
  ret i1 %cmp
}

define <2 x i1> @is_pow2or0_negate_op_vec(<2 x i32> %x) {
; CHECK-LABEL: @is_pow2or0_negate_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.ctpop.v2i32(<2 x i32> [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult <2 x i32> [[TMP1]], <i32 2, i32 2>
; CHECK-NEXT:    ret <2 x i1> [[CMP]]
;
  %neg = sub <2 x i32> zeroinitializer, %x
  %and = and <2 x i32> %neg, %x
  %cmp = icmp eq <2 x i32> %and, %x
  ret <2 x i1> %cmp
}

define i1 @is_pow2or0_decrement_op(i8 %x) {
; CHECK-LABEL: @is_pow2or0_decrement_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i8 @llvm.ctpop.i8(i8 [[X:%.*]]), !range [[RNG1:![0-9]+]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i8 [[TMP1]], 2
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %dec = add i8 %x, -1
  %and = and i8 %dec, %x
  %cmp = icmp eq i8 %and, 0
  ret i1 %cmp
}

define <2 x i1> @is_pow2or0_decrement_op_vec(<2 x i8> %x) {
; CHECK-LABEL: @is_pow2or0_decrement_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult <2 x i8> [[TMP1]], <i8 2, i8 2>
; CHECK-NEXT:    ret <2 x i1> [[CMP]]
;
  %dec = add <2 x i8> %x, <i8 -1, i8 -1>
  %and = and <2 x i8> %dec, %x
  %cmp = icmp eq <2 x i8> %and, zeroinitializer
  ret <2 x i1> %cmp
}

define i1 @isnot_pow2or0_negate_op(i32 %x) {
; CHECK-LABEL: @isnot_pow2or0_negate_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  %cmp = icmp ne i32 %and, %x
  ret i1 %cmp
}

define <2 x i1> @isnot_pow2or0_negate_op_vec(<2 x i32> %x) {
; CHECK-LABEL: @isnot_pow2or0_negate_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.ctpop.v2i32(<2 x i32> [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt <2 x i32> [[TMP1]], <i32 1, i32 1>
; CHECK-NEXT:    ret <2 x i1> [[CMP]]
;
  %neg = sub <2 x i32> zeroinitializer, %x
  %and = and <2 x i32> %neg, %x
  %cmp = icmp ne <2 x i32> %and, %x
  ret <2 x i1> %cmp
}

define i1 @isnot_pow2or0_decrement_op(i8 %x) {
; CHECK-LABEL: @isnot_pow2or0_decrement_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i8 @llvm.ctpop.i8(i8 [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i8 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %dec = add i8 %x, -1
  %and = and i8 %dec, %x
  %cmp = icmp ne i8 %and, 0
  ret i1 %cmp
}

define <2 x i1> @isnot_pow2or0_decrement_op_vec(<2 x i8> %x) {
; CHECK-LABEL: @isnot_pow2or0_decrement_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt <2 x i8> [[TMP1]], <i8 1, i8 1>
; CHECK-NEXT:    ret <2 x i1> [[CMP]]
;
  %dec = add <2 x i8> %x, <i8 -1, i8 -1>
  %and = and <2 x i8> %dec, %x
  %cmp = icmp ne <2 x i8> %and, zeroinitializer
  ret <2 x i1> %cmp
}

define i1 @is_pow2or0_negate_op_commute1(i32 %p) {
; CHECK-LABEL: @is_pow2or0_negate_op_commute1(
; CHECK-NEXT:    [[X:%.*]] = srem i32 42, [[P:%.*]]
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X]]), !range [[RNG2:![0-9]+]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[TMP1]], 2
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %x = srem i32 42, %p ; thwart complexity-based canonicalization
  %neg = sub i32 0, %x
  %and = and i32 %x, %neg
  %cmp = icmp eq i32 %and, %x
  ret i1 %cmp
}

; x can't be <= complexity of the 'neg' but >= complexity of the 'and'.

define i1 @isnot_pow2or0_negate_op_commute2(i32 %p) {
; CHECK-LABEL: @isnot_pow2or0_negate_op_commute2(
; CHECK-NEXT:    [[X:%.*]] = urem i32 42, [[P:%.*]]
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X]]), !range [[RNG2]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %x = urem i32 42, %p ; thwart complexity-based canonicalization
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  %cmp = icmp ne i32 %x, %and
  ret i1 %cmp
}

define i1 @isnot_pow2or0_negate_op_commute3(i32 %p) {
; CHECK-LABEL: @isnot_pow2or0_negate_op_commute3(
; CHECK-NEXT:    [[X:%.*]] = urem i32 42, [[P:%.*]]
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X]]), !range [[RNG2]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %x = urem i32 42, %p ; thwart complexity-based canonicalization
  %neg = sub i32 0, %x
  %and = and i32 %x, %neg
  %cmp = icmp ne i32 %x, %and
  ret i1 %cmp
}

declare void @use(i32)

define i1 @is_pow2or0_negate_op_extra_use1(i32 %x) {
; CHECK-LABEL: @is_pow2or0_negate_op_extra_use1(
; CHECK-NEXT:    [[NEG:%.*]] = sub i32 0, [[X:%.*]]
; CHECK-NEXT:    call void @use(i32 [[NEG]])
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[TMP1]], 2
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %neg = sub i32 0, %x
  call void @use(i32 %neg)
  %and = and i32 %neg, %x
  %cmp = icmp eq i32 %and, %x
  ret i1 %cmp
}

define i1 @is_pow2or0_negate_op_extra_use2(i32 %x) {
; CHECK-LABEL: @is_pow2or0_negate_op_extra_use2(
; CHECK-NEXT:    [[NEG:%.*]] = sub i32 0, [[X:%.*]]
; CHECK-NEXT:    [[AND:%.*]] = and i32 [[NEG]], [[X]]
; CHECK-NEXT:    call void @use(i32 [[AND]])
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[AND]], [[X]]
; CHECK-NEXT:    ret i1 [[CMP]]
;
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  call void @use(i32 %and)
  %cmp = icmp eq i32 %and, %x
  ret i1 %cmp
}

declare i32 @llvm.ctpop.i32(i32)
declare <2 x i8> @llvm.ctpop.v2i8(<2 x i8>)

; (X != 0) && (ctpop(X) u< 2) --> ctpop(X) == 1

define i1 @is_pow2_ctpop(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @is_pow2_ctpop_logical(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  %notzero = icmp ne i32 %x, 0
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

; Extra uses don't change the fold.
declare void @use_i1(i1)

define i1 @is_pow2_ctpop_extra_uses(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_extra_uses(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[NOTZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  call void @use_i1(i1 %cmp)
  %notzero = icmp ne i32 %x, 0
  call void @use_i1(i1 %notzero)
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @is_pow2_ctpop_extra_uses_logical(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_extra_uses_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[NOTZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  call void @use_i1(i1 %cmp)
  %notzero = icmp ne i32 %x, 0
  call void @use_i1(i1 %notzero)
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

; Test vector type and commuted 'and' operands.

define <2 x i1> @is_pow2_ctpop_commute_vec(<2 x i8> %x) {
; CHECK-LABEL: @is_pow2_ctpop_commute_vec(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq <2 x i8> [[T0]], <i8 1, i8 1>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp ult <2 x i8> %t0, <i8 2, i8 2>
  %notzero = icmp ne <2 x i8> %x, zeroinitializer
  %r = and <2 x i1> %cmp, %notzero
  ret <2 x i1> %r
}

; Negative test - wrong constant.

define i1 @is_pow2_ctpop_wrong_cmp_op1(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_cmp_op1(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 3
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = and i1 [[NOTZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 3
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @is_pow2_ctpop_wrong_cmp_op1_logical(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_cmp_op1_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 3
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = select i1 [[NOTZERO]], i1 [[CMP]], i1 false
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 3
  %notzero = icmp ne i32 %x, 0
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

; Negative test - wrong constant.

define i1 @is_pow2_ctpop_wrong_cmp_op2(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_cmp_op2(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 1
; CHECK-NEXT:    [[R:%.*]] = and i1 [[NOTZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  %notzero = icmp ne i32 %x, 1
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @is_pow2_ctpop_wrong_cmp_op2_logical(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_cmp_op2_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 1
; CHECK-NEXT:    [[R:%.*]] = select i1 [[NOTZERO]], i1 [[CMP]], i1 false
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  %notzero = icmp ne i32 %x, 1
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

; Negative test - wrong predicate.

define i1 @is_pow2_ctpop_wrong_pred1(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_pred1(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 2
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = and i1 [[NOTZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 2
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @is_pow2_ctpop_wrong_pred1_logical(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_pred1_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 2
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = select i1 [[NOTZERO]], i1 [[CMP]], i1 false
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 2
  %notzero = icmp ne i32 %x, 0
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

; Negative test - wrong predicate.

define i1 @is_pow2_ctpop_wrong_pred2(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_pred2(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    [[CMP2:%.*]] = icmp sgt i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = and i1 [[CMP2]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  %cmp2 = icmp sgt i32 %x, 0
  %r = and i1 %cmp2, %cmp
  ret i1 %r
}

define i1 @is_pow2_ctpop_wrong_pred2_logical(i32 %x) {
; CHECK-LABEL: @is_pow2_ctpop_wrong_pred2_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    [[CMP2:%.*]] = icmp sgt i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = select i1 [[CMP2]], i1 [[CMP]], i1 false
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ult i32 %t0, 2
  %cmp2 = icmp sgt i32 %x, 0
  %r = select i1 %cmp2, i1 %cmp, i1 false
  ret i1 %r
}

; (X == 0) || (ctpop(X) u> 1) --> ctpop(X) != 1

define i1 @isnot_pow2_ctpop(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  %iszero = icmp eq i32 %x, 0
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2_ctpop_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  %iszero = icmp eq i32 %x, 0
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

; Extra uses don't change the fold.

define i1 @isnot_pow2_ctpop_extra_uses(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_extra_uses(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[ISZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  call void @use_i1(i1 %cmp)
  %iszero = icmp eq i32 %x, 0
  call void @use_i1(i1 %iszero)
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2_ctpop_extra_uses_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_extra_uses_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[ISZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  call void @use_i1(i1 %cmp)
  %iszero = icmp eq i32 %x, 0
  call void @use_i1(i1 %iszero)
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

; Test vector type and commuted 'or' operands.

define <2 x i1> @isnot_pow2_ctpop_commute_vec(<2 x i8> %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_commute_vec(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne <2 x i8> [[T0]], <i8 1, i8 1>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp ugt <2 x i8> %t0, <i8 1, i8 1>
  %iszero = icmp eq <2 x i8> %x, zeroinitializer
  %r = or <2 x i1> %cmp, %iszero
  ret <2 x i1> %r
}

; Negative test - wrong constant.

define i1 @isnot_pow2_ctpop_wrong_cmp_op1(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_wrong_cmp_op1(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 2
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = or i1 [[ISZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 2
  %iszero = icmp eq i32 %x, 0
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2_ctpop_wrong_cmp_op1_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_wrong_cmp_op1_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 2
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = select i1 [[ISZERO]], i1 true, i1 [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 2
  %iszero = icmp eq i32 %x, 0
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

; Negative test - wrong constant.

define i1 @isnot_pow2_ctpop_wrong_cmp_op2(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_wrong_cmp_op2(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 1
; CHECK-NEXT:    [[R:%.*]] = or i1 [[ISZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  %iszero = icmp eq i32 %x, 1
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2_ctpop_wrong_cmp_op2_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_wrong_cmp_op2_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 1
; CHECK-NEXT:    [[R:%.*]] = select i1 [[ISZERO]], i1 true, i1 [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  %iszero = icmp eq i32 %x, 1
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

; Negative test - wrong predicate.

define i1 @isnot_pow2_ctpop_wrong_pred2(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_wrong_pred2(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    [[CMP2:%.*]] = icmp slt i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = or i1 [[CMP2]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  %cmp2 = icmp slt i32 %x, 0
  %r = or i1 %cmp2, %cmp
  ret i1 %r
}

define i1 @isnot_pow2_ctpop_wrong_pred2_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2_ctpop_wrong_pred2_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    [[CMP2:%.*]] = icmp slt i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = select i1 [[CMP2]], i1 true, i1 [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ugt i32 %t0, 1
  %cmp2 = icmp slt i32 %x, 0
  %r = select i1 %cmp2, i1 true, i1 %cmp
  ret i1 %r
}

define i1 @is_pow2_negate_op(i32 %x) {
; CHECK-LABEL: @is_pow2_negate_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  %cmp = icmp eq i32 %and, %x
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @is_pow2_negate_op_logical(i32 %x) {
; CHECK-LABEL: @is_pow2_negate_op_logical(
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  %cmp = icmp eq i32 %and, %x
  %notzero = icmp ne i32 %x, 0
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

define <2 x i1> @is_pow2_negate_op_vec(<2 x i32> %x) {
; CHECK-LABEL: @is_pow2_negate_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.ctpop.v2i32(<2 x i32> [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq <2 x i32> [[TMP1]], <i32 1, i32 1>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %neg = sub <2 x i32> zeroinitializer, %x
  %and = and <2 x i32> %neg, %x
  %cmp = icmp eq <2 x i32> %and, %x
  %notzero = icmp ne <2 x i32> %x, zeroinitializer
  %r = and <2 x i1> %cmp, %notzero
  ret <2 x i1> %r
}

define i1 @is_pow2_decrement_op(i8 %x) {
; CHECK-LABEL: @is_pow2_decrement_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i8 @llvm.ctpop.i8(i8 [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq i8 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %dec = add i8 %x, -1
  %and = and i8 %dec, %x
  %cmp = icmp eq i8 %and, 0
  %notzero = icmp ne i8 %x, 0
  %r = and i1 %cmp, %notzero
  ret i1 %r
}

define i1 @is_pow2_decrement_op_logical(i8 %x) {
; CHECK-LABEL: @is_pow2_decrement_op_logical(
; CHECK-NEXT:    [[TMP1:%.*]] = call i8 @llvm.ctpop.i8(i8 [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq i8 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %dec = add i8 %x, -1
  %and = and i8 %dec, %x
  %cmp = icmp eq i8 %and, 0
  %notzero = icmp ne i8 %x, 0
  %r = select i1 %cmp, i1 %notzero, i1 false
  ret i1 %r
}

define <2 x i1> @is_pow2_decrement_op_vec(<2 x i8> %x) {
; CHECK-LABEL: @is_pow2_decrement_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp eq <2 x i8> [[TMP1]], <i8 1, i8 1>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %dec = add <2 x i8> %x, <i8 -1, i8 -1>
  %and = and <2 x i8> %dec, %x
  %cmp = icmp eq <2 x i8> %and, zeroinitializer
  %notzero = icmp ne <2 x i8> %x, zeroinitializer
  %r = and <2 x i1> %notzero, %cmp
  ret <2 x i1> %r
}

define i1 @isnot_pow2_negate_op(i32 %x) {
; CHECK-LABEL: @isnot_pow2_negate_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  %cmp = icmp ne i32 %and, %x
  %iszero = icmp eq i32 %x, 0
  %r = or i1 %cmp, %iszero
  ret i1 %r
}

define i1 @isnot_pow2_negate_op_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2_negate_op_logical(
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %neg = sub i32 0, %x
  %and = and i32 %neg, %x
  %cmp = icmp ne i32 %and, %x
  %iszero = icmp eq i32 %x, 0
  %r = select i1 %cmp, i1 true, i1 %iszero
  ret i1 %r
}

define <2 x i1> @isnot_pow2_negate_op_vec(<2 x i32> %x) {
; CHECK-LABEL: @isnot_pow2_negate_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.ctpop.v2i32(<2 x i32> [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne <2 x i32> [[TMP1]], <i32 1, i32 1>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %neg = sub <2 x i32> zeroinitializer, %x
  %and = and <2 x i32> %neg, %x
  %cmp = icmp ne <2 x i32> %and, %x
  %iszero = icmp eq <2 x i32> %x, zeroinitializer
  %r = or <2 x i1> %iszero, %cmp
  ret <2 x i1> %r
}

define i1 @isnot_pow2_decrement_op(i8 %x) {
; CHECK-LABEL: @isnot_pow2_decrement_op(
; CHECK-NEXT:    [[TMP1:%.*]] = call i8 @llvm.ctpop.i8(i8 [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne i8 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %dec = add i8 %x, -1
  %and = and i8 %dec, %x
  %cmp = icmp ne i8 %and, 0
  %iszero = icmp eq i8 %x, 0
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2_decrement_op_logical(i8 %x) {
; CHECK-LABEL: @isnot_pow2_decrement_op_logical(
; CHECK-NEXT:    [[TMP1:%.*]] = call i8 @llvm.ctpop.i8(i8 [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne i8 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %dec = add i8 %x, -1
  %and = and i8 %dec, %x
  %cmp = icmp ne i8 %and, 0
  %iszero = icmp eq i8 %x, 0
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

define <2 x i1> @isnot_pow2_decrement_op_vec(<2 x i8> %x) {
; CHECK-LABEL: @isnot_pow2_decrement_op_vec(
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp ne <2 x i8> [[TMP1]], <i8 1, i8 1>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %dec = add <2 x i8> %x, <i8 -1, i8 -1>
  %and = and <2 x i8> %dec, %x
  %cmp = icmp ne <2 x i8> %and, zeroinitializer
  %iszero = icmp eq <2 x i8> %x, zeroinitializer
  %r = or <2 x i1> %cmp, %iszero
  ret <2 x i1> %r
}

; (ctpop(X) == 1) || (X == 0) --> ctpop(X) u< 2

define i1 @is_pow2or0_ctpop(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 1
  %iszero = icmp eq i32 %x, 0
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @is_pow2or0_ctpop_swap_cmp(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_swap_cmp(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 1
  %iszero = icmp eq i32 %x, 0
  %r = or i1 %cmp, %iszero
  ret i1 %r
}

define i1 @is_pow2or0_ctpop_logical(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 1
  %iszero = icmp eq i32 %x, 0
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

define <2 x i1> @is_pow2or0_ctpop_commute_vec(<2 x i8> %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_commute_vec(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp ult <2 x i8> [[T0]], <i8 2, i8 2>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp eq <2 x i8> %t0, <i8 1, i8 1>
  %iszero = icmp eq <2 x i8> %x, <i8 0, i8 0>
  %r = or <2 x i1> %iszero, %cmp
  ret <2 x i1> %r
}

; Extra uses don't change the fold.

define i1 @is_pow2or0_ctpop_extra_uses(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_extra_uses(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    call void @use(i32 [[T0]])
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[ISZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  call void @use(i32 %t0)
  %cmp = icmp eq i32 %t0, 1
  call void @use_i1(i1 %cmp)
  %iszero = icmp eq i32 %x, 0
  call void @use_i1(i1 %iszero)
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @is_pow2or0_ctpop_logical_extra_uses(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_logical_extra_uses(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    call void @use(i32 [[T0]])
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[ISZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp ult i32 [[T0]], 2
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  call void @use(i32 %t0)
  %cmp = icmp eq i32 %t0, 1
  call void @use_i1(i1 %cmp)
  %iszero = icmp eq i32 %x, 0
  call void @use_i1(i1 %iszero)
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

; Negative test - wrong constant.

define i1 @is_pow2or0_ctpop_wrong_cmp_op1(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_wrong_cmp_op1(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[T0]], 2
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = or i1 [[ISZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 2
  %iszero = icmp eq i32 %x, 0
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @is_pow2or0_ctpop_wrong_cmp_op1_logical(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_wrong_cmp_op1_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[T0]], 3
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = select i1 [[ISZERO]], i1 true, i1 [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 3
  %iszero = icmp eq i32 %x, 0
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

define <2 x i1> @is_pow2or0_ctpop_commute_vec_wrong_cmp_op1(<2 x i8> %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_commute_vec_wrong_cmp_op1(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq <2 x i8> [[T0]], <i8 -1, i8 1>
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq <2 x i8> [[X]], zeroinitializer
; CHECK-NEXT:    [[R:%.*]] = or <2 x i1> [[CMP]], [[ISZERO]]
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp eq <2 x i8> %t0, <i8 -1, i8 1>
  %iszero = icmp eq <2 x i8> %x, <i8 0, i8 0>
  %r = or <2 x i1> %cmp, %iszero
  ret <2 x i1> %r
}

; Negative test - wrong predicate.

define i1 @is_pow2or0_ctpop_wrong_pred1(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_wrong_pred1(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = or i1 [[ISZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 1
  %iszero = icmp eq i32 %x, 0
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @is_pow2or0_ctpop_wrong_pred2(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_wrong_pred2(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = or i1 [[ISZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 1
  %iszero = icmp ne i32 %x, 0
  %r = or i1 %iszero, %cmp
  ret i1 %r
}

define i1 @is_pow2or0_ctpop_wrong_pred2_logical(i32 %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_wrong_pred2_logical(
; CHECK-NEXT:    ret i1 true
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 1
  %iszero = icmp ne i32 %x, 0
  %r = select i1 %iszero, i1 true, i1 %cmp
  ret i1 %r
}

define <2 x i1> @is_pow2or0_ctpop_commute_vec_wrong_pred3(<2 x i8> %x) {
; CHECK-LABEL: @is_pow2or0_ctpop_commute_vec_wrong_pred3(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq <2 x i8> [[T0]], <i8 1, i8 1>
; CHECK-NEXT:    [[ISZERO:%.*]] = icmp eq <2 x i8> [[X]], zeroinitializer
; CHECK-NEXT:    [[R:%.*]] = and <2 x i1> [[CMP]], [[ISZERO]]
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp eq <2 x i8> %t0, <i8 1, i8 1>
  %iszero = icmp eq <2 x i8> %x, <i8 0, i8 0>
  %r = and <2 x i1> %cmp, %iszero
  ret <2 x i1> %r
}

; (ctpop(X) != 1) && (X != 0) --> ctpop(X) u> 1

define i1 @isnot_pow2nor0_ctpop(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 1
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2nor0_ctpop_swap_cmp(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_swap_cmp(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 1
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %cmp, %notzero
  ret i1 %r
}

define i1 @isnot_pow2nor0_ctpop_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[R:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 1
  %notzero = icmp ne i32 %x, 0
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

define <2 x i1> @isnot_pow2nor0_ctpop_commute_vec(<2 x i8> %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_commute_vec(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[R:%.*]] = icmp ugt <2 x i8> [[T0]], <i8 1, i8 1>
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp ne <2 x i8> %t0, <i8 1, i8 1>
  %notzero = icmp ne <2 x i8> %x, <i8 0, i8 0>
  %r = and <2 x i1> %notzero, %cmp
  ret <2 x i1> %r
}

; Extra uses don't change the fold.

define i1 @isnot_pow2nor0_ctpop_extra_uses(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_extra_uses(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    call void @use(i32 [[T0]])
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[NOTZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  call void @use(i32 %t0)
  %cmp = icmp ne i32 %t0, 1
  call void @use_i1(i1 %cmp)
  %notzero = icmp ne i32 %x, 0
  call void @use_i1(i1 %notzero)
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2nor0_ctpop_logical_extra_uses(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_logical_extra_uses(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    call void @use(i32 [[T0]])
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne i32 [[T0]], 1
; CHECK-NEXT:    call void @use_i1(i1 [[CMP]])
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    call void @use_i1(i1 [[NOTZERO]])
; CHECK-NEXT:    [[R:%.*]] = icmp ugt i32 [[T0]], 1
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  call void @use(i32 %t0)
  %cmp = icmp ne i32 %t0, 1
  call void @use_i1(i1 %cmp)
  %notzero = icmp ne i32 %x, 0
  call void @use_i1(i1 %notzero)
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

; Negative test - wrong constant.

define i1 @isnot_pow2nor0_ctpop_wrong_cmp_op1(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_wrong_cmp_op1(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne i32 [[T0]], 4
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = and i1 [[NOTZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 4
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2nor0_ctpop_wrong_cmp_op1_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_wrong_cmp_op1_logical(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne i32 [[T0]], 5
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = select i1 [[NOTZERO]], i1 [[CMP]], i1 false
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp ne i32 %t0, 5
  %notzero = icmp ne i32 %x, 0
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

define <2 x i1> @isnot_pow2nor0_ctpop_commute_vec_wrong_cmp_op1(<2 x i8> %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_commute_vec_wrong_cmp_op1(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne <2 x i8> [[T0]], <i8 0, i8 -1>
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne <2 x i8> [[X]], zeroinitializer
; CHECK-NEXT:    [[R:%.*]] = and <2 x i1> [[CMP]], [[NOTZERO]]
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp ne <2 x i8> %t0, <i8 0, i8 -1>
  %notzero = icmp ne <2 x i8> %x, <i8 0, i8 0>
  %r = and <2 x i1> %cmp, %notzero
  ret <2 x i1> %r
}

; Negative test - wrong predicate.

define i1 @isnot_pow2nor0_ctpop_wrong_pred1(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_wrong_pred1(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = and i1 [[NOTZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 1
  %notzero = icmp ne i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2nor0_ctpop_wrong_pred2(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_wrong_pred2(
; CHECK-NEXT:    [[T0:%.*]] = tail call i32 @llvm.ctpop.i32(i32 [[X:%.*]]), !range [[RNG0]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[T0]], 1
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp eq i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = and i1 [[NOTZERO]], [[CMP]]
; CHECK-NEXT:    ret i1 [[R]]
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 1
  %notzero = icmp eq i32 %x, 0
  %r = and i1 %notzero, %cmp
  ret i1 %r
}

define i1 @isnot_pow2nor0_ctpop_wrong_pred2_logical(i32 %x) {
; CHECK-LABEL: @isnot_pow2nor0_ctpop_wrong_pred2_logical(
; CHECK-NEXT:    ret i1 false
;
  %t0 = tail call i32 @llvm.ctpop.i32(i32 %x)
  %cmp = icmp eq i32 %t0, 1
  %notzero = icmp eq i32 %x, 0
  %r = select i1 %notzero, i1 %cmp, i1 false
  ret i1 %r
}

define <2 x i1> @isnot_pow2nor0_wrong_pred3_ctpop_commute_vec(<2 x i8> %x) {
; CHECK-LABEL: @isnot_pow2nor0_wrong_pred3_ctpop_commute_vec(
; CHECK-NEXT:    [[T0:%.*]] = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> [[X:%.*]]), !range [[RNG1]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp ne <2 x i8> [[T0]], <i8 1, i8 1>
; CHECK-NEXT:    [[NOTZERO:%.*]] = icmp ne <2 x i8> [[X]], zeroinitializer
; CHECK-NEXT:    [[R:%.*]] = or <2 x i1> [[CMP]], [[NOTZERO]]
; CHECK-NEXT:    ret <2 x i1> [[R]]
;
  %t0 = tail call <2 x i8> @llvm.ctpop.v2i8(<2 x i8> %x)
  %cmp = icmp ne <2 x i8> %t0, <i8 1, i8 1>
  %notzero = icmp ne <2 x i8> %x, <i8 0, i8 0>
  %r = or <2 x i1> %cmp, %notzero
  ret <2 x i1> %r
}