; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=ipsccp -S %s | FileCheck %s

define i8 @range_from_lshr(i8 %a) {
; CHECK-LABEL: @range_from_lshr(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_SHR:%.*]] = lshr i8 [[A:%.*]], 1
; CHECK-NEXT:    [[ADD_1:%.*]] = add nuw i8 [[A_SHR]], 1
; CHECK-NEXT:    [[ADD_2:%.*]] = add nuw nsw i8 [[A_SHR]], -128
; CHECK-NEXT:    [[ADD_3:%.*]] = add nsw i8 [[A_SHR]], -127
; CHECK-NEXT:    [[ADD_4:%.*]] = add nsw i8 [[A_SHR]], -1
; CHECK-NEXT:    [[RES_1:%.*]] = xor i8 [[ADD_1]], [[ADD_2]]
; CHECK-NEXT:    [[RES_2:%.*]] = xor i8 [[RES_1]], [[ADD_3]]
; CHECK-NEXT:    [[RES_3:%.*]] = xor i8 [[RES_2]], [[ADD_4]]
; CHECK-NEXT:    ret i8 [[RES_3]]
;
entry:
  %a.shr = lshr i8 %a, 1
  %add.1 = add i8 %a.shr, 1
  %add.2 = add i8 %a.shr, 128
  %add.3 = add i8 %a.shr, 129
  %add.4 = add i8 %a.shr, -1
  %res.1 = xor i8 %add.1, %add.2
  %res.2 = xor i8 %res.1, %add.3
  %res.3 = xor i8 %res.2, %add.4
  ret i8 %res.3
}

define i8 @a_and_15_add_1(i8 %a) {
; CHECK-LABEL: @a_and_15_add_1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_AND:%.*]] = and i8 [[A:%.*]], 15
; CHECK-NEXT:    [[ADD_1:%.*]] = add nuw nsw i8 [[A_AND]], 1
; CHECK-NEXT:    ret i8 [[ADD_1]]
;
entry:
  %a.and = and i8 %a, 15
  %add.1 = add i8 %a.and, 1
  ret i8 %add.1
}

define <4 x i8> @range_from_lshr_vec(<4 x i8> %a) {
; CHECK-LABEL: @range_from_lshr_vec(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_SHR:%.*]] = lshr <4 x i8> [[A:%.*]], <i8 1, i8 2, i8 3, i8 4>
; CHECK-NEXT:    [[ADD_1:%.*]] = add <4 x i8> [[A_SHR]], <i8 1, i8 2, i8 3, i8 4>
; CHECK-NEXT:    ret <4 x i8> [[ADD_1]]
;
entry:
  %a.shr = lshr <4 x i8> %a, <i8 1, i8 2, i8 3, i8 4>
  %add.1 = add <4 x i8> %a.shr, <i8 1, i8 2, i8 3, i8 4>
  ret <4 x i8> %add.1
}

define <4 x i8> @range_from_lshr_vec_2(<4 x i8> %a) {
; CHECK-LABEL: @range_from_lshr_vec_2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_SHR:%.*]] = lshr <4 x i8> [[A:%.*]], <i8 1, i8 1, i8 1, i8 1>
; CHECK-NEXT:    [[ADD_1:%.*]] = add <4 x i8> [[A_SHR]], <i8 2, i8 2, i8 2, i8 2>
; CHECK-NEXT:    ret <4 x i8> [[ADD_1]]
;
entry:
  %a.shr = lshr <4 x i8> %a, <i8 1, i8 1, i8 1, i8 1>
  %add.1 = add <4 x i8> %a.shr, <i8 2, i8 2, i8 2, i8 2>
  ret <4 x i8> %add.1
}

define i8 @sge_0_and_sle_90(i8 %a) {
; CHECK-LABEL: @sge_0_and_sle_90(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SGT:%.*]] = icmp sge i8 [[A:%.*]], 0
; CHECK-NEXT:    [[SLT:%.*]] = icmp sle i8 [[A]], 90
; CHECK-NEXT:    [[AND:%.*]] = and i1 [[SGT]], [[SLT]]
; CHECK-NEXT:    br i1 [[AND]], label [[THEN:%.*]], label [[ELSE:%.*]]
; CHECK:       then:
; CHECK-NEXT:    [[ADD_1:%.*]] = add nuw nsw i8 [[A]], 1
; CHECK-NEXT:    [[ADD_2:%.*]] = add nsw i8 [[A]], -1
; CHECK-NEXT:    [[ADD_3:%.*]] = add nuw nsw i8 [[A]], -91
; CHECK-NEXT:    [[ADD_4:%.*]] = add nsw i8 [[A]], -90
; CHECK-NEXT:    [[RES_1:%.*]] = xor i8 [[ADD_1]], [[ADD_2]]
; CHECK-NEXT:    [[RES_2:%.*]] = xor i8 [[RES_1]], [[ADD_3]]
; CHECK-NEXT:    [[RES_3:%.*]] = xor i8 [[RES_2]], [[ADD_4]]
; CHECK-NEXT:    ret i8 [[RES_3]]
; CHECK:       else:
; CHECK-NEXT:    [[ADD_5:%.*]] = add i8 [[A]], 1
; CHECK-NEXT:    [[ADD_6:%.*]] = add i8 [[A]], -1
; CHECK-NEXT:    [[ADD_7:%.*]] = add i8 [[A]], -91
; CHECK-NEXT:    [[ADD_8:%.*]] = add i8 [[A]], -90
; CHECK-NEXT:    [[RES_4:%.*]] = xor i8 [[ADD_5]], [[ADD_6]]
; CHECK-NEXT:    [[RES_5:%.*]] = xor i8 [[RES_4]], [[ADD_7]]
; CHECK-NEXT:    [[RES_6:%.*]] = xor i8 [[RES_5]], [[ADD_8]]
; CHECK-NEXT:    ret i8 [[RES_6]]
;
entry:
  %sgt = icmp sge i8 %a, 0
  %slt = icmp sle i8 %a, 90
  %and = and i1 %sgt, %slt
  br i1 %and, label %then, label %else

then:
  %add.1 = add i8 %a, 1
  %add.2 = add i8 %a, -1
  %add.3 = add i8 %a, 165
  %add.4 = add i8 %a, 166
  %res.1 = xor i8 %add.1, %add.2
  %res.2 = xor i8 %res.1, %add.3
  %res.3 = xor i8 %res.2, %add.4
  ret i8 %res.3

else:
  %add.5 = add i8 %a, 1
  %add.6 = add i8 %a, -1
  %add.7 = add i8 %a, 165
  %add.8 = add i8 %a, 166
  %res.4 = xor i8 %add.5, %add.6
  %res.5 = xor i8 %res.4, %add.7
  %res.6 = xor i8 %res.5, %add.8
  ret i8 %res.6
}

define i16 @sge_with_sext_to_zext_conversion(i8 %a)  {
; CHECK-LABEL: @sge_with_sext_to_zext_conversion(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP:%.*]] = icmp sgt i8 [[A:%.*]], 0
; CHECK-NEXT:    br i1 [[CMP]], label [[THEN:%.*]], label [[ELSE:%.*]]
; CHECK:       then:
; CHECK-NEXT:    [[SEXT:%.*]] = zext i8 [[A]] to i16
; CHECK-NEXT:    [[ADD_1:%.*]] = add i16 [[SEXT]], 1
; CHECK-NEXT:    [[ADD_2:%.*]] = add i16 [[SEXT]], -128
; CHECK-NEXT:    [[ADD_3:%.*]] = add i16 [[SEXT]], -127
; CHECK-NEXT:    [[RES_1:%.*]] = xor i16 [[ADD_1]], [[ADD_2]]
; CHECK-NEXT:    [[RES_2:%.*]] = xor i16 [[RES_1]], [[ADD_3]]
; CHECK-NEXT:    ret i16 [[RES_2]]
; CHECK:       else:
; CHECK-NEXT:    [[SEXT_2:%.*]] = sext i8 [[A]] to i16
; CHECK-NEXT:    [[ADD_4:%.*]] = add nsw i16 [[SEXT_2]], 1
; CHECK-NEXT:    [[ADD_5:%.*]] = add nsw i16 [[SEXT_2]], -128
; CHECK-NEXT:    [[ADD_6:%.*]] = add nsw i16 [[SEXT_2]], -127
; CHECK-NEXT:    [[RES_3:%.*]] = xor i16 [[ADD_4]], [[ADD_5]]
; CHECK-NEXT:    [[RES_4:%.*]] = xor i16 [[RES_3]], [[ADD_6]]
; CHECK-NEXT:    ret i16 [[RES_4]]
;
entry:
  %cmp = icmp sgt i8 %a, 0
  br i1 %cmp, label %then, label %else

then:
  %sext = sext i8 %a to i16
  %add.1 = add i16 %sext, 1
  %add.2 = add i16 %sext, 65408
  %add.3 = add i16 %sext, 65409
  %res.1 = xor i16 %add.1, %add.2
  %res.2 = xor i16 %res.1, %add.3
  ret i16 %res.2

else:
  %sext.2 = sext i8 %a to i16
  %add.4 = add i16 %sext.2, 1
  %add.5 = add i16 %sext.2, 65408
  %add.6 = add i16 %sext.2, 65409
  %res.3 = xor i16 %add.4, %add.5
  %res.4 = xor i16 %res.3, %add.6
  ret i16 %res.4
}

@c = internal global <6 x i8> zeroinitializer, align 8

; Test case for PR60280.
define <6 x i8> @vector_constant_replacement_in_add(<6 x i8> %a) {
; CHECK-LABEL: @vector_constant_replacement_in_add(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[ADD:%.*]] = add <6 x i8> [[A:%.*]], zeroinitializer
; CHECK-NEXT:    ret <6 x i8> [[ADD]]
;
entry:
  %c = load <6 x i8>, ptr @c, align 8
  %add = add <6 x i8> %a, %c
  ret <6 x i8> %add
}

declare i32 @callee()

; Test case for PR60278.
define i64 @constant_ptrtoint_replacement(i64 %a) {
; CHECK-LABEL: @constant_ptrtoint_replacement(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add i64 [[A:%.*]], ptrtoint (ptr @callee to i64)
; CHECK-NEXT:    ret i64 [[RES]]
;
entry:
  %fn.addr = ptrtoint ptr @callee to i64
  %res = add i64 %a, %fn.addr
  ret i64 %res
}

define internal <4 x i8> @test_propagate_argument(<4 x i8> %a, <4 x i8> %b) {
; CHECK-LABEL: @test_propagate_argument(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[ADD:%.*]] = add <4 x i8> [[A:%.*]], <i8 3, i8 3, i8 3, i8 3>
; CHECK-NEXT:    ret <4 x i8> [[ADD]]
;
entry:
  %add = add <4 x i8> %a, %b
  ret <4 x i8> %add
}

define <4 x i8> @test_propagate_caller(<4 x i8> %a) {
; CHECK-LABEL: @test_propagate_caller(
; CHECK-NEXT:    [[RES_1:%.*]] = call <4 x i8> @test_propagate_argument(<4 x i8> [[A:%.*]], <4 x i8> <i8 3, i8 3, i8 3, i8 3>)
; CHECK-NEXT:    ret <4 x i8> [[RES_1]]
;
  %add = add <4 x i8> <i8 1, i8 1, i8 1, i8 1>, <i8 2, i8 2, i8 2, i8 2>
  %res.1 = call <4 x i8> @test_propagate_argument(<4 x i8> %a, <4 x i8> %add)
  ret <4 x i8> %res.1
}

define i16 @test_add_in_different_block(i1 %c, i8 %a) {
; CHECK-LABEL: @test_add_in_different_block(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i8 [[A:%.*]], 0
; CHECK-NEXT:    [[COND4:%.*]] = select i1 [[CMP]], i8 1, i8 0
; CHECK-NEXT:    [[CONV:%.*]] = zext i8 [[COND4]] to i16
; CHECK-NEXT:    br i1 [[C:%.*]], label [[THEN:%.*]], label [[ELSE:%.*]]
; CHECK:       then:
; CHECK-NEXT:    [[ADD:%.*]] = add i16 1, [[CONV]]
; CHECK-NEXT:    ret i16 [[ADD]]
; CHECK:       else:
; CHECK-NEXT:    ret i16 0
;
entry:
  %cmp = icmp eq i8 %a, 0
  %cond4 = select i1 %cmp, i8 1, i8 0
  %conv = sext i8 %cond4 to i16
  br i1 %c, label %then, label %else

then:
  %add = add i16 1, %conv
  ret i16 %add

else:
  ret i16 0
}
