; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=instcombine -S | FileCheck %s

define i1 @test_eq(i1 %cond) {
; CHECK-LABEL: @test_eq(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    [[COMPARE:%.*]] = xor i1 [[COND]], true
; CHECK-NEXT:    ret i1 [[COMPARE]]
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi i32 [123, %if.true], [456, %if.false]
  br label %exit

exit:
  %compare = icmp eq i32 %phi, 456
  ret i1 %compare
}

define i1 @test_slt(i1 %cond) {
; CHECK-LABEL: @test_slt(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret i1 [[COND]]
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi i32 [123, %if.true], [456, %if.false]
  br label %exit

exit:
  %compare = icmp slt i32 %phi, 456
  ret i1 %compare
}

define i1 @test_sle(i1 %cond) {
; CHECK-LABEL: @test_sle(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret i1 true
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi i32 [123, %if.true], [456, %if.false]
  br label %exit

exit:
  %compare = icmp sle i32 %phi, 456
  ret i1 %compare
}

define i1 @test_ne(i1 %cond) {
; CHECK-LABEL: @test_ne(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret i1 [[COND]]
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi i32 [123, %if.true], [456, %if.false]
  br label %exit

exit:
  %compare = icmp ne i32 %phi, 456
  ret i1 %compare
}

define i1 @test_ne_undef(i1 %cond) {
; CHECK-LABEL: @test_ne_undef(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret i1 false
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi i32 [undef, %if.true], [456, %if.false]
  br label %exit

exit:
  %compare = icmp ne i32 %phi, 456
  ret i1 %compare
}

define <2 x i1> @test_ne_int_vector(i1 %cond) {
; CHECK-LABEL: @test_ne_int_vector(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    [[COMPARE:%.*]] = phi <2 x i1> [ <i1 true, i1 false>, [[IF_FALSE]] ], [ <i1 false, i1 true>, [[IF_TRUE]] ]
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret <2 x i1> [[COMPARE]]
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi <2 x i32> [<i32 123, i32 123>, %if.true], [<i32 456, i32 456>, %if.false]
  br label %exit

exit:
  %compare = icmp ne <2 x i32> %phi, <i32 123, i32 456>
  ret <2 x i1> %compare
}

; TODO: We can also constant-fold this comparison for floats.
define i1 @test_ne_float(i1 %cond) {
; CHECK-LABEL: @test_ne_float(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    [[PHI:%.*]] = phi float [ 1.000000e+00, [[IF_TRUE]] ], [ 1.250000e+00, [[IF_FALSE]] ]
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    [[COMPARE:%.*]] = fcmp one float [[PHI]], 1.250000e+00
; CHECK-NEXT:    ret i1 [[COMPARE]]
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi float [1.0, %if.true], [1.25, %if.false]
  br label %exit

exit:
  %compare = fcmp one float %phi, 1.25
  ret i1 %compare
}

define i1 @test_ne_float_undef(i1 %cond) {
; CHECK-LABEL: @test_ne_float_undef(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret i1 true
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi float [1.0, %if.true], [undef, %if.false]
  br label %exit

exit:
  %compare = fcmp one float %phi, 1.25
  ret i1 %compare
}

define <2 x i1> @test_ne_float_vector(i1 %cond) {
; CHECK-LABEL: @test_ne_float_vector(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 [[COND:%.*]], label [[IF_TRUE:%.*]], label [[IF_FALSE:%.*]]
; CHECK:       if.true:
; CHECK-NEXT:    br label [[MERGE:%.*]]
; CHECK:       if.false:
; CHECK-NEXT:    br label [[MERGE]]
; CHECK:       merge:
; CHECK-NEXT:    [[PHI:%.*]] = phi <2 x float> [ <float 1.232500e+02, float 1.232500e+02>, [[IF_TRUE]] ], [ <float 4.562500e+02, float 4.562500e+02>, [[IF_FALSE]] ]
; CHECK-NEXT:    br label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    [[COMPARE:%.*]] = fcmp one <2 x float> [[PHI]], <float 1.232500e+02, float 4.562500e+02>
; CHECK-NEXT:    ret <2 x i1> [[COMPARE]]
;
entry:
  br i1 %cond, label %if.true, label %if.false

if.true:
  br label %merge

if.false:
  br label %merge

merge:
  %phi = phi <2 x float> [<float 123.25, float 123.25>, %if.true], [<float 456.25, float 456.25>, %if.false]
  br label %exit

exit:
  %compare = fcmp one <2 x float> %phi, <float 123.25, float 456.25>
  ret <2 x i1> %compare
}
