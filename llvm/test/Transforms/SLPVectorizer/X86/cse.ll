; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=slp-vectorizer -S -mtriple=i386-apple-macosx10.8.0 -mcpu=corei7-avx | FileCheck %s

target datalayout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:128:128-n8:16:32-S128"
target triple = "i386-apple-macosx10.8.0"

;int test(ptr G) {
;  G[0] = 1+Gptr4;
;  G[1] = 6+Gptr3;
;  G[2] = 7+Gptr4;
;  G[3] = 8+Gptr4;
;}

define i32 @test(ptr nocapture %G) {
; CHECK-LABEL: @test(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds double, ptr [[G:%.*]], i64 5
; CHECK-NEXT:    [[TMP0:%.*]] = load <2 x double>, ptr [[ARRAYIDX]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = fmul <2 x double> [[TMP0]], <double 4.000000e+00, double 3.000000e+00>
; CHECK-NEXT:    [[TMP2:%.*]] = fadd <2 x double> [[TMP1]], <double 1.000000e+00, double 6.000000e+00>
; CHECK-NEXT:    store <2 x double> [[TMP2]], ptr [[G]], align 8
; CHECK-NEXT:    [[ARRAYIDX9:%.*]] = getelementptr inbounds double, ptr [[G]], i64 2
; CHECK-NEXT:    [[TMP3:%.*]] = extractelement <2 x double> [[TMP0]], i32 1
; CHECK-NEXT:    [[MUL11:%.*]] = fmul double [[TMP3]], 4.000000e+00
; CHECK-NEXT:    [[TMP4:%.*]] = insertelement <2 x double> [[TMP1]], double [[MUL11]], i32 1
; CHECK-NEXT:    [[TMP5:%.*]] = fadd <2 x double> [[TMP4]], <double 7.000000e+00, double 8.000000e+00>
; CHECK-NEXT:    store <2 x double> [[TMP5]], ptr [[ARRAYIDX9]], align 8
; CHECK-NEXT:    ret i32 undef
;
entry:
  %arrayidx = getelementptr inbounds double, ptr %G, i64 5
  %0 = load double, ptr %arrayidx, align 8
  %mul = fmul double %0, 4.000000e+00
  %add = fadd double %mul, 1.000000e+00
  store double %add, ptr %G, align 8
  %arrayidx2 = getelementptr inbounds double, ptr %G, i64 6
  %1 = load double, ptr %arrayidx2, align 8
  %mul3 = fmul double %1, 3.000000e+00
  %add4 = fadd double %mul3, 6.000000e+00
  %arrayidx5 = getelementptr inbounds double, ptr %G, i64 1
  store double %add4, ptr %arrayidx5, align 8
  %add8 = fadd double %mul, 7.000000e+00
  %arrayidx9 = getelementptr inbounds double, ptr %G, i64 2
  store double %add8, ptr %arrayidx9, align 8
  %mul11 = fmul double %1, 4.000000e+00
  %add12 = fadd double %mul11, 8.000000e+00
  %arrayidx13 = getelementptr inbounds double, ptr %G, i64 3
  store double %add12, ptr %arrayidx13, align 8
  ret i32 undef
}

;int foo(ptr A, int n) {
;  A[0] = Aptr 7.9 * n + 6.0;
;  A[1] = Aptr 7.7 * n + 2.0;
;  A[2] = Aptr 7.6 * n + 3.0;
;  A[3] = Aptr 7.4 * n + 4.0;
;}

define i32 @foo(ptr nocapture %A, i32 %n) {
; CHECK-LABEL: @foo(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CONV:%.*]] = sitofp i32 [[N:%.*]] to double
; CHECK-NEXT:    [[TMP0:%.*]] = load <4 x double>, ptr [[A:%.*]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = fmul <4 x double> [[TMP0]], <double 7.900000e+00, double 7.700000e+00, double 7.600000e+00, double 7.400000e+00>
; CHECK-NEXT:    [[TMP2:%.*]] = insertelement <4 x double> poison, double [[CONV]], i32 0
; CHECK-NEXT:    [[TMP3:%.*]] = shufflevector <4 x double> [[TMP2]], <4 x double> poison, <4 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP4:%.*]] = fmul <4 x double> [[TMP3]], [[TMP1]]
; CHECK-NEXT:    [[TMP5:%.*]] = fadd <4 x double> [[TMP4]], <double 6.000000e+00, double 2.000000e+00, double 3.000000e+00, double 4.000000e+00>
; CHECK-NEXT:    store <4 x double> [[TMP5]], ptr [[A]], align 8
; CHECK-NEXT:    ret i32 undef
;
entry:
  %0 = load double, ptr %A, align 8
  %mul = fmul double %0, 7.900000e+00
  %conv = sitofp i32 %n to double
  %mul1 = fmul double %conv, %mul
  %add = fadd double %mul1, 6.000000e+00
  store double %add, ptr %A, align 8
  %arrayidx3 = getelementptr inbounds double, ptr %A, i64 1
  %1 = load double, ptr %arrayidx3, align 8
  %mul4 = fmul double %1, 7.700000e+00
  %mul6 = fmul double %conv, %mul4
  %add7 = fadd double %mul6, 2.000000e+00
  store double %add7, ptr %arrayidx3, align 8
  %arrayidx9 = getelementptr inbounds double, ptr %A, i64 2
  %2 = load double, ptr %arrayidx9, align 8
  %mul10 = fmul double %2, 7.600000e+00
  %mul12 = fmul double %conv, %mul10
  %add13 = fadd double %mul12, 3.000000e+00
  store double %add13, ptr %arrayidx9, align 8
  %arrayidx15 = getelementptr inbounds double, ptr %A, i64 3
  %3 = load double, ptr %arrayidx15, align 8
  %mul16 = fmul double %3, 7.400000e+00
  %mul18 = fmul double %conv, %mul16
  %add19 = fadd double %mul18, 4.000000e+00
  store double %add19, ptr %arrayidx15, align 8
  ret i32 undef
}

; int test2(ptr G, int k) {
;   if (k) {
;     G[0] = 1+Gptr4;
;     G[1] = 6+Gptr3;
;   } else {
;     G[2] = 7+Gptr4;
;     G[3] = 8+Gptr3;
;   }
; }

; We can't merge the gather sequences because one does not dominate the other.

define i32 @test2(ptr nocapture %G, i32 %k) {
; CHECK-LABEL: @test2(
; CHECK-NEXT:    [[TMP1:%.*]] = icmp eq i32 [[K:%.*]], 0
; CHECK-NEXT:    [[TMP2:%.*]] = getelementptr inbounds double, ptr [[G:%.*]], i64 5
; CHECK-NEXT:    [[TMP3:%.*]] = load double, ptr [[TMP2]], align 8
; CHECK-NEXT:    [[TMP4:%.*]] = fmul double [[TMP3]], 4.000000e+00
; CHECK-NEXT:    br i1 [[TMP1]], label [[TMP12:%.*]], label [[TMP5:%.*]]
; CHECK:       5:
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr inbounds double, ptr [[G]], i64 6
; CHECK-NEXT:    [[TMP7:%.*]] = load double, ptr [[TMP6]], align 8
; CHECK-NEXT:    [[TMP8:%.*]] = fmul double [[TMP7]], 3.000000e+00
; CHECK-NEXT:    [[TMP9:%.*]] = insertelement <2 x double> poison, double [[TMP4]], i32 0
; CHECK-NEXT:    [[TMP10:%.*]] = insertelement <2 x double> [[TMP9]], double [[TMP8]], i32 1
; CHECK-NEXT:    [[TMP11:%.*]] = fadd <2 x double> [[TMP10]], <double 1.000000e+00, double 6.000000e+00>
; CHECK-NEXT:    store <2 x double> [[TMP11]], ptr [[G]], align 8
; CHECK-NEXT:    br label [[TMP20:%.*]]
; CHECK:       12:
; CHECK-NEXT:    [[TMP13:%.*]] = getelementptr inbounds double, ptr [[G]], i64 2
; CHECK-NEXT:    [[TMP14:%.*]] = getelementptr inbounds double, ptr [[G]], i64 6
; CHECK-NEXT:    [[TMP15:%.*]] = load double, ptr [[TMP14]], align 8
; CHECK-NEXT:    [[TMP16:%.*]] = fmul double [[TMP15]], 3.000000e+00
; CHECK-NEXT:    [[TMP17:%.*]] = insertelement <2 x double> poison, double [[TMP4]], i32 0
; CHECK-NEXT:    [[TMP18:%.*]] = insertelement <2 x double> [[TMP17]], double [[TMP16]], i32 1
; CHECK-NEXT:    [[TMP19:%.*]] = fadd <2 x double> [[TMP18]], <double 7.000000e+00, double 8.000000e+00>
; CHECK-NEXT:    store <2 x double> [[TMP19]], ptr [[TMP13]], align 8
; CHECK-NEXT:    br label [[TMP20]]
; CHECK:       20:
; CHECK-NEXT:    ret i32 undef
;
  %1 = icmp eq i32 %k, 0
  %2 = getelementptr inbounds double, ptr %G, i64 5
  %3 = load double, ptr %2, align 8
  %4 = fmul double %3, 4.000000e+00
  br i1 %1, label %12, label %5

; <label>:5                                       ; preds = %0
  %6 = fadd double %4, 1.000000e+00
  store double %6, ptr %G, align 8
  %7 = getelementptr inbounds double, ptr %G, i64 6
  %8 = load double, ptr %7, align 8
  %9 = fmul double %8, 3.000000e+00
  %10 = fadd double %9, 6.000000e+00
  %11 = getelementptr inbounds double, ptr %G, i64 1
  store double %10, ptr %11, align 8
  br label %20

; <label>:12                                      ; preds = %0
  %13 = fadd double %4, 7.000000e+00
  %14 = getelementptr inbounds double, ptr %G, i64 2
  store double %13, ptr %14, align 8
  %15 = getelementptr inbounds double, ptr %G, i64 6
  %16 = load double, ptr %15, align 8
  %17 = fmul double %16, 3.000000e+00
  %18 = fadd double %17, 8.000000e+00
  %19 = getelementptr inbounds double, ptr %G, i64 3
  store double %18, ptr %19, align 8
  br label %20

; <label>:20                                      ; preds = %12, %5
  ret i32 undef
}


;int foo(ptr A, int n) {
;  A[0] = Aptr 7.9 * n + 6.0;
;  A[1] = Aptr 7.9 * n + 6.0;
;  A[2] = Aptr 7.9 * n + 6.0;
;  A[3] = Aptr 7.9 * n + 6.0;
;}

define i32 @foo4(ptr nocapture %A, i32 %n) {
; CHECK-LABEL: @foo4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CONV:%.*]] = sitofp i32 [[N:%.*]] to double
; CHECK-NEXT:    [[TMP0:%.*]] = load <4 x double>, ptr [[A:%.*]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = fmul <4 x double> [[TMP0]], <double 7.900000e+00, double 7.900000e+00, double 7.900000e+00, double 7.900000e+00>
; CHECK-NEXT:    [[TMP2:%.*]] = insertelement <4 x double> poison, double [[CONV]], i32 0
; CHECK-NEXT:    [[TMP3:%.*]] = shufflevector <4 x double> [[TMP2]], <4 x double> poison, <4 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP4:%.*]] = fmul <4 x double> [[TMP3]], [[TMP1]]
; CHECK-NEXT:    [[TMP5:%.*]] = fadd <4 x double> [[TMP4]], <double 6.000000e+00, double 6.000000e+00, double 6.000000e+00, double 6.000000e+00>
; CHECK-NEXT:    store <4 x double> [[TMP5]], ptr [[A]], align 8
; CHECK-NEXT:    ret i32 undef
;
entry:
  %0 = load double, ptr %A, align 8
  %mul = fmul double %0, 7.900000e+00
  %conv = sitofp i32 %n to double
  %mul1 = fmul double %conv, %mul
  %add = fadd double %mul1, 6.000000e+00
  store double %add, ptr %A, align 8
  %arrayidx3 = getelementptr inbounds double, ptr %A, i64 1
  %1 = load double, ptr %arrayidx3, align 8
  %mul4 = fmul double %1, 7.900000e+00
  %mul6 = fmul double %conv, %mul4
  %add7 = fadd double %mul6, 6.000000e+00
  store double %add7, ptr %arrayidx3, align 8
  %arrayidx9 = getelementptr inbounds double, ptr %A, i64 2
  %2 = load double, ptr %arrayidx9, align 8
  %mul10 = fmul double %2, 7.900000e+00
  %mul12 = fmul double %conv, %mul10
  %add13 = fadd double %mul12, 6.000000e+00
  store double %add13, ptr %arrayidx9, align 8
  %arrayidx15 = getelementptr inbounds double, ptr %A, i64 3
  %3 = load double, ptr %arrayidx15, align 8
  %mul16 = fmul double %3, 7.900000e+00
  %mul18 = fmul double %conv, %mul16
  %add19 = fadd double %mul18, 6.000000e+00
  store double %add19, ptr %arrayidx15, align 8
  ret i32 undef
}

;int partial_mrg(ptr A, int n) {
;  A[0] = Aptr n;
;  A[1] = Aptr n;
;  if (n < 4) return 0;
;  A[2] = Aptr n;
;  A[3] = Aptr (n+4);
;}

define i32 @partial_mrg(ptr nocapture %A, i32 %n) {
; CHECK-LABEL: @partial_mrg(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CONV:%.*]] = sitofp i32 [[N:%.*]] to double
; CHECK-NEXT:    [[TMP0:%.*]] = load <2 x double>, ptr [[A:%.*]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = insertelement <2 x double> poison, double [[CONV]], i32 0
; CHECK-NEXT:    [[TMP2:%.*]] = shufflevector <2 x double> [[TMP1]], <2 x double> poison, <2 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP3:%.*]] = fmul <2 x double> [[TMP2]], [[TMP0]]
; CHECK-NEXT:    store <2 x double> [[TMP3]], ptr [[A]], align 8
; CHECK-NEXT:    [[CMP:%.*]] = icmp slt i32 [[N]], 4
; CHECK-NEXT:    br i1 [[CMP]], label [[RETURN:%.*]], label [[IF_END:%.*]]
; CHECK:       if.end:
; CHECK-NEXT:    [[ARRAYIDX7:%.*]] = getelementptr inbounds double, ptr [[A]], i64 2
; CHECK-NEXT:    [[ADD:%.*]] = add nsw i32 [[N]], 4
; CHECK-NEXT:    [[CONV12:%.*]] = sitofp i32 [[ADD]] to double
; CHECK-NEXT:    [[TMP4:%.*]] = load <2 x double>, ptr [[ARRAYIDX7]], align 8
; CHECK-NEXT:    [[TMP5:%.*]] = insertelement <2 x double> [[TMP1]], double [[CONV12]], i32 1
; CHECK-NEXT:    [[TMP6:%.*]] = fmul <2 x double> [[TMP5]], [[TMP4]]
; CHECK-NEXT:    store <2 x double> [[TMP6]], ptr [[ARRAYIDX7]], align 8
; CHECK-NEXT:    br label [[RETURN]]
; CHECK:       return:
; CHECK-NEXT:    ret i32 0
;
entry:
  %0 = load double, ptr %A, align 8
  %conv = sitofp i32 %n to double
  %mul = fmul double %conv, %0
  store double %mul, ptr %A, align 8
  %arrayidx2 = getelementptr inbounds double, ptr %A, i64 1
  %1 = load double, ptr %arrayidx2, align 8
  %mul4 = fmul double %conv, %1
  store double %mul4, ptr %arrayidx2, align 8
  %cmp = icmp slt i32 %n, 4
  br i1 %cmp, label %return, label %if.end

if.end:                                           ; preds = %entry
  %arrayidx7 = getelementptr inbounds double, ptr %A, i64 2
  %2 = load double, ptr %arrayidx7, align 8
  %mul9 = fmul double %conv, %2
  store double %mul9, ptr %arrayidx7, align 8
  %arrayidx11 = getelementptr inbounds double, ptr %A, i64 3
  %3 = load double, ptr %arrayidx11, align 8
  %add = add nsw i32 %n, 4
  %conv12 = sitofp i32 %add to double
  %mul13 = fmul double %conv12, %3
  store double %mul13, ptr %arrayidx11, align 8
  br label %return

return:                                           ; preds = %entry, %if.end
  ret i32 0
}

%class.B.53.55 = type { %class.A.52.54, double }
%class.A.52.54 = type { double, double, double }

@a = external global double, align 8

define void @PR19646(ptr %this) {
; CHECK-LABEL: @PR19646(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br i1 undef, label [[IF_END13:%.*]], label [[IF_END13]]
; CHECK:       sw.epilog7:
; CHECK-NEXT:    [[DOTIN:%.*]] = getelementptr inbounds [[CLASS_B_53_55:%.*]], ptr [[THIS:%.*]], i64 0, i32 0, i32 1
; CHECK-NEXT:    [[TMP0:%.*]] = load double, ptr [[DOTIN]], align 8
; CHECK-NEXT:    [[ADD:%.*]] = fadd double undef, 0.000000e+00
; CHECK-NEXT:    [[ADD6:%.*]] = fadd double [[ADD]], [[TMP0]]
; CHECK-NEXT:    [[TMP1:%.*]] = load double, ptr @a, align 8
; CHECK-NEXT:    [[ADD8:%.*]] = fadd double [[TMP1]], 0.000000e+00
; CHECK-NEXT:    [[_DY:%.*]] = getelementptr inbounds [[CLASS_B_53_55]], ptr [[THIS]], i64 0, i32 0, i32 2
; CHECK-NEXT:    [[TMP2:%.*]] = load double, ptr [[_DY]], align 8
; CHECK-NEXT:    [[ADD10:%.*]] = fadd double [[ADD8]], [[TMP2]]
; CHECK-NEXT:    br i1 undef, label [[IF_THEN12:%.*]], label [[IF_END13]]
; CHECK:       if.then12:
; CHECK-NEXT:    [[TMP3:%.*]] = load double, ptr undef, align 8
; CHECK-NEXT:    br label [[IF_END13]]
; CHECK:       if.end13:
; CHECK-NEXT:    [[X_1:%.*]] = phi double [ 0.000000e+00, [[IF_THEN12]] ], [ [[ADD6]], [[SW_EPILOG7:%.*]] ], [ undef, [[ENTRY:%.*]] ], [ undef, [[ENTRY]] ]
; CHECK-NEXT:    [[B_0:%.*]] = phi double [ [[TMP3]], [[IF_THEN12]] ], [ [[ADD10]], [[SW_EPILOG7]] ], [ undef, [[ENTRY]] ], [ undef, [[ENTRY]] ]
; CHECK-NEXT:    unreachable
;
entry:
  br i1 undef, label %if.end13, label %if.end13

sw.epilog7:                                       ; No predecessors!
  %.in = getelementptr inbounds %class.B.53.55, ptr %this, i64 0, i32 0, i32 1
  %0 = load double, ptr %.in, align 8
  %add = fadd double undef, 0.000000e+00
  %add6 = fadd double %add, %0
  %1 = load double, ptr @a, align 8
  %add8 = fadd double %1, 0.000000e+00
  %_dy = getelementptr inbounds %class.B.53.55, ptr %this, i64 0, i32 0, i32 2
  %2 = load double, ptr %_dy, align 8
  %add10 = fadd double %add8, %2
  br i1 undef, label %if.then12, label %if.end13

if.then12:                                        ; preds = %sw.epilog7
  %3 = load double, ptr undef, align 8
  br label %if.end13

if.end13:                                         ; preds = %if.then12, %sw.epilog7, %entry
  %x.1 = phi double [ 0.000000e+00, %if.then12 ], [ %add6, %sw.epilog7 ], [ undef, %entry ], [ undef, %entry ]
  %b.0 = phi double [ %3, %if.then12 ], [ %add10, %sw.epilog7 ], [ undef, %entry], [ undef, %entry ]
  unreachable
}

define void @cse_for_hoisted_instructions_in_preheader(ptr %dst, i32 %a, i1 %c) {
; CHECK-LABEL: @cse_for_hoisted_instructions_in_preheader(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = insertelement <2 x i32> poison, i32 [[A:%.*]], i32 0
; CHECK-NEXT:    [[TMP1:%.*]] = shufflevector <2 x i32> [[TMP0]], <2 x i32> poison, <2 x i32> zeroinitializer
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[TMP2:%.*]] = or <2 x i32> <i32 22, i32 22>, [[TMP1]]
; CHECK-NEXT:    [[TMP3:%.*]] = or <2 x i32> [[TMP2]], <i32 3, i32 3>
; CHECK-NEXT:    store <2 x i32> [[TMP3]], ptr [[DST:%.*]], align 4
; CHECK-NEXT:    [[OR_2:%.*]] = or i32 [[A]], 3
; CHECK-NEXT:    [[GEP_2:%.*]] = getelementptr inbounds i32, ptr [[DST]], i64 10
; CHECK-NEXT:    store i32 [[OR_2]], ptr [[GEP_2]], align 4
; CHECK-NEXT:    [[OR_3:%.*]] = or i32 [[A]], 3
; CHECK-NEXT:    [[GEP_3:%.*]] = getelementptr inbounds i32, ptr [[DST]], i64 11
; CHECK-NEXT:    store i32 [[OR_3]], ptr [[GEP_3]], align 4
; CHECK-NEXT:    br i1 [[C:%.*]], label [[LOOP]], label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
;
entry:
  br label %loop

loop:
  %or.a = or i32 22, %a
  %or.0 = or i32 %or.a, 3
  store i32 %or.0, ptr %dst
  %or.a.2 = or i32 22, %a
  %or.1 = or i32 %or.a.2, 3
  %gep.1 = getelementptr inbounds i32, ptr %dst, i64 1
  store i32 %or.1, ptr %gep.1
  %or.2 = or i32 %a, 3
  %gep.2 = getelementptr inbounds i32, ptr %dst, i64 10
  store i32 %or.2, ptr %gep.2
  %or.3 = or i32 %a, 3
  %gep.3 = getelementptr inbounds i32, ptr %dst, i64 11
  store i32 %or.3, ptr %gep.3
  br i1 %c, label %loop, label %exit

exit:
  ret void
}
