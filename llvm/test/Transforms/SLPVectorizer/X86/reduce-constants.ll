; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -mtriple=x86_64 -passes=slp-vectorizer < %s | FileCheck %s

define double @test(double %m, double %a) {
; CHECK-LABEL: @test(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = call fast double @llvm.maxnum.f64(double 0.000000e+00, double [[M:%.*]])
; CHECK-NEXT:    [[TMP1:%.*]] = call fast double @llvm.maxnum.f64(double [[TMP0]], double [[A:%.*]])
; CHECK-NEXT:    ret double [[TMP1]]
;
entry:
  %c = tail call fast double @llvm.maxnum.f64(double %m, double 0.000000e+00)
  %c1 = tail call fast double @llvm.maxnum.f64(double %a, double %c)
  %c2 = tail call fast double @llvm.maxnum.f64(double %c1, double 0.000000e+00)
  ret double %c2
}

declare double @llvm.maxnum.f64(double, double)