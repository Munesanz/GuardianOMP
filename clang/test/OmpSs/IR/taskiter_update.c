// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// RUN: %clang_cc1 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s
// expected-no-diagnostics
// CHECK-LABEL: @foo(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[N_ADDR:%.*]] = alloca i32, align 4
// CHECK-NEXT:    [[I:%.*]] = alloca i32, align 4
// CHECK-NEXT:    store i32 [[N:%.*]], ptr [[N_ADDR]], align 4
// CHECK-NEXT:    store i32 0, ptr [[I]], align 4, !dbg [[DBG9:![0-9]+]]
// CHECK-NEXT:    [[TMP0:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([13 x i8] c"TASKITER.FOR\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr [[I]], i32 undef), "QUAL.OSS.LOOP.IND.VAR"(ptr [[I]]), "QUAL.OSS.LOOP.LOWER.BOUND"(ptr @compute_lb), "QUAL.OSS.LOOP.UPPER.BOUND"(ptr @compute_ub), "QUAL.OSS.LOOP.STEP"(ptr @compute_step), "QUAL.OSS.LOOP.UPDATE"(i1 true), "QUAL.OSS.LOOP.TYPE"(i64 0, i64 1, i64 1, i64 1, i64 1) ], !dbg [[DBG10:![0-9]+]]
// CHECK-NEXT:    call void @llvm.directive.region.exit(token [[TMP0]]), !dbg [[DBG11:![0-9]+]]
// CHECK-NEXT:    ret void, !dbg [[DBG12:![0-9]+]]
//
void foo(int n) {
  #pragma oss taskiter update
  for (int i = 0; i < 10; ++i) { }
}


