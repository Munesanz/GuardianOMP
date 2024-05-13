// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// RUN: %clang_cc1 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s
// expected-no-diagnostics

// CHECK-LABEL: @main(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[RETVAL:%.*]] = alloca i32, align 4
// CHECK-NEXT:    [[A:%.*]] = alloca i32, align 4
// CHECK-NEXT:    store i32 0, ptr [[RETVAL]], align 4
// CHECK-NEXT:    store i32 0, ptr [[A]], align 4, !dbg [[DBG9:![0-9]+]]
// CHECK-NEXT:    [[TMP0:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.SHARED"(ptr [[A]], i32 undef), "QUAL.OSS.DEP.IN"(ptr [[A]], [2 x i8] c"a\00", ptr @compute_dep, ptr [[A]]) ], !dbg [[DBG10:![0-9]+]]
// CHECK-NEXT:    [[TMP1:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.SHARED"(ptr [[A]], i32 undef), "QUAL.OSS.DEP.REDUCTION"(i32 6000, ptr [[A]], [2 x i8] c"a\00", ptr @compute_dep.1, ptr [[A]]), "QUAL.OSS.DEP.REDUCTION.INIT"(ptr [[A]], ptr @red_init), "QUAL.OSS.DEP.REDUCTION.COMBINE"(ptr [[A]], ptr @red_comb) ], !dbg [[DBG11:![0-9]+]]
// CHECK-NEXT:    [[TMP2:%.*]] = load i32, ptr [[A]], align 4, !dbg [[DBG12:![0-9]+]]
// CHECK-NEXT:    [[INC:%.*]] = add nsw i32 [[TMP2]], 1, !dbg [[DBG12]]
// CHECK-NEXT:    store i32 [[INC]], ptr [[A]], align 4, !dbg [[DBG12]]
// CHECK-NEXT:    call void @llvm.directive.region.exit(token [[TMP1]]), !dbg [[DBG13:![0-9]+]]
// CHECK-NEXT:    call void @llvm.directive.region.exit(token [[TMP0]]), !dbg [[DBG14:![0-9]+]]
// CHECK-NEXT:    ret i32 0, !dbg [[DBG15:![0-9]+]]
//
int main()
{
  int a = 0;
  #pragma oss task in(a)
  {
    #pragma oss task reduction(+: a)
    a++;
  }
  return 0;
}

// The red_init/red_comb allocas should not be between these regions entry