// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// RUN: %clang_cc1 -triple x86_64-gnu-linux -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=LIN64
// RUN: %clang_cc1 -triple ppc64 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=PPC64
// RUN: %clang_cc1 -triple aarch64 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=AARCH64
// expected-no-diagnostics

// LIN64-LABEL: @foo(
// LIN64-NEXT:  entry:
// LIN64-NEXT:    [[X_ADDR:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[A:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[B:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[C:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
// LIN64-NEXT:    [[__VLA_EXPR0:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[M:%.*]] = alloca i32, align 4
// LIN64-NEXT:    store i32 [[X:%.*]], ptr [[X_ADDR]], align 4
// LIN64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[X_ADDR]], align 4, !dbg [[DBG9:![0-9]+]]
// LIN64-NEXT:    [[TMP1:%.*]] = zext i32 [[TMP0]] to i64, !dbg [[DBG10:![0-9]+]]
// LIN64-NEXT:    [[TMP2:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG10]]
// LIN64-NEXT:    store ptr [[TMP2]], ptr [[SAVED_STACK]], align 8, !dbg [[DBG10]]
// LIN64-NEXT:    [[VLA:%.*]] = alloca i32, i64 [[TMP1]], align 16, !dbg [[DBG10]]
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[__VLA_EXPR0]], align 8, !dbg [[DBG10]]
// LIN64-NEXT:    [[TMP3:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr [[X_ADDR]], i32 undef) ], !dbg [[DBG11:![0-9]+]]
// LIN64-NEXT:    [[D:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[E:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[F:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[SAVED_STACK1:%.*]] = alloca ptr, align 8
// LIN64-NEXT:    [[__VLA_EXPR1:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[X_ADDR]], align 4, !dbg [[DBG12:![0-9]+]]
// LIN64-NEXT:    [[TMP5:%.*]] = zext i32 [[TMP4]] to i64, !dbg [[DBG13:![0-9]+]]
// LIN64-NEXT:    [[TMP6:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG13]]
// LIN64-NEXT:    store ptr [[TMP6]], ptr [[SAVED_STACK1]], align 8, !dbg [[DBG13]]
// LIN64-NEXT:    [[VLA2:%.*]] = alloca i32, i64 [[TMP5]], align 16, !dbg [[DBG13]]
// LIN64-NEXT:    store i64 [[TMP5]], ptr [[__VLA_EXPR1]], align 8, !dbg [[DBG13]]
// LIN64-NEXT:    [[TMP7:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00") ], !dbg [[DBG14:![0-9]+]]
// LIN64-NEXT:    [[G:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[H:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[I:%.*]] = alloca i32, align 4
// LIN64-NEXT:    call void @llvm.directive.region.exit(token [[TMP7]]), !dbg [[DBG15:![0-9]+]]
// LIN64-NEXT:    [[TMP8:%.*]] = load ptr, ptr [[SAVED_STACK1]], align 8, !dbg [[DBG16:![0-9]+]]
// LIN64-NEXT:    call void @llvm.stackrestore(ptr [[TMP8]]), !dbg [[DBG16]]
// LIN64-NEXT:    call void @llvm.directive.region.exit(token [[TMP3]]), !dbg [[DBG16]]
// LIN64-NEXT:    [[TMP9:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00") ], !dbg [[DBG17:![0-9]+]]
// LIN64-NEXT:    [[J:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[K:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[L:%.*]] = alloca i32, align 4
// LIN64-NEXT:    call void @llvm.directive.region.exit(token [[TMP9]]), !dbg [[DBG18:![0-9]+]]
// LIN64-NEXT:    [[TMP10:%.*]] = load ptr, ptr [[SAVED_STACK]], align 8, !dbg [[DBG19:![0-9]+]]
// LIN64-NEXT:    call void @llvm.stackrestore(ptr [[TMP10]]), !dbg [[DBG19]]
// LIN64-NEXT:    ret void, !dbg [[DBG19]]
//
// PPC64-LABEL: @foo(
// PPC64-NEXT:  entry:
// PPC64-NEXT:    [[X_ADDR:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[A:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[B:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[C:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
// PPC64-NEXT:    [[__VLA_EXPR0:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[M:%.*]] = alloca i32, align 4
// PPC64-NEXT:    store i32 [[X:%.*]], ptr [[X_ADDR]], align 4
// PPC64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[X_ADDR]], align 4, !dbg [[DBG9:![0-9]+]]
// PPC64-NEXT:    [[TMP1:%.*]] = zext i32 [[TMP0]] to i64, !dbg [[DBG10:![0-9]+]]
// PPC64-NEXT:    [[TMP2:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG10]]
// PPC64-NEXT:    store ptr [[TMP2]], ptr [[SAVED_STACK]], align 8, !dbg [[DBG10]]
// PPC64-NEXT:    [[VLA:%.*]] = alloca i32, i64 [[TMP1]], align 4, !dbg [[DBG10]]
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[__VLA_EXPR0]], align 8, !dbg [[DBG10]]
// PPC64-NEXT:    [[TMP3:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr [[X_ADDR]], i32 undef) ], !dbg [[DBG11:![0-9]+]]
// PPC64-NEXT:    [[D:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[E:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[F:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[SAVED_STACK1:%.*]] = alloca ptr, align 8
// PPC64-NEXT:    [[__VLA_EXPR1:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[X_ADDR]], align 4, !dbg [[DBG12:![0-9]+]]
// PPC64-NEXT:    [[TMP5:%.*]] = zext i32 [[TMP4]] to i64, !dbg [[DBG13:![0-9]+]]
// PPC64-NEXT:    [[TMP6:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG13]]
// PPC64-NEXT:    store ptr [[TMP6]], ptr [[SAVED_STACK1]], align 8, !dbg [[DBG13]]
// PPC64-NEXT:    [[VLA2:%.*]] = alloca i32, i64 [[TMP5]], align 4, !dbg [[DBG13]]
// PPC64-NEXT:    store i64 [[TMP5]], ptr [[__VLA_EXPR1]], align 8, !dbg [[DBG13]]
// PPC64-NEXT:    [[TMP7:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00") ], !dbg [[DBG14:![0-9]+]]
// PPC64-NEXT:    [[G:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[H:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[I:%.*]] = alloca i32, align 4
// PPC64-NEXT:    call void @llvm.directive.region.exit(token [[TMP7]]), !dbg [[DBG15:![0-9]+]]
// PPC64-NEXT:    [[TMP8:%.*]] = load ptr, ptr [[SAVED_STACK1]], align 8, !dbg [[DBG16:![0-9]+]]
// PPC64-NEXT:    call void @llvm.stackrestore(ptr [[TMP8]]), !dbg [[DBG16]]
// PPC64-NEXT:    call void @llvm.directive.region.exit(token [[TMP3]]), !dbg [[DBG16]]
// PPC64-NEXT:    [[TMP9:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00") ], !dbg [[DBG17:![0-9]+]]
// PPC64-NEXT:    [[J:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[K:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[L:%.*]] = alloca i32, align 4
// PPC64-NEXT:    call void @llvm.directive.region.exit(token [[TMP9]]), !dbg [[DBG18:![0-9]+]]
// PPC64-NEXT:    [[TMP10:%.*]] = load ptr, ptr [[SAVED_STACK]], align 8, !dbg [[DBG19:![0-9]+]]
// PPC64-NEXT:    call void @llvm.stackrestore(ptr [[TMP10]]), !dbg [[DBG19]]
// PPC64-NEXT:    ret void, !dbg [[DBG19]]
//
// AARCH64-LABEL: @foo(
// AARCH64-NEXT:  entry:
// AARCH64-NEXT:    [[X_ADDR:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[A:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[B:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[C:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
// AARCH64-NEXT:    [[__VLA_EXPR0:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[M:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    store i32 [[X:%.*]], ptr [[X_ADDR]], align 4
// AARCH64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[X_ADDR]], align 4, !dbg [[DBG13:![0-9]+]]
// AARCH64-NEXT:    [[TMP1:%.*]] = zext i32 [[TMP0]] to i64, !dbg [[DBG14:![0-9]+]]
// AARCH64-NEXT:    [[TMP2:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG14]]
// AARCH64-NEXT:    store ptr [[TMP2]], ptr [[SAVED_STACK]], align 8, !dbg [[DBG14]]
// AARCH64-NEXT:    [[VLA:%.*]] = alloca i32, i64 [[TMP1]], align 4, !dbg [[DBG14]]
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[__VLA_EXPR0]], align 8, !dbg [[DBG14]]
// AARCH64-NEXT:    [[TMP3:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr [[X_ADDR]], i32 undef) ], !dbg [[DBG15:![0-9]+]]
// AARCH64-NEXT:    [[D:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[E:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[F:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[SAVED_STACK1:%.*]] = alloca ptr, align 8
// AARCH64-NEXT:    [[__VLA_EXPR1:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[X_ADDR]], align 4, !dbg [[DBG16:![0-9]+]]
// AARCH64-NEXT:    [[TMP5:%.*]] = zext i32 [[TMP4]] to i64, !dbg [[DBG17:![0-9]+]]
// AARCH64-NEXT:    [[TMP6:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG17]]
// AARCH64-NEXT:    store ptr [[TMP6]], ptr [[SAVED_STACK1]], align 8, !dbg [[DBG17]]
// AARCH64-NEXT:    [[VLA2:%.*]] = alloca i32, i64 [[TMP5]], align 4, !dbg [[DBG17]]
// AARCH64-NEXT:    store i64 [[TMP5]], ptr [[__VLA_EXPR1]], align 8, !dbg [[DBG17]]
// AARCH64-NEXT:    [[TMP7:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00") ], !dbg [[DBG18:![0-9]+]]
// AARCH64-NEXT:    [[G:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[H:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[I:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    call void @llvm.directive.region.exit(token [[TMP7]]), !dbg [[DBG19:![0-9]+]]
// AARCH64-NEXT:    [[TMP8:%.*]] = load ptr, ptr [[SAVED_STACK1]], align 8, !dbg [[DBG20:![0-9]+]]
// AARCH64-NEXT:    call void @llvm.stackrestore(ptr [[TMP8]]), !dbg [[DBG20]]
// AARCH64-NEXT:    call void @llvm.directive.region.exit(token [[TMP3]]), !dbg [[DBG20]]
// AARCH64-NEXT:    [[TMP9:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00") ], !dbg [[DBG21:![0-9]+]]
// AARCH64-NEXT:    [[J:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[K:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[L:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    call void @llvm.directive.region.exit(token [[TMP9]]), !dbg [[DBG22:![0-9]+]]
// AARCH64-NEXT:    [[TMP10:%.*]] = load ptr, ptr [[SAVED_STACK]], align 8, !dbg [[DBG23:![0-9]+]]
// AARCH64-NEXT:    call void @llvm.stackrestore(ptr [[TMP10]]), !dbg [[DBG23]]
// AARCH64-NEXT:    ret void, !dbg [[DBG23]]
//
void foo(int x) {
  int a, b, c;
  int va[x];
  #pragma oss task firstprivate(x)
  {
      int d, e, f;
      int va1[x];
      #pragma oss task
      {
          int g, h, i;
      }
  }
  #pragma oss task
  {
      int j, k, l;
  }
  int m;
}







