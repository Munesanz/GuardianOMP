// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py UTC_ARGS: --function-signature
// RUN: %clang_cc1 -triple x86_64-gnu-linux -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=LIN64
// RUN: %clang_cc1 -triple ppc64 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=PPC64
// RUN: %clang_cc1 -triple aarch64 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=AARCH64
// expected-no-diagnostics

#pragma oss task final(a)
// LIN64-LABEL: define {{[^@]+}}@bar
// LIN64-SAME: (i32 noundef [[A:%.*]]) #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
// LIN64-NEXT:  entry:
// LIN64-NEXT:    [[A_ADDR:%.*]] = alloca i32, align 4
// LIN64-NEXT:    store i32 [[A]], ptr [[A_ADDR]], align 4
// LIN64-NEXT:    ret void, !dbg [[DBG9:![0-9]+]]
//
// PPC64-LABEL: define {{[^@]+}}@bar
// PPC64-SAME: (i32 noundef signext [[A:%.*]]) #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
// PPC64-NEXT:  entry:
// PPC64-NEXT:    [[A_ADDR:%.*]] = alloca i32, align 4
// PPC64-NEXT:    store i32 [[A]], ptr [[A_ADDR]], align 4
// PPC64-NEXT:    ret void, !dbg [[DBG9:![0-9]+]]
//
// AARCH64-LABEL: define {{[^@]+}}@bar
// AARCH64-SAME: (i32 noundef [[A:%.*]]) #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
// AARCH64-NEXT:  entry:
// AARCH64-NEXT:    [[A_ADDR:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    store i32 [[A]], ptr [[A_ADDR]], align 4
// AARCH64-NEXT:    ret void, !dbg [[DBG9:![0-9]+]]
//
void bar(int a) {}

// LIN64-LABEL: define {{[^@]+}}@foo
// LIN64-SAME: () #[[ATTR0]] !dbg [[DBG10:![0-9]+]] {
// LIN64-NEXT:  entry:
// LIN64-NEXT:    [[A:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[CALL_ARG:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[A]], align 4, !dbg [[DBG11:![0-9]+]]
// LIN64-NEXT:    [[TOBOOL:%.*]] = icmp ne i32 [[TMP0]], 0, !dbg [[DBG12:![0-9]+]]
// LIN64-NEXT:    [[TMP1:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FINAL"(i1 [[TOBOOL]]) ], !dbg [[DBG12]]
// LIN64-NEXT:    call void @llvm.directive.region.exit(token [[TMP1]]), !dbg [[DBG13:![0-9]+]]
// LIN64-NEXT:    store i32 3, ptr [[CALL_ARG]], align 4, !dbg [[DBG14:![0-9]+]]
// LIN64-NEXT:    [[TMP2:%.*]] = load i32, ptr [[CALL_ARG]], align 4, !dbg [[DBG15:![0-9]+]]
// LIN64-NEXT:    [[TOBOOL1:%.*]] = icmp ne i32 [[TMP2]], 0, !dbg [[DBG16:![0-9]+]]
// LIN64-NEXT:    [[TMP3:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr [[CALL_ARG]], i32 undef), "QUAL.OSS.FINAL"(i1 [[TOBOOL1]]), "QUAL.OSS.DEVICE.DEVFUNC"([4 x i8] c"bar\00"), "QUAL.OSS.DECL.SOURCE"([17 x i8] c"task_final.c:7:9\00") ], !dbg [[DBG16]]
// LIN64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[CALL_ARG]], align 4, !dbg [[DBG14]]
// LIN64-NEXT:    call void @bar(i32 noundef [[TMP4]]), !dbg [[DBG16]]
// LIN64-NEXT:    call void @llvm.directive.region.exit(token [[TMP3]]), !dbg [[DBG16]]
// LIN64-NEXT:    ret void, !dbg [[DBG17:![0-9]+]]
//
// PPC64-LABEL: define {{[^@]+}}@foo
// PPC64-SAME: () #[[ATTR0]] !dbg [[DBG10:![0-9]+]] {
// PPC64-NEXT:  entry:
// PPC64-NEXT:    [[A:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[CALL_ARG:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[A]], align 4, !dbg [[DBG11:![0-9]+]]
// PPC64-NEXT:    [[TOBOOL:%.*]] = icmp ne i32 [[TMP0]], 0, !dbg [[DBG12:![0-9]+]]
// PPC64-NEXT:    [[TMP1:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FINAL"(i1 [[TOBOOL]]) ], !dbg [[DBG12]]
// PPC64-NEXT:    call void @llvm.directive.region.exit(token [[TMP1]]), !dbg [[DBG13:![0-9]+]]
// PPC64-NEXT:    store i32 3, ptr [[CALL_ARG]], align 4, !dbg [[DBG14:![0-9]+]]
// PPC64-NEXT:    [[TMP2:%.*]] = load i32, ptr [[CALL_ARG]], align 4, !dbg [[DBG15:![0-9]+]]
// PPC64-NEXT:    [[TOBOOL1:%.*]] = icmp ne i32 [[TMP2]], 0, !dbg [[DBG16:![0-9]+]]
// PPC64-NEXT:    [[TMP3:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr [[CALL_ARG]], i32 undef), "QUAL.OSS.FINAL"(i1 [[TOBOOL1]]), "QUAL.OSS.DEVICE.DEVFUNC"([4 x i8] c"bar\00"), "QUAL.OSS.DECL.SOURCE"([17 x i8] c"task_final.c:7:9\00") ], !dbg [[DBG16]]
// PPC64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[CALL_ARG]], align 4, !dbg [[DBG14]]
// PPC64-NEXT:    call void @bar(i32 noundef signext [[TMP4]]), !dbg [[DBG16]]
// PPC64-NEXT:    call void @llvm.directive.region.exit(token [[TMP3]]), !dbg [[DBG16]]
// PPC64-NEXT:    ret void, !dbg [[DBG17:![0-9]+]]
//
// AARCH64-LABEL: define {{[^@]+}}@foo
// AARCH64-SAME: () #[[ATTR0]] !dbg [[DBG10:![0-9]+]] {
// AARCH64-NEXT:  entry:
// AARCH64-NEXT:    [[A:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[CALL_ARG:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[A]], align 4, !dbg [[DBG11:![0-9]+]]
// AARCH64-NEXT:    [[TOBOOL:%.*]] = icmp ne i32 [[TMP0]], 0, !dbg [[DBG12:![0-9]+]]
// AARCH64-NEXT:    [[TMP1:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FINAL"(i1 [[TOBOOL]]) ], !dbg [[DBG12]]
// AARCH64-NEXT:    call void @llvm.directive.region.exit(token [[TMP1]]), !dbg [[DBG13:![0-9]+]]
// AARCH64-NEXT:    store i32 3, ptr [[CALL_ARG]], align 4, !dbg [[DBG14:![0-9]+]]
// AARCH64-NEXT:    [[TMP2:%.*]] = load i32, ptr [[CALL_ARG]], align 4, !dbg [[DBG15:![0-9]+]]
// AARCH64-NEXT:    [[TOBOOL1:%.*]] = icmp ne i32 [[TMP2]], 0, !dbg [[DBG16:![0-9]+]]
// AARCH64-NEXT:    [[TMP3:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr [[CALL_ARG]], i32 undef), "QUAL.OSS.FINAL"(i1 [[TOBOOL1]]), "QUAL.OSS.DEVICE.DEVFUNC"([4 x i8] c"bar\00"), "QUAL.OSS.DECL.SOURCE"([17 x i8] c"task_final.c:7:9\00") ], !dbg [[DBG16]]
// AARCH64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[CALL_ARG]], align 4, !dbg [[DBG14]]
// AARCH64-NEXT:    call void @bar(i32 noundef [[TMP4]]), !dbg [[DBG16]]
// AARCH64-NEXT:    call void @llvm.directive.region.exit(token [[TMP3]]), !dbg [[DBG16]]
// AARCH64-NEXT:    ret void, !dbg [[DBG17:![0-9]+]]
//
void foo() {
    int a;
    #pragma oss task final(a)
    {}
    bar(3);
}


