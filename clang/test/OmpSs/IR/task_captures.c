// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py UTC_ARGS: --include-generated-funcs
// RUN: %clang_cc1 -triple x86_64-gnu-linux -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=LIN64
// RUN: %clang_cc1 -triple ppc64 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=PPC64
// RUN: %clang_cc1 -triple aarch64 -verify -fompss-2 -disable-llvm-passes -ferror-limit 100 %s -S -emit-llvm -o - | FileCheck %s --check-prefixes=AARCH64
// expected-no-diagnostics
void vla_senction_dep(int n, int k, int j) {
    int array[n + 1][k + 2][j + 3];
    int array2[n + 1][k + 2][j + 3];
    // DSA duplicated clauses are removed
    #pragma oss task out(array[0 : 5]) in(array, array2) shared(array, array) shared(array)
    {}
}

// LIN64-LABEL: @vla_senction_dep(
// LIN64-NEXT:  entry:
// LIN64-NEXT:    [[N_ADDR:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[K_ADDR:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[J_ADDR:%.*]] = alloca i32, align 4
// LIN64-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
// LIN64-NEXT:    [[__VLA_EXPR0:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[__VLA_EXPR1:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[__VLA_EXPR2:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[__VLA_EXPR3:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[__VLA_EXPR4:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[__VLA_EXPR5:%.*]] = alloca i64, align 8
// LIN64-NEXT:    store i32 [[N:%.*]], ptr [[N_ADDR]], align 4
// LIN64-NEXT:    store i32 [[K:%.*]], ptr [[K_ADDR]], align 4
// LIN64-NEXT:    store i32 [[J:%.*]], ptr [[J_ADDR]], align 4
// LIN64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[N_ADDR]], align 4, !dbg [[DBG9:![0-9]+]]
// LIN64-NEXT:    [[ADD:%.*]] = add nsw i32 [[TMP0]], 1, !dbg [[DBG10:![0-9]+]]
// LIN64-NEXT:    [[TMP1:%.*]] = zext i32 [[ADD]] to i64, !dbg [[DBG11:![0-9]+]]
// LIN64-NEXT:    [[TMP2:%.*]] = load i32, ptr [[K_ADDR]], align 4, !dbg [[DBG12:![0-9]+]]
// LIN64-NEXT:    [[ADD1:%.*]] = add nsw i32 [[TMP2]], 2, !dbg [[DBG13:![0-9]+]]
// LIN64-NEXT:    [[TMP3:%.*]] = zext i32 [[ADD1]] to i64, !dbg [[DBG11]]
// LIN64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[J_ADDR]], align 4, !dbg [[DBG14:![0-9]+]]
// LIN64-NEXT:    [[ADD2:%.*]] = add nsw i32 [[TMP4]], 3, !dbg [[DBG15:![0-9]+]]
// LIN64-NEXT:    [[TMP5:%.*]] = zext i32 [[ADD2]] to i64, !dbg [[DBG11]]
// LIN64-NEXT:    [[TMP6:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG11]]
// LIN64-NEXT:    store ptr [[TMP6]], ptr [[SAVED_STACK]], align 8, !dbg [[DBG11]]
// LIN64-NEXT:    [[TMP7:%.*]] = mul nuw i64 [[TMP1]], [[TMP3]], !dbg [[DBG11]]
// LIN64-NEXT:    [[TMP8:%.*]] = mul nuw i64 [[TMP7]], [[TMP5]], !dbg [[DBG11]]
// LIN64-NEXT:    [[VLA:%.*]] = alloca i32, i64 [[TMP8]], align 16, !dbg [[DBG11]]
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[__VLA_EXPR0]], align 8, !dbg [[DBG11]]
// LIN64-NEXT:    store i64 [[TMP3]], ptr [[__VLA_EXPR1]], align 8, !dbg [[DBG11]]
// LIN64-NEXT:    store i64 [[TMP5]], ptr [[__VLA_EXPR2]], align 8, !dbg [[DBG11]]
// LIN64-NEXT:    [[TMP9:%.*]] = load i32, ptr [[N_ADDR]], align 4, !dbg [[DBG16:![0-9]+]]
// LIN64-NEXT:    [[ADD3:%.*]] = add nsw i32 [[TMP9]], 1, !dbg [[DBG17:![0-9]+]]
// LIN64-NEXT:    [[TMP10:%.*]] = zext i32 [[ADD3]] to i64, !dbg [[DBG18:![0-9]+]]
// LIN64-NEXT:    [[TMP11:%.*]] = load i32, ptr [[K_ADDR]], align 4, !dbg [[DBG19:![0-9]+]]
// LIN64-NEXT:    [[ADD4:%.*]] = add nsw i32 [[TMP11]], 2, !dbg [[DBG20:![0-9]+]]
// LIN64-NEXT:    [[TMP12:%.*]] = zext i32 [[ADD4]] to i64, !dbg [[DBG18]]
// LIN64-NEXT:    [[TMP13:%.*]] = load i32, ptr [[J_ADDR]], align 4, !dbg [[DBG21:![0-9]+]]
// LIN64-NEXT:    [[ADD5:%.*]] = add nsw i32 [[TMP13]], 3, !dbg [[DBG22:![0-9]+]]
// LIN64-NEXT:    [[TMP14:%.*]] = zext i32 [[ADD5]] to i64, !dbg [[DBG18]]
// LIN64-NEXT:    [[TMP15:%.*]] = mul nuw i64 [[TMP10]], [[TMP12]], !dbg [[DBG18]]
// LIN64-NEXT:    [[TMP16:%.*]] = mul nuw i64 [[TMP15]], [[TMP14]], !dbg [[DBG18]]
// LIN64-NEXT:    [[VLA6:%.*]] = alloca i32, i64 [[TMP16]], align 16, !dbg [[DBG18]]
// LIN64-NEXT:    store i64 [[TMP10]], ptr [[__VLA_EXPR3]], align 8, !dbg [[DBG18]]
// LIN64-NEXT:    store i64 [[TMP12]], ptr [[__VLA_EXPR4]], align 8, !dbg [[DBG18]]
// LIN64-NEXT:    store i64 [[TMP14]], ptr [[__VLA_EXPR5]], align 8, !dbg [[DBG18]]
// LIN64-NEXT:    [[TMP17:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.SHARED"(ptr [[VLA]], i32 undef), "QUAL.OSS.VLA.DIMS"(ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]), "QUAL.OSS.SHARED"(ptr [[VLA6]], i32 undef), "QUAL.OSS.VLA.DIMS"(ptr [[VLA6]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.CAPTURED"(i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.DEP.IN"(ptr [[VLA]], [6 x i8] c"array\00", ptr @compute_dep, ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]), "QUAL.OSS.DEP.IN"(ptr [[VLA6]], [7 x i8] c"array2\00", ptr @compute_dep.1, ptr [[VLA6]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.DEP.OUT"(ptr [[VLA]], [13 x i8] c"array[0 : 5]\00", ptr @compute_dep.2, ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]) ], !dbg [[DBG23:![0-9]+]]
// LIN64-NEXT:    call void @llvm.directive.region.exit(token [[TMP17]]), !dbg [[DBG24:![0-9]+]]
// LIN64-NEXT:    [[TMP18:%.*]] = load ptr, ptr [[SAVED_STACK]], align 8, !dbg [[DBG25:![0-9]+]]
// LIN64-NEXT:    call void @llvm.stackrestore(ptr [[TMP18]]), !dbg [[DBG25]]
// LIN64-NEXT:    ret void, !dbg [[DBG25]]
//
//
// LIN64-LABEL: @compute_dep(
// LIN64-NEXT:  entry:
// LIN64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T:%.*]], align 8
// LIN64-NEXT:    [[ARRAY_ADDR:%.*]] = alloca ptr, align 8
// LIN64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// LIN64-NEXT:    store ptr [[ARRAY:%.*]], ptr [[ARRAY_ADDR]], align 8
// LIN64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// LIN64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// LIN64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// LIN64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// LIN64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// LIN64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 0
// LIN64-NEXT:    store ptr [[ARRAY]], ptr [[TMP5]], align 8
// LIN64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 1
// LIN64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// LIN64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 2
// LIN64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// LIN64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 3
// LIN64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// LIN64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 4
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// LIN64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 5
// LIN64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// LIN64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 6
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// LIN64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 7
// LIN64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// LIN64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 8
// LIN64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// LIN64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 9
// LIN64-NEXT:    store i64 [[TMP0]], ptr [[TMP14]], align 8
// LIN64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], align 8
// LIN64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T]] [[TMP15]]
//
//
// LIN64-LABEL: @compute_dep.1(
// LIN64-NEXT:  entry:
// LIN64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T_0:%.*]], align 8
// LIN64-NEXT:    [[ARRAY2_ADDR:%.*]] = alloca ptr, align 8
// LIN64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// LIN64-NEXT:    store ptr [[ARRAY2:%.*]], ptr [[ARRAY2_ADDR]], align 8
// LIN64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// LIN64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// LIN64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// LIN64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// LIN64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// LIN64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 0
// LIN64-NEXT:    store ptr [[ARRAY2]], ptr [[TMP5]], align 8
// LIN64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 1
// LIN64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// LIN64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 2
// LIN64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// LIN64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 3
// LIN64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// LIN64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 4
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// LIN64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 5
// LIN64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// LIN64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 6
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// LIN64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 7
// LIN64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// LIN64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 8
// LIN64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// LIN64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 9
// LIN64-NEXT:    store i64 [[TMP0]], ptr [[TMP14]], align 8
// LIN64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], align 8
// LIN64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP15]]
//
//
// LIN64-LABEL: @compute_dep.2(
// LIN64-NEXT:  entry:
// LIN64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T_1:%.*]], align 8
// LIN64-NEXT:    [[ARRAY_ADDR:%.*]] = alloca ptr, align 8
// LIN64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// LIN64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// LIN64-NEXT:    store ptr [[ARRAY:%.*]], ptr [[ARRAY_ADDR]], align 8
// LIN64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// LIN64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// LIN64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// LIN64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// LIN64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// LIN64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 0
// LIN64-NEXT:    store ptr [[ARRAY]], ptr [[TMP5]], align 8
// LIN64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 1
// LIN64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// LIN64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 2
// LIN64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// LIN64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 3
// LIN64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// LIN64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 4
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// LIN64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 5
// LIN64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// LIN64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 6
// LIN64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// LIN64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 7
// LIN64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// LIN64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 8
// LIN64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// LIN64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 9
// LIN64-NEXT:    store i64 6, ptr [[TMP14]], align 8
// LIN64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], align 8, !dbg [[DBG29:![0-9]+]]
// LIN64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T_1]] [[TMP15]], !dbg [[DBG29]]
//
//
// PPC64-LABEL: @vla_senction_dep(
// PPC64-NEXT:  entry:
// PPC64-NEXT:    [[N_ADDR:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[K_ADDR:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[J_ADDR:%.*]] = alloca i32, align 4
// PPC64-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
// PPC64-NEXT:    [[__VLA_EXPR0:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[__VLA_EXPR1:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[__VLA_EXPR2:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[__VLA_EXPR3:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[__VLA_EXPR4:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[__VLA_EXPR5:%.*]] = alloca i64, align 8
// PPC64-NEXT:    store i32 [[N:%.*]], ptr [[N_ADDR]], align 4
// PPC64-NEXT:    store i32 [[K:%.*]], ptr [[K_ADDR]], align 4
// PPC64-NEXT:    store i32 [[J:%.*]], ptr [[J_ADDR]], align 4
// PPC64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[N_ADDR]], align 4, !dbg [[DBG9:![0-9]+]]
// PPC64-NEXT:    [[ADD:%.*]] = add nsw i32 [[TMP0]], 1, !dbg [[DBG10:![0-9]+]]
// PPC64-NEXT:    [[TMP1:%.*]] = zext i32 [[ADD]] to i64, !dbg [[DBG11:![0-9]+]]
// PPC64-NEXT:    [[TMP2:%.*]] = load i32, ptr [[K_ADDR]], align 4, !dbg [[DBG12:![0-9]+]]
// PPC64-NEXT:    [[ADD1:%.*]] = add nsw i32 [[TMP2]], 2, !dbg [[DBG13:![0-9]+]]
// PPC64-NEXT:    [[TMP3:%.*]] = zext i32 [[ADD1]] to i64, !dbg [[DBG11]]
// PPC64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[J_ADDR]], align 4, !dbg [[DBG14:![0-9]+]]
// PPC64-NEXT:    [[ADD2:%.*]] = add nsw i32 [[TMP4]], 3, !dbg [[DBG15:![0-9]+]]
// PPC64-NEXT:    [[TMP5:%.*]] = zext i32 [[ADD2]] to i64, !dbg [[DBG11]]
// PPC64-NEXT:    [[TMP6:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG11]]
// PPC64-NEXT:    store ptr [[TMP6]], ptr [[SAVED_STACK]], align 8, !dbg [[DBG11]]
// PPC64-NEXT:    [[TMP7:%.*]] = mul nuw i64 [[TMP1]], [[TMP3]], !dbg [[DBG11]]
// PPC64-NEXT:    [[TMP8:%.*]] = mul nuw i64 [[TMP7]], [[TMP5]], !dbg [[DBG11]]
// PPC64-NEXT:    [[VLA:%.*]] = alloca i32, i64 [[TMP8]], align 4, !dbg [[DBG11]]
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[__VLA_EXPR0]], align 8, !dbg [[DBG11]]
// PPC64-NEXT:    store i64 [[TMP3]], ptr [[__VLA_EXPR1]], align 8, !dbg [[DBG11]]
// PPC64-NEXT:    store i64 [[TMP5]], ptr [[__VLA_EXPR2]], align 8, !dbg [[DBG11]]
// PPC64-NEXT:    [[TMP9:%.*]] = load i32, ptr [[N_ADDR]], align 4, !dbg [[DBG16:![0-9]+]]
// PPC64-NEXT:    [[ADD3:%.*]] = add nsw i32 [[TMP9]], 1, !dbg [[DBG17:![0-9]+]]
// PPC64-NEXT:    [[TMP10:%.*]] = zext i32 [[ADD3]] to i64, !dbg [[DBG18:![0-9]+]]
// PPC64-NEXT:    [[TMP11:%.*]] = load i32, ptr [[K_ADDR]], align 4, !dbg [[DBG19:![0-9]+]]
// PPC64-NEXT:    [[ADD4:%.*]] = add nsw i32 [[TMP11]], 2, !dbg [[DBG20:![0-9]+]]
// PPC64-NEXT:    [[TMP12:%.*]] = zext i32 [[ADD4]] to i64, !dbg [[DBG18]]
// PPC64-NEXT:    [[TMP13:%.*]] = load i32, ptr [[J_ADDR]], align 4, !dbg [[DBG21:![0-9]+]]
// PPC64-NEXT:    [[ADD5:%.*]] = add nsw i32 [[TMP13]], 3, !dbg [[DBG22:![0-9]+]]
// PPC64-NEXT:    [[TMP14:%.*]] = zext i32 [[ADD5]] to i64, !dbg [[DBG18]]
// PPC64-NEXT:    [[TMP15:%.*]] = mul nuw i64 [[TMP10]], [[TMP12]], !dbg [[DBG18]]
// PPC64-NEXT:    [[TMP16:%.*]] = mul nuw i64 [[TMP15]], [[TMP14]], !dbg [[DBG18]]
// PPC64-NEXT:    [[VLA6:%.*]] = alloca i32, i64 [[TMP16]], align 4, !dbg [[DBG18]]
// PPC64-NEXT:    store i64 [[TMP10]], ptr [[__VLA_EXPR3]], align 8, !dbg [[DBG18]]
// PPC64-NEXT:    store i64 [[TMP12]], ptr [[__VLA_EXPR4]], align 8, !dbg [[DBG18]]
// PPC64-NEXT:    store i64 [[TMP14]], ptr [[__VLA_EXPR5]], align 8, !dbg [[DBG18]]
// PPC64-NEXT:    [[TMP17:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.SHARED"(ptr [[VLA]], i32 undef), "QUAL.OSS.VLA.DIMS"(ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]), "QUAL.OSS.SHARED"(ptr [[VLA6]], i32 undef), "QUAL.OSS.VLA.DIMS"(ptr [[VLA6]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.CAPTURED"(i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.DEP.IN"(ptr [[VLA]], [6 x i8] c"array\00", ptr @compute_dep, ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]), "QUAL.OSS.DEP.IN"(ptr [[VLA6]], [7 x i8] c"array2\00", ptr @compute_dep.1, ptr [[VLA6]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.DEP.OUT"(ptr [[VLA]], [13 x i8] c"array[0 : 5]\00", ptr @compute_dep.2, ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]) ], !dbg [[DBG23:![0-9]+]]
// PPC64-NEXT:    call void @llvm.directive.region.exit(token [[TMP17]]), !dbg [[DBG24:![0-9]+]]
// PPC64-NEXT:    [[TMP18:%.*]] = load ptr, ptr [[SAVED_STACK]], align 8, !dbg [[DBG25:![0-9]+]]
// PPC64-NEXT:    call void @llvm.stackrestore(ptr [[TMP18]]), !dbg [[DBG25]]
// PPC64-NEXT:    ret void, !dbg [[DBG25]]
//
//
// PPC64-LABEL: @compute_dep(
// PPC64-NEXT:  entry:
// PPC64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T:%.*]], align 8
// PPC64-NEXT:    [[ARRAY_ADDR:%.*]] = alloca ptr, align 8
// PPC64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// PPC64-NEXT:    store ptr [[ARRAY:%.*]], ptr [[ARRAY_ADDR]], align 8
// PPC64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// PPC64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// PPC64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// PPC64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// PPC64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// PPC64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 0
// PPC64-NEXT:    store ptr [[ARRAY]], ptr [[TMP5]], align 8
// PPC64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 1
// PPC64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// PPC64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 2
// PPC64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// PPC64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 3
// PPC64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// PPC64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 4
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// PPC64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 5
// PPC64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// PPC64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 6
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// PPC64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 7
// PPC64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// PPC64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 8
// PPC64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// PPC64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 9
// PPC64-NEXT:    store i64 [[TMP0]], ptr [[TMP14]], align 8
// PPC64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], align 8
// PPC64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T]] [[TMP15]]
//
//
// PPC64-LABEL: @compute_dep.1(
// PPC64-NEXT:  entry:
// PPC64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T_0:%.*]], align 8
// PPC64-NEXT:    [[ARRAY2_ADDR:%.*]] = alloca ptr, align 8
// PPC64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// PPC64-NEXT:    store ptr [[ARRAY2:%.*]], ptr [[ARRAY2_ADDR]], align 8
// PPC64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// PPC64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// PPC64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// PPC64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// PPC64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// PPC64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 0
// PPC64-NEXT:    store ptr [[ARRAY2]], ptr [[TMP5]], align 8
// PPC64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 1
// PPC64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// PPC64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 2
// PPC64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// PPC64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 3
// PPC64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// PPC64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 4
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// PPC64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 5
// PPC64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// PPC64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 6
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// PPC64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 7
// PPC64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// PPC64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 8
// PPC64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// PPC64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 9
// PPC64-NEXT:    store i64 [[TMP0]], ptr [[TMP14]], align 8
// PPC64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], align 8
// PPC64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP15]]
//
//
// PPC64-LABEL: @compute_dep.2(
// PPC64-NEXT:  entry:
// PPC64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T_1:%.*]], align 8
// PPC64-NEXT:    [[ARRAY_ADDR:%.*]] = alloca ptr, align 8
// PPC64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// PPC64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// PPC64-NEXT:    store ptr [[ARRAY:%.*]], ptr [[ARRAY_ADDR]], align 8
// PPC64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// PPC64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// PPC64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// PPC64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// PPC64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// PPC64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 0
// PPC64-NEXT:    store ptr [[ARRAY]], ptr [[TMP5]], align 8
// PPC64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 1
// PPC64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// PPC64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 2
// PPC64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// PPC64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 3
// PPC64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// PPC64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 4
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// PPC64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 5
// PPC64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// PPC64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 6
// PPC64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// PPC64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 7
// PPC64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// PPC64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 8
// PPC64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// PPC64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 9
// PPC64-NEXT:    store i64 6, ptr [[TMP14]], align 8
// PPC64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], align 8, !dbg [[DBG29:![0-9]+]]
// PPC64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T_1]] [[TMP15]], !dbg [[DBG29]]
//
//
// AARCH64-LABEL: @vla_senction_dep(
// AARCH64-NEXT:  entry:
// AARCH64-NEXT:    [[N_ADDR:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[K_ADDR:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[J_ADDR:%.*]] = alloca i32, align 4
// AARCH64-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
// AARCH64-NEXT:    [[__VLA_EXPR0:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[__VLA_EXPR1:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[__VLA_EXPR2:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[__VLA_EXPR3:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[__VLA_EXPR4:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[__VLA_EXPR5:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    store i32 [[N:%.*]], ptr [[N_ADDR]], align 4
// AARCH64-NEXT:    store i32 [[K:%.*]], ptr [[K_ADDR]], align 4
// AARCH64-NEXT:    store i32 [[J:%.*]], ptr [[J_ADDR]], align 4
// AARCH64-NEXT:    [[TMP0:%.*]] = load i32, ptr [[N_ADDR]], align 4, !dbg [[DBG13:![0-9]+]]
// AARCH64-NEXT:    [[ADD:%.*]] = add nsw i32 [[TMP0]], 1, !dbg [[DBG14:![0-9]+]]
// AARCH64-NEXT:    [[TMP1:%.*]] = zext i32 [[ADD]] to i64, !dbg [[DBG15:![0-9]+]]
// AARCH64-NEXT:    [[TMP2:%.*]] = load i32, ptr [[K_ADDR]], align 4, !dbg [[DBG16:![0-9]+]]
// AARCH64-NEXT:    [[ADD1:%.*]] = add nsw i32 [[TMP2]], 2, !dbg [[DBG17:![0-9]+]]
// AARCH64-NEXT:    [[TMP3:%.*]] = zext i32 [[ADD1]] to i64, !dbg [[DBG15]]
// AARCH64-NEXT:    [[TMP4:%.*]] = load i32, ptr [[J_ADDR]], align 4, !dbg [[DBG18:![0-9]+]]
// AARCH64-NEXT:    [[ADD2:%.*]] = add nsw i32 [[TMP4]], 3, !dbg [[DBG19:![0-9]+]]
// AARCH64-NEXT:    [[TMP5:%.*]] = zext i32 [[ADD2]] to i64, !dbg [[DBG15]]
// AARCH64-NEXT:    [[TMP6:%.*]] = call ptr @llvm.stacksave(), !dbg [[DBG15]]
// AARCH64-NEXT:    store ptr [[TMP6]], ptr [[SAVED_STACK]], align 8, !dbg [[DBG15]]
// AARCH64-NEXT:    [[TMP7:%.*]] = mul nuw i64 [[TMP1]], [[TMP3]], !dbg [[DBG15]]
// AARCH64-NEXT:    [[TMP8:%.*]] = mul nuw i64 [[TMP7]], [[TMP5]], !dbg [[DBG15]]
// AARCH64-NEXT:    [[VLA:%.*]] = alloca i32, i64 [[TMP8]], align 4, !dbg [[DBG15]]
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[__VLA_EXPR0]], align 8, !dbg [[DBG15]]
// AARCH64-NEXT:    store i64 [[TMP3]], ptr [[__VLA_EXPR1]], align 8, !dbg [[DBG15]]
// AARCH64-NEXT:    store i64 [[TMP5]], ptr [[__VLA_EXPR2]], align 8, !dbg [[DBG15]]
// AARCH64-NEXT:    [[TMP9:%.*]] = load i32, ptr [[N_ADDR]], align 4, !dbg [[DBG20:![0-9]+]]
// AARCH64-NEXT:    [[ADD3:%.*]] = add nsw i32 [[TMP9]], 1, !dbg [[DBG21:![0-9]+]]
// AARCH64-NEXT:    [[TMP10:%.*]] = zext i32 [[ADD3]] to i64, !dbg [[DBG22:![0-9]+]]
// AARCH64-NEXT:    [[TMP11:%.*]] = load i32, ptr [[K_ADDR]], align 4, !dbg [[DBG23:![0-9]+]]
// AARCH64-NEXT:    [[ADD4:%.*]] = add nsw i32 [[TMP11]], 2, !dbg [[DBG24:![0-9]+]]
// AARCH64-NEXT:    [[TMP12:%.*]] = zext i32 [[ADD4]] to i64, !dbg [[DBG22]]
// AARCH64-NEXT:    [[TMP13:%.*]] = load i32, ptr [[J_ADDR]], align 4, !dbg [[DBG25:![0-9]+]]
// AARCH64-NEXT:    [[ADD5:%.*]] = add nsw i32 [[TMP13]], 3, !dbg [[DBG26:![0-9]+]]
// AARCH64-NEXT:    [[TMP14:%.*]] = zext i32 [[ADD5]] to i64, !dbg [[DBG22]]
// AARCH64-NEXT:    [[TMP15:%.*]] = mul nuw i64 [[TMP10]], [[TMP12]], !dbg [[DBG22]]
// AARCH64-NEXT:    [[TMP16:%.*]] = mul nuw i64 [[TMP15]], [[TMP14]], !dbg [[DBG22]]
// AARCH64-NEXT:    [[VLA6:%.*]] = alloca i32, i64 [[TMP16]], align 4, !dbg [[DBG22]]
// AARCH64-NEXT:    store i64 [[TMP10]], ptr [[__VLA_EXPR3]], align 8, !dbg [[DBG22]]
// AARCH64-NEXT:    store i64 [[TMP12]], ptr [[__VLA_EXPR4]], align 8, !dbg [[DBG22]]
// AARCH64-NEXT:    store i64 [[TMP14]], ptr [[__VLA_EXPR5]], align 8, !dbg [[DBG22]]
// AARCH64-NEXT:    [[TMP17:%.*]] = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.SHARED"(ptr [[VLA]], i32 undef), "QUAL.OSS.VLA.DIMS"(ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]), "QUAL.OSS.SHARED"(ptr [[VLA6]], i32 undef), "QUAL.OSS.VLA.DIMS"(ptr [[VLA6]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.CAPTURED"(i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.DEP.IN"(ptr [[VLA]], [6 x i8] c"array\00", ptr @compute_dep, ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]), "QUAL.OSS.DEP.IN"(ptr [[VLA6]], [7 x i8] c"array2\00", ptr @compute_dep.1, ptr [[VLA6]], i64 [[TMP10]], i64 [[TMP12]], i64 [[TMP14]]), "QUAL.OSS.DEP.OUT"(ptr [[VLA]], [13 x i8] c"array[0 : 5]\00", ptr @compute_dep.2, ptr [[VLA]], i64 [[TMP1]], i64 [[TMP3]], i64 [[TMP5]]) ], !dbg [[DBG27:![0-9]+]]
// AARCH64-NEXT:    call void @llvm.directive.region.exit(token [[TMP17]]), !dbg [[DBG28:![0-9]+]]
// AARCH64-NEXT:    [[TMP18:%.*]] = load ptr, ptr [[SAVED_STACK]], align 8, !dbg [[DBG29:![0-9]+]]
// AARCH64-NEXT:    call void @llvm.stackrestore(ptr [[TMP18]]), !dbg [[DBG29]]
// AARCH64-NEXT:    ret void, !dbg [[DBG29]]
//
//
// AARCH64-LABEL: @compute_dep(
// AARCH64-NEXT:  entry:
// AARCH64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T:%.*]], align 8
// AARCH64-NEXT:    [[ARRAY_ADDR:%.*]] = alloca ptr, align 8
// AARCH64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    store ptr [[ARRAY:%.*]], ptr [[ARRAY_ADDR]], align 8
// AARCH64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// AARCH64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// AARCH64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// AARCH64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// AARCH64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// AARCH64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 0
// AARCH64-NEXT:    store ptr [[ARRAY]], ptr [[TMP5]], align 8
// AARCH64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 1
// AARCH64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// AARCH64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 2
// AARCH64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// AARCH64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 3
// AARCH64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// AARCH64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 4
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// AARCH64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 5
// AARCH64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// AARCH64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 6
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// AARCH64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 7
// AARCH64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// AARCH64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 8
// AARCH64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// AARCH64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 9
// AARCH64-NEXT:    store i64 [[TMP0]], ptr [[TMP14]], align 8
// AARCH64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], align 8
// AARCH64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T]] [[TMP15]]
//
//
// AARCH64-LABEL: @compute_dep.1(
// AARCH64-NEXT:  entry:
// AARCH64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T_0:%.*]], align 8
// AARCH64-NEXT:    [[ARRAY2_ADDR:%.*]] = alloca ptr, align 8
// AARCH64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    store ptr [[ARRAY2:%.*]], ptr [[ARRAY2_ADDR]], align 8
// AARCH64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// AARCH64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// AARCH64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// AARCH64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// AARCH64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// AARCH64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 0
// AARCH64-NEXT:    store ptr [[ARRAY2]], ptr [[TMP5]], align 8
// AARCH64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 1
// AARCH64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// AARCH64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 2
// AARCH64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// AARCH64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 3
// AARCH64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// AARCH64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 4
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// AARCH64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 5
// AARCH64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// AARCH64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 6
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// AARCH64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 7
// AARCH64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// AARCH64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 8
// AARCH64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// AARCH64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 9
// AARCH64-NEXT:    store i64 [[TMP0]], ptr [[TMP14]], align 8
// AARCH64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], align 8
// AARCH64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP15]]
//
//
// AARCH64-LABEL: @compute_dep.2(
// AARCH64-NEXT:  entry:
// AARCH64-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T_1:%.*]], align 8
// AARCH64-NEXT:    [[ARRAY_ADDR:%.*]] = alloca ptr, align 8
// AARCH64-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[DOTADDR1:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    [[DOTADDR2:%.*]] = alloca i64, align 8
// AARCH64-NEXT:    store ptr [[ARRAY:%.*]], ptr [[ARRAY_ADDR]], align 8
// AARCH64-NEXT:    store i64 [[TMP0:%.*]], ptr [[DOTADDR]], align 8
// AARCH64-NEXT:    store i64 [[TMP1:%.*]], ptr [[DOTADDR1]], align 8
// AARCH64-NEXT:    store i64 [[TMP2:%.*]], ptr [[DOTADDR2]], align 8
// AARCH64-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP2]], 4
// AARCH64-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
// AARCH64-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 0
// AARCH64-NEXT:    store ptr [[ARRAY]], ptr [[TMP5]], align 8
// AARCH64-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 1
// AARCH64-NEXT:    store i64 [[TMP3]], ptr [[TMP6]], align 8
// AARCH64-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 2
// AARCH64-NEXT:    store i64 0, ptr [[TMP7]], align 8
// AARCH64-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 3
// AARCH64-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
// AARCH64-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 4
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[TMP9]], align 8
// AARCH64-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 5
// AARCH64-NEXT:    store i64 0, ptr [[TMP10]], align 8
// AARCH64-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 6
// AARCH64-NEXT:    store i64 [[TMP1]], ptr [[TMP11]], align 8
// AARCH64-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 7
// AARCH64-NEXT:    store i64 [[TMP0]], ptr [[TMP12]], align 8
// AARCH64-NEXT:    [[TMP13:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 8
// AARCH64-NEXT:    store i64 0, ptr [[TMP13]], align 8
// AARCH64-NEXT:    [[TMP14:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], i32 0, i32 9
// AARCH64-NEXT:    store i64 6, ptr [[TMP14]], align 8
// AARCH64-NEXT:    [[TMP15:%.*]] = load [[STRUCT__DEPEND_UNPACK_T_1]], ptr [[RETVAL]], align 8, !dbg [[DBG33:![0-9]+]]
// AARCH64-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T_1]] [[TMP15]], !dbg [[DBG33]]
//
