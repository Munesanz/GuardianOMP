; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
; ModuleID = 'taskloop_multideps.ll'
source_filename = "taskloop_multideps.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; This test checks we use nanos6 lower bound to build
; multidep loop and call to register dep

; Also, taskloop having multideps using the loop iterator
; means num_deps = -1

; Also multideps using loop iterator are assumed discrete,
; so upper_bound = lower_bound

; int v[10];
; int main() {
;     #pragma oss taskloop out( { v[i], i=0;j } )
;     for (int j = 0; j < 10; ++j) { }
; }

%struct._depend_unpack_t = type { i32, i32, i32, i32 }
%struct._depend_unpack_t.0 = type { ptr, i64, i64, i64 }

@v = global [10 x i32] zeroinitializer, align 16

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !5 {
entry:
  %j = alloca i32, align 4
  %i = alloca i32, align 4
  store i32 0, ptr %j, align 4, !dbg !9
  store i32 0, ptr %i, align 4, !dbg !10
  %0 = call token @llvm.directive.region.entry() [ "DIR.OSS"([9 x i8] c"TASKLOOP\00"), "QUAL.OSS.SHARED"(ptr @v, [10 x i32] undef), "QUAL.OSS.PRIVATE"(ptr %j, i32 undef), "QUAL.OSS.PRIVATE"(ptr %i, i32 undef), "QUAL.OSS.LOOP.IND.VAR"(ptr %j), "QUAL.OSS.LOOP.LOWER.BOUND"(ptr @compute_lb), "QUAL.OSS.LOOP.UPPER.BOUND"(ptr @compute_ub), "QUAL.OSS.LOOP.STEP"(ptr @compute_step), "QUAL.OSS.LOOP.TYPE"(i64 0, i64 1, i64 1, i64 1, i64 1), "QUAL.OSS.MULTIDEP.RANGE.OUT"(ptr %i, ptr @compute_dep, ptr %i, ptr %j, ptr @v, [16 x i8] c"{ v[i], i=0;j }\00", ptr @compute_dep.1, ptr %i, ptr %j, ptr @v) ], !dbg !11
  call void @llvm.directive.region.exit(token %0), !dbg !12
  ret i32 0, !dbg !13
}

; Function Attrs: nounwind
declare token @llvm.directive.region.entry() #1

; Function Attrs: nounwind
declare void @llvm.directive.region.exit(token) #1

define internal i32 @compute_lb() #2 !dbg !14 {
entry:
  ret i32 0, !dbg !15
}

define internal i32 @compute_ub() #2 !dbg !17 {
entry:
  ret i32 10, !dbg !18
}

define internal i32 @compute_step() #2 !dbg !20 {
entry:
  ret i32 1, !dbg !21
}

define internal %struct._depend_unpack_t @compute_dep(ptr %i, ptr %j, i64 %0) #2 !dbg !23 {
entry:
  %retval = alloca %struct._depend_unpack_t, align 4
  %i.addr = alloca ptr, align 8
  %j.addr = alloca ptr, align 8
  %.addr = alloca i64, align 8
  store ptr %i, ptr %i.addr, align 8
  store ptr %j, ptr %j.addr, align 8
  store i64 %0, ptr %.addr, align 8
  switch i64 %0, label %3 [
    i64 0, label %4
  ]

1:                                                ; preds = %4, %3
  %2 = load %struct._depend_unpack_t, ptr %retval, align 4, !dbg !24
  ret %struct._depend_unpack_t %2, !dbg !24

3:                                                ; preds = %entry
  br label %1

4:                                                ; preds = %entry
  %5 = load i32, ptr %i, align 4, !dbg !26
  %6 = load i32, ptr %j, align 4, !dbg !24
  %7 = add i32 0, %6
  %8 = add i32 %7, -1
  %9 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 0
  store i32 0, ptr %9, align 4
  %10 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 1
  store i32 %5, ptr %10, align 4
  %11 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 2
  store i32 %8, ptr %11, align 4
  %12 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 3
  store i32 1, ptr %12, align 4
  br label %1
}

define internal %struct._depend_unpack_t.0 @compute_dep.1(ptr %i, ptr %j, ptr %v) #2 !dbg !27 {
entry:
  %retval = alloca %struct._depend_unpack_t.0, align 8
  %i.addr = alloca ptr, align 8
  %j.addr = alloca ptr, align 8
  %v.addr = alloca ptr, align 8
  store ptr %i, ptr %i.addr, align 8
  store ptr %j, ptr %j.addr, align 8
  store ptr %v, ptr %v.addr, align 8
  %0 = load i32, ptr %i, align 4, !dbg !28
  %1 = sext i32 %0 to i64
  %2 = add i64 %1, 1
  %arraydecay = getelementptr inbounds [10 x i32], ptr %v, i64 0, i64 0, !dbg !30
  %3 = mul i64 %1, 4
  %4 = mul i64 %2, 4
  %5 = getelementptr inbounds %struct._depend_unpack_t.0, ptr %retval, i32 0, i32 0
  store ptr %arraydecay, ptr %5, align 8
  %6 = getelementptr inbounds %struct._depend_unpack_t.0, ptr %retval, i32 0, i32 1
  store i64 40, ptr %6, align 8
  %7 = getelementptr inbounds %struct._depend_unpack_t.0, ptr %retval, i32 0, i32 2
  store i64 %3, ptr %7, align 8
  %8 = getelementptr inbounds %struct._depend_unpack_t.0, ptr %retval, i32 0, i32 3
  store i64 %4, ptr %8, align 8
  %9 = load %struct._depend_unpack_t.0, ptr %retval, align 8, !dbg !30
  ret %struct._depend_unpack_t.0 %9, !dbg !30
}

attributes #0 = { noinline nounwind optnone "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-features"="+cx8,+mmx,+sse,+sse2,+x87" }
attributes #1 = { nounwind }
attributes #2 = { "min-legal-vector-width"="0" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.ident = !{!4}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "", isOptimized: false, runtimeVersion: 0, emissionKind: NoDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "<stdin>", directory: "")
!2 = !{i32 2, !"Debug Info Version", i32 3}
!3 = !{i32 1, !"wchar_size", i32 4}
!4 = !{!""}
!5 = distinct !DISubprogram(name: "main", scope: !6, file: !6, line: 2, type: !7, scopeLine: 2, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!6 = !DIFile(filename: "taskloop_multideps.ll", directory: "")
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 4, column: 14, scope: !5)
!10 = !DILocation(line: 3, column: 39, scope: !5)
!11 = !DILocation(line: 4, column: 10, scope: !5)
!12 = !DILocation(line: 4, column: 36, scope: !5)
!13 = !DILocation(line: 5, column: 1, scope: !5)
!14 = distinct !DISubprogram(linkageName: "compute_lb", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!15 = !DILocation(line: 4, column: 18, scope: !16)
!16 = !DILexicalBlockFile(scope: !14, file: !6, discriminator: 0)
!17 = distinct !DISubprogram(linkageName: "compute_ub", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!18 = !DILocation(line: 4, column: 25, scope: !19)
!19 = !DILexicalBlockFile(scope: !17, file: !6, discriminator: 0)
!20 = distinct !DISubprogram(linkageName: "compute_step", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!21 = !DILocation(line: 4, column: 29, scope: !22)
!22 = !DILexicalBlockFile(scope: !20, file: !6, discriminator: 0)
!23 = distinct !DISubprogram(linkageName: "compute_dep", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!24 = !DILocation(line: 3, column: 43, scope: !25)
!25 = !DILexicalBlockFile(scope: !23, file: !6, discriminator: 0)
!26 = !DILocation(line: 3, column: 39, scope: !25)
!27 = distinct !DISubprogram(linkageName: "compute_dep.1", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!28 = !DILocation(line: 3, column: 35, scope: !29)
!29 = !DILexicalBlockFile(scope: !27, file: !6, discriminator: 0)
!30 = !DILocation(line: 3, column: 33, scope: !29)
; CHECK-LABEL: define {{[^@]+}}@main
; CHECK-SAME: () #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[J:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[I:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i32 0, ptr [[J]], align 4, !dbg [[DBG9:![0-9]+]]
; CHECK-NEXT:    store i32 0, ptr [[I]], align 4, !dbg [[DBG10:![0-9]+]]
; CHECK-NEXT:    [[TMP0:%.*]] = alloca ptr, align 8, !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG11]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 -1, ptr [[NUM_DEPS]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_step(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[TMP4]], [[TMP3]], !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP8:%.*]] = sdiv i32 [[TMP7]], [[TMP5]], !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP10:%.*]] = sext i32 [[TMP9]] to i64, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP11:%.*]] = mul i64 1, [[TMP10]], !dbg [[DBG11]]
; CHECK-NEXT:    call void @nanos6_create_loop(ptr @task_info_var_main, ptr @task_invocation_info_main, ptr null, i64 16, ptr [[TMP0]], ptr [[TMP1]], i64 4, i64 [[TMP2]], i64 0, i64 [[TMP11]], i64 0, i64 0), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP12:%.*]] = load ptr, ptr [[TMP0]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP12]], i64 16, !dbg [[DBG11]]
; CHECK-NEXT:    [[GEP_V:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TMP12]], i32 0, i32 0, !dbg [[DBG11]]
; CHECK-NEXT:    store ptr @v, ptr [[GEP_V]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP13:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP13]]), !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_END3:%.*]], !dbg [[DBG11]]
; CHECK:       final.end:
; CHECK-NEXT:    ret i32 0, !dbg [[DBG12:![0-9]+]]
; CHECK:       final.then:
; CHECK-NEXT:    [[TMP14:%.*]] = call i32 @compute_lb(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP15:%.*]] = call i32 @compute_ub(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP16:%.*]] = call i32 @compute_step(), !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP14]], ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_COND:%.*]], !dbg [[DBG11]]
; CHECK:       for.cond:
; CHECK-NEXT:    [[TMP17:%.*]] = load i32, ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP18:%.*]] = icmp slt i32 [[TMP17]], [[TMP15]], !dbg [[DBG11]]
; CHECK-NEXT:    br i1 [[TMP18]], label [[TMP19:%.*]], label [[FOR_END:%.*]], !dbg [[DBG11]]
; CHECK:       19:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]], !dbg [[DBG11]]
; CHECK:       for.body:
; CHECK-NEXT:    br label [[FOR_INCR:%.*]], !dbg [[DBG12]]
; CHECK:       for.end:
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG11]]
; CHECK:       for.incr:
; CHECK-NEXT:    [[TMP20:%.*]] = load i32, ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP21:%.*]] = add i32 [[TMP20]], [[TMP16]], !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP21]], ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_COND]], !dbg [[DBG11]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP22:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP23:%.*]] = icmp ne i32 [[TMP22]], 0, !dbg [[DBG11]]
; CHECK-NEXT:    br i1 [[TMP23]], label [[FINAL_THEN:%.*]], label [[CODEREPL:%.*]], !dbg [[DBG11]]
; CHECK:       for.end3:
; CHECK-NEXT:    br label [[FINAL_END]], !dbg [[DBG11]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_lb
; CHECK-SAME: () #[[ATTR2:[0-9]+]] !dbg [[DBG13:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 0, !dbg [[DBG14:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_ub
; CHECK-SAME: () #[[ATTR2]] !dbg [[DBG16:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 10, !dbg [[DBG17:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_step
; CHECK-SAME: () #[[ATTR2]] !dbg [[DBG19:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 1, !dbg [[DBG20:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_dep
; CHECK-SAME: (ptr [[I:%.*]], ptr [[J:%.*]], i64 [[TMP0:%.*]]) #[[ATTR2]] !dbg [[DBG22:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T:%.*]], align 4
; CHECK-NEXT:    [[I_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[J_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[DOTADDR:%.*]] = alloca i64, align 8
; CHECK-NEXT:    store ptr [[I]], ptr [[I_ADDR]], align 8
; CHECK-NEXT:    store ptr [[J]], ptr [[J_ADDR]], align 8
; CHECK-NEXT:    store i64 [[TMP0]], ptr [[DOTADDR]], align 8
; CHECK-NEXT:    switch i64 [[TMP0]], label [[TMP3:%.*]] [
; CHECK-NEXT:    i64 0, label [[TMP4:%.*]]
; CHECK-NEXT:    ]
; CHECK:       1:
; CHECK-NEXT:    [[TMP2:%.*]] = load [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], align 4, !dbg [[DBG23:![0-9]+]]
; CHECK-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T]] [[TMP2]], !dbg [[DBG23]]
; CHECK:       3:
; CHECK-NEXT:    br label [[TMP1:%.*]]
; CHECK:       4:
; CHECK-NEXT:    [[TMP5:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG25:![0-9]+]]
; CHECK-NEXT:    [[TMP6:%.*]] = load i32, ptr [[J]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP7:%.*]] = add i32 0, [[TMP6]]
; CHECK-NEXT:    [[TMP8:%.*]] = add i32 [[TMP7]], -1
; CHECK-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 0
; CHECK-NEXT:    store i32 0, ptr [[TMP9]], align 4
; CHECK-NEXT:    [[TMP10:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 1
; CHECK-NEXT:    store i32 [[TMP5]], ptr [[TMP10]], align 4
; CHECK-NEXT:    [[TMP11:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 2
; CHECK-NEXT:    store i32 [[TMP8]], ptr [[TMP11]], align 4
; CHECK-NEXT:    [[TMP12:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 3
; CHECK-NEXT:    store i32 1, ptr [[TMP12]], align 4
; CHECK-NEXT:    br label [[TMP1]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_dep.1
; CHECK-SAME: (ptr [[I:%.*]], ptr [[J:%.*]], ptr [[V:%.*]]) #[[ATTR2]] !dbg [[DBG26:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T_0:%.*]], align 8
; CHECK-NEXT:    [[I_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[J_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[V_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    store ptr [[I]], ptr [[I_ADDR]], align 8
; CHECK-NEXT:    store ptr [[J]], ptr [[J_ADDR]], align 8
; CHECK-NEXT:    store ptr [[V]], ptr [[V_ADDR]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG27:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = sext i32 [[TMP0]] to i64
; CHECK-NEXT:    [[TMP2:%.*]] = add i64 [[TMP1]], 1
; CHECK-NEXT:    [[ARRAYDECAY:%.*]] = getelementptr inbounds [10 x i32], ptr [[V]], i64 0, i64 0, !dbg [[DBG29:![0-9]+]]
; CHECK-NEXT:    [[TMP3:%.*]] = mul i64 [[TMP1]], 4
; CHECK-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
; CHECK-NEXT:    [[TMP5:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 0
; CHECK-NEXT:    store ptr [[ARRAYDECAY]], ptr [[TMP5]], align 8
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 1
; CHECK-NEXT:    store i64 40, ptr [[TMP6]], align 8
; CHECK-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 2
; CHECK-NEXT:    store i64 [[TMP3]], ptr [[TMP7]], align 8
; CHECK-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], i32 0, i32 3
; CHECK-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
; CHECK-NEXT:    [[TMP9:%.*]] = load [[STRUCT__DEPEND_UNPACK_T_0]], ptr [[RETVAL]], align 8, !dbg [[DBG29]]
; CHECK-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP9]], !dbg [[DBG29]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_main
; CHECK-SAME: (ptr [[V:%.*]], ptr [[J:%.*]], ptr [[I:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG30:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG31:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    [[LB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T:%.*]], ptr [[LOOP_BOUNDS]], i32 0, i32 0, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP1:%.*]] = load i64, ptr [[LB_GEP]], align 8, !dbg [[DBG31]]
; CHECK-NEXT:    [[LB:%.*]] = trunc i64 [[TMP1]] to i32, !dbg [[DBG31]]
; CHECK-NEXT:    [[UB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T]], ptr [[LOOP_BOUNDS]], i32 0, i32 1, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[UB_GEP]], align 8, !dbg [[DBG31]]
; CHECK-NEXT:    [[UB:%.*]] = trunc i64 [[TMP2]] to i32, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb(), !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub(), !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_step(), !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[UB]], [[LB]], !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP8:%.*]] = sdiv i32 [[TMP7]], [[TMP5]], !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], 1, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP10:%.*]] = sext i32 [[TMP9]] to i64, !dbg [[DBG31]]
; CHECK-NEXT:    [[LOOP:%.*]] = alloca i32, align 4, !dbg [[DBG31]]
; CHECK-NEXT:    store i32 [[LB]], ptr [[LOOP]], align 4, !dbg [[DBG31]]
; CHECK-NEXT:    br label [[FOR_COND1:%.*]], !dbg [[DBG31]]
; CHECK:       for.cond1:
; CHECK-NEXT:    [[TMP11:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP12:%.*]] = icmp slt i32 [[TMP11]], [[UB]], !dbg [[DBG31]]
; CHECK-NEXT:    br i1 [[TMP12]], label [[TMP13:%.*]], label [[DOTEXITSTUB:%.*]], !dbg [[DBG31]]
; CHECK:       13:
; CHECK-NEXT:    [[TMP14:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP15:%.*]] = sext i32 [[TMP14]] to i64, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP16:%.*]] = udiv i64 [[TMP15]], 1, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP17:%.*]] = sext i32 [[TMP5]] to i64, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP18:%.*]] = mul i64 [[TMP16]], [[TMP17]], !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP19:%.*]] = sext i32 [[TMP3]] to i64, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP20:%.*]] = add i64 [[TMP18]], [[TMP19]], !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP21:%.*]] = mul i64 [[TMP16]], 1, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP22:%.*]] = sext i32 [[TMP14]] to i64, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP23:%.*]] = sub i64 [[TMP22]], [[TMP21]], !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP24:%.*]] = trunc i64 [[TMP20]] to i32, !dbg [[DBG31]]
; CHECK-NEXT:    store i32 [[TMP24]], ptr [[J]], align 4, !dbg [[DBG31]]
; CHECK-NEXT:    br label [[FOR_BODY2:%.*]], !dbg [[DBG31]]
; CHECK:       for.body2:
; CHECK-NEXT:    br label [[FOR_INCR4:%.*]], !dbg [[DBG32:![0-9]+]]
; CHECK:       for.incr4:
; CHECK-NEXT:    [[TMP25:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG31]]
; CHECK-NEXT:    [[TMP26:%.*]] = add i32 [[TMP25]], 1, !dbg [[DBG31]]
; CHECK-NEXT:    store i32 [[TMP26]], ptr [[LOOP]], align 4, !dbg [[DBG31]]
; CHECK-NEXT:    br label [[FOR_COND1]], !dbg [[DBG31]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_V:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[LOAD_GEP_V:%.*]] = load ptr, ptr [[GEP_V]], align 8
; CHECK-NEXT:    [[GEP_J:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 1
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 2
; CHECK-NEXT:    [[TLATE_LOAD_GEP_V:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    store ptr [[LOAD_GEP_V]], ptr [[TLATE_LOAD_GEP_V]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[TLATE_LOAD_GEP_V]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP1]], label [[TMP2:%.*]], label [[TMP8:%.*]]
; CHECK:       2:
; CHECK-NEXT:    [[LOCAL_LOOKUP_V:%.*]] = getelementptr [[NANOS6_ADDRESS_TRANSLATION_ENTRY_T:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE]], i32 0, i32 0
; CHECK-NEXT:    [[TMP3:%.*]] = load i64, ptr [[LOCAL_LOOKUP_V]], align 8
; CHECK-NEXT:    [[DEVICE_LOOKUP_V:%.*]] = getelementptr [[NANOS6_ADDRESS_TRANSLATION_ENTRY_T]], ptr [[ADDRESS_TRANSLATION_TABLE]], i32 0, i32 1
; CHECK-NEXT:    [[TMP4:%.*]] = load i64, ptr [[DEVICE_LOOKUP_V]], align 8
; CHECK-NEXT:    [[TMP5:%.*]] = sub i64 0, [[TMP3]]
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr i8, ptr [[TMP0]], i64 [[TMP5]]
; CHECK-NEXT:    [[TMP7:%.*]] = getelementptr i8, ptr [[TMP6]], i64 [[TMP4]]
; CHECK-NEXT:    store ptr [[TMP7]], ptr [[TLATE_LOAD_GEP_V]], align 8
; CHECK-NEXT:    br label [[TMP8]]
; CHECK:       8:
; CHECK-NEXT:    [[TMP9:%.*]] = load ptr, ptr [[TLATE_LOAD_GEP_V]], align 8
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main(ptr [[TMP9]], ptr [[GEP_J]], ptr [[GEP_I]], ptr [[LOOP_BOUNDS]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_deps_main
; CHECK-SAME: (ptr [[V:%.*]], ptr [[J:%.*]], ptr [[I:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[HANDLER:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[LB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T:%.*]], ptr [[LOOP_BOUNDS]], i32 0, i32 0
; CHECK-NEXT:    [[TMP0:%.*]] = load i64, ptr [[LB_GEP]], align 8
; CHECK-NEXT:    [[LB:%.*]] = trunc i64 [[TMP0]] to i32
; CHECK-NEXT:    [[UB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T]], ptr [[LOOP_BOUNDS]], i32 0, i32 1
; CHECK-NEXT:    [[TMP1:%.*]] = load i64, ptr [[UB_GEP]], align 8
; CHECK-NEXT:    [[TMP2:%.*]] = trunc i64 [[TMP1]] to i32
; CHECK-NEXT:    [[UB:%.*]] = sub i32 [[TMP2]], 1
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb()
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub()
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_step()
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[TMP4]], [[TMP3]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1
; CHECK-NEXT:    [[TMP8:%.*]] = sdiv i32 [[TMP7]], [[TMP5]]
; CHECK-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], 1
; CHECK-NEXT:    [[TMP10:%.*]] = sext i32 [[TMP9]] to i64
; CHECK-NEXT:    [[J_LB:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[J_UB:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[TMP11:%.*]] = sext i32 [[LB]] to i64
; CHECK-NEXT:    [[TMP12:%.*]] = udiv i64 [[TMP11]], 1
; CHECK-NEXT:    [[TMP13:%.*]] = sext i32 [[TMP5]] to i64
; CHECK-NEXT:    [[TMP14:%.*]] = mul i64 [[TMP12]], [[TMP13]]
; CHECK-NEXT:    [[TMP15:%.*]] = sext i32 [[TMP3]] to i64
; CHECK-NEXT:    [[TMP16:%.*]] = add i64 [[TMP14]], [[TMP15]]
; CHECK-NEXT:    [[TMP17:%.*]] = mul i64 [[TMP12]], 1
; CHECK-NEXT:    [[TMP18:%.*]] = sext i32 [[LB]] to i64
; CHECK-NEXT:    [[TMP19:%.*]] = sub i64 [[TMP18]], [[TMP17]]
; CHECK-NEXT:    [[TMP20:%.*]] = trunc i64 [[TMP16]] to i32
; CHECK-NEXT:    store i32 [[TMP20]], ptr [[J_LB]], align 4
; CHECK-NEXT:    [[TMP21:%.*]] = sext i32 [[UB]] to i64
; CHECK-NEXT:    [[TMP22:%.*]] = udiv i64 [[TMP21]], 1
; CHECK-NEXT:    [[TMP23:%.*]] = sext i32 [[TMP5]] to i64
; CHECK-NEXT:    [[TMP24:%.*]] = mul i64 [[TMP22]], [[TMP23]]
; CHECK-NEXT:    [[TMP25:%.*]] = sext i32 [[TMP3]] to i64
; CHECK-NEXT:    [[TMP26:%.*]] = add i64 [[TMP24]], [[TMP25]]
; CHECK-NEXT:    [[TMP27:%.*]] = mul i64 [[TMP22]], 1
; CHECK-NEXT:    [[TMP28:%.*]] = sext i32 [[UB]] to i64
; CHECK-NEXT:    [[TMP29:%.*]] = sub i64 [[TMP28]], [[TMP27]]
; CHECK-NEXT:    [[TMP30:%.*]] = trunc i64 [[TMP26]] to i32
; CHECK-NEXT:    store i32 [[TMP30]], ptr [[J_UB]], align 4
; CHECK-NEXT:    [[I_REMAP:%.*]] = alloca i32, align 4
; CHECK-NEXT:    br label [[TMP31:%.*]]
; CHECK:       31:
; CHECK-NEXT:    store i32 0, ptr [[I]], align 4
; CHECK-NEXT:    [[TMP32:%.*]] = call [[STRUCT__DEPEND_UNPACK_T:%.*]] @compute_dep(ptr [[I]], ptr [[J_LB]], i64 0)
; CHECK-NEXT:    [[TMP33:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP32]], 0
; CHECK-NEXT:    [[TMP34:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP32]], 2
; CHECK-NEXT:    [[TMP35:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP32]], 3
; CHECK-NEXT:    store i32 [[TMP33]], ptr [[I]], align 4
; CHECK-NEXT:    br label [[FOR_COND:%.*]]
; CHECK:       for.cond:
; CHECK-NEXT:    [[TMP36:%.*]] = load i32, ptr [[I]], align 4
; CHECK-NEXT:    [[TMP37:%.*]] = icmp sle i32 [[TMP36]], [[TMP34]]
; CHECK-NEXT:    br i1 [[TMP37]], label [[FOR_BODY:%.*]], label [[TMP46:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[TMP38:%.*]] = call [[STRUCT__DEPEND_UNPACK_T]] @compute_dep(ptr [[I]], ptr [[J_LB]], i64 0)
; CHECK-NEXT:    [[TMP39:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP38]], 1
; CHECK-NEXT:    store i32 [[TMP39]], ptr [[I_REMAP]], align 4
; CHECK-NEXT:    [[TMP40:%.*]] = call [[STRUCT__DEPEND_UNPACK_T_0:%.*]] @compute_dep.1(ptr [[I_REMAP]], ptr [[J_LB]], ptr [[V]])
; CHECK-NEXT:    [[TMP41:%.*]] = call [[STRUCT__DEPEND_UNPACK_T_0]] @compute_dep.1(ptr [[I_REMAP]], ptr [[J_LB]], ptr [[V]])
; CHECK-NEXT:    [[TMP42:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP40]], 0
; CHECK-NEXT:    [[TMP43:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP40]], 1
; CHECK-NEXT:    [[TMP44:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP40]], 2
; CHECK-NEXT:    [[TMP45:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T_0]] [[TMP41]], 3
; CHECK-NEXT:    call void @nanos6_register_region_write_depinfo1(ptr [[HANDLER]], i32 0, ptr @[[GLOB1:[0-9]+]], ptr [[TMP42]], i64 [[TMP43]], i64 [[TMP44]], i64 [[TMP45]])
; CHECK-NEXT:    br label [[FOR_INCR:%.*]]
; CHECK:       46:
; CHECK-NEXT:    ret void
; CHECK:       for.incr:
; CHECK-NEXT:    [[TMP47:%.*]] = load i32, ptr [[I]], align 4
; CHECK-NEXT:    [[TMP48:%.*]] = add i32 [[TMP47]], [[TMP35]]
; CHECK-NEXT:    store i32 [[TMP48]], ptr [[I]], align 4
; CHECK-NEXT:    br label [[FOR_COND]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_deps_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[HANDLER:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_V:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[LOAD_GEP_V:%.*]] = load ptr, ptr [[GEP_V]], align 8
; CHECK-NEXT:    [[GEP_J:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 1
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 2
; CHECK-NEXT:    call void @nanos6_unpacked_deps_main(ptr [[LOAD_GEP_V]], ptr [[GEP_J]], ptr [[GEP_I]], ptr [[LOOP_BOUNDS]], ptr [[HANDLER]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_constructor_register_task_info() {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_main)
; CHECK-NEXT:    ret void
;