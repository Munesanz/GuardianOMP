; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
; ModuleID = 'collapse_dep.ll'
source_filename = "collapse_dep.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; int array[50];
; int main() {
;     #pragma oss taskloop collapse(2) in( array[i + j] )
;     for (int i = 0; i < 10; ++i) {
;         for (int j = 0; j < 10; ++j) {
;         }
;     }
; }

%struct._depend_unpack_t = type { ptr, i64, i64, i64 }

@array = global [50 x i32] zeroinitializer, align 16

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !5 {
entry:
  %i = alloca i32, align 4
  %j = alloca i32, align 4
  store i32 0, ptr %i, align 4, !dbg !9
  store i32 0, ptr %j, align 4, !dbg !10
  %0 = call token @llvm.directive.region.entry() [ "DIR.OSS"([9 x i8] c"TASKLOOP\00"), "QUAL.OSS.SHARED"(ptr @array, [50 x i32] undef), "QUAL.OSS.PRIVATE"(ptr %i, i32 undef), "QUAL.OSS.PRIVATE"(ptr %j, i32 undef), "QUAL.OSS.LOOP.IND.VAR"(ptr %i, ptr %j), "QUAL.OSS.LOOP.LOWER.BOUND"(ptr @compute_lb, ptr @compute_lb.1), "QUAL.OSS.LOOP.UPPER.BOUND"(ptr @compute_ub, ptr @compute_ub.2), "QUAL.OSS.LOOP.STEP"(ptr @compute_step, ptr @compute_step.3), "QUAL.OSS.LOOP.TYPE"(i64 0, i64 1, i64 1, i64 1, i64 1, i64 0, i64 1, i64 1, i64 1, i64 1), "QUAL.OSS.DEP.IN"(ptr @array, [13 x i8] c"array[i + j]\00", ptr @compute_dep, ptr %i, ptr %j, ptr @array) ], !dbg !11
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

define internal i32 @compute_lb.1() #2 !dbg !23 {
entry:
  ret i32 0, !dbg !24
}

define internal i32 @compute_ub.2() #2 !dbg !26 {
entry:
  ret i32 10, !dbg !27
}

define internal i32 @compute_step.3() #2 !dbg !29 {
entry:
  ret i32 1, !dbg !30
}

define internal %struct._depend_unpack_t @compute_dep(ptr %i, ptr %j, ptr %array) #2 !dbg !32 {
entry:
  %retval = alloca %struct._depend_unpack_t, align 8
  %i.addr = alloca ptr, align 8
  %j.addr = alloca ptr, align 8
  %array.addr = alloca ptr, align 8
  store ptr %i, ptr %i.addr, align 8
  store ptr %j, ptr %j.addr, align 8
  store ptr %array, ptr %array.addr, align 8
  %0 = load i32, ptr %i, align 4, !dbg !33
  %1 = load i32, ptr %j, align 4, !dbg !35
  %add = add nsw i32 %0, %1, !dbg !36
  %2 = sext i32 %add to i64
  %3 = add i64 %2, 1
  %arraydecay = getelementptr inbounds [50 x i32], ptr %array, i64 0, i64 0, !dbg !37
  %4 = mul i64 %2, 4
  %5 = mul i64 %3, 4
  %6 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 0
  store ptr %arraydecay, ptr %6, align 8
  %7 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 1
  store i64 200, ptr %7, align 8
  %8 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 2
  store i64 %4, ptr %8, align 8
  %9 = getelementptr inbounds %struct._depend_unpack_t, ptr %retval, i32 0, i32 3
  store i64 %5, ptr %9, align 8
  %10 = load %struct._depend_unpack_t, ptr %retval, align 8, !dbg !37
  ret %struct._depend_unpack_t %10, !dbg !37
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
!6 = !DIFile(filename: "collapse_dep.ll", directory: "")
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 4, column: 14, scope: !5)
!10 = !DILocation(line: 5, column: 18, scope: !5)
!11 = !DILocation(line: 5, column: 14, scope: !5)
!12 = !DILocation(line: 6, column: 9, scope: !5)
!13 = !DILocation(line: 8, column: 1, scope: !5)
!14 = distinct !DISubprogram(linkageName: "compute_lb", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!15 = !DILocation(line: 4, column: 18, scope: !16)
!16 = !DILexicalBlockFile(scope: !14, file: !6, discriminator: 0)
!17 = distinct !DISubprogram(linkageName: "compute_ub", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!18 = !DILocation(line: 4, column: 25, scope: !19)
!19 = !DILexicalBlockFile(scope: !17, file: !6, discriminator: 0)
!20 = distinct !DISubprogram(linkageName: "compute_step", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!21 = !DILocation(line: 4, column: 29, scope: !22)
!22 = !DILexicalBlockFile(scope: !20, file: !6, discriminator: 0)
!23 = distinct !DISubprogram(linkageName: "compute_lb.1", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!24 = !DILocation(line: 5, column: 22, scope: !25)
!25 = !DILexicalBlockFile(scope: !23, file: !6, discriminator: 0)
!26 = distinct !DISubprogram(linkageName: "compute_ub.2", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!27 = !DILocation(line: 5, column: 29, scope: !28)
!28 = !DILexicalBlockFile(scope: !26, file: !6, discriminator: 0)
!29 = distinct !DISubprogram(linkageName: "compute_step.3", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!30 = !DILocation(line: 5, column: 33, scope: !31)
!31 = !DILexicalBlockFile(scope: !29, file: !6, discriminator: 0)
!32 = distinct !DISubprogram(linkageName: "compute_dep", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!33 = !DILocation(line: 3, column: 48, scope: !34)
!34 = !DILexicalBlockFile(scope: !32, file: !6, discriminator: 0)
!35 = !DILocation(line: 3, column: 52, scope: !34)
!36 = !DILocation(line: 3, column: 50, scope: !34)
!37 = !DILocation(line: 3, column: 42, scope: !34)
; CHECK-LABEL: define {{[^@]+}}@main
; CHECK-SAME: () #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[I:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[J:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i32 0, ptr [[I]], align 4, !dbg [[DBG9:![0-9]+]]
; CHECK-NEXT:    store i32 0, ptr [[J]], align 4, !dbg [[DBG10:![0-9]+]]
; CHECK-NEXT:    [[TMP0:%.*]] = alloca ptr, align 8, !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG11]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP3:%.*]] = add i64 [[TMP2]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    store i64 [[TMP3]], ptr [[NUM_DEPS]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP4:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_lb(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP6:%.*]] = call i32 @compute_ub(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP7:%.*]] = call i32 @compute_step(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP8:%.*]] = sub i32 [[TMP6]], [[TMP5]], !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP9:%.*]] = sub i32 [[TMP8]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP10:%.*]] = sdiv i32 [[TMP9]], [[TMP7]], !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP11:%.*]] = add i32 [[TMP10]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP12:%.*]] = sext i32 [[TMP11]] to i64, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP13:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP5]], ptr [[I]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP14:%.*]] = call i32 @compute_lb.1(), !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP13]], ptr [[I]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP15:%.*]] = call i32 @compute_ub.2(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP16:%.*]] = call i32 @compute_step.3(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP17:%.*]] = sub i32 [[TMP15]], [[TMP14]], !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP18:%.*]] = sub i32 [[TMP17]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP19:%.*]] = sdiv i32 [[TMP18]], [[TMP16]], !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP20:%.*]] = add i32 [[TMP19]], 1, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP21:%.*]] = sext i32 [[TMP20]] to i64, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP22:%.*]] = mul i64 1, [[TMP12]], !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP23:%.*]] = mul i64 [[TMP22]], [[TMP21]], !dbg [[DBG11]]
; CHECK-NEXT:    call void @nanos6_create_loop(ptr @task_info_var_main, ptr @task_invocation_info_main, ptr null, i64 16, ptr [[TMP0]], ptr [[TMP1]], i64 4, i64 [[TMP4]], i64 0, i64 [[TMP23]], i64 0, i64 0), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP24:%.*]] = load ptr, ptr [[TMP0]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP24]], i64 16, !dbg [[DBG11]]
; CHECK-NEXT:    [[GEP_ARRAY:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TMP24]], i32 0, i32 0, !dbg [[DBG11]]
; CHECK-NEXT:    store ptr @array, ptr [[GEP_ARRAY]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP25:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG11]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP25]]), !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_END7:%.*]], !dbg [[DBG11]]
; CHECK:       final.end:
; CHECK-NEXT:    ret i32 0, !dbg [[DBG12:![0-9]+]]
; CHECK:       final.then:
; CHECK-NEXT:    [[TMP26:%.*]] = call i32 @compute_lb(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP27:%.*]] = call i32 @compute_ub(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP28:%.*]] = call i32 @compute_step(), !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP26]], ptr [[I]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_COND1:%.*]], !dbg [[DBG11]]
; CHECK:       for.cond1:
; CHECK-NEXT:    [[TMP29:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP30:%.*]] = icmp slt i32 [[TMP29]], [[TMP27]], !dbg [[DBG11]]
; CHECK-NEXT:    br i1 [[TMP30]], label [[TMP31:%.*]], label [[FOR_END3:%.*]], !dbg [[DBG11]]
; CHECK:       31:
; CHECK-NEXT:    br label [[TMP32:%.*]], !dbg [[DBG11]]
; CHECK:       32:
; CHECK-NEXT:    br label [[FOR_BODY2:%.*]], !dbg [[DBG11]]
; CHECK:       for.body2:
; CHECK-NEXT:    [[TMP33:%.*]] = call i32 @compute_lb.1(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP34:%.*]] = call i32 @compute_ub.2(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP35:%.*]] = call i32 @compute_step.3(), !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP33]], ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_COND:%.*]], !dbg [[DBG11]]
; CHECK:       for.cond:
; CHECK-NEXT:    [[TMP36:%.*]] = load i32, ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP37:%.*]] = icmp slt i32 [[TMP36]], [[TMP34]], !dbg [[DBG11]]
; CHECK-NEXT:    br i1 [[TMP37]], label [[TMP38:%.*]], label [[FOR_END:%.*]], !dbg [[DBG11]]
; CHECK:       38:
; CHECK-NEXT:    br label [[TMP39:%.*]], !dbg [[DBG11]]
; CHECK:       39:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]], !dbg [[DBG11]]
; CHECK:       for.body:
; CHECK-NEXT:    br label [[FOR_INCR:%.*]], !dbg [[DBG12]]
; CHECK:       for.end:
; CHECK-NEXT:    br label [[FOR_INCR4:%.*]], !dbg [[DBG11]]
; CHECK:       for.incr:
; CHECK-NEXT:    [[TMP40:%.*]] = load i32, ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP41:%.*]] = add i32 [[TMP40]], [[TMP35]], !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP41]], ptr [[J]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_COND]], !dbg [[DBG11]]
; CHECK:       for.end3:
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG11]]
; CHECK:       for.incr4:
; CHECK-NEXT:    [[TMP42:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP43:%.*]] = add i32 [[TMP42]], [[TMP28]], !dbg [[DBG11]]
; CHECK-NEXT:    store i32 [[TMP43]], ptr [[I]], align 4, !dbg [[DBG11]]
; CHECK-NEXT:    br label [[FOR_COND1]], !dbg [[DBG11]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP44:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG11]]
; CHECK-NEXT:    [[TMP45:%.*]] = icmp ne i32 [[TMP44]], 0, !dbg [[DBG11]]
; CHECK-NEXT:    br i1 [[TMP45]], label [[FINAL_THEN:%.*]], label [[CODEREPL:%.*]], !dbg [[DBG11]]
; CHECK:       for.end7:
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
; CHECK-LABEL: define {{[^@]+}}@compute_lb.1
; CHECK-SAME: () #[[ATTR2]] !dbg [[DBG22:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 0, !dbg [[DBG23:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_ub.2
; CHECK-SAME: () #[[ATTR2]] !dbg [[DBG25:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 10, !dbg [[DBG26:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_step.3
; CHECK-SAME: () #[[ATTR2]] !dbg [[DBG28:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 1, !dbg [[DBG29:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_dep
; CHECK-SAME: (ptr [[I:%.*]], ptr [[J:%.*]], ptr [[ARRAY:%.*]]) #[[ATTR2]] !dbg [[DBG31:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RETVAL:%.*]] = alloca [[STRUCT__DEPEND_UNPACK_T:%.*]], align 8
; CHECK-NEXT:    [[I_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[J_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[ARRAY_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    store ptr [[I]], ptr [[I_ADDR]], align 8
; CHECK-NEXT:    store ptr [[J]], ptr [[J_ADDR]], align 8
; CHECK-NEXT:    store ptr [[ARRAY]], ptr [[ARRAY_ADDR]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG32:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = load i32, ptr [[J]], align 4, !dbg [[DBG34:![0-9]+]]
; CHECK-NEXT:    [[ADD:%.*]] = add nsw i32 [[TMP0]], [[TMP1]], !dbg [[DBG35:![0-9]+]]
; CHECK-NEXT:    [[TMP2:%.*]] = sext i32 [[ADD]] to i64
; CHECK-NEXT:    [[TMP3:%.*]] = add i64 [[TMP2]], 1
; CHECK-NEXT:    [[ARRAYDECAY:%.*]] = getelementptr inbounds [50 x i32], ptr [[ARRAY]], i64 0, i64 0, !dbg [[DBG36:![0-9]+]]
; CHECK-NEXT:    [[TMP4:%.*]] = mul i64 [[TMP2]], 4
; CHECK-NEXT:    [[TMP5:%.*]] = mul i64 [[TMP3]], 4
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 0
; CHECK-NEXT:    store ptr [[ARRAYDECAY]], ptr [[TMP6]], align 8
; CHECK-NEXT:    [[TMP7:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 1
; CHECK-NEXT:    store i64 200, ptr [[TMP7]], align 8
; CHECK-NEXT:    [[TMP8:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 2
; CHECK-NEXT:    store i64 [[TMP4]], ptr [[TMP8]], align 8
; CHECK-NEXT:    [[TMP9:%.*]] = getelementptr inbounds [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], i32 0, i32 3
; CHECK-NEXT:    store i64 [[TMP5]], ptr [[TMP9]], align 8
; CHECK-NEXT:    [[TMP10:%.*]] = load [[STRUCT__DEPEND_UNPACK_T]], ptr [[RETVAL]], align 8, !dbg [[DBG36]]
; CHECK-NEXT:    ret [[STRUCT__DEPEND_UNPACK_T]] [[TMP10]], !dbg [[DBG36]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_main
; CHECK-SAME: (ptr [[ARRAY:%.*]], ptr [[I:%.*]], ptr [[J:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG37:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG38:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    [[LB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T:%.*]], ptr [[LOOP_BOUNDS]], i32 0, i32 0, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP1:%.*]] = load i64, ptr [[LB_GEP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    [[UB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T]], ptr [[LOOP_BOUNDS]], i32 0, i32 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[UB_GEP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_step(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[TMP4]], [[TMP3]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP8:%.*]] = sdiv i32 [[TMP7]], [[TMP5]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP10:%.*]] = sext i32 [[TMP9]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP11:%.*]] = sub i32 [[TMP4]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    store i32 [[TMP3]], ptr [[I]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP12:%.*]] = call i32 @compute_lb.1(), !dbg [[DBG38]]
; CHECK-NEXT:    store i32 [[TMP11]], ptr [[I]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP13:%.*]] = call i32 @compute_ub.2(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP14:%.*]] = call i32 @compute_step.3(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP15:%.*]] = sub i32 [[TMP13]], [[TMP12]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP16:%.*]] = sub i32 [[TMP15]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP17:%.*]] = sdiv i32 [[TMP16]], [[TMP14]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP18:%.*]] = add i32 [[TMP17]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP19:%.*]] = sext i32 [[TMP18]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP20:%.*]] = sext i32 [[TMP3]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP21:%.*]] = sext i32 [[TMP4]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[LOOP:%.*]] = alloca i64, align 8, !dbg [[DBG38]]
; CHECK-NEXT:    store i64 [[TMP1]], ptr [[LOOP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    br label [[FOR_COND5:%.*]], !dbg [[DBG38]]
; CHECK:       for.cond5:
; CHECK-NEXT:    [[TMP22:%.*]] = load i64, ptr [[LOOP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP23:%.*]] = icmp ult i64 [[TMP22]], [[TMP2]], !dbg [[DBG38]]
; CHECK-NEXT:    br i1 [[TMP23]], label [[TMP24:%.*]], label [[DOTEXITSTUB:%.*]], !dbg [[DBG38]]
; CHECK:       24:
; CHECK-NEXT:    [[TMP25:%.*]] = load i64, ptr [[LOOP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP26:%.*]] = mul i64 1, [[TMP19]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP27:%.*]] = udiv i64 [[TMP25]], [[TMP26]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP28:%.*]] = sext i32 [[TMP5]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP29:%.*]] = mul i64 [[TMP27]], [[TMP28]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP30:%.*]] = sext i32 [[TMP3]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP31:%.*]] = add i64 [[TMP29]], [[TMP30]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP32:%.*]] = mul i64 [[TMP27]], [[TMP26]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP33:%.*]] = sub i64 [[TMP25]], [[TMP32]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP34:%.*]] = trunc i64 [[TMP31]] to i32, !dbg [[DBG38]]
; CHECK-NEXT:    store i32 [[TMP34]], ptr [[I]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    br label [[TMP35:%.*]], !dbg [[DBG38]]
; CHECK:       35:
; CHECK-NEXT:    [[TMP36:%.*]] = udiv i64 [[TMP33]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP37:%.*]] = sext i32 [[TMP14]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP38:%.*]] = mul i64 [[TMP36]], [[TMP37]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP39:%.*]] = sext i32 [[TMP12]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP40:%.*]] = add i64 [[TMP38]], [[TMP39]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP41:%.*]] = mul i64 [[TMP36]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP42:%.*]] = sub i64 [[TMP33]], [[TMP41]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP43:%.*]] = trunc i64 [[TMP40]] to i32, !dbg [[DBG38]]
; CHECK-NEXT:    store i32 [[TMP43]], ptr [[J]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    br label [[FOR_BODY6:%.*]], !dbg [[DBG38]]
; CHECK:       for.body6:
; CHECK-NEXT:    br label [[FOR_INCR8:%.*]], !dbg [[DBG39:![0-9]+]]
; CHECK:       for.incr8:
; CHECK-NEXT:    [[TMP44:%.*]] = load i64, ptr [[LOOP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP45:%.*]] = add i64 [[TMP44]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    store i64 [[TMP45]], ptr [[LOOP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    br label [[FOR_COND5]], !dbg [[DBG38]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_ARRAY:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[LOAD_GEP_ARRAY:%.*]] = load ptr, ptr [[GEP_ARRAY]], align 8
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 1
; CHECK-NEXT:    [[GEP_J:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 2
; CHECK-NEXT:    [[TLATE_LOAD_GEP_ARRAY:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    store ptr [[LOAD_GEP_ARRAY]], ptr [[TLATE_LOAD_GEP_ARRAY]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[TLATE_LOAD_GEP_ARRAY]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP1]], label [[TMP2:%.*]], label [[TMP8:%.*]]
; CHECK:       2:
; CHECK-NEXT:    [[LOCAL_LOOKUP_ARRAY:%.*]] = getelementptr [[NANOS6_ADDRESS_TRANSLATION_ENTRY_T:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE]], i32 0, i32 0
; CHECK-NEXT:    [[TMP3:%.*]] = load i64, ptr [[LOCAL_LOOKUP_ARRAY]], align 8
; CHECK-NEXT:    [[DEVICE_LOOKUP_ARRAY:%.*]] = getelementptr [[NANOS6_ADDRESS_TRANSLATION_ENTRY_T]], ptr [[ADDRESS_TRANSLATION_TABLE]], i32 0, i32 1
; CHECK-NEXT:    [[TMP4:%.*]] = load i64, ptr [[DEVICE_LOOKUP_ARRAY]], align 8
; CHECK-NEXT:    [[TMP5:%.*]] = sub i64 0, [[TMP3]]
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr i8, ptr [[TMP0]], i64 [[TMP5]]
; CHECK-NEXT:    [[TMP7:%.*]] = getelementptr i8, ptr [[TMP6]], i64 [[TMP4]]
; CHECK-NEXT:    store ptr [[TMP7]], ptr [[TLATE_LOAD_GEP_ARRAY]], align 8
; CHECK-NEXT:    br label [[TMP8]]
; CHECK:       8:
; CHECK-NEXT:    [[TMP9:%.*]] = load ptr, ptr [[TLATE_LOAD_GEP_ARRAY]], align 8
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main(ptr [[TMP9]], ptr [[GEP_I]], ptr [[GEP_J]], ptr [[LOOP_BOUNDS]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_deps_main
; CHECK-SAME: (ptr [[ARRAY:%.*]], ptr [[I:%.*]], ptr [[J:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[HANDLER:%.*]]) {
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
; CHECK-NEXT:    [[TMP11:%.*]] = sub i32 [[TMP4]], 1
; CHECK-NEXT:    store i32 [[TMP3]], ptr [[I]], align 4
; CHECK-NEXT:    [[TMP12:%.*]] = call i32 @compute_lb.1()
; CHECK-NEXT:    store i32 [[TMP11]], ptr [[I]], align 4
; CHECK-NEXT:    [[TMP13:%.*]] = call i32 @compute_ub.2()
; CHECK-NEXT:    [[TMP14:%.*]] = call i32 @compute_step.3()
; CHECK-NEXT:    [[TMP15:%.*]] = sub i32 [[TMP13]], [[TMP12]]
; CHECK-NEXT:    [[TMP16:%.*]] = sub i32 [[TMP15]], 1
; CHECK-NEXT:    [[TMP17:%.*]] = sdiv i32 [[TMP16]], [[TMP14]]
; CHECK-NEXT:    [[TMP18:%.*]] = add i32 [[TMP17]], 1
; CHECK-NEXT:    [[TMP19:%.*]] = sext i32 [[TMP18]] to i64
; CHECK-NEXT:    [[I_LB:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[I_UB:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[TMP20:%.*]] = mul i64 1, [[TMP19]]
; CHECK-NEXT:    [[TMP21:%.*]] = sext i32 [[LB]] to i64
; CHECK-NEXT:    [[TMP22:%.*]] = udiv i64 [[TMP21]], [[TMP20]]
; CHECK-NEXT:    [[TMP23:%.*]] = sext i32 [[TMP5]] to i64
; CHECK-NEXT:    [[TMP24:%.*]] = mul i64 [[TMP22]], [[TMP23]]
; CHECK-NEXT:    [[TMP25:%.*]] = sext i32 [[TMP3]] to i64
; CHECK-NEXT:    [[TMP26:%.*]] = add i64 [[TMP24]], [[TMP25]]
; CHECK-NEXT:    [[TMP27:%.*]] = mul i64 [[TMP22]], [[TMP20]]
; CHECK-NEXT:    [[TMP28:%.*]] = sext i32 [[LB]] to i64
; CHECK-NEXT:    [[TMP29:%.*]] = sub i64 [[TMP28]], [[TMP27]]
; CHECK-NEXT:    [[TMP30:%.*]] = trunc i64 [[TMP26]] to i32
; CHECK-NEXT:    store i32 [[TMP30]], ptr [[I_LB]], align 4
; CHECK-NEXT:    [[TMP31:%.*]] = mul i64 1, [[TMP19]]
; CHECK-NEXT:    [[TMP32:%.*]] = sext i32 [[UB]] to i64
; CHECK-NEXT:    [[TMP33:%.*]] = udiv i64 [[TMP32]], [[TMP31]]
; CHECK-NEXT:    [[TMP34:%.*]] = sext i32 [[TMP5]] to i64
; CHECK-NEXT:    [[TMP35:%.*]] = mul i64 [[TMP33]], [[TMP34]]
; CHECK-NEXT:    [[TMP36:%.*]] = sext i32 [[TMP3]] to i64
; CHECK-NEXT:    [[TMP37:%.*]] = add i64 [[TMP35]], [[TMP36]]
; CHECK-NEXT:    [[TMP38:%.*]] = mul i64 [[TMP33]], [[TMP31]]
; CHECK-NEXT:    [[TMP39:%.*]] = sext i32 [[UB]] to i64
; CHECK-NEXT:    [[TMP40:%.*]] = sub i64 [[TMP39]], [[TMP38]]
; CHECK-NEXT:    [[TMP41:%.*]] = trunc i64 [[TMP37]] to i32
; CHECK-NEXT:    store i32 [[TMP41]], ptr [[I_UB]], align 4
; CHECK-NEXT:    [[J_LB:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[J_UB:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[TMP42:%.*]] = udiv i64 [[TMP29]], 1
; CHECK-NEXT:    [[TMP43:%.*]] = sext i32 [[TMP14]] to i64
; CHECK-NEXT:    [[TMP44:%.*]] = mul i64 [[TMP42]], [[TMP43]]
; CHECK-NEXT:    [[TMP45:%.*]] = sext i32 [[TMP12]] to i64
; CHECK-NEXT:    [[TMP46:%.*]] = add i64 [[TMP44]], [[TMP45]]
; CHECK-NEXT:    [[TMP47:%.*]] = mul i64 [[TMP42]], 1
; CHECK-NEXT:    [[TMP48:%.*]] = sub i64 [[TMP29]], [[TMP47]]
; CHECK-NEXT:    [[TMP49:%.*]] = trunc i64 [[TMP46]] to i32
; CHECK-NEXT:    store i32 [[TMP49]], ptr [[J_LB]], align 4
; CHECK-NEXT:    [[TMP50:%.*]] = udiv i64 [[TMP40]], 1
; CHECK-NEXT:    [[TMP51:%.*]] = sext i32 [[TMP14]] to i64
; CHECK-NEXT:    [[TMP52:%.*]] = mul i64 [[TMP50]], [[TMP51]]
; CHECK-NEXT:    [[TMP53:%.*]] = sext i32 [[TMP12]] to i64
; CHECK-NEXT:    [[TMP54:%.*]] = add i64 [[TMP52]], [[TMP53]]
; CHECK-NEXT:    [[TMP55:%.*]] = mul i64 [[TMP50]], 1
; CHECK-NEXT:    [[TMP56:%.*]] = sub i64 [[TMP40]], [[TMP55]]
; CHECK-NEXT:    [[TMP57:%.*]] = trunc i64 [[TMP54]] to i32
; CHECK-NEXT:    store i32 [[TMP57]], ptr [[J_UB]], align 4
; CHECK-NEXT:    [[TMP58:%.*]] = call [[STRUCT__DEPEND_UNPACK_T:%.*]] @compute_dep(ptr [[I_LB]], ptr [[J_LB]], ptr [[ARRAY]])
; CHECK-NEXT:    [[TMP59:%.*]] = call [[STRUCT__DEPEND_UNPACK_T]] @compute_dep(ptr [[I_UB]], ptr [[J_UB]], ptr [[ARRAY]])
; CHECK-NEXT:    [[TMP60:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP58]], 0
; CHECK-NEXT:    [[TMP61:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP58]], 1
; CHECK-NEXT:    [[TMP62:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP58]], 2
; CHECK-NEXT:    [[TMP63:%.*]] = extractvalue [[STRUCT__DEPEND_UNPACK_T]] [[TMP59]], 3
; CHECK-NEXT:    call void @nanos6_register_region_read_depinfo1(ptr [[HANDLER]], i32 0, ptr @[[GLOB1:[0-9]+]], ptr [[TMP60]], i64 [[TMP61]], i64 [[TMP62]], i64 [[TMP63]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_deps_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[HANDLER:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_ARRAY:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[LOAD_GEP_ARRAY:%.*]] = load ptr, ptr [[GEP_ARRAY]], align 8
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 1
; CHECK-NEXT:    [[GEP_J:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 2
; CHECK-NEXT:    call void @nanos6_unpacked_deps_main(ptr [[LOAD_GEP_ARRAY]], ptr [[GEP_I]], ptr [[GEP_J]], ptr [[LOOP_BOUNDS]], ptr [[HANDLER]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_constructor_register_task_info() {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_main)
; CHECK-NEXT:    ret void
;