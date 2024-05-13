; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
; ModuleID = 'taskloop_final_loop.ll'
source_filename = "taskloop_final_loop.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Checking only that we build the loop in final context correctly

@sum = dso_local global i32 0, align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @taskloop(i32 %lb, i32 %ub, i32 %step) #0 !dbg !8 {
entry:
  %lb.addr = alloca i32, align 4
  %ub.addr = alloca i32, align 4
  %step.addr = alloca i32, align 4
  %i = alloca i32, align 4
  store i32 %lb, ptr %lb.addr, align 4
  store i32 %ub, ptr %ub.addr, align 4
  store i32 %step, ptr %step.addr, align 4
  %0 = load i32, ptr %lb.addr, align 4, !dbg !10
  store i32 %0, ptr %i, align 4, !dbg !11
  %1 = call token @llvm.directive.region.entry() [ "DIR.OSS"([9 x i8] c"TASKLOOP\00"), "QUAL.OSS.SHARED"(ptr @sum, i32 undef), "QUAL.OSS.PRIVATE"(ptr %i, i32 undef), "QUAL.OSS.FIRSTPRIVATE"(ptr %lb.addr, i32 undef), "QUAL.OSS.FIRSTPRIVATE"(ptr %ub.addr, i32 undef), "QUAL.OSS.FIRSTPRIVATE"(ptr %step.addr, i32 undef), "QUAL.OSS.LOOP.IND.VAR"(ptr %i), "QUAL.OSS.LOOP.LOWER.BOUND"(ptr @compute_lb, ptr %lb.addr), "QUAL.OSS.LOOP.UPPER.BOUND"(ptr @compute_ub, ptr %ub.addr), "QUAL.OSS.LOOP.STEP"(ptr @compute_step, ptr %step.addr), "QUAL.OSS.LOOP.TYPE"(i64 0, i64 1, i64 1, i64 1, i64 1) ], !dbg !12
  %2 = load i32, ptr %i, align 4, !dbg !13
  %3 = load i32, ptr @sum, align 4, !dbg !14
  %add = add nsw i32 %3, %2, !dbg !14
  store i32 %add, ptr @sum, align 4, !dbg !14
  call void @llvm.directive.region.exit(token %1), !dbg !15
  ret void, !dbg !16
}

; Function Attrs: nounwind
declare token @llvm.directive.region.entry() #1

; Function Attrs: nounwind
declare void @llvm.directive.region.exit(token) #1

define internal i32 @compute_lb(ptr %lb) #2 !dbg !17 {
entry:
  %lb.addr = alloca ptr, align 8
  store ptr %lb, ptr %lb.addr, align 8
  %0 = load i32, ptr %lb, align 4, !dbg !18
  ret i32 %0, !dbg !18
}

define internal i32 @compute_ub(ptr %ub) #2 !dbg !19 {
entry:
  %ub.addr = alloca ptr, align 8
  store ptr %ub, ptr %ub.addr, align 8
  %0 = load i32, ptr %ub, align 4, !dbg !20
  ret i32 %0, !dbg !20
}

define internal i32 @compute_step(ptr %step) #2 !dbg !21 {
entry:
  %step.addr = alloca ptr, align 8
  store ptr %step, ptr %step.addr, align 8
  %0 = load i32, ptr %step, align 4, !dbg !22
  ret i32 %0, !dbg !22
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nounwind }
attributes #2 = { "min-legal-vector-width"="0" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4, !5, !6}
!llvm.ident = !{!7}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "human", isOptimized: false, runtimeVersion: 0, emissionKind: NoDebug, enums: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "taskloop_final_loop.ll", directory: "")
!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!5 = !{i32 7, !"uwtable", i32 1}
!6 = !{i32 7, !"frame-pointer", i32 2}
!7 = !{!""}
!8 = distinct !DISubprogram(name: "taskloop", scope: !1, file: !1, line: 2, type: !9, scopeLine: 2, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!9 = !DISubroutineType(types: !2)
!10 = !DILocation(line: 4, column: 18, scope: !8)
!11 = !DILocation(line: 4, column: 14, scope: !8)
!12 = !DILocation(line: 4, column: 10, scope: !8)
!13 = !DILocation(line: 5, column: 12, scope: !8)
!14 = !DILocation(line: 5, column: 9, scope: !8)
!15 = !DILocation(line: 5, column: 5, scope: !8)
!16 = !DILocation(line: 6, column: 1, scope: !8)
!17 = distinct !DISubprogram(linkageName: "compute_lb", scope: !1, file: !1, type: !9, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !2)
!18 = !DILocation(line: 4, column: 18, scope: !17)
!19 = distinct !DISubprogram(linkageName: "compute_ub", scope: !1, file: !1, type: !9, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !2)
!20 = !DILocation(line: 4, column: 26, scope: !19)
!21 = distinct !DISubprogram(linkageName: "compute_step", scope: !1, file: !1, type: !9, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !2)
!22 = !DILocation(line: 4, column: 35, scope: !21)
; CHECK-LABEL: define {{[^@]+}}@taskloop
; CHECK-SAME: (i32 [[LB:%.*]], i32 [[UB:%.*]], i32 [[STEP:%.*]]) #[[ATTR0:[0-9]+]] !dbg [[DBG8:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[LB_ADDR:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[UB_ADDR:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[STEP_ADDR:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[I:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i32 [[LB]], ptr [[LB_ADDR]], align 4
; CHECK-NEXT:    store i32 [[UB]], ptr [[UB_ADDR]], align 4
; CHECK-NEXT:    store i32 [[STEP]], ptr [[STEP_ADDR]], align 4
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr [[LB_ADDR]], align 4, !dbg [[DBG10:![0-9]+]]
; CHECK-NEXT:    store i32 [[TMP0]], ptr [[I]], align 4, !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG12:![0-9]+]]
; CHECK-NEXT:    [[TMP2:%.*]] = alloca ptr, align 8, !dbg [[DBG12]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG12]]
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG12]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS]], align 8, !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP3:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_lb(ptr [[LB_ADDR]]), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_ub(ptr [[UB_ADDR]]), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP6:%.*]] = call i32 @compute_step(ptr [[STEP_ADDR]]), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP5]], [[TMP4]], !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP8:%.*]] = sub i32 [[TMP7]], 1, !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP9:%.*]] = sdiv i32 [[TMP8]], [[TMP6]], !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP10:%.*]] = add i32 [[TMP9]], 1, !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP11:%.*]] = sext i32 [[TMP10]] to i64, !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP12:%.*]] = mul i64 1, [[TMP11]], !dbg [[DBG12]]
; CHECK-NEXT:    call void @nanos6_create_loop(ptr @task_info_var_taskloop, ptr @task_invocation_info_taskloop, ptr null, i64 32, ptr [[TMP1]], ptr [[TMP2]], i64 4, i64 [[TMP3]], i64 0, i64 [[TMP12]], i64 0, i64 0), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP13:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG12]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP13]], i64 32, !dbg [[DBG12]]
; CHECK-NEXT:    [[GEP_SUM:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP:%.*]], ptr [[TMP13]], i32 0, i32 0, !dbg [[DBG12]]
; CHECK-NEXT:    store ptr @sum, ptr [[GEP_SUM]], align 8, !dbg [[DBG12]]
; CHECK-NEXT:    [[GEP_LB_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP]], ptr [[TMP13]], i32 0, i32 2, !dbg [[DBG12]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_LB_ADDR]], ptr align 4 [[LB_ADDR]], i64 4, i1 false), !dbg [[DBG12]]
; CHECK-NEXT:    [[GEP_UB_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP]], ptr [[TMP13]], i32 0, i32 3, !dbg [[DBG12]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_UB_ADDR]], ptr align 4 [[UB_ADDR]], i64 4, i1 false), !dbg [[DBG12]]
; CHECK-NEXT:    [[GEP_STEP_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP]], ptr [[TMP13]], i32 0, i32 4, !dbg [[DBG12]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_STEP_ADDR]], ptr align 4 [[STEP_ADDR]], i64 4, i1 false), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP14:%.*]] = load ptr, ptr [[TMP2]], align 8, !dbg [[DBG12]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP14]]), !dbg [[DBG12]]
; CHECK-NEXT:    br label [[FOR_END3:%.*]], !dbg [[DBG12]]
; CHECK:       final.end:
; CHECK-NEXT:    ret void, !dbg [[DBG13:![0-9]+]]
; CHECK:       final.then:
; CHECK-NEXT:    [[TMP15:%.*]] = call i32 @compute_lb(ptr [[LB_ADDR]]), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP16:%.*]] = call i32 @compute_ub(ptr [[UB_ADDR]]), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP17:%.*]] = call i32 @compute_step(ptr [[STEP_ADDR]]), !dbg [[DBG12]]
; CHECK-NEXT:    store i32 [[TMP15]], ptr [[I]], align 4, !dbg [[DBG12]]
; CHECK-NEXT:    br label [[FOR_COND:%.*]], !dbg [[DBG12]]
; CHECK:       for.cond:
; CHECK-NEXT:    [[TMP18:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP19:%.*]] = icmp slt i32 [[TMP18]], [[TMP16]], !dbg [[DBG12]]
; CHECK-NEXT:    br i1 [[TMP19]], label [[TMP20:%.*]], label [[FOR_END:%.*]], !dbg [[DBG12]]
; CHECK:       20:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]], !dbg [[DBG12]]
; CHECK:       for.body:
; CHECK-NEXT:    [[TMP21:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG14:![0-9]+]]
; CHECK-NEXT:    [[TMP22:%.*]] = load i32, ptr @sum, align 4, !dbg [[DBG15:![0-9]+]]
; CHECK-NEXT:    [[ADD_CLONE:%.*]] = add nsw i32 [[TMP22]], [[TMP21]], !dbg [[DBG15]]
; CHECK-NEXT:    store i32 [[ADD_CLONE]], ptr @sum, align 4, !dbg [[DBG15]]
; CHECK-NEXT:    br label [[FOR_INCR:%.*]], !dbg [[DBG13]]
; CHECK:       for.end:
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG12]]
; CHECK:       for.incr:
; CHECK-NEXT:    [[TMP23:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP24:%.*]] = add i32 [[TMP23]], [[TMP17]], !dbg [[DBG12]]
; CHECK-NEXT:    store i32 [[TMP24]], ptr [[I]], align 4, !dbg [[DBG12]]
; CHECK-NEXT:    br label [[FOR_COND]], !dbg [[DBG12]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP25:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG12]]
; CHECK-NEXT:    [[TMP26:%.*]] = icmp ne i32 [[TMP25]], 0, !dbg [[DBG12]]
; CHECK-NEXT:    br i1 [[TMP26]], label [[FINAL_THEN:%.*]], label [[CODEREPL:%.*]], !dbg [[DBG12]]
; CHECK:       for.end3:
; CHECK-NEXT:    br label [[FINAL_END]], !dbg [[DBG12]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_lb
; CHECK-SAME: (ptr [[LB:%.*]]) #[[ATTR2:[0-9]+]] !dbg [[DBG16:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[LB_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    store ptr [[LB]], ptr [[LB_ADDR]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr [[LB]], align 4, !dbg [[DBG17:![0-9]+]]
; CHECK-NEXT:    ret i32 [[TMP0]], !dbg [[DBG17]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_ub
; CHECK-SAME: (ptr [[UB:%.*]]) #[[ATTR2]] !dbg [[DBG18:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[UB_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    store ptr [[UB]], ptr [[UB_ADDR]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr [[UB]], align 4, !dbg [[DBG19:![0-9]+]]
; CHECK-NEXT:    ret i32 [[TMP0]], !dbg [[DBG19]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_step
; CHECK-SAME: (ptr [[STEP:%.*]]) #[[ATTR2]] !dbg [[DBG20:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[STEP_ADDR:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    store ptr [[STEP]], ptr [[STEP_ADDR]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr [[STEP]], align 4, !dbg [[DBG21:![0-9]+]]
; CHECK-NEXT:    ret i32 [[TMP0]], !dbg [[DBG21]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_taskloop
; CHECK-SAME: (ptr [[SUM:%.*]], ptr [[I:%.*]], ptr [[LB_ADDR:%.*]], ptr [[UB_ADDR:%.*]], ptr [[STEP_ADDR:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG22:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG23:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    [[LB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T:%.*]], ptr [[LOOP_BOUNDS]], i32 0, i32 0, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP1:%.*]] = load i64, ptr [[LB_GEP]], align 8, !dbg [[DBG23]]
; CHECK-NEXT:    [[LB5:%.*]] = trunc i64 [[TMP1]] to i32, !dbg [[DBG23]]
; CHECK-NEXT:    [[UB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T]], ptr [[LOOP_BOUNDS]], i32 0, i32 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[UB_GEP]], align 8, !dbg [[DBG23]]
; CHECK-NEXT:    [[UB6:%.*]] = trunc i64 [[TMP2]] to i32, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb(ptr [[LB_ADDR]]), !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub(ptr [[UB_ADDR]]), !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_step(ptr [[STEP_ADDR]]), !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[UB6]], [[LB5]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP8:%.*]] = sdiv i32 [[TMP7]], [[TMP5]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP10:%.*]] = sext i32 [[TMP9]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[LOOP:%.*]] = alloca i32, align 4, !dbg [[DBG23]]
; CHECK-NEXT:    store i32 [[LB5]], ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    br label [[FOR_COND1:%.*]], !dbg [[DBG23]]
; CHECK:       for.cond1:
; CHECK-NEXT:    [[TMP11:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP12:%.*]] = icmp slt i32 [[TMP11]], [[UB6]], !dbg [[DBG23]]
; CHECK-NEXT:    br i1 [[TMP12]], label [[TMP13:%.*]], label [[DOTEXITSTUB:%.*]], !dbg [[DBG23]]
; CHECK:       13:
; CHECK-NEXT:    [[TMP14:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP15:%.*]] = sext i32 [[TMP14]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP16:%.*]] = udiv i64 [[TMP15]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP17:%.*]] = sext i32 [[TMP5]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP18:%.*]] = mul i64 [[TMP16]], [[TMP17]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP19:%.*]] = sext i32 [[TMP3]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP20:%.*]] = add i64 [[TMP18]], [[TMP19]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP21:%.*]] = mul i64 [[TMP16]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP22:%.*]] = sext i32 [[TMP14]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP23:%.*]] = sub i64 [[TMP22]], [[TMP21]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP24:%.*]] = trunc i64 [[TMP20]] to i32, !dbg [[DBG23]]
; CHECK-NEXT:    store i32 [[TMP24]], ptr [[I]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    br label [[FOR_BODY2:%.*]], !dbg [[DBG23]]
; CHECK:       for.body2:
; CHECK-NEXT:    [[TMP25:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG24:![0-9]+]]
; CHECK-NEXT:    [[TMP26:%.*]] = load i32, ptr [[SUM]], align 4, !dbg [[DBG25:![0-9]+]]
; CHECK-NEXT:    [[ADD:%.*]] = add nsw i32 [[TMP26]], [[TMP25]], !dbg [[DBG25]]
; CHECK-NEXT:    store i32 [[ADD]], ptr [[SUM]], align 4, !dbg [[DBG25]]
; CHECK-NEXT:    br label [[FOR_INCR4:%.*]], !dbg [[DBG26:![0-9]+]]
; CHECK:       for.incr4:
; CHECK-NEXT:    [[TMP27:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP28:%.*]] = add i32 [[TMP27]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    store i32 [[TMP28]], ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    br label [[FOR_COND1]], !dbg [[DBG23]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_taskloop
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_SUM:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[LOAD_GEP_SUM:%.*]] = load ptr, ptr [[GEP_SUM]], align 8
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP]], ptr [[TASK_ARGS]], i32 0, i32 1
; CHECK-NEXT:    [[GEP_LB_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP]], ptr [[TASK_ARGS]], i32 0, i32 2
; CHECK-NEXT:    [[GEP_UB_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP]], ptr [[TASK_ARGS]], i32 0, i32 3
; CHECK-NEXT:    [[GEP_STEP_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_TASKLOOP]], ptr [[TASK_ARGS]], i32 0, i32 4
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_taskloop(ptr [[LOAD_GEP_SUM]], ptr [[GEP_I]], ptr [[GEP_LB_ADDR]], ptr [[GEP_UB_ADDR]], ptr [[GEP_STEP_ADDR]], ptr [[LOOP_BOUNDS]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_constructor_register_task_info() {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_taskloop)
; CHECK-NEXT:    ret void
;