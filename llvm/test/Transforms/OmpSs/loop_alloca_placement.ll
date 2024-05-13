; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s

; ModuleID = 'loop_alloca_placement.ll'
source_filename = "loop_alloca_placement.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Loop transformation should place constant allocas
; outside the loop. Otherwise the stack will grow
; every iteration and potentially raise a stack
; smashing in the execution.
; VLAs do not need this because they use
; llvm.stacksave/stackrestore

; int main() {
;     #pragma oss taskloop
;     for (int i = 0; i < 10; ++i) {
;         int array[10];
;         #pragma oss task
;         {
;             if (i > 78) {
;                 int array1[10];
;             }
;             array[0]++;
;         }
;     }
; }

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !5 {
entry:
  %retval = alloca i32, align 4
  %i = alloca i32, align 4
  store i32 0, ptr %retval, align 4
  store i32 0, ptr %i, align 4, !dbg !9
  %0 = call token @llvm.directive.region.entry() [ "DIR.OSS"([9 x i8] c"TASKLOOP\00"), "QUAL.OSS.PRIVATE"(ptr %i, i32 undef), "QUAL.OSS.LOOP.IND.VAR"(ptr %i), "QUAL.OSS.LOOP.LOWER.BOUND"(ptr @compute_lb), "QUAL.OSS.LOOP.UPPER.BOUND"(ptr @compute_ub), "QUAL.OSS.LOOP.STEP"(ptr @compute_step), "QUAL.OSS.LOOP.TYPE"(i64 0, i64 1, i64 1, i64 1, i64 1) ], !dbg !10
  %array = alloca [10 x i32], align 16
  %1 = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr %i, i32 undef), "QUAL.OSS.FIRSTPRIVATE"(ptr %array, [10 x i32] undef) ], !dbg !11
  %array1 = alloca [10 x i32], align 16
  %2 = load i32, ptr %i, align 4, !dbg !12
  %cmp = icmp sgt i32 %2, 78, !dbg !13
  br i1 %cmp, label %if.then, label %if.end, !dbg !12

if.then:                                          ; preds = %entry
  br label %if.end, !dbg !14

if.end:                                           ; preds = %if.then, %entry
  %arrayidx = getelementptr inbounds [10 x i32], ptr %array, i64 0, i64 0, !dbg !15
  %3 = load i32, ptr %arrayidx, align 16, !dbg !16
  %inc = add nsw i32 %3, 1, !dbg !16
  store i32 %inc, ptr %arrayidx, align 16, !dbg !16
  call void @llvm.directive.region.exit(token %1), !dbg !17
  call void @llvm.directive.region.exit(token %0), !dbg !18
  %4 = load i32, ptr %retval, align 4, !dbg !19
  ret i32 %4, !dbg !19
}

; Function Attrs: nounwind
declare token @llvm.directive.region.entry() #1

; Function Attrs: nounwind
declare void @llvm.directive.region.exit(token) #1

define internal i32 @compute_lb() #2 !dbg !20 {
entry:
  ret i32 0, !dbg !21
}

define internal i32 @compute_ub() #2 !dbg !23 {
entry:
  ret i32 10, !dbg !24
}

define internal i32 @compute_step() #2 !dbg !26 {
entry:
  ret i32 1, !dbg !27
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
!5 = distinct !DISubprogram(name: "main", scope: !6, file: !6, line: 1, type: !7, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!6 = !DIFile(filename: "loop_alloca_placement.ll", directory: "")
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 3, column: 14, scope: !5)
!10 = !DILocation(line: 3, column: 10, scope: !5)
!11 = !DILocation(line: 5, column: 17, scope: !5)
!12 = !DILocation(line: 7, column: 17, scope: !5)
!13 = !DILocation(line: 7, column: 19, scope: !5)
!14 = !DILocation(line: 9, column: 13, scope: !5)
!15 = !DILocation(line: 10, column: 13, scope: !5)
!16 = !DILocation(line: 10, column: 21, scope: !5)
!17 = !DILocation(line: 11, column: 9, scope: !5)
!18 = !DILocation(line: 12, column: 5, scope: !5)
!19 = !DILocation(line: 13, column: 1, scope: !5)
!20 = distinct !DISubprogram(linkageName: "compute_lb", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!21 = !DILocation(line: 3, column: 18, scope: !22)
!22 = !DILexicalBlockFile(scope: !20, file: !6, discriminator: 0)
!23 = distinct !DISubprogram(linkageName: "compute_ub", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!24 = !DILocation(line: 3, column: 25, scope: !25)
!25 = !DILexicalBlockFile(scope: !23, file: !6, discriminator: 0)
!26 = distinct !DISubprogram(linkageName: "compute_step", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!27 = !DILocation(line: 3, column: 29, scope: !28)
!28 = !DILexicalBlockFile(scope: !26, file: !6, discriminator: 0)
; CHECK-LABEL: define {{[^@]+}}@main
; CHECK-SAME: () #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RETVAL:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[I:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i32 0, ptr [[RETVAL]], align 4
; CHECK-NEXT:    store i32 0, ptr [[I]], align 4, !dbg [[DBG9:![0-9]+]]
; CHECK-NEXT:    [[TMP0:%.*]] = alloca ptr, align 8, !dbg [[DBG10:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[NUM_DEPS15:%.*]] = alloca i64, align 8, !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FINAL_COND8:%.*]], !dbg [[DBG10]]
; CHECK:       codeRepl14:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS15]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[NUM_DEPS15]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_step(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[TMP4]], [[TMP3]], !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP8:%.*]] = sdiv i32 [[TMP7]], [[TMP5]], !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP9:%.*]] = add i32 [[TMP8]], 1, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP10:%.*]] = sext i32 [[TMP9]] to i64, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP11:%.*]] = mul i64 1, [[TMP10]], !dbg [[DBG10]]
; CHECK-NEXT:    call void @nanos6_create_loop(ptr @task_info_var_main.10, ptr @task_invocation_info_main.6, ptr null, i64 16, ptr [[TMP0]], ptr [[TMP1]], i64 4, i64 [[TMP2]], i64 0, i64 [[TMP11]], i64 0, i64 0), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP12:%.*]] = load ptr, ptr [[TMP0]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[ARGS_END16:%.*]] = getelementptr i8, ptr [[TMP12]], i64 16, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP13:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP13]]), !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FOR_END12:%.*]], !dbg [[DBG10]]
; CHECK:       final.end7:
; CHECK-NEXT:    [[TMP14:%.*]] = load i32, ptr [[RETVAL]], align 4, !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    ret i32 [[TMP14]], !dbg [[DBG11]]
; CHECK:       final.then9:
; CHECK-NEXT:    [[ARRAY1_CLONE1:%.*]] = alloca [10 x i32], align 16, !dbg [[DBG10]]
; CHECK-NEXT:    [[ARRAY_CLONE:%.*]] = alloca [10 x i32], align 16, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP15:%.*]] = call i32 @compute_lb(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP16:%.*]] = call i32 @compute_ub(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP17:%.*]] = call i32 @compute_step(), !dbg [[DBG10]]
; CHECK-NEXT:    store i32 [[TMP15]], ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FOR_COND:%.*]], !dbg [[DBG10]]
; CHECK:       for.cond:
; CHECK-NEXT:    [[TMP18:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP19:%.*]] = icmp slt i32 [[TMP18]], [[TMP16]], !dbg [[DBG10]]
; CHECK-NEXT:    br i1 [[TMP19]], label [[TMP20:%.*]], label [[FOR_END:%.*]], !dbg [[DBG10]]
; CHECK:       20:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]], !dbg [[DBG10]]
; CHECK:       for.body:
; CHECK-NEXT:    br label [[TMP21:%.*]], !dbg [[DBG12:![0-9]+]]
; CHECK:       21:
; CHECK-NEXT:    [[TMP22:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG13:![0-9]+]]
; CHECK-NEXT:    [[CMP_CLONE2:%.*]] = icmp sgt i32 [[TMP22]], 78, !dbg [[DBG14:![0-9]+]]
; CHECK-NEXT:    br i1 [[CMP_CLONE2]], label [[IF_THEN_CLONE3:%.*]], label [[IF_END_CLONE4:%.*]], !dbg [[DBG13]]
; CHECK:       if.then.clone3:
; CHECK-NEXT:    br label [[IF_END_CLONE4]], !dbg [[DBG15:![0-9]+]]
; CHECK:       if.end.clone4:
; CHECK-NEXT:    [[ARRAYIDX_CLONE5:%.*]] = getelementptr inbounds [10 x i32], ptr [[ARRAY_CLONE]], i64 0, i64 0, !dbg [[DBG16:![0-9]+]]
; CHECK-NEXT:    [[TMP23:%.*]] = load i32, ptr [[ARRAYIDX_CLONE5]], align 16, !dbg [[DBG17:![0-9]+]]
; CHECK-NEXT:    [[INC_CLONE6:%.*]] = add nsw i32 [[TMP23]], 1, !dbg [[DBG17]]
; CHECK-NEXT:    store i32 [[INC_CLONE6]], ptr [[ARRAYIDX_CLONE5]], align 16, !dbg [[DBG17]]
; CHECK-NEXT:    br label [[TMP24:%.*]], !dbg [[DBG18:![0-9]+]]
; CHECK:       24:
; CHECK-NEXT:    br label [[FOR_INCR:%.*]], !dbg [[DBG11]]
; CHECK:       for.end:
; CHECK-NEXT:    br label [[FINAL_END7:%.*]], !dbg [[DBG10]]
; CHECK:       for.incr:
; CHECK-NEXT:    [[TMP25:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP26:%.*]] = add i32 [[TMP25]], [[TMP17]], !dbg [[DBG10]]
; CHECK-NEXT:    store i32 [[TMP26]], ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FOR_COND]], !dbg [[DBG10]]
; CHECK:       final.cond8:
; CHECK-NEXT:    [[TMP27:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP28:%.*]] = icmp ne i32 [[TMP27]], 0, !dbg [[DBG10]]
; CHECK-NEXT:    br i1 [[TMP28]], label [[FINAL_THEN9:%.*]], label [[CODEREPL14:%.*]], !dbg [[DBG10]]
; CHECK:       for.end12:
; CHECK-NEXT:    br label [[FINAL_END7]], !dbg [[DBG10]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_lb
; CHECK-SAME: () #[[ATTR2:[0-9]+]] !dbg [[DBG19:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 0, !dbg [[DBG20:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_ub
; CHECK-SAME: () #[[ATTR2]] !dbg [[DBG22:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 10, !dbg [[DBG23:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@compute_step
; CHECK-SAME: () #[[ATTR2]] !dbg [[DBG25:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i32 1, !dbg [[DBG26:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_main
; CHECK-SAME: (ptr [[I:%.*]], ptr [[ARRAY:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG28:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG29:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    [[ARRAY1:%.*]] = alloca [10 x i32], align 16
; CHECK-NEXT:    [[TMP1:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG30:![0-9]+]]
; CHECK-NEXT:    [[CMP:%.*]] = icmp sgt i32 [[TMP1]], 78, !dbg [[DBG31:![0-9]+]]
; CHECK-NEXT:    br i1 [[CMP]], label [[IF_THEN:%.*]], label [[IF_END:%.*]], !dbg [[DBG30]]
; CHECK:       if.then:
; CHECK-NEXT:    br label [[IF_END]], !dbg [[DBG32:![0-9]+]]
; CHECK:       if.end:
; CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds [10 x i32], ptr [[ARRAY]], i64 0, i64 0, !dbg [[DBG33:![0-9]+]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i32, ptr [[ARRAYIDX]], align 16, !dbg [[DBG34:![0-9]+]]
; CHECK-NEXT:    [[INC:%.*]] = add nsw i32 [[TMP2]], 1, !dbg [[DBG34]]
; CHECK-NEXT:    store i32 [[INC]], ptr [[ARRAYIDX]], align 16, !dbg [[DBG34]]
; CHECK-NEXT:    br label [[DOTEXITSTUB:%.*]], !dbg [[DBG35:![0-9]+]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[GEP_ARRAY:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 1
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main(ptr [[GEP_I]], ptr [[GEP_ARRAY]], ptr [[DEVICE_ENV]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_constructor_register_task_info() {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_main)
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_main.10)
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_main.4
; CHECK-SAME: (ptr [[I:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG36:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    [[TMP0:%.*]] = alloca ptr, align 8, !dbg [[DBG37:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG37]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG37]]
; CHECK-NEXT:    br label [[TMP2:%.*]], !dbg [[DBG38:![0-9]+]]
; CHECK:       2:
; CHECK-NEXT:    [[LB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T:%.*]], ptr [[LOOP_BOUNDS]], i32 0, i32 0, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP3:%.*]] = load i64, ptr [[LB_GEP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    [[LB:%.*]] = trunc i64 [[TMP3]] to i32, !dbg [[DBG38]]
; CHECK-NEXT:    [[UB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T]], ptr [[LOOP_BOUNDS]], i32 0, i32 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP4:%.*]] = load i64, ptr [[UB_GEP]], align 8, !dbg [[DBG38]]
; CHECK-NEXT:    [[UB:%.*]] = trunc i64 [[TMP4]] to i32, !dbg [[DBG38]]
; CHECK-NEXT:    [[ARRAY:%.*]] = alloca [10 x i32], align 16, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @compute_lb(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP6:%.*]] = call i32 @compute_ub(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP7:%.*]] = call i32 @compute_step(), !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP8:%.*]] = sub i32 [[UB]], [[LB]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP9:%.*]] = sub i32 [[TMP8]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP10:%.*]] = sdiv i32 [[TMP9]], [[TMP7]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP11:%.*]] = add i32 [[TMP10]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP12:%.*]] = sext i32 [[TMP11]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[LOOP:%.*]] = alloca i32, align 4, !dbg [[DBG38]]
; CHECK-NEXT:    store i32 [[LB]], ptr [[LOOP]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    br label [[FOR_COND10:%.*]], !dbg [[DBG38]]
; CHECK:       for.cond10:
; CHECK-NEXT:    [[TMP13:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP14:%.*]] = icmp slt i32 [[TMP13]], [[UB]], !dbg [[DBG38]]
; CHECK-NEXT:    br i1 [[TMP14]], label [[TMP15:%.*]], label [[DOTEXITSTUB:%.*]], !dbg [[DBG38]]
; CHECK:       15:
; CHECK-NEXT:    [[TMP16:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP17:%.*]] = sext i32 [[TMP16]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP18:%.*]] = udiv i64 [[TMP17]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP19:%.*]] = sext i32 [[TMP7]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP20:%.*]] = mul i64 [[TMP18]], [[TMP19]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP21:%.*]] = sext i32 [[TMP5]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP22:%.*]] = add i64 [[TMP20]], [[TMP21]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP23:%.*]] = mul i64 [[TMP18]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP24:%.*]] = sext i32 [[TMP16]] to i64, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP25:%.*]] = sub i64 [[TMP24]], [[TMP23]], !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP26:%.*]] = trunc i64 [[TMP22]] to i32, !dbg [[DBG38]]
; CHECK-NEXT:    store i32 [[TMP26]], ptr [[I]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    br label [[FOR_BODY11:%.*]], !dbg [[DBG38]]
; CHECK:       for.body11:
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG37]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP27:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG37]]
; CHECK-NEXT:    [[TMP28:%.*]] = icmp ne i32 [[TMP27]], 0, !dbg [[DBG37]]
; CHECK-NEXT:    br i1 [[TMP28]], label [[FINAL_THEN:%.*]], label [[CODEREPL:%.*]], !dbg [[DBG37]]
; CHECK:       final.then:
; CHECK-NEXT:    [[ARRAY1_CLONE:%.*]] = alloca [10 x i32], align 16, !dbg [[DBG37]]
; CHECK-NEXT:    [[TMP29:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG39:![0-9]+]]
; CHECK-NEXT:    [[CMP_CLONE:%.*]] = icmp sgt i32 [[TMP29]], 78, !dbg [[DBG40:![0-9]+]]
; CHECK-NEXT:    br i1 [[CMP_CLONE]], label [[IF_THEN_CLONE:%.*]], label [[IF_END_CLONE:%.*]], !dbg [[DBG39]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS]], align 8, !dbg [[DBG37]]
; CHECK-NEXT:    [[TMP30:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG37]]
; CHECK-NEXT:    call void @nanos6_create_task(ptr @task_info_var_main, ptr @task_invocation_info_main, ptr null, i64 48, ptr [[TMP0]], ptr [[TMP1]], i64 0, i64 [[TMP30]]), !dbg [[DBG37]]
; CHECK-NEXT:    [[TMP31:%.*]] = load ptr, ptr [[TMP0]], align 8, !dbg [[DBG37]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP31]], i64 48, !dbg [[DBG37]]
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TMP31]], i32 0, i32 0, !dbg [[DBG37]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_I]], ptr align 4 [[I]], i64 4, i1 false), !dbg [[DBG37]]
; CHECK-NEXT:    [[GEP_ARRAY:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP31]], i32 0, i32 1, !dbg [[DBG37]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_ARRAY]], ptr align 4 [[ARRAY]], i64 40, i1 false), !dbg [[DBG37]]
; CHECK-NEXT:    [[TMP32:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG37]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP32]]), !dbg [[DBG37]]
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG37]]
; CHECK:       if.then.clone:
; CHECK-NEXT:    br label [[IF_END_CLONE]], !dbg [[DBG41:![0-9]+]]
; CHECK:       if.end.clone:
; CHECK-NEXT:    [[ARRAYIDX_CLONE:%.*]] = getelementptr inbounds [10 x i32], ptr [[ARRAY]], i64 0, i64 0, !dbg [[DBG42:![0-9]+]]
; CHECK-NEXT:    [[TMP33:%.*]] = load i32, ptr [[ARRAYIDX_CLONE]], align 16, !dbg [[DBG43:![0-9]+]]
; CHECK-NEXT:    [[INC_CLONE:%.*]] = add nsw i32 [[TMP33]], 1, !dbg [[DBG43]]
; CHECK-NEXT:    store i32 [[INC_CLONE]], ptr [[ARRAYIDX_CLONE]], align 16, !dbg [[DBG43]]
; CHECK-NEXT:    br label [[FINAL_END]], !dbg [[DBG44:![0-9]+]]
; CHECK:       final.end:
; CHECK-NEXT:    br label [[FOR_INCR13:%.*]], !dbg [[DBG45:![0-9]+]]
; CHECK:       for.incr13:
; CHECK-NEXT:    [[TMP34:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    [[TMP35:%.*]] = add i32 [[TMP34]], 1, !dbg [[DBG38]]
; CHECK-NEXT:    store i32 [[TMP35]], ptr [[LOOP]], align 4, !dbg [[DBG38]]
; CHECK-NEXT:    br label [[FOR_COND10]], !dbg [[DBG38]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main.5
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main.4(ptr [[GEP_I]], ptr [[LOOP_BOUNDS]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
