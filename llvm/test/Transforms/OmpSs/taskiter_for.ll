; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
; ModuleID = 'taskiter_for.ll'
source_filename = "taskiter_for.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; NOTE: this tests is made by hand using
; short step();
; int main() {
;     #pragma oss task for
;     for (int i = 0; i < 10; i+=step()) {
;     }
;     #pragma oss taskwait
; }

; Function Attrs: noinline nounwind optnone uwtabl; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !5 {
entry:
  %i = alloca i32, align 4
  store i32 0, ptr %i, align 4, !dbg !9
  %0 = call token @llvm.directive.region.entry() [ "DIR.OSS"([9 x i8] c"TASK.FOR\00"), "QUAL.OSS.PRIVATE"(ptr %i, i32 undef), "QUAL.OSS.LOOP.IND.VAR"(ptr %i), "QUAL.OSS.LOOP.LOWER.BOUND"(ptr @compute_lb), "QUAL.OSS.LOOP.UPPER.BOUND"(ptr @compute_ub), "QUAL.OSS.LOOP.STEP"(ptr @compute_step), "QUAL.OSS.LOOP.TYPE"(i64 0, i64 1, i64 1, i64 1, i64 1) ], !dbg !10
  call void @llvm.directive.region.exit(token %0), !dbg !11
  %1 = call i1 @llvm.directive.marker() [ "DIR.OSS"([9 x i8] c"TASKWAIT\00") ], !dbg !12
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

define internal i16 @compute_step() #2 !dbg !20 {
entry:
  %call = call signext i16 (...) @step(), !dbg !21
  ret i16 %call, !dbg !21
}

declare signext i16 @step(...) #3

; Function Attrs: nounwind
declare i1 @llvm.directive.marker() #1

attributes #0 = { noinline nounwind optnone "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-features"="+cx8,+mmx,+sse,+sse2,+x87" }
attributes #1 = { nounwind }
attributes #2 = { "min-legal-vector-width"="0" }
attributes #3 = { "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-features"="+cx8,+mmx,+sse,+sse2,+x87" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.ident = !{!4}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "", isOptimized: false, runtimeVersion: 0, emissionKind: NoDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "<stdin>", directory: "")
!2 = !{i32 2, !"Debug Info Version", i32 3}
!3 = !{i32 1, !"wchar_size", i32 4}
!4 = !{!""}
!5 = distinct !DISubprogram(name: "main", scope: !6, file: !6, line: 2, type: !7, scopeLine: 2, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!6 = !DIFile(filename: "taskiter_for.ll", directory: "")
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 4, column: 14, scope: !5)
!10 = !DILocation(line: 4, column: 10, scope: !5)
!11 = !DILocation(line: 5, column: 5, scope: !5)
!12 = !DILocation(line: 6, column: 13, scope: !5)
!13 = !DILocation(line: 7, column: 1, scope: !5)
!14 = distinct !DISubprogram(linkageName: "compute_lb", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!15 = !DILocation(line: 4, column: 18, scope: !16)
!16 = !DILexicalBlockFile(scope: !14, file: !6, discriminator: 0)
!17 = distinct !DISubprogram(linkageName: "compute_ub", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!18 = !DILocation(line: 4, column: 25, scope: !19)
!19 = !DILexicalBlockFile(scope: !17, file: !6, discriminator: 0)
!20 = distinct !DISubprogram(linkageName: "compute_step", scope: !1, file: !1, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !8)
!21 = !DILocation(line: 4, column: 32, scope: !22)
!22 = !DILexicalBlockFile(scope: !20, file: !6, discriminator: 0)
; CHECK-LABEL: define {{[^@]+}}@main
; CHECK-SAME: () #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[I:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i32 0, ptr [[I]], align 4, !dbg [[DBG9:![0-9]+]]
; CHECK-NEXT:    [[TMP0:%.*]] = alloca ptr, align 8, !dbg [[DBG10:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG10]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i16 @compute_step(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[TMP4]], [[TMP3]], !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP8:%.*]] = sext i16 [[TMP5]] to i32, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP9:%.*]] = sdiv i32 [[TMP7]], [[TMP8]], !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP10:%.*]] = add i32 [[TMP9]], 1, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP11:%.*]] = sext i32 [[TMP10]] to i64, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP12:%.*]] = mul i64 1, [[TMP11]], !dbg [[DBG10]]
; CHECK-NEXT:    call void @nanos6_create_loop(ptr @task_info_var_main, ptr @task_invocation_info_main, ptr null, i64 16, ptr [[TMP0]], ptr [[TMP1]], i64 8, i64 [[TMP2]], i64 0, i64 [[TMP12]], i64 0, i64 0), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP13:%.*]] = load ptr, ptr [[TMP0]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP13]], i64 16, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP14:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG10]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP14]]), !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FOR_END3:%.*]], !dbg [[DBG10]]
; CHECK:       final.end:
; CHECK-NEXT:    call void @nanos6_taskwait(ptr @[[GLOB1:[0-9]+]]), !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    ret i32 0, !dbg [[DBG12:![0-9]+]]
; CHECK:       final.then:
; CHECK-NEXT:    [[TMP15:%.*]] = call i32 @compute_lb(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP16:%.*]] = call i32 @compute_ub(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP17:%.*]] = call i16 @compute_step(), !dbg [[DBG10]]
; CHECK-NEXT:    store i32 [[TMP15]], ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FOR_COND:%.*]], !dbg [[DBG10]]
; CHECK:       for.cond:
; CHECK-NEXT:    [[TMP18:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP19:%.*]] = icmp slt i32 [[TMP18]], [[TMP16]], !dbg [[DBG10]]
; CHECK-NEXT:    br i1 [[TMP19]], label [[TMP20:%.*]], label [[FOR_END:%.*]], !dbg [[DBG10]]
; CHECK:       20:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]], !dbg [[DBG10]]
; CHECK:       for.body:
; CHECK-NEXT:    br label [[FOR_INCR:%.*]], !dbg [[DBG11]]
; CHECK:       for.end:
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG10]]
; CHECK:       for.incr:
; CHECK-NEXT:    [[TMP21:%.*]] = load i32, ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP22:%.*]] = sext i16 [[TMP17]] to i32, !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP23:%.*]] = add i32 [[TMP21]], [[TMP22]], !dbg [[DBG10]]
; CHECK-NEXT:    store i32 [[TMP23]], ptr [[I]], align 4, !dbg [[DBG10]]
; CHECK-NEXT:    br label [[FOR_COND]], !dbg [[DBG10]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP24:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG10]]
; CHECK-NEXT:    [[TMP25:%.*]] = icmp ne i32 [[TMP24]], 0, !dbg [[DBG10]]
; CHECK-NEXT:    br i1 [[TMP25]], label [[FINAL_THEN:%.*]], label [[CODEREPL:%.*]], !dbg [[DBG10]]
; CHECK:       for.end3:
; CHECK-NEXT:    br label [[FINAL_END]], !dbg [[DBG10]]
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
; CHECK-NEXT:    [[CALL:%.*]] = call signext i16 (...) @step(), !dbg [[DBG20:![0-9]+]]
; CHECK-NEXT:    ret i16 [[CALL]], !dbg [[DBG20]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_main
; CHECK-SAME: (ptr [[I:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG22:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG23:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    [[LB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T:%.*]], ptr [[LOOP_BOUNDS]], i32 0, i32 0, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP1:%.*]] = load i64, ptr [[LB_GEP]], align 8, !dbg [[DBG23]]
; CHECK-NEXT:    [[LB:%.*]] = trunc i64 [[TMP1]] to i32, !dbg [[DBG23]]
; CHECK-NEXT:    [[UB_GEP:%.*]] = getelementptr [[NANOS6_LOOP_BOUNDS_T]], ptr [[LOOP_BOUNDS]], i32 0, i32 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[UB_GEP]], align 8, !dbg [[DBG23]]
; CHECK-NEXT:    [[UB:%.*]] = trunc i64 [[TMP2]] to i32, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP3:%.*]] = call i32 @compute_lb(), !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP4:%.*]] = call i32 @compute_ub(), !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP5:%.*]] = call i16 @compute_step(), !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP6:%.*]] = sub i32 [[UB]], [[LB]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP7:%.*]] = sub i32 [[TMP6]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP8:%.*]] = sext i16 [[TMP5]] to i32, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP9:%.*]] = sdiv i32 [[TMP7]], [[TMP8]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP10:%.*]] = add i32 [[TMP9]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP11:%.*]] = sext i32 [[TMP10]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[LOOP:%.*]] = alloca i32, align 4, !dbg [[DBG23]]
; CHECK-NEXT:    store i32 [[LB]], ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    br label [[FOR_COND1:%.*]], !dbg [[DBG23]]
; CHECK:       for.cond1:
; CHECK-NEXT:    [[TMP12:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP13:%.*]] = icmp slt i32 [[TMP12]], [[UB]], !dbg [[DBG23]]
; CHECK-NEXT:    br i1 [[TMP13]], label [[TMP14:%.*]], label [[DOTEXITSTUB:%.*]], !dbg [[DBG23]]
; CHECK:       14:
; CHECK-NEXT:    [[TMP15:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP16:%.*]] = sext i32 [[TMP15]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP17:%.*]] = udiv i64 [[TMP16]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP18:%.*]] = sext i16 [[TMP5]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP19:%.*]] = mul i64 [[TMP17]], [[TMP18]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP20:%.*]] = sext i32 [[TMP3]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP21:%.*]] = add i64 [[TMP19]], [[TMP20]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP22:%.*]] = mul i64 [[TMP17]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP23:%.*]] = sext i32 [[TMP15]] to i64, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP24:%.*]] = sub i64 [[TMP23]], [[TMP22]], !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP25:%.*]] = trunc i64 [[TMP21]] to i32, !dbg [[DBG23]]
; CHECK-NEXT:    store i32 [[TMP25]], ptr [[I]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    br label [[FOR_BODY2:%.*]], !dbg [[DBG23]]
; CHECK:       for.body2:
; CHECK-NEXT:    br label [[FOR_INCR4:%.*]], !dbg [[DBG24:![0-9]+]]
; CHECK:       for.incr4:
; CHECK-NEXT:    [[TMP26:%.*]] = load i32, ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    [[TMP27:%.*]] = add i32 [[TMP26]], 1, !dbg [[DBG23]]
; CHECK-NEXT:    store i32 [[TMP27]], ptr [[LOOP]], align 4, !dbg [[DBG23]]
; CHECK-NEXT:    br label [[FOR_COND1]], !dbg [[DBG23]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[LOOP_BOUNDS:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_I:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main(ptr [[GEP_I]], ptr [[LOOP_BOUNDS]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_constructor_register_task_info() {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_main)
; CHECK-NEXT:    ret void
;