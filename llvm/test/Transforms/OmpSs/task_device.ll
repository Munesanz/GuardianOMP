; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
; ModuleID = 'task_devices.ll'
source_filename = "task_devices.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Do check for device id in impl. info, sizeof offset arrays and ndrange capture

; Function Attrs: noinline nounwind optnone
define dso_local void @foo(i8 noundef signext %a, i16 noundef signext %s, i32 noundef %i) #0 !dbg !5 {
entry:
  %a.addr = alloca i8, align 1
  %s.addr = alloca i16, align 2
  %i.addr = alloca i32, align 4
  store i8 %a, ptr %a.addr, align 1
  store i16 %s, ptr %s.addr, align 2
  store i32 %i, ptr %i.addr, align 4
  ret void, !dbg !9
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !10 {
entry:
  %call_arg = alloca i8, align 1
  %call_arg1 = alloca i16, align 2
  %call_arg2 = alloca i32, align 4
  store i8 1, ptr %call_arg, align 1, !dbg !11
  store i16 1, ptr %call_arg1, align 2, !dbg !12
  store i32 1, ptr %call_arg2, align 4, !dbg !13
  %0 = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.FIRSTPRIVATE"(ptr %call_arg, i8 undef), "QUAL.OSS.FIRSTPRIVATE"(ptr %call_arg1, i16 undef), "QUAL.OSS.FIRSTPRIVATE"(ptr %call_arg2, i32 undef), "QUAL.OSS.DEVICE"(i32 1), "QUAL.OSS.DEVICE.DEVFUNC"([4 x i8] c"foo\00"), "QUAL.OSS.DEVICE.NDRANGE"(i32 1, i32 1, i32 2), "QUAL.OSS.DECL.SOURCE"([8 x i8] c"foo:1:9\00") ], !dbg !14
  call void @llvm.directive.region.exit(token %0), !dbg !14
  ret i32 0, !dbg !15
}

; Function Attrs: nounwind
declare token @llvm.directive.region.entry() #1

; Function Attrs: nounwind
declare void @llvm.directive.region.exit(token) #1

attributes #0 = { noinline nounwind optnone "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-features"="+cx8,+mmx,+sse,+sse2,+x87" }
attributes #1 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.ident = !{!4}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "", isOptimized: false, runtimeVersion: 0, emissionKind: NoDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "<stdin>", directory: "")
!2 = !{i32 2, !"Debug Info Version", i32 3}
!3 = !{i32 1, !"wchar_size", i32 4}
!4 = !{!""}
!5 = distinct !DISubprogram(name: "foo", scope: !6, file: !6, line: 2, type: !7, scopeLine: 2, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!6 = !DIFile(filename: "task_device.ll", directory: "")
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 2, column: 35, scope: !5)
!10 = distinct !DISubprogram(name: "main", scope: !6, file: !6, line: 3, type: !7, scopeLine: 3, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!11 = !DILocation(line: 4, column: 9, scope: !10)
!12 = !DILocation(line: 4, column: 12, scope: !10)
!13 = !DILocation(line: 4, column: 15, scope: !10)
!14 = !DILocation(line: 4, column: 5, scope: !10)
!15 = !DILocation(line: 5, column: 1, scope: !10)
; CHECK-LABEL: define {{[^@]+}}@foo
; CHECK-SAME: (i8 noundef signext [[A:%.*]], i16 noundef signext [[S:%.*]], i32 noundef [[I:%.*]]) #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_ADDR:%.*]] = alloca i8, align 1
; CHECK-NEXT:    [[S_ADDR:%.*]] = alloca i16, align 2
; CHECK-NEXT:    [[I_ADDR:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i8 [[A]], ptr [[A_ADDR]], align 1
; CHECK-NEXT:    store i16 [[S]], ptr [[S_ADDR]], align 2
; CHECK-NEXT:    store i32 [[I]], ptr [[I_ADDR]], align 4
; CHECK-NEXT:    ret void, !dbg [[DBG9:![0-9]+]]
;
;
; CHECK-LABEL: define {{[^@]+}}@main
; CHECK-SAME: () #[[ATTR0]] !dbg [[DBG10:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CALL_ARG:%.*]] = alloca i8, align 1
; CHECK-NEXT:    [[CALL_ARG1:%.*]] = alloca i16, align 2
; CHECK-NEXT:    [[CALL_ARG2:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i8 1, ptr [[CALL_ARG]], align 1, !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    store i16 1, ptr [[CALL_ARG1]], align 2, !dbg [[DBG12:![0-9]+]]
; CHECK-NEXT:    store i32 1, ptr [[CALL_ARG2]], align 4, !dbg [[DBG13:![0-9]+]]
; CHECK-NEXT:    [[TMP0:%.*]] = alloca ptr, align 8, !dbg [[DBG14:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP2:%.*]] = alloca ptr, align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP3:%.*]] = alloca ptr, align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[NUM_DEPS5:%.*]] = alloca i64, align 8, !dbg [[DBG14]]
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG14]]
; CHECK:       codeRepl4:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS5]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP4:%.*]] = load i64, ptr [[NUM_DEPS5]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    call void @nanos6_create_task(ptr @task_info_var_main.10, ptr @task_invocation_info_main.6, ptr null, i64 64, ptr [[TMP2]], ptr [[TMP3]], i64 0, i64 [[TMP4]]), !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP5:%.*]] = load ptr, ptr [[TMP2]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[ARGS_END6:%.*]] = getelementptr i8, ptr [[TMP5]], i64 64, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE07:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0:%.*]], ptr [[TMP5]], i32 0, i32 0, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 1, ptr [[GEP_DEV_NDRANGE07]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE18:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 1, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE18]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE29:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 2, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE29]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE010:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 3, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 2, ptr [[GEP_DEV_NDRANGE010]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE111:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 4, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE111]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE212:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 5, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE212]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_SHM13:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 6, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 0, ptr [[GEP_DEV_SHM13]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_CALL_ARG14:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 7, !dbg [[DBG14]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 1 [[GEP_CALL_ARG14]], ptr align 1 [[CALL_ARG]], i64 1, i1 false), !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_CALL_ARG115:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 8, !dbg [[DBG14]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 2 [[GEP_CALL_ARG115]], ptr align 2 [[CALL_ARG1]], i64 2, i1 false), !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_CALL_ARG216:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TMP5]], i32 0, i32 9, !dbg [[DBG14]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_CALL_ARG216]], ptr align 4 [[CALL_ARG2]], i64 4, i1 false), !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP6:%.*]] = load ptr, ptr [[TMP3]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP6]]), !dbg [[DBG14]]
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG14]]
; CHECK:       final.end:
; CHECK-NEXT:    ret i32 0, !dbg [[DBG15:![0-9]+]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP7:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    call void @nanos6_create_task(ptr @task_info_var_main, ptr @task_invocation_info_main, ptr null, i64 64, ptr [[TMP0]], ptr [[TMP1]], i64 0, i64 [[TMP7]]), !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP8:%.*]] = load ptr, ptr [[TMP0]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP8]], i64 64, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE0:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TMP8]], i32 0, i32 0, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 1, ptr [[GEP_DEV_NDRANGE0]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE1:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 1, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE1]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE2:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 2, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE2]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE01:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 3, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 2, ptr [[GEP_DEV_NDRANGE01]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE12:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 4, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE12]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_NDRANGE23:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 5, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 -1, ptr [[GEP_DEV_NDRANGE23]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_DEV_SHM:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 6, !dbg [[DBG14]]
; CHECK-NEXT:    store i64 0, ptr [[GEP_DEV_SHM]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_CALL_ARG:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 7, !dbg [[DBG14]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 1 [[GEP_CALL_ARG]], ptr align 1 [[CALL_ARG]], i64 1, i1 false), !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_CALL_ARG1:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 8, !dbg [[DBG14]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 2 [[GEP_CALL_ARG1]], ptr align 2 [[CALL_ARG1]], i64 2, i1 false), !dbg [[DBG14]]
; CHECK-NEXT:    [[GEP_CALL_ARG2:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TMP8]], i32 0, i32 9, !dbg [[DBG14]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_CALL_ARG2]], ptr align 4 [[CALL_ARG2]], i64 4, i1 false), !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP9:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG14]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP9]]), !dbg [[DBG14]]
; CHECK-NEXT:    br label [[FINAL_END]], !dbg [[DBG14]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP10:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG14]]
; CHECK-NEXT:    [[TMP11:%.*]] = icmp ne i32 [[TMP10]], 0, !dbg [[DBG14]]
; CHECK-NEXT:    br i1 [[TMP11]], label [[CODEREPL:%.*]], label [[CODEREPL4:%.*]], !dbg [[DBG14]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_main
; CHECK-SAME: (ptr [[CALL_ARG:%.*]], ptr [[CALL_ARG1:%.*]], ptr [[CALL_ARG2:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG16:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[FINAL_THEN:%.*]], !dbg [[DBG17:![0-9]+]]
; CHECK:       final.then:
; CHECK-NEXT:    br label [[DOTEXITSTUB:%.*]], !dbg [[DBG18:![0-9]+]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_CALL_ARG:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 7
; CHECK-NEXT:    [[GEP_CALL_ARG1:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 8
; CHECK-NEXT:    [[GEP_CALL_ARG2:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN]], ptr [[TASK_ARGS]], i32 0, i32 9
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main(ptr [[GEP_CALL_ARG]], ptr [[GEP_CALL_ARG1]], ptr [[GEP_CALL_ARG2]], ptr [[DEVICE_ENV]], ptr [[ADDRESS_TRANSLATION_TABLE]])
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
; CHECK-SAME: (ptr [[CALL_ARG:%.*]], ptr [[CALL_ARG1:%.*]], ptr [[CALL_ARG2:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG19:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG20:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    br label [[DOTEXITSTUB:%.*]], !dbg [[DBG21:![0-9]+]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main.5
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_CALL_ARG:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0:%.*]], ptr [[TASK_ARGS]], i32 0, i32 7
; CHECK-NEXT:    [[GEP_CALL_ARG1:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TASK_ARGS]], i32 0, i32 8
; CHECK-NEXT:    [[GEP_CALL_ARG2:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN_0]], ptr [[TASK_ARGS]], i32 0, i32 9
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main.4(ptr [[GEP_CALL_ARG]], ptr [[GEP_CALL_ARG1]], ptr [[GEP_CALL_ARG2]], ptr [[DEVICE_ENV]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;