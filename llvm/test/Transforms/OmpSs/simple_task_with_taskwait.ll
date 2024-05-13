; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
source_filename = "simple_task_with_taskwait.ll"

define void @foo(i32 %x, i32 %y) !dbg !6 {
entry:
  %x.addr = alloca i32, align 4
  %y.addr = alloca i32, align 4
  %x_orig = alloca i32, align 4
  %y_orig = alloca i32, align 4
  %z_orig = alloca i32, align 4
  %z = alloca i32, align 4
  store i32 %x, ptr %x.addr, align 4
  store i32 %y, ptr %y.addr, align 4
  %0 = load i32, ptr %x.addr, align 4
  store i32 %0, ptr %x_orig, align 4
  %1 = load i32, ptr %y.addr, align 4
  store i32 %1, ptr %y_orig, align 4
  store i32 42, ptr %z_orig, align 4
  %2 = load i32, ptr %z_orig, align 4
  store i32 %2, ptr %z, align 4

  %3 = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.SHARED"(ptr %x.addr, i32 undef), "QUAL.OSS.PRIVATE"(ptr %z, i32 undef), "QUAL.OSS.FIRSTPRIVATE"(ptr %y.addr, i32 undef) ], !dbg !8
  %4 = load i32, ptr %x.addr, align 4
  %inc = add nsw i32 %4, 1
  store i32 %inc, ptr %x.addr, align 4
  %5 = load i32, ptr %y.addr, align 4
  %inc1 = add nsw i32 %5, 1
  store i32 %inc1, ptr %y.addr, align 4
  %6 = load i32, ptr %z, align 4
  %inc2 = add nsw i32 %6, 1
  store i32 %inc2, ptr %z, align 4
  call void @llvm.directive.region.exit(token %3), !dbg !9

  %7 = call i1 @llvm.directive.marker() [ "DIR.OSS"([9 x i8] c"TASKWAIT\00") ], !dbg !10
  ret void
}

declare token @llvm.directive.region.entry()
declare void @llvm.directive.region.exit(token)
declare i1 @llvm.directive.marker()

!llvm.module.flags = !{!3}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "human", isOptimized: false, runtimeVersion: 0, emissionKind: NoDebug, enums: !2, nameTableKind: None)
!1 = !DIFile(filename: "simple_task_with_taskwait.c", directory: "")!2 = !{}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!6 = distinct !DISubprogram(name: "foo", scope: !1, file: !1, line: 4, type: !7, scopeLine: 4, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!7 = !DISubroutineType(types: !2)
!8 = !DILocation(line: 5, column: 9, scope: !6)
!9 = !DILocation(line: 5, column: 9, scope: !6)
!10 = !DILocation(line: 5, column: 9, scope: !6)
; CHECK-LABEL: @foo(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[X_ADDR:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[Y_ADDR:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[X_ORIG:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[Y_ORIG:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[Z_ORIG:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[Z:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i32 [[X:%.*]], ptr [[X_ADDR]], align 4
; CHECK-NEXT:    store i32 [[Y:%.*]], ptr [[Y_ADDR]], align 4
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr [[X_ADDR]], align 4
; CHECK-NEXT:    store i32 [[TMP0]], ptr [[X_ORIG]], align 4
; CHECK-NEXT:    [[TMP1:%.*]] = load i32, ptr [[Y_ADDR]], align 4
; CHECK-NEXT:    store i32 [[TMP1]], ptr [[Y_ORIG]], align 4
; CHECK-NEXT:    store i32 42, ptr [[Z_ORIG]], align 4
; CHECK-NEXT:    [[TMP2:%.*]] = load i32, ptr [[Z_ORIG]], align 4
; CHECK-NEXT:    store i32 [[TMP2]], ptr [[Z]], align 4
; CHECK-NEXT:    [[TMP3:%.*]] = alloca ptr, align 8, !dbg [[DBG6:![0-9]+]]
; CHECK-NEXT:    [[TMP4:%.*]] = alloca ptr, align 8, !dbg [[DBG6]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG6]]
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG6]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS]], align 8, !dbg [[DBG6]]
; CHECK-NEXT:    [[TMP5:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG6]]
; CHECK-NEXT:    call void @nanos6_create_task(ptr @task_info_var_foo, ptr @task_invocation_info_foo, ptr null, i64 16, ptr [[TMP3]], ptr [[TMP4]], i64 0, i64 [[TMP5]]), !dbg [[DBG6]]
; CHECK-NEXT:    [[TMP6:%.*]] = load ptr, ptr [[TMP3]], align 8, !dbg [[DBG6]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP6]], i64 16, !dbg [[DBG6]]
; CHECK-NEXT:    [[GEP_X_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_FOO:%.*]], ptr [[TMP6]], i32 0, i32 0, !dbg [[DBG6]]
; CHECK-NEXT:    store ptr [[X_ADDR]], ptr [[GEP_X_ADDR]], align 8, !dbg [[DBG6]]
; CHECK-NEXT:    [[GEP_Y_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_FOO]], ptr [[TMP6]], i32 0, i32 2, !dbg [[DBG6]]
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 4 [[GEP_Y_ADDR]], ptr align 4 [[Y_ADDR]], i64 4, i1 false), !dbg [[DBG6]]
; CHECK-NEXT:    [[TMP7:%.*]] = load ptr, ptr [[TMP4]], align 8, !dbg [[DBG6]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP7]]), !dbg [[DBG6]]
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG6]]
; CHECK:       final.end:
; CHECK-NEXT:    call void @nanos6_taskwait(ptr @[[GLOB1:[0-9]+]]), !dbg [[DBG6]]
; CHECK-NEXT:    ret void
; CHECK:       final.then:
; CHECK-NEXT:    [[TMP8:%.*]] = load i32, ptr [[X_ADDR]], align 4
; CHECK-NEXT:    [[INC_CLONE:%.*]] = add nsw i32 [[TMP8]], 1
; CHECK-NEXT:    store i32 [[INC_CLONE]], ptr [[X_ADDR]], align 4
; CHECK-NEXT:    [[TMP9:%.*]] = load i32, ptr [[Y_ADDR]], align 4
; CHECK-NEXT:    [[INC1_CLONE:%.*]] = add nsw i32 [[TMP9]], 1
; CHECK-NEXT:    store i32 [[INC1_CLONE]], ptr [[Y_ADDR]], align 4
; CHECK-NEXT:    [[TMP10:%.*]] = load i32, ptr [[Z]], align 4
; CHECK-NEXT:    [[INC2_CLONE:%.*]] = add nsw i32 [[TMP10]], 1
; CHECK-NEXT:    store i32 [[INC2_CLONE]], ptr [[Z]], align 4
; CHECK-NEXT:    br label [[FINAL_END]], !dbg [[DBG6]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP11:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG6]]
; CHECK-NEXT:    [[TMP12:%.*]] = icmp ne i32 [[TMP11]], 0, !dbg [[DBG6]]
; CHECK-NEXT:    br i1 [[TMP12]], label [[FINAL_THEN:%.*]], label [[CODEREPL:%.*]], !dbg [[DBG6]]
;
;
; CHECK-LABEL: @nanos6_unpacked_task_region_foo(
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG8:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    [[TMP1:%.*]] = load i32, ptr [[X_ADDR:%.*]], align 4
; CHECK-NEXT:    [[INC:%.*]] = add nsw i32 [[TMP1]], 1
; CHECK-NEXT:    store i32 [[INC]], ptr [[X_ADDR]], align 4
; CHECK-NEXT:    [[TMP2:%.*]] = load i32, ptr [[Y_ADDR:%.*]], align 4
; CHECK-NEXT:    [[INC1:%.*]] = add nsw i32 [[TMP2]], 1
; CHECK-NEXT:    store i32 [[INC1]], ptr [[Y_ADDR]], align 4
; CHECK-NEXT:    [[TMP3:%.*]] = load i32, ptr [[Z:%.*]], align 4
; CHECK-NEXT:    [[INC2:%.*]] = add nsw i32 [[TMP3]], 1
; CHECK-NEXT:    store i32 [[INC2]], ptr [[Z]], align 4
; CHECK-NEXT:    br label [[DOTEXITSTUB:%.*]], !dbg [[DBG8]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: @nanos6_ol_task_region_foo(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_X_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_FOO:%.*]], ptr [[TASK_ARGS:%.*]], i32 0, i32 0
; CHECK-NEXT:    [[LOAD_GEP_X_ADDR:%.*]] = load ptr, ptr [[GEP_X_ADDR]], align 8
; CHECK-NEXT:    [[GEP_Z:%.*]] = getelementptr [[NANOS6_TASK_ARGS_FOO]], ptr [[TASK_ARGS]], i32 0, i32 1
; CHECK-NEXT:    [[GEP_Y_ADDR:%.*]] = getelementptr [[NANOS6_TASK_ARGS_FOO]], ptr [[TASK_ARGS]], i32 0, i32 2
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE:%.*]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_foo(ptr [[LOAD_GEP_X_ADDR]], ptr [[GEP_Z]], ptr [[GEP_Y_ADDR]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: @nanos6_constructor_register_task_info(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_foo)
; CHECK-NEXT:    ret void
;