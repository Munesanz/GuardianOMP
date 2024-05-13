; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
; ModuleID = 'nested_const_expr_to_instr.ll'
source_filename = "nested_const_expr_to_instr.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; int array[10];
; int main() {
;     #pragma oss task
;     {
;         *(int *)((int)array) = 0;
;     }
; }

@array = global [10 x i32] zeroinitializer, align 16

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !5 {
entry:
  %0 = call token @llvm.directive.region.entry() [ "DIR.OSS"([5 x i8] c"TASK\00"), "QUAL.OSS.SHARED"(ptr @array, [10 x i32] undef) ], !dbg !9
  store i32 0, ptr inttoptr (i64 sext (i32 ptrtoint (ptr @array to i32) to i64) to ptr), align 4, !dbg !10
  call void @llvm.directive.region.exit(token %0), !dbg !11
  ret i32 0, !dbg !12
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
!5 = distinct !DISubprogram(name: "main", scope: !6, file: !6, line: 2, type: !7, scopeLine: 2, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!6 = !DIFile(filename: "nested_const_expr_to_instr.ll", directory: "")
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 3, column: 13, scope: !5)
!10 = !DILocation(line: 5, column: 30, scope: !5)
!11 = !DILocation(line: 6, column: 5, scope: !5)
!12 = !DILocation(line: 7, column: 1, scope: !5)
; CHECK-LABEL: define {{[^@]+}}@main
; CHECK-SAME: () #[[ATTR0:[0-9]+]] !dbg [[DBG5:![0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = alloca ptr, align 8, !dbg [[DBG9:![0-9]+]]
; CHECK-NEXT:    [[TMP1:%.*]] = alloca ptr, align 8, !dbg [[DBG9]]
; CHECK-NEXT:    [[NUM_DEPS:%.*]] = alloca i64, align 8, !dbg [[DBG9]]
; CHECK-NEXT:    br label [[FINAL_COND:%.*]], !dbg [[DBG9]]
; CHECK:       codeRepl:
; CHECK-NEXT:    store i64 0, ptr [[NUM_DEPS]], align 8, !dbg [[DBG9]]
; CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[NUM_DEPS]], align 8, !dbg [[DBG9]]
; CHECK-NEXT:    call void @nanos6_create_task(ptr @task_info_var_main, ptr @task_invocation_info_main, ptr null, i64 16, ptr [[TMP0]], ptr [[TMP1]], i64 0, i64 [[TMP2]]), !dbg [[DBG9]]
; CHECK-NEXT:    [[TMP3:%.*]] = load ptr, ptr [[TMP0]], align 8, !dbg [[DBG9]]
; CHECK-NEXT:    [[ARGS_END:%.*]] = getelementptr i8, ptr [[TMP3]], i64 16, !dbg [[DBG9]]
; CHECK-NEXT:    [[GEP_ARRAY:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TMP3]], i32 0, i32 0, !dbg [[DBG9]]
; CHECK-NEXT:    store ptr @array, ptr [[GEP_ARRAY]], align 8, !dbg [[DBG9]]
; CHECK-NEXT:    [[TMP4:%.*]] = load ptr, ptr [[TMP1]], align 8, !dbg [[DBG9]]
; CHECK-NEXT:    call void @nanos6_submit_task(ptr [[TMP4]]), !dbg [[DBG9]]
; CHECK-NEXT:    br label [[FINAL_END:%.*]], !dbg [[DBG9]]
; CHECK:       final.end:
; CHECK-NEXT:    ret i32 0, !dbg [[DBG10:![0-9]+]]
; CHECK:       final.then:
; CHECK-NEXT:    store i32 0, ptr inttoptr (i64 sext (i32 ptrtoint (ptr @array to i32) to i64) to ptr), align 4, !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    br label [[FINAL_END]], !dbg [[DBG10]]
; CHECK:       final.cond:
; CHECK-NEXT:    [[TMP5:%.*]] = call i32 @nanos6_in_final(), !dbg [[DBG9]]
; CHECK-NEXT:    [[TMP6:%.*]] = icmp ne i32 [[TMP5]], 0, !dbg [[DBG9]]
; CHECK-NEXT:    br i1 [[TMP6]], label [[FINAL_THEN:%.*]], label [[CODEREPL:%.*]], !dbg [[DBG9]]
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_unpacked_task_region_main
; CHECK-SAME: (ptr [[ARRAY:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) !dbg [[DBG12:![0-9]+]] {
; CHECK-NEXT:  newFuncRoot:
; CHECK-NEXT:    br label [[TMP0:%.*]], !dbg [[DBG13:![0-9]+]]
; CHECK:       0:
; CHECK-NEXT:    [[TMP1:%.*]] = ptrtoint ptr [[ARRAY]] to i32
; CHECK-NEXT:    [[TMP2:%.*]] = sext i32 [[TMP1]] to i64
; CHECK-NEXT:    [[TMP3:%.*]] = inttoptr i64 [[TMP2]] to ptr
; CHECK-NEXT:    store i32 0, ptr [[TMP3]], align 4, !dbg [[DBG14:![0-9]+]]
; CHECK-NEXT:    br label [[DOTEXITSTUB:%.*]], !dbg [[DBG15:![0-9]+]]
; CHECK:       .exitStub:
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_ol_task_region_main
; CHECK-SAME: (ptr [[TASK_ARGS:%.*]], ptr [[DEVICE_ENV:%.*]], ptr [[ADDRESS_TRANSLATION_TABLE:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[GEP_ARRAY:%.*]] = getelementptr [[NANOS6_TASK_ARGS_MAIN:%.*]], ptr [[TASK_ARGS]], i32 0, i32 0
; CHECK-NEXT:    [[LOAD_GEP_ARRAY:%.*]] = load ptr, ptr [[GEP_ARRAY]], align 8
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ne ptr [[ADDRESS_TRANSLATION_TABLE]], null
; CHECK-NEXT:    br i1 [[TMP0]], label [[TMP1:%.*]], label [[TMP2:%.*]]
; CHECK:       1:
; CHECK-NEXT:    br label [[TMP2]]
; CHECK:       2:
; CHECK-NEXT:    call void @nanos6_unpacked_task_region_main(ptr [[LOAD_GEP_ARRAY]], ptr [[DEVICE_ENV]], ptr [[ADDRESS_TRANSLATION_TABLE]])
; CHECK-NEXT:    ret void
;
;
; CHECK-LABEL: define {{[^@]+}}@nanos6_constructor_register_task_info() {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_register_task_info(ptr @task_info_var_main)
; CHECK-NEXT:    ret void
;
