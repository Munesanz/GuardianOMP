; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --include-generated-funcs
; RUN: opt %s -passes=ompss-2 -S | FileCheck %s
; ModuleID = 'critical.ll'
source_filename = "critical.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !5 {
entry:
  %0 = call i1 @llvm.directive.marker() [ "DIR.OSS"([15 x i8] c"CRITICAL.START\00", [24 x i8] c"nanos6_critical_default\00") ], !dbg !9
  %1 = call i1 @llvm.directive.marker() [ "DIR.OSS"([13 x i8] c"CRITICAL.END\00", [24 x i8] c"nanos6_critical_default\00") ], !dbg !10
  %2 = call i1 @llvm.directive.marker() [ "DIR.OSS"([15 x i8] c"CRITICAL.START\00", [24 x i8] c"nanos6_critical_default\00") ], !dbg !11
  %3 = call i1 @llvm.directive.marker() [ "DIR.OSS"([13 x i8] c"CRITICAL.END\00", [24 x i8] c"nanos6_critical_default\00") ], !dbg !12
  %4 = call i1 @llvm.directive.marker() [ "DIR.OSS"([15 x i8] c"CRITICAL.START\00", [21 x i8] c"nanos6_critical_asdf\00") ], !dbg !13
  %5 = call i1 @llvm.directive.marker() [ "DIR.OSS"([13 x i8] c"CRITICAL.END\00", [21 x i8] c"nanos6_critical_asdf\00") ], !dbg !14
  %6 = call i1 @llvm.directive.marker() [ "DIR.OSS"([15 x i8] c"CRITICAL.START\00", [21 x i8] c"nanos6_critical_asdf\00") ], !dbg !15
  %7 = call i1 @llvm.directive.marker() [ "DIR.OSS"([13 x i8] c"CRITICAL.END\00", [21 x i8] c"nanos6_critical_asdf\00") ], !dbg !16
  ret i32 0, !dbg !17
}

; Function Attrs: nounwind
declare i1 @llvm.directive.marker() #1

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
!5 = distinct !DISubprogram(name: "main", scope: !6, file: !6, line: 1, type: !7, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!6 = !DIFile(filename: "critical.ll", directory: "")
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 2, column: 11, scope: !5)
!10 = !DILocation(line: 3, column: 4, scope: !5)
!11 = !DILocation(line: 4, column: 11, scope: !5)
!12 = !DILocation(line: 5, column: 4, scope: !5)
!13 = !DILocation(line: 6, column: 11, scope: !5)
!14 = !DILocation(line: 7, column: 4, scope: !5)
!15 = !DILocation(line: 8, column: 11, scope: !5)
!16 = !DILocation(line: 9, column: 4, scope: !5)
!17 = !DILocation(line: 10, column: 1, scope: !5)
; CHECK-LABEL: @main(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    call void @nanos6_user_lock(ptr @nanos6_critical_default, ptr @[[GLOB0:[0-9]+]]), !dbg [[DBG9:![0-9]+]]
; CHECK-NEXT:    call void @nanos6_user_unlock(ptr @nanos6_critical_default), !dbg [[DBG10:![0-9]+]]
; CHECK-NEXT:    call void @nanos6_user_lock(ptr @nanos6_critical_default, ptr @[[GLOB2:[0-9]+]]), !dbg [[DBG11:![0-9]+]]
; CHECK-NEXT:    call void @nanos6_user_unlock(ptr @nanos6_critical_default), !dbg [[DBG12:![0-9]+]]
; CHECK-NEXT:    call void @nanos6_user_lock(ptr @nanos6_critical_asdf, ptr @[[GLOB4:[0-9]+]]), !dbg [[DBG13:![0-9]+]]
; CHECK-NEXT:    call void @nanos6_user_unlock(ptr @nanos6_critical_asdf), !dbg [[DBG14:![0-9]+]]
; CHECK-NEXT:    call void @nanos6_user_lock(ptr @nanos6_critical_asdf, ptr @[[GLOB6:[0-9]+]]), !dbg [[DBG15:![0-9]+]]
; CHECK-NEXT:    call void @nanos6_user_unlock(ptr @nanos6_critical_asdf), !dbg [[DBG16:![0-9]+]]
; CHECK-NEXT:    ret i32 0, !dbg [[DBG17:![0-9]+]]
;