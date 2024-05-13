; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --prefix-filecheck-ir-name abc
; RUN: opt -passes=dse -S < %s | FileCheck %s

; Make sure invokes are not removed as dead stores.
define void @test_nounwind_invoke() personality ptr @__gxx_personality_v0 {
; CHECK-LABEL: @test_nounwind_invoke(
; CHECK-NEXT:  bb:
; CHECK-NEXT:    [[TMP:%.*]] = alloca i32, align 4
; CHECK-NEXT:    invoke void @foo(ptr [[TMP]])
; CHECK-NEXT:    to label [[BB1:%.*]] unwind label [[BB2:%.*]]
; CHECK:       bb1:
; CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 4, ptr [[TMP]])
; CHECK-NEXT:    ret void
; CHECK:       bb2:
; CHECK-NEXT:    [[ABCTMP1:%.*]] = landingpad { ptr, i32 }
; CHECK-NEXT:    cleanup
; CHECK-NEXT:    resume { ptr, i32 } [[ABCTMP1]]
;
bb:
  %tmp = alloca i32, align 4
  ; 'foo' is 'argmemonly', meaning it can only write to memory pointed by %tmp.
  ; And this def is killed by 'call @llvm.lifetime.end.p0' in bb1 without
  ; being used elsewhere, becoming a dead store. But we shouldn't remove this
  ; because invokes are terminators and thus cannot be removed.
  invoke void @foo(ptr %tmp)
  to label %bb1 unwind label %bb2

bb1:                                              ; preds = %bb
  call void @llvm.lifetime.end.p0(i64 4, ptr %tmp)
  ret void

bb2:                                              ; preds = %bb
  %tmp1 = landingpad { ptr, i32 }
  cleanup
  resume { ptr, i32 } %tmp1
}

; Function Attrs: argmemonly nocallback nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture) #0
; Function Attrs: argmemonly nounwind willreturn
declare void @foo(ptr) #1
declare i32 @__gxx_personality_v0(...)

attributes #0 = { argmemonly nocallback nofree nosync nounwind willreturn }
attributes #1 = { argmemonly nounwind willreturn }
