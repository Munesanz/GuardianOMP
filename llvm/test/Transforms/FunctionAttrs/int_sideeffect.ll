; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --check-attributes
; RUN: opt -S < %s -passes=function-attrs | FileCheck %s

declare void @llvm.sideeffect()

; Don't add readnone or similar attributes when an @llvm.sideeffect() intrinsic
; is present.

define void @test() {
; CHECK: Function Attrs: mustprogress nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite)
; CHECK-LABEL: @test(
; CHECK-NEXT:    call void @llvm.sideeffect()
; CHECK-NEXT:    ret void
;
  call void @llvm.sideeffect()
  ret void
}

define void @loop() {
; CHECK: Function Attrs: nofree noreturn nosync nounwind memory(inaccessiblemem: readwrite)
; CHECK-LABEL: @loop(
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    call void @llvm.sideeffect()
; CHECK-NEXT:    br label [[LOOP]]
;
  br label %loop

loop:
  call void @llvm.sideeffect()
  br label %loop
}
