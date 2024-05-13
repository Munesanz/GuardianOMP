; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature
; RUN: opt < %s -passes=globalopt -S | FileCheck %s

declare token @llvm.call.preallocated.setup(i32)
declare ptr @llvm.call.preallocated.arg(token, i32)
declare i32 @__CxxFrameHandler3(...)

; Don't touch functions with any musttail calls
define internal i32 @preallocated_musttail(ptr preallocated(i32) %p) {
; CHECK-LABEL: define {{[^@]+}}@preallocated_musttail
; CHECK-SAME: (ptr preallocated(i32) [[P:%.*]]) unnamed_addr {
; CHECK-NEXT:    [[RV:%.*]] = load i32, ptr [[P]], align 4
; CHECK-NEXT:    ret i32 [[RV]]
;
  %rv = load i32, ptr %p
  ret i32 %rv
}

define i32 @call_preallocated_musttail(ptr preallocated(i32) %a) {
; CHECK-LABEL: define {{[^@]+}}@call_preallocated_musttail
; CHECK-SAME: (ptr preallocated(i32) [[A:%.*]]) local_unnamed_addr {
; CHECK-NEXT:    [[R:%.*]] = musttail call i32 @preallocated_musttail(ptr preallocated(i32) [[A]])
; CHECK-NEXT:    ret i32 [[R]]
;
  %r = musttail call i32 @preallocated_musttail(ptr preallocated(i32) %a)
  ret i32 %r
}

define i32 @call_preallocated_musttail_without_musttail() {
; CHECK-LABEL: define {{[^@]+}}@call_preallocated_musttail_without_musttail() local_unnamed_addr {
; CHECK-NEXT:    [[C:%.*]] = call token @llvm.call.preallocated.setup(i32 1)
; CHECK-NEXT:    [[N:%.*]] = call ptr @llvm.call.preallocated.arg(token [[C]], i32 0) #[[ATTR1:[0-9]+]]
; CHECK-NEXT:    [[R:%.*]] = call i32 @preallocated_musttail(ptr preallocated(i32) [[N]]) [ "preallocated"(token [[C]]) ]
; CHECK-NEXT:    ret i32 [[R]]
;
  %c = call token @llvm.call.preallocated.setup(i32 1)
  %N = call ptr @llvm.call.preallocated.arg(token %c, i32 0) preallocated(i32)
  %r = call i32 @preallocated_musttail(ptr preallocated(i32) %N) ["preallocated"(token %c)]
  ret i32 %r
}

; Check that only one alloca per preallocated arg
define internal i32 @preallocated(ptr preallocated(i32) %a) {
; CHECK-LABEL: define {{[^@]+}}@preallocated
; CHECK-SAME: (ptr [[A:%.*]]) unnamed_addr {
; CHECK-NEXT:    [[RV:%.*]] = load i32, ptr [[A]], align 4
; CHECK-NEXT:    ret i32 [[RV]]
;
  %rv = load i32, ptr %a
  ret i32 %rv
}

declare void @foo(ptr)

define i32 @call_preallocated_multiple_args() {
; CHECK-LABEL: define {{[^@]+}}@call_preallocated_multiple_args() local_unnamed_addr {
; CHECK-NEXT:    [[TMP1:%.*]] = call ptr @llvm.stacksave()
; CHECK-NEXT:    [[PAARG:%.*]] = alloca i32, align 4
; CHECK-NEXT:    call void @foo(ptr [[PAARG]])
; CHECK-NEXT:    call void @foo(ptr [[PAARG]])
; CHECK-NEXT:    call void @foo(ptr [[PAARG]])
; CHECK-NEXT:    [[R:%.*]] = call fastcc i32 @preallocated(ptr [[PAARG]])
; CHECK-NEXT:    call void @llvm.stackrestore(ptr [[TMP1]])
; CHECK-NEXT:    ret i32 [[R]]
;
  %c = call token @llvm.call.preallocated.setup(i32 1)
  %a1 = call ptr @llvm.call.preallocated.arg(token %c, i32 0) preallocated(i32)
  call void @foo(ptr %a1)
  %a2 = call ptr @llvm.call.preallocated.arg(token %c, i32 0) preallocated(i32)
  call void @foo(ptr %a2)
  %a3 = call ptr @llvm.call.preallocated.arg(token %c, i32 0) preallocated(i32)
  call void @foo(ptr %a3)
  %r = call i32 @preallocated(ptr preallocated(i32) %a3) ["preallocated"(token %c)]
  ret i32 %r
}

; Don't touch functions with any invokes
define internal i32 @preallocated_invoke(ptr preallocated(i32) %p) {
; CHECK-LABEL: define {{[^@]+}}@preallocated_invoke
; CHECK-SAME: (ptr preallocated(i32) [[P:%.*]]) unnamed_addr {
; CHECK-NEXT:    [[RV:%.*]] = load i32, ptr [[P]], align 4
; CHECK-NEXT:    ret i32 [[RV]]
;
  %rv = load i32, ptr %p
  ret i32 %rv
}

define i32 @call_preallocated_invoke() personality ptr @__CxxFrameHandler3 {
; CHECK-LABEL: define {{[^@]+}}@call_preallocated_invoke() local_unnamed_addr personality ptr @__CxxFrameHandler3 {
; CHECK-NEXT:    [[C:%.*]] = call token @llvm.call.preallocated.setup(i32 1)
; CHECK-NEXT:    [[A:%.*]] = call ptr @llvm.call.preallocated.arg(token [[C]], i32 0) #[[ATTR1]]
; CHECK-NEXT:    [[R:%.*]] = invoke i32 @preallocated_invoke(ptr preallocated(i32) [[A]]) [ "preallocated"(token [[C]]) ]
; CHECK-NEXT:    to label [[CONTA:%.*]] unwind label [[CONTB:%.*]]
; CHECK:       conta:
; CHECK-NEXT:    ret i32 [[R]]
; CHECK:       contb:
; CHECK-NEXT:    [[S:%.*]] = catchswitch within none [label %catch] unwind to caller
; CHECK:       catch:
; CHECK-NEXT:    [[P:%.*]] = catchpad within [[S]] []
; CHECK-NEXT:    catchret from [[P]] to label [[CONT:%.*]]
; CHECK:       cont:
; CHECK-NEXT:    ret i32 42
;
  %c = call token @llvm.call.preallocated.setup(i32 1)
  %a = call ptr @llvm.call.preallocated.arg(token %c, i32 0) preallocated(i32)
  %r = invoke i32 @preallocated_invoke(ptr preallocated(i32) %a) ["preallocated"(token %c)]
  to label %conta unwind label %contb
conta:
  ret i32 %r
contb:
  %s = catchswitch within none [label %catch] unwind to caller
catch:
  %p = catchpad within %s []
  catchret from %p to label %cont
cont:
  ret i32 42
}
