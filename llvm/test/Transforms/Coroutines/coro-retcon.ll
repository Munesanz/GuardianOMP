; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; First example from Doc/Coroutines.rst (two block loop) converted to retcon
; RUN: opt < %s -passes='default<O2>' -S | FileCheck %s
; RUN: opt < %s -passes='module(coro-early),cgscc(coro-split),module(coro-cleanup)' -S | FileCheck --check-prefix=CORO %s

define ptr @f(ptr %buffer, i32 %n) {
; CHECK-LABEL: @f(
; CHECK-NEXT:  coro.return:
; CHECK-NEXT:    store i32 [[N:%.*]], ptr [[BUFFER:%.*]], align 4
; CHECK-NEXT:    tail call void @print(i32 [[N]])
; CHECK-NEXT:    ret ptr @f.resume.0
;
; CORO-LABEL: @f(
; CORO-NEXT:  entry:
; CORO-NEXT:    [[N_VAL_SPILL_ADDR:%.*]] = getelementptr inbounds [[F_FRAME:%.*]], ptr [[BUFFER:%.*]], i32 0, i32 0
; CORO-NEXT:    store i32 [[N:%.*]], ptr [[N_VAL_SPILL_ADDR]], align 4
; CORO-NEXT:    call void @print(i32 [[N]])
; CORO-NEXT:    ret ptr @f.resume.0
;
entry:
  %id = call token @llvm.coro.id.retcon(i32 8, i32 4, ptr %buffer, ptr @prototype, ptr @allocate, ptr @deallocate)
  %hdl = call ptr @llvm.coro.begin(token %id, ptr null)
  br label %loop

loop:
  %n.val = phi i32 [ %n, %entry ], [ %inc, %resume ]
  call void @print(i32 %n.val)
  %unwind0 = call i1 (...) @llvm.coro.suspend.retcon.i1()
  br i1 %unwind0, label %cleanup, label %resume

resume:
  %inc = add i32 %n.val, 1
  br label %loop

cleanup:
  call i1 @llvm.coro.end(ptr %hdl, i1 0)
  unreachable
}



define i32 @main() {
; CHECK-LABEL: @main(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    tail call void @print(i32 4)
; CHECK-NEXT:    tail call void @print(i32 5), !noalias !0
; CHECK-NEXT:    tail call void @print(i32 6), !noalias !3
; CHECK-NEXT:    ret i32 0
;
; CORO-LABEL: @main(
; CORO-NEXT:  entry:
; CORO-NEXT:    [[TMP0:%.*]] = alloca [8 x i8], align 4
; CORO-NEXT:    [[CONT0:%.*]] = call ptr @f(ptr [[TMP0]], i32 4)
; CORO-NEXT:    [[CONT1:%.*]] = call ptr [[CONT0]](ptr [[TMP0]], i1 zeroext false)
; CORO-NEXT:    [[CONT2:%.*]] = call ptr [[CONT1]](ptr [[TMP0]], i1 zeroext false)
; CORO-NEXT:    [[TMP1:%.*]] = call ptr [[CONT2]](ptr [[TMP0]], i1 zeroext true)
; CORO-NEXT:    ret i32 0
;
entry:
  %0 = alloca [8 x i8], align 4
  %prepare = call ptr @llvm.coro.prepare.retcon(ptr @f)
  %cont0 = call ptr %prepare(ptr %0, i32 4)
  %cont1 = call ptr %cont0(ptr %0, i1 zeroext false)
  %cont2 = call ptr %cont1(ptr %0, i1 zeroext false)
  call ptr %cont2(ptr %0, i1 zeroext true)
  ret i32 0
}

;   Unfortunately, we don't seem to fully optimize this right now due
;   to some sort of phase-ordering thing.

define hidden { ptr, ptr } @g(ptr %buffer, ptr %ptr) {
; CHECK-LABEL: @g(
; CHECK-NEXT:  coro.return:
; CHECK-NEXT:    [[TMP0:%.*]] = tail call ptr @allocate(i32 8)
; CHECK-NEXT:    store ptr [[TMP0]], ptr [[BUFFER:%.*]], align 8
; CHECK-NEXT:    store ptr [[PTR:%.*]], ptr [[TMP0]], align 8
; CHECK-NEXT:    [[TMP1:%.*]] = insertvalue { ptr, ptr } { ptr @g.resume.0, ptr undef }, ptr [[PTR]], 1
; CHECK-NEXT:    ret { ptr, ptr } [[TMP1]]
;
; CORO-LABEL: @g(
; CORO-NEXT:  entry:
; CORO-NEXT:    [[TMP0:%.*]] = call ptr @allocate(i32 8)
; CORO-NEXT:    store ptr [[TMP0]], ptr [[BUFFER:%.*]], align 8
; CORO-NEXT:    [[PTR_SPILL_ADDR:%.*]] = getelementptr inbounds [[G_FRAME:%.*]], ptr [[TMP0]], i32 0, i32 0
; CORO-NEXT:    store ptr [[PTR:%.*]], ptr [[PTR_SPILL_ADDR]], align 8
; CORO-NEXT:    [[PTR_RELOAD_ADDR:%.*]] = getelementptr inbounds [[G_FRAME]], ptr [[TMP0]], i32 0, i32 0
; CORO-NEXT:    [[PTR_RELOAD:%.*]] = load ptr, ptr [[PTR_RELOAD_ADDR]], align 8
; CORO-NEXT:    [[TMP1:%.*]] = insertvalue { ptr, ptr } undef, ptr @g.resume.0, 0
; CORO-NEXT:    [[TMP2:%.*]] = insertvalue { ptr, ptr } [[TMP1]], ptr [[PTR_RELOAD]], 1
; CORO-NEXT:    ret { ptr, ptr } [[TMP2]]
;
entry:
  %id = call token @llvm.coro.id.retcon(i32 8, i32 4, ptr %buffer, ptr @g_prototype, ptr @allocate, ptr @deallocate)
  %hdl = call ptr @llvm.coro.begin(token %id, ptr null)
  br label %loop

loop:
  %unwind0 = call i1 (...) @llvm.coro.suspend.retcon.i1(ptr %ptr)
  br i1 %unwind0, label %cleanup, label %resume

resume:
  br label %loop

cleanup:
  call i1 @llvm.coro.end(ptr %hdl, i1 0)
  unreachable
}

define ptr @nosuspend(ptr %buffer, i32 %n) {
; CHECK-LABEL: @nosuspend(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A:%.*]] = alloca i32, align 4
; CHECK-NEXT:    store i32 [[N:%.*]], ptr [[A]], align 4
; CHECK-NEXT:    call void @use_var_ptr(ptr nonnull [[A]])
; CHECK-NEXT:    [[AL:%.*]] = load i32, ptr [[A]], align 4
; CHECK-NEXT:    call void @use_var(i32 [[AL]])
; CHECK-NEXT:    ret ptr null
;
; CORO-LABEL: @nosuspend(
; CORO-NEXT:  entry:
; CORO-NEXT:    [[A:%.*]] = alloca i32, align 4
; CORO-NEXT:    store i32 [[N:%.*]], ptr [[A]], align 4
; CORO-NEXT:    call void @use_var_ptr(ptr [[A]])
; CORO-NEXT:    [[AL:%.*]] = load i32, ptr [[A]], align 4
; CORO-NEXT:    call void @use_var(i32 [[AL]])
; CORO-NEXT:    ret ptr null
;
entry:
  %id = call token @llvm.coro.id.retcon(i32 8, i32 4, ptr %buffer, ptr @prototype, ptr @allocate, ptr @deallocate)
  %hdl = call ptr @llvm.coro.begin(token %id, ptr null)
  %a = alloca i32
  store i32 %n, ptr %a
  br label %cleanup

cleanup:
  call void @use_var_ptr(ptr %a)
  %al = load i32, ptr %a
  call void @use_var(i32 %al)
  call i1 @llvm.coro.end(ptr %hdl, i1 0)
  ret ptr %hdl
}

declare token @llvm.coro.id.retcon(i32, i32, ptr, ptr, ptr, ptr)
declare ptr @llvm.coro.begin(token, ptr)
declare i1 @llvm.coro.suspend.retcon.i1(...)
declare i1 @llvm.coro.end(ptr, i1)
declare ptr @llvm.coro.prepare.retcon(ptr)

declare void @use_var(i32)
declare void @use_var_ptr(ptr)

declare ptr @prototype(ptr, i1 zeroext)
declare {ptr,ptr} @g_prototype(ptr, i1 zeroext)

declare noalias ptr @allocate(i32 %size)
declare void @deallocate(ptr %ptr)

declare void @print(i32)
