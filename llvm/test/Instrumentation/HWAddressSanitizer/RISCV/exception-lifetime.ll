; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 2
; Test allocas with multiple lifetime ends, as frequently seen for exception
; handling.
;
; RUN: opt -passes=hwasan -hwasan-use-after-scope -S -o - %s | FileCheck %s

target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "riscv64-unknown-linux"

declare void @mayFail(ptr %x) sanitize_hwaddress
declare void @onExcept(ptr %x) sanitize_hwaddress

declare void @llvm.lifetime.start.p0(i64, ptr nocapture) nounwind
declare void @llvm.lifetime.end.p0(i64, ptr nocapture) nounwind
declare i32 @__gxx_personality_v0(...)

define void @test() sanitize_hwaddress personality ptr @__gxx_personality_v0 {
; CHECK-LABEL: define void @test
; CHECK-SAME: () #[[ATTR0:[0-9]+]] personality ptr @__hwasan_personality_thunk.__gxx_personality_v0 {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = load i64, ptr @__hwasan_tls, align 8
; CHECK-NEXT:    [[TMP1:%.*]] = and i64 [[TMP0]], 72057594037927935
; CHECK-NEXT:    [[TMP2:%.*]] = ashr i64 [[TMP0]], 3
; CHECK-NEXT:    [[TMP3:%.*]] = call ptr @llvm.frameaddress.p0(i32 0)
; CHECK-NEXT:    [[TMP4:%.*]] = ptrtoint ptr [[TMP3]] to i64
; CHECK-NEXT:    [[TMP5:%.*]] = shl i64 [[TMP4]], 44
; CHECK-NEXT:    [[TMP6:%.*]] = or i64 ptrtoint (ptr @test to i64), [[TMP5]]
; CHECK-NEXT:    [[TMP7:%.*]] = inttoptr i64 [[TMP1]] to ptr
; CHECK-NEXT:    store i64 [[TMP6]], ptr [[TMP7]], align 8
; CHECK-NEXT:    [[TMP8:%.*]] = ashr i64 [[TMP0]], 56
; CHECK-NEXT:    [[TMP9:%.*]] = shl nuw nsw i64 [[TMP8]], 12
; CHECK-NEXT:    [[TMP10:%.*]] = xor i64 [[TMP9]], -1
; CHECK-NEXT:    [[TMP11:%.*]] = add i64 [[TMP0]], 8
; CHECK-NEXT:    [[TMP12:%.*]] = and i64 [[TMP11]], [[TMP10]]
; CHECK-NEXT:    store i64 [[TMP12]], ptr @__hwasan_tls, align 8
; CHECK-NEXT:    [[TMP13:%.*]] = or i64 [[TMP1]], 4294967295
; CHECK-NEXT:    [[HWASAN_SHADOW:%.*]] = add i64 [[TMP13]], 1
; CHECK-NEXT:    [[TMP14:%.*]] = inttoptr i64 [[HWASAN_SHADOW]] to ptr
; CHECK-NEXT:    [[HWASAN_UAR_TAG:%.*]] = lshr i64 [[TMP4]], 56
; CHECK-NEXT:    [[X:%.*]] = alloca { i32, [12 x i8] }, align 16
; CHECK-NEXT:    [[TMP15:%.*]] = xor i64 [[TMP2]], 0
; CHECK-NEXT:    [[TMP16:%.*]] = ptrtoint ptr [[X]] to i64
; CHECK-NEXT:    [[TMP17:%.*]] = shl i64 [[TMP15]], 56
; CHECK-NEXT:    [[TMP18:%.*]] = or i64 [[TMP16]], [[TMP17]]
; CHECK-NEXT:    [[X_HWASAN:%.*]] = inttoptr i64 [[TMP18]] to ptr
; CHECK-NEXT:    [[EXN_SLOT:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[EHSELECTOR_SLOT:%.*]] = alloca i32, align 4
; CHECK-NEXT:    call void @llvm.lifetime.start.p0(i64 16, ptr [[X]])
; CHECK-NEXT:    [[TMP19:%.*]] = trunc i64 [[TMP15]] to i8
; CHECK-NEXT:    [[TMP20:%.*]] = ptrtoint ptr [[X]] to i64
; CHECK-NEXT:    [[TMP21:%.*]] = and i64 [[TMP20]], 72057594037927935
; CHECK-NEXT:    [[TMP22:%.*]] = lshr i64 [[TMP21]], 4
; CHECK-NEXT:    [[TMP23:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP22]]
; CHECK-NEXT:    [[TMP24:%.*]] = getelementptr i8, ptr [[TMP23]], i32 0
; CHECK-NEXT:    store i8 4, ptr [[TMP24]], align 1
; CHECK-NEXT:    [[TMP25:%.*]] = getelementptr i8, ptr [[X]], i32 15
; CHECK-NEXT:    store i8 [[TMP19]], ptr [[TMP25]], align 1
; CHECK-NEXT:    invoke void @mayFail(ptr [[X_HWASAN]])
; CHECK-NEXT:    to label [[INVOKE_CONT:%.*]] unwind label [[LPAD:%.*]]
; CHECK:       invoke.cont:
; CHECK-NEXT:    [[TMP26:%.*]] = trunc i64 [[HWASAN_UAR_TAG]] to i8
; CHECK-NEXT:    [[TMP27:%.*]] = ptrtoint ptr [[X]] to i64
; CHECK-NEXT:    [[TMP28:%.*]] = and i64 [[TMP27]], 72057594037927935
; CHECK-NEXT:    [[TMP29:%.*]] = lshr i64 [[TMP28]], 4
; CHECK-NEXT:    [[TMP30:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP29]]
; CHECK-NEXT:    call void @llvm.memset.p0.i64(ptr align 1 [[TMP30]], i8 [[TMP26]], i64 1, i1 false)
; CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 16, ptr [[X]])
; CHECK-NEXT:    ret void
; CHECK:       lpad:
; CHECK-NEXT:    [[TMP31:%.*]] = landingpad { ptr, i32 }
; CHECK-NEXT:    cleanup
; CHECK-NEXT:    [[TMP32:%.*]] = extractvalue { ptr, i32 } [[TMP31]], 0
; CHECK-NEXT:    call void @llvm.hwasan.check.memaccess.shortgranules(ptr [[TMP14]], ptr [[EXN_SLOT]], i32 19)
; CHECK-NEXT:    store ptr [[TMP32]], ptr [[EXN_SLOT]], align 8
; CHECK-NEXT:    [[TMP33:%.*]] = extractvalue { ptr, i32 } [[TMP31]], 1
; CHECK-NEXT:    call void @llvm.hwasan.check.memaccess.shortgranules(ptr [[TMP14]], ptr [[EHSELECTOR_SLOT]], i32 18)
; CHECK-NEXT:    store i32 [[TMP33]], ptr [[EHSELECTOR_SLOT]], align 4
; CHECK-NEXT:    call void @onExcept(ptr [[X_HWASAN]])
; CHECK-NEXT:    [[TMP34:%.*]] = trunc i64 [[HWASAN_UAR_TAG]] to i8
; CHECK-NEXT:    [[TMP35:%.*]] = ptrtoint ptr [[X]] to i64
; CHECK-NEXT:    [[TMP36:%.*]] = and i64 [[TMP35]], 72057594037927935
; CHECK-NEXT:    [[TMP37:%.*]] = lshr i64 [[TMP36]], 4
; CHECK-NEXT:    [[TMP38:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP37]]
; CHECK-NEXT:    call void @llvm.memset.p0.i64(ptr align 1 [[TMP38]], i8 [[TMP34]], i64 1, i1 false)
; CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 16, ptr [[X]])
; CHECK-NEXT:    br label [[EH_RESUME:%.*]]
; CHECK:       eh.resume:
; CHECK-NEXT:    call void @llvm.hwasan.check.memaccess.shortgranules(ptr [[TMP14]], ptr [[EXN_SLOT]], i32 3)
; CHECK-NEXT:    [[EXN:%.*]] = load ptr, ptr [[EXN_SLOT]], align 8
; CHECK-NEXT:    call void @llvm.hwasan.check.memaccess.shortgranules(ptr [[TMP14]], ptr [[EHSELECTOR_SLOT]], i32 2)
; CHECK-NEXT:    [[SEL:%.*]] = load i32, ptr [[EHSELECTOR_SLOT]], align 4
; CHECK-NEXT:    [[LPAD_VAL:%.*]] = insertvalue { ptr, i32 } undef, ptr [[EXN]], 0
; CHECK-NEXT:    [[LPAD_VAL1:%.*]] = insertvalue { ptr, i32 } [[LPAD_VAL]], i32 [[SEL]], 1
; CHECK-NEXT:    resume { ptr, i32 } [[LPAD_VAL1]]
;
entry:
  %x = alloca i32, align 8
  %exn.slot = alloca ptr, align 8
  %ehselector.slot = alloca i32, align 4
  call void @llvm.lifetime.start.p0(i64 8, ptr %x)
  invoke void @mayFail(ptr %x) to label %invoke.cont unwind label %lpad

invoke.cont:                                      ; preds = %entry

  call void @llvm.lifetime.end.p0(i64 8, ptr %x)
  ret void

lpad:                                             ; preds = %entry

  %0 = landingpad { ptr, i32 }
  cleanup
  %1 = extractvalue { ptr, i32 } %0, 0
  store ptr %1, ptr %exn.slot, align 8
  %2 = extractvalue { ptr, i32 } %0, 1
  store i32 %2, ptr %ehselector.slot, align 4
  call void @onExcept(ptr %x) #18
  call void @llvm.lifetime.end.p0(i64 8, ptr %x)
  br label %eh.resume

eh.resume:                                        ; preds = %lpad
  %exn = load ptr, ptr %exn.slot, align 8
  %sel = load i32, ptr %ehselector.slot, align 4
  %lpad.val = insertvalue { ptr, i32 } undef, ptr %exn, 0
  %lpad.val1 = insertvalue { ptr, i32 } %lpad.val, i32 %sel, 1
  resume { ptr, i32 } %lpad.val1
}
