; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt --bpf-ir-peephole -mtriple=bpf-pc-linux -S %s | FileCheck %s
; Source:
;   #define AA 40
;   struct t {
;     char a[20];
;   };
;   void foo(ptr);
;
;   int test1() {
;     const int a = 8;
;     char tmp[AA + sizeof(struct t) + a];
;     foo(tmp);
;     return 0;
;   }
;
;   int test2(int b) {
;     const int a = 8;
;     char tmp[a + b];
;     foo(tmp);
;     return 0;
;   }
; Compilation flag:
;   clang -target bpf -O2 -S -emit-llvm t.c -Xclang -disable-llvm-passes

source_filename = "t.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

; Function Attrs: nounwind
define dso_local i32 @test1() {
; CHECK-LABEL: @test1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    call void @llvm.lifetime.start.p0(i64 4, ptr [[A]])
; CHECK-NEXT:    store i32 8, ptr [[A]], align 4
; CHECK-NEXT:    [[VLA:%.*]] = alloca i8, i64 68, align 1
; CHECK-NEXT:    call void @foo(ptr [[VLA]])
; CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 4, ptr [[A]])
; CHECK-NEXT:    ret i32 0
;
entry:
  %a = alloca i32, align 4
  %saved_stack = alloca ptr, align 8
  call void @llvm.lifetime.start.p0(i64 4, ptr %a)
  store i32 8, ptr %a, align 4
  %0 = call ptr @llvm.stacksave()
  store ptr %0, ptr %saved_stack, align 8
  %vla = alloca i8, i64 68, align 1
  call void @foo(ptr %vla)
  %1 = load ptr, ptr %saved_stack, align 8
  call void @llvm.stackrestore(ptr %1)
  call void @llvm.lifetime.end.p0(i64 4, ptr %a)
  ret i32 0
}

declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture)

declare ptr @llvm.stacksave()

declare dso_local void @foo(ptr)

declare void @llvm.stackrestore(ptr)

declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture)

define dso_local i32 @test2(i32 %b) {
; CHECK-LABEL: @test2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[B_ADDR:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[A:%.*]] = alloca i32, align 4
; CHECK-NEXT:    [[SAVED_STACK:%.*]] = alloca ptr, align 8
; CHECK-NEXT:    [[__VLA_EXPR0:%.*]] = alloca i64, align 8
; CHECK-NEXT:    store i32 [[B:%.*]], ptr [[B_ADDR]], align 4
; CHECK-NEXT:    call void @llvm.lifetime.start.p0(i64 4, ptr [[A]])
; CHECK-NEXT:    store i32 8, ptr [[A]], align 4
; CHECK-NEXT:    [[TMP1:%.*]] = load i32, ptr [[B_ADDR]], align 4
; CHECK-NEXT:    [[ADD:%.*]] = add nsw i32 8, [[TMP1]]
; CHECK-NEXT:    [[TMP2:%.*]] = zext i32 [[ADD]] to i64
; CHECK-NEXT:    [[VLA:%.*]] = alloca i8, i64 [[TMP2]], align 1
; CHECK-NEXT:    store i64 [[TMP2]], ptr [[__VLA_EXPR0]], align 8
; CHECK-NEXT:    call void @foo(ptr [[VLA]])
; CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 4, ptr [[A]])
; CHECK-NEXT:    ret i32 0
;
entry:
  %b.addr = alloca i32, align 4
  %a = alloca i32, align 4
  %saved_stack = alloca ptr, align 8
  %__vla_expr0 = alloca i64, align 8
  store i32 %b, ptr %b.addr, align 4
  call void @llvm.lifetime.start.p0(i64 4, ptr %a)
  store i32 8, ptr %a, align 4
  %0 = load i32, ptr %b.addr, align 4
  %add = add nsw i32 8, %0
  %1 = zext i32 %add to i64
  %2 = call ptr @llvm.stacksave()
  store ptr %2, ptr %saved_stack, align 8
  %vla = alloca i8, i64 %1, align 1
  store i64 %1, ptr %__vla_expr0, align 8
  call void @foo(ptr %vla)
  %3 = load ptr, ptr %saved_stack, align 8
  call void @llvm.stackrestore(ptr %3)
  call void @llvm.lifetime.end.p0(i64 4, ptr %a)
  ret i32 0
}
