; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 2
; Test alloca instrumentation.
;
; RUN: opt < %s -passes=hwasan -hwasan-use-stack-safety=0 -S | FileCheck %s
; RUN: opt < %s -passes=hwasan -hwasan-use-stack-safety=0 -hwasan-instrument-with-calls=0 -S | FileCheck %s  --check-prefixes=INLINE

target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

declare void @use32(ptr)

define void @test_alloca() sanitize_hwaddress {
; CHECK-LABEL: define void @test_alloca
; CHECK-SAME: () #[[ATTR0:[0-9]+]] personality ptr @__hwasan_personality_thunk {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[DOTHWASAN_SHADOW:%.*]] = call ptr asm "", "=r,0"(ptr null)
; CHECK-NEXT:    [[TMP0:%.*]] = call ptr @llvm.frameaddress.p0(i32 0)
; CHECK-NEXT:    [[TMP1:%.*]] = ptrtoint ptr [[TMP0]] to i64
; CHECK-NEXT:    [[TMP2:%.*]] = lshr i64 [[TMP1]], 20
; CHECK-NEXT:    [[TMP3:%.*]] = xor i64 [[TMP1]], [[TMP2]]
; CHECK-NEXT:    [[HWASAN_STACK_BASE_TAG:%.*]] = and i64 [[TMP3]], 63
; CHECK-NEXT:    [[TMP4:%.*]] = lshr i64 [[TMP1]], 57
; CHECK-NEXT:    [[HWASAN_UAR_TAG:%.*]] = and i64 [[TMP4]], 63
; CHECK-NEXT:    [[X:%.*]] = alloca { i32, [12 x i8] }, align 16
; CHECK-NEXT:    [[TMP5:%.*]] = xor i64 [[HWASAN_STACK_BASE_TAG]], 0
; CHECK-NEXT:    [[TMP6:%.*]] = ptrtoint ptr [[X]] to i64
; CHECK-NEXT:    [[TMP7:%.*]] = shl i64 [[TMP5]], 57
; CHECK-NEXT:    [[TMP8:%.*]] = or i64 [[TMP6]], [[TMP7]]
; CHECK-NEXT:    [[X_HWASAN:%.*]] = inttoptr i64 [[TMP8]] to ptr
; CHECK-NEXT:    [[TMP9:%.*]] = trunc i64 [[TMP5]] to i8
; CHECK-NEXT:    call void @__hwasan_tag_memory(ptr [[X]], i8 [[TMP9]], i64 16)
; CHECK-NEXT:    call void @use32(ptr nonnull [[X_HWASAN]])
; CHECK-NEXT:    [[TMP10:%.*]] = trunc i64 [[HWASAN_UAR_TAG]] to i8
; CHECK-NEXT:    call void @__hwasan_tag_memory(ptr [[X]], i8 [[TMP10]], i64 16)
; CHECK-NEXT:    ret void
;
; INLINE-LABEL: define void @test_alloca
; INLINE-SAME: () #[[ATTR0:[0-9]+]] personality ptr @__hwasan_personality_thunk {
; INLINE-NEXT:  entry:
; INLINE-NEXT:    [[TMP0:%.*]] = load i64, ptr @__hwasan_tls, align 8
; INLINE-NEXT:    [[TMP1:%.*]] = and i64 [[TMP0]], -9079256848778919937
; INLINE-NEXT:    [[TMP2:%.*]] = ashr i64 [[TMP0]], 3
; INLINE-NEXT:    [[TMP3:%.*]] = call ptr @llvm.frameaddress.p0(i32 0)
; INLINE-NEXT:    [[TMP4:%.*]] = ptrtoint ptr [[TMP3]] to i64
; INLINE-NEXT:    [[TMP5:%.*]] = shl i64 [[TMP4]], 44
; INLINE-NEXT:    [[TMP6:%.*]] = or i64 ptrtoint (ptr @test_alloca to i64), [[TMP5]]
; INLINE-NEXT:    [[TMP7:%.*]] = inttoptr i64 [[TMP1]] to ptr
; INLINE-NEXT:    store i64 [[TMP6]], ptr [[TMP7]], align 8
; INLINE-NEXT:    [[TMP8:%.*]] = ashr i64 [[TMP0]], 56
; INLINE-NEXT:    [[TMP9:%.*]] = shl nuw nsw i64 [[TMP8]], 12
; INLINE-NEXT:    [[TMP10:%.*]] = xor i64 [[TMP9]], -1
; INLINE-NEXT:    [[TMP11:%.*]] = add i64 [[TMP0]], 8
; INLINE-NEXT:    [[TMP12:%.*]] = and i64 [[TMP11]], [[TMP10]]
; INLINE-NEXT:    store i64 [[TMP12]], ptr @__hwasan_tls, align 8
; INLINE-NEXT:    [[TMP13:%.*]] = or i64 [[TMP1]], 4294967295
; INLINE-NEXT:    [[HWASAN_SHADOW:%.*]] = add i64 [[TMP13]], 1
; INLINE-NEXT:    [[TMP14:%.*]] = inttoptr i64 [[HWASAN_SHADOW]] to ptr
; INLINE-NEXT:    [[TMP15:%.*]] = lshr i64 [[TMP4]], 57
; INLINE-NEXT:    [[HWASAN_UAR_TAG:%.*]] = and i64 [[TMP15]], 63
; INLINE-NEXT:    [[X:%.*]] = alloca { i32, [12 x i8] }, align 16
; INLINE-NEXT:    [[TMP16:%.*]] = xor i64 [[TMP2]], 0
; INLINE-NEXT:    [[TMP17:%.*]] = ptrtoint ptr [[X]] to i64
; INLINE-NEXT:    [[TMP18:%.*]] = shl i64 [[TMP16]], 57
; INLINE-NEXT:    [[TMP19:%.*]] = or i64 [[TMP17]], [[TMP18]]
; INLINE-NEXT:    [[X_HWASAN:%.*]] = inttoptr i64 [[TMP19]] to ptr
; INLINE-NEXT:    [[TMP20:%.*]] = trunc i64 [[TMP16]] to i8
; INLINE-NEXT:    [[TMP21:%.*]] = ptrtoint ptr [[X]] to i64
; INLINE-NEXT:    [[TMP22:%.*]] = and i64 [[TMP21]], -9079256848778919937
; INLINE-NEXT:    [[TMP23:%.*]] = lshr i64 [[TMP22]], 4
; INLINE-NEXT:    [[TMP24:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP23]]
; INLINE-NEXT:    [[TMP25:%.*]] = getelementptr i8, ptr [[TMP24]], i32 0
; INLINE-NEXT:    store i8 4, ptr [[TMP25]], align 1
; INLINE-NEXT:    [[TMP26:%.*]] = getelementptr i8, ptr [[X]], i32 15
; INLINE-NEXT:    store i8 [[TMP20]], ptr [[TMP26]], align 1
; INLINE-NEXT:    call void @use32(ptr nonnull [[X_HWASAN]])
; INLINE-NEXT:    [[TMP27:%.*]] = trunc i64 [[HWASAN_UAR_TAG]] to i8
; INLINE-NEXT:    [[TMP28:%.*]] = ptrtoint ptr [[X]] to i64
; INLINE-NEXT:    [[TMP29:%.*]] = and i64 [[TMP28]], -9079256848778919937
; INLINE-NEXT:    [[TMP30:%.*]] = lshr i64 [[TMP29]], 4
; INLINE-NEXT:    [[TMP31:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP30]]
; INLINE-NEXT:    call void @llvm.memset.p0.i64(ptr align 1 [[TMP31]], i8 [[TMP27]], i64 1, i1 false)
; INLINE-NEXT:    ret void
;
entry:
  %x = alloca i32, align 4
  call void @use32(ptr nonnull %x)
  ret void
}


define i32 @test_simple(ptr %a) sanitize_hwaddress {
; CHECK-LABEL: define i32 @test_simple
; CHECK-SAME: (ptr [[A:%.*]]) #[[ATTR0]] personality ptr @__hwasan_personality_thunk {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[DOTHWASAN_SHADOW:%.*]] = call ptr asm "", "=r,0"(ptr null)
; CHECK-NEXT:    [[TMP0:%.*]] = call ptr @llvm.frameaddress.p0(i32 0)
; CHECK-NEXT:    [[TMP1:%.*]] = ptrtoint ptr [[TMP0]] to i64
; CHECK-NEXT:    [[TMP2:%.*]] = lshr i64 [[TMP1]], 20
; CHECK-NEXT:    [[TMP3:%.*]] = xor i64 [[TMP1]], [[TMP2]]
; CHECK-NEXT:    [[HWASAN_STACK_BASE_TAG:%.*]] = and i64 [[TMP3]], 63
; CHECK-NEXT:    [[TMP4:%.*]] = lshr i64 [[TMP1]], 57
; CHECK-NEXT:    [[HWASAN_UAR_TAG:%.*]] = and i64 [[TMP4]], 63
; CHECK-NEXT:    [[BUF_SROA_0:%.*]] = alloca { i8, [15 x i8] }, align 16
; CHECK-NEXT:    [[TMP5:%.*]] = xor i64 [[HWASAN_STACK_BASE_TAG]], 0
; CHECK-NEXT:    [[TMP6:%.*]] = ptrtoint ptr [[BUF_SROA_0]] to i64
; CHECK-NEXT:    [[TMP7:%.*]] = shl i64 [[TMP5]], 57
; CHECK-NEXT:    [[TMP8:%.*]] = or i64 [[TMP6]], [[TMP7]]
; CHECK-NEXT:    [[BUF_SROA_0_HWASAN:%.*]] = inttoptr i64 [[TMP8]] to ptr
; CHECK-NEXT:    [[TMP9:%.*]] = trunc i64 [[TMP5]] to i8
; CHECK-NEXT:    call void @__hwasan_tag_memory(ptr [[BUF_SROA_0]], i8 [[TMP9]], i64 16)
; CHECK-NEXT:    [[TMP10:%.*]] = ptrtoint ptr [[BUF_SROA_0_HWASAN]] to i64
; CHECK-NEXT:    call void @__hwasan_store1(i64 [[TMP10]])
; CHECK-NEXT:    store volatile i8 0, ptr [[BUF_SROA_0_HWASAN]], align 4
; CHECK-NEXT:    [[TMP11:%.*]] = trunc i64 [[HWASAN_UAR_TAG]] to i8
; CHECK-NEXT:    call void @__hwasan_tag_memory(ptr [[BUF_SROA_0]], i8 [[TMP11]], i64 16)
; CHECK-NEXT:    ret i32 0
;
; INLINE-LABEL: define i32 @test_simple
; INLINE-SAME: (ptr [[A:%.*]]) #[[ATTR0]] personality ptr @__hwasan_personality_thunk {
; INLINE-NEXT:  entry:
; INLINE-NEXT:    [[TMP0:%.*]] = load i64, ptr @__hwasan_tls, align 8
; INLINE-NEXT:    [[TMP1:%.*]] = and i64 [[TMP0]], -9079256848778919937
; INLINE-NEXT:    [[TMP2:%.*]] = ashr i64 [[TMP0]], 3
; INLINE-NEXT:    [[TMP3:%.*]] = call ptr @llvm.frameaddress.p0(i32 0)
; INLINE-NEXT:    [[TMP4:%.*]] = ptrtoint ptr [[TMP3]] to i64
; INLINE-NEXT:    [[TMP5:%.*]] = shl i64 [[TMP4]], 44
; INLINE-NEXT:    [[TMP6:%.*]] = or i64 ptrtoint (ptr @test_simple to i64), [[TMP5]]
; INLINE-NEXT:    [[TMP7:%.*]] = inttoptr i64 [[TMP1]] to ptr
; INLINE-NEXT:    store i64 [[TMP6]], ptr [[TMP7]], align 8
; INLINE-NEXT:    [[TMP8:%.*]] = ashr i64 [[TMP0]], 56
; INLINE-NEXT:    [[TMP9:%.*]] = shl nuw nsw i64 [[TMP8]], 12
; INLINE-NEXT:    [[TMP10:%.*]] = xor i64 [[TMP9]], -1
; INLINE-NEXT:    [[TMP11:%.*]] = add i64 [[TMP0]], 8
; INLINE-NEXT:    [[TMP12:%.*]] = and i64 [[TMP11]], [[TMP10]]
; INLINE-NEXT:    store i64 [[TMP12]], ptr @__hwasan_tls, align 8
; INLINE-NEXT:    [[TMP13:%.*]] = or i64 [[TMP1]], 4294967295
; INLINE-NEXT:    [[HWASAN_SHADOW:%.*]] = add i64 [[TMP13]], 1
; INLINE-NEXT:    [[TMP14:%.*]] = inttoptr i64 [[HWASAN_SHADOW]] to ptr
; INLINE-NEXT:    [[TMP15:%.*]] = lshr i64 [[TMP4]], 57
; INLINE-NEXT:    [[HWASAN_UAR_TAG:%.*]] = and i64 [[TMP15]], 63
; INLINE-NEXT:    [[BUF_SROA_0:%.*]] = alloca { i8, [15 x i8] }, align 16
; INLINE-NEXT:    [[TMP16:%.*]] = xor i64 [[TMP2]], 0
; INLINE-NEXT:    [[TMP17:%.*]] = ptrtoint ptr [[BUF_SROA_0]] to i64
; INLINE-NEXT:    [[TMP18:%.*]] = shl i64 [[TMP16]], 57
; INLINE-NEXT:    [[TMP19:%.*]] = or i64 [[TMP17]], [[TMP18]]
; INLINE-NEXT:    [[BUF_SROA_0_HWASAN:%.*]] = inttoptr i64 [[TMP19]] to ptr
; INLINE-NEXT:    [[TMP20:%.*]] = trunc i64 [[TMP16]] to i8
; INLINE-NEXT:    [[TMP21:%.*]] = ptrtoint ptr [[BUF_SROA_0]] to i64
; INLINE-NEXT:    [[TMP22:%.*]] = and i64 [[TMP21]], -9079256848778919937
; INLINE-NEXT:    [[TMP23:%.*]] = lshr i64 [[TMP22]], 4
; INLINE-NEXT:    [[TMP24:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP23]]
; INLINE-NEXT:    [[TMP25:%.*]] = getelementptr i8, ptr [[TMP24]], i32 0
; INLINE-NEXT:    store i8 1, ptr [[TMP25]], align 1
; INLINE-NEXT:    [[TMP26:%.*]] = getelementptr i8, ptr [[BUF_SROA_0]], i32 15
; INLINE-NEXT:    store i8 [[TMP20]], ptr [[TMP26]], align 1
; INLINE-NEXT:    [[TMP27:%.*]] = ptrtoint ptr [[BUF_SROA_0_HWASAN]] to i64
; INLINE-NEXT:    [[TMP28:%.*]] = lshr i64 [[TMP27]], 57
; INLINE-NEXT:    [[TMP29:%.*]] = trunc i64 [[TMP28]] to i8
; INLINE-NEXT:    [[TMP30:%.*]] = and i64 [[TMP27]], -9079256848778919937
; INLINE-NEXT:    [[TMP31:%.*]] = lshr i64 [[TMP30]], 4
; INLINE-NEXT:    [[TMP32:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP31]]
; INLINE-NEXT:    [[TMP33:%.*]] = load i8, ptr [[TMP32]], align 1
; INLINE-NEXT:    [[TMP34:%.*]] = icmp ne i8 [[TMP29]], [[TMP33]]
; INLINE-NEXT:    br i1 [[TMP34]], label [[TMP35:%.*]], label [[TMP49:%.*]], !prof [[PROF1:![0-9]+]]
; INLINE:       35:
; INLINE-NEXT:    [[TMP36:%.*]] = icmp ugt i8 [[TMP33]], 15
; INLINE-NEXT:    br i1 [[TMP36]], label [[TMP37:%.*]], label [[TMP38:%.*]], !prof [[PROF1]]
; INLINE:       37:
; INLINE-NEXT:    call void asm sideeffect "int3\0Anopl 80([[RAX:%.*]])", "{rdi}"(i64 [[TMP27]])
; INLINE-NEXT:    unreachable
; INLINE:       38:
; INLINE-NEXT:    [[TMP39:%.*]] = and i64 [[TMP27]], 15
; INLINE-NEXT:    [[TMP40:%.*]] = trunc i64 [[TMP39]] to i8
; INLINE-NEXT:    [[TMP41:%.*]] = add i8 [[TMP40]], 0
; INLINE-NEXT:    [[TMP42:%.*]] = icmp uge i8 [[TMP41]], [[TMP33]]
; INLINE-NEXT:    br i1 [[TMP42]], label [[TMP37]], label [[TMP43:%.*]], !prof [[PROF1]]
; INLINE:       43:
; INLINE-NEXT:    [[TMP44:%.*]] = or i64 [[TMP30]], 15
; INLINE-NEXT:    [[TMP45:%.*]] = inttoptr i64 [[TMP44]] to ptr
; INLINE-NEXT:    [[TMP46:%.*]] = load i8, ptr [[TMP45]], align 1
; INLINE-NEXT:    [[TMP47:%.*]] = icmp ne i8 [[TMP29]], [[TMP46]]
; INLINE-NEXT:    br i1 [[TMP47]], label [[TMP37]], label [[TMP48:%.*]], !prof [[PROF1]]
; INLINE:       48:
; INLINE-NEXT:    br label [[TMP49]]
; INLINE:       49:
; INLINE-NEXT:    store volatile i8 0, ptr [[BUF_SROA_0_HWASAN]], align 4
; INLINE-NEXT:    [[TMP50:%.*]] = trunc i64 [[HWASAN_UAR_TAG]] to i8
; INLINE-NEXT:    [[TMP51:%.*]] = ptrtoint ptr [[BUF_SROA_0]] to i64
; INLINE-NEXT:    [[TMP52:%.*]] = and i64 [[TMP51]], -9079256848778919937
; INLINE-NEXT:    [[TMP53:%.*]] = lshr i64 [[TMP52]], 4
; INLINE-NEXT:    [[TMP54:%.*]] = getelementptr i8, ptr [[TMP14]], i64 [[TMP53]]
; INLINE-NEXT:    call void @llvm.memset.p0.i64(ptr align 1 [[TMP54]], i8 [[TMP50]], i64 1, i1 false)
; INLINE-NEXT:    ret i32 0
;
entry:
  %buf.sroa.0 = alloca i8, align 4
  call void @llvm.lifetime.start.p0(i64 1, ptr nonnull %buf.sroa.0)
  store volatile i8 0, ptr %buf.sroa.0, align 4
  call void @llvm.lifetime.end.p0(i64 1, ptr nonnull %buf.sroa.0)
  ret i32 0
}

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture)

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture)