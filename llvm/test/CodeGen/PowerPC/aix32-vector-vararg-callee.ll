; NOTE: Assertions have been autogenerated by utils/update_mir_test_checks.py
; RUN: llc -verify-machineinstrs -stop-before=ppc-vsx-copy -vec-extabi \
; RUN:     -mcpu=pwr7  -mtriple powerpc-ibm-aix-xcoff < %s | \
; RUN: FileCheck %s

; Testing passing a vector <4 x i32> through ellipses of a variadic function.
define <4 x i32> @callee(i32 %count, ...) {
  ; CHECK-LABEL: name: callee
  ; CHECK: bb.0.entry:
  ; CHECK:   liveins: $r4, $r5, $r6, $r7, $r8, $r9, $r10
  ; CHECK:   [[COPY:%[0-9]+]]:gprc = COPY $r10
  ; CHECK:   [[COPY1:%[0-9]+]]:gprc = COPY $r9
  ; CHECK:   [[COPY2:%[0-9]+]]:gprc = COPY $r8
  ; CHECK:   [[COPY3:%[0-9]+]]:gprc = COPY $r7
  ; CHECK:   [[COPY4:%[0-9]+]]:gprc = COPY $r6
  ; CHECK:   [[COPY5:%[0-9]+]]:gprc = COPY $r5
  ; CHECK:   [[COPY6:%[0-9]+]]:gprc = COPY $r4
  ; CHECK:   STW [[COPY6]], 0, %fixed-stack.0 :: (store (s32) into %fixed-stack.0)
  ; CHECK:   STW [[COPY5]], 4, %fixed-stack.0 :: (store (s32) into %fixed-stack.0 + 4)
  ; CHECK:   STW [[COPY4]], 8, %fixed-stack.0 :: (store (s32))
  ; CHECK:   STW [[COPY3]], 12, %fixed-stack.0 :: (store (s32))
  ; CHECK:   STW [[COPY2]], 16, %fixed-stack.0 :: (store (s32))
  ; CHECK:   STW [[COPY1]], 20, %fixed-stack.0 :: (store (s32))
  ; CHECK:   STW [[COPY]], 24, %fixed-stack.0 :: (store (s32))
  ; CHECK:   LIFETIME_START %stack.0.arg_list
  ; CHECK:   [[ADDI:%[0-9]+]]:gprc = ADDI %fixed-stack.0, 0
  ; CHECK:   STW killed [[ADDI]], 0, %stack.0.arg_list :: (store (s32) into %ir.arg_list)
  ; CHECK:   [[ADDI1:%[0-9]+]]:gprc = ADDI %fixed-stack.0, 15
  ; CHECK:   [[RLWINM:%[0-9]+]]:gprc = RLWINM killed [[ADDI1]], 0, 0, 27
  ; CHECK:   [[LXVW4X:%[0-9]+]]:vsrc = LXVW4X $zero, killed [[RLWINM]] :: (load (s128) from %ir.argp.cur.aligned)
  ; CHECK:   LIFETIME_END %stack.0.arg_list
  ; CHECK:   $v2 = COPY [[LXVW4X]]
  ; CHECK:   BLR implicit $lr, implicit $rm, implicit $v2
entry:
  %arg_list = alloca ptr, align 4
  call void @llvm.lifetime.start.p0(i64 4, ptr nonnull %arg_list)
  call void @llvm.va_start(ptr nonnull %arg_list)
  %argp.cur = load ptr, ptr %arg_list, align 4
  %0 = ptrtoint ptr %argp.cur to i32
  %1 = add i32 %0, 15
  %2 = and i32 %1, -16
  %argp.cur.aligned = inttoptr i32 %2 to ptr
  %argp.next = getelementptr inbounds i8, ptr %argp.cur.aligned, i32 16
  store ptr %argp.next, ptr %arg_list, align 4
  %3 = inttoptr i32 %2 to ptr
  %4 = load <4 x i32>, ptr %3, align 16
  call void @llvm.va_end(ptr nonnull %arg_list)
  call void @llvm.lifetime.end.p0(i64 4, ptr nonnull %arg_list)
  ret <4 x i32> %4
}

declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture)

declare void @llvm.va_start(ptr)

declare void @llvm.va_end(ptr)

declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture)

