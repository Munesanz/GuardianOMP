; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -mtriple=amdgcn-amd-amdhsa -passes=separate-const-offset-from-gep \
; RUN:       -reassociate-geps-verify-no-dead-code -S | FileCheck %s

%struct.Packed = type <{ [3 x i32], [8 x i64] }> ; <> means packed

@packed_struct_array = addrspace(3) global [1024 x %struct.Packed] poison, align 1

; Verifies we can emit correct uglygep if the address is not natually
; aligned. This shoult not produce a no-op bitcast with opaque
; pointers.
define ptr addrspace(3) @packed_struct(i32 %i, i32 %j) {
; CHECK-LABEL: @packed_struct(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = sext i32 [[I:%.*]] to i64
; CHECK-NEXT:    [[TMP1:%.*]] = sext i32 [[J:%.*]] to i64
; CHECK-NEXT:    [[TMP2:%.*]] = getelementptr [1024 x %struct.Packed], ptr addrspace(3) @packed_struct_array, i64 0, i64 [[TMP0]], i32 1, i64 [[TMP1]]
; CHECK-NEXT:    [[UGLYGEP:%.*]] = getelementptr inbounds i8, ptr addrspace(3) [[TMP2]], i64 100
; CHECK-NEXT:    ret ptr addrspace(3) [[UGLYGEP]]
;
entry:
  %add = add nsw i32 %j, 3
  %add1 = add nsw i32 %i, 1
  %arrayidx3 = getelementptr inbounds [1024 x %struct.Packed], ptr addrspace(3) @packed_struct_array, i64 0, i32 %add1, i32 1, i32 %add
  ret ptr addrspace(3) %arrayidx3
}
