; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=vector-combine -S -mtriple=amdgcn-amd-amdhsa | FileCheck %s --check-prefixes=CHECK

; ModuleID = 'load-as-transition.ll'
target datalayout = "e-p:64:64-p1:64:64-p2:32:32-p3:32:32-p4:64:64-p5:32:32-p6:32:32-i64:64-v16:16-v24:32-v32:32-v48:64-v96:128-v192:256-v256:256-v512:512-v1024:1024-v2048:2048-n32:64-S32-A5-ni:7"
target triple = "amdgcn-amd-amdhsa"

%struct.hoge = type { float }

define protected amdgpu_kernel void @load_from_other_as(ptr nocapture nonnull %resultptr) local_unnamed_addr #0 {
; CHECK-LABEL: @load_from_other_as(
; CHECK-NEXT:  bb:
; CHECK-NEXT:    [[A:%.*]] = alloca [[STRUCT_HOGE:%.*]], align 4, addrspace(5)
; CHECK-NEXT:    [[TMP0:%.*]] = addrspacecast ptr addrspace(5) [[A]] to ptr
; CHECK-NEXT:    [[TMP1:%.*]] = load <1 x float>, ptr [[TMP0]], align 4
; CHECK-NEXT:    [[E:%.*]] = shufflevector <1 x float> [[TMP1]], <1 x float> poison, <4 x i32> <i32 0, i32 poison, i32 poison, i32 poison>
; CHECK-NEXT:    store <4 x float> [[E]], ptr [[RESULTPTR:%.*]], align 16
; CHECK-NEXT:    ret void
;
bb:
  %a = alloca %struct.hoge, align 4, addrspace(5)
  %b = addrspacecast ptr addrspace(5) %a to ptr
  %d = load float, ptr %b, align 4
  %e = insertelement <4 x float> poison, float %d, i32 0
  store <4 x float> %e, ptr %resultptr, align 16
  ret void
}

attributes #0 = { "use-soft-float"="false" }

!llvm.ident = !{!0}

!0 = !{!"clang version 12.0.0"}
