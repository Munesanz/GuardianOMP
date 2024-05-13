; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -o - %s -mtriple=amdgcn-amd-amdhsa -mcpu=gfx90a -verify-machineinstrs | FileCheck %s

@global = external protected addrspace(4) externally_initialized global [4096 x i64], align 16

define hidden fastcc void @bar(i32 %arg, ptr %arg1, ptr %arg2, ptr %arg3, ptr %arg4, ptr %arg5, ptr %arg6) unnamed_addr align 2 {
; CHECK-LABEL: bar:
; CHECK:       ; %bb.0: ; %bb
; CHECK-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; CHECK-NEXT:    v_mov_b32_e32 v15, v12
; CHECK-NEXT:    v_mov_b32_e32 v14, v11
; CHECK-NEXT:    v_mov_b32_e32 v13, v10
; CHECK-NEXT:    v_mov_b32_e32 v12, v9
; CHECK-NEXT:    v_mov_b32_e32 v11, v8
; CHECK-NEXT:    v_mov_b32_e32 v10, v7
; CHECK-NEXT:    v_mov_b32_e32 v9, v6
; CHECK-NEXT:    v_mov_b32_e32 v8, v5
; CHECK-NEXT:    v_mov_b32_e32 v7, v4
; CHECK-NEXT:    v_mov_b32_e32 v6, v3
; CHECK-NEXT:    s_cmp_lt_i32 s4, 3
; CHECK-NEXT:    s_cbranch_scc0 .LBB0_3
; CHECK-NEXT:  ; %bb.1: ; %LeafBlock
; CHECK-NEXT:    s_cbranch_scc1 .LBB0_5
; CHECK-NEXT:  ; %bb.2: ; %bb7
; CHECK-NEXT:    flat_load_dwordx2 v[2:3], v[0:1]
; CHECK-NEXT:    s_getpc_b64 s[16:17]
; CHECK-NEXT:    s_add_u32 s16, s16, global@rel32@lo+1948
; CHECK-NEXT:    s_addc_u32 s17, s17, global@rel32@hi+1956
; CHECK-NEXT:    v_mov_b32_e32 v5, 0
; CHECK-NEXT:    v_mov_b32_e32 v0, s16
; CHECK-NEXT:    v_mov_b32_e32 v1, s17
; CHECK-NEXT:    s_getpc_b64 s[18:19]
; CHECK-NEXT:    s_add_u32 s18, s18, eggs@rel32@lo+4
; CHECK-NEXT:    s_addc_u32 s19, s19, eggs@rel32@hi+12
; CHECK-NEXT:    s_setpc_b64 s[18:19]
; CHECK-NEXT:  .LBB0_3: ; %LeafBlock1
; CHECK-NEXT:    s_cbranch_scc0 .LBB0_5
; CHECK-NEXT:  ; %bb.4: ; %bb8
; CHECK-NEXT:    v_mov_b32_e32 v0, v1
; CHECK-NEXT:    v_mov_b32_e32 v1, v2
; CHECK-NEXT:    v_mov_b32_e32 v2, v6
; CHECK-NEXT:    v_mov_b32_e32 v3, v7
; CHECK-NEXT:    v_mov_b32_e32 v4, v8
; CHECK-NEXT:    v_mov_b32_e32 v5, v9
; CHECK-NEXT:    v_mov_b32_e32 v6, v10
; CHECK-NEXT:    v_mov_b32_e32 v7, v11
; CHECK-NEXT:    v_mov_b32_e32 v8, v12
; CHECK-NEXT:    v_mov_b32_e32 v9, v13
; CHECK-NEXT:    v_mov_b32_e32 v10, v14
; CHECK-NEXT:    v_mov_b32_e32 v11, v15
; CHECK-NEXT:    s_getpc_b64 s[16:17]
; CHECK-NEXT:    s_add_u32 s16, s16, quux@rel32@lo+4
; CHECK-NEXT:    s_addc_u32 s17, s17, quux@rel32@hi+12
; CHECK-NEXT:    s_setpc_b64 s[16:17]
; CHECK-NEXT:  .LBB0_5: ; %bb9
; CHECK-NEXT:    s_setpc_b64 s[30:31]
bb:
  switch i32 undef, label %bb9 [
    i32 3, label %bb8
    i32 1, label %bb7
  ]

bb7:                                              ; preds = %bb
  %tmp = load ptr, ptr undef, align 8
  tail call fastcc void @eggs(ptr noundef addrspacecast (ptr addrspace(4) getelementptr inbounds ([4096 x i64], ptr addrspace(4) @global, i64 0, i64 243) to ptr), ptr %tmp, ptr undef, ptr noundef nonnull align 8 dereferenceable(24) %arg2, ptr noundef %arg3, ptr noundef %arg4, ptr noundef %arg5)
  br label %bb9

bb8:                                              ; preds = %bb
  tail call fastcc void @quux(ptr noundef nonnull align 8 dereferenceable(24) %arg1, ptr noundef nonnull align 8 dereferenceable(24) %arg2, ptr noundef %arg3, ptr noundef %arg4, ptr noundef %arg5, ptr noundef nonnull align 8 dereferenceable(8) %arg6)
  br label %bb9

bb9:                                              ; preds = %bb8, %bb7, %bb
  ret void
}

declare dso_local fastcc void @eggs(ptr, ptr, ptr, ptr, ptr, ptr, ptr) unnamed_addr align 2

declare dso_local fastcc void @quux(ptr, ptr, ptr, ptr, ptr, ptr) unnamed_addr align 2
