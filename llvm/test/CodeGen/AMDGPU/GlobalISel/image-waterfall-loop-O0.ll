; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -global-isel -O0 -mtriple=amdgcn-amd-amdhsa -mcpu=gfx1031 -verify-machineinstrs -o - %s | FileCheck %s

; Make sure the waterfall loop does not fail the verifier after regalloc fast
;
; FIXME: There are a lot of extra spills that aren't needed. This is due to the unmerge_merge combine
;        running after RegBankSelect which inserts a lot of COPY instructions, but the original merge
;        instruction (G_BUILD_VECTOR) stays because it has more than one use.
;        Those spills are not present when optimizations are enabled.
define <4 x float> @waterfall_loop(<8 x i32> %vgpr_srd) {
; CHECK-LABEL: waterfall_loop:
; CHECK:       ; %bb.0: ; %bb
; CHECK-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; CHECK-NEXT:    s_waitcnt_vscnt null, 0x0
; CHECK-NEXT:    s_xor_saveexec_b32 s4, -1
; CHECK-NEXT:    buffer_store_dword v8, off, s[0:3], s32 offset:76 ; 4-byte Folded Spill
; CHECK-NEXT:    s_mov_b32 exec_lo, s4
; CHECK-NEXT:    buffer_store_dword v0, off, s[0:3], s32 offset:68 ; 4-byte Folded Spill
; CHECK-NEXT:    v_mov_b32_e32 v15, v1
; CHECK-NEXT:    buffer_store_dword v15, off, s[0:3], s32 offset:64 ; 4-byte Folded Spill
; CHECK-NEXT:    v_mov_b32_e32 v14, v2
; CHECK-NEXT:    buffer_store_dword v14, off, s[0:3], s32 offset:60 ; 4-byte Folded Spill
; CHECK-NEXT:    v_mov_b32_e32 v13, v3
; CHECK-NEXT:    buffer_store_dword v13, off, s[0:3], s32 offset:56 ; 4-byte Folded Spill
; CHECK-NEXT:    v_mov_b32_e32 v12, v4
; CHECK-NEXT:    buffer_store_dword v12, off, s[0:3], s32 offset:52 ; 4-byte Folded Spill
; CHECK-NEXT:    v_mov_b32_e32 v11, v5
; CHECK-NEXT:    buffer_store_dword v11, off, s[0:3], s32 offset:48 ; 4-byte Folded Spill
; CHECK-NEXT:    v_mov_b32_e32 v10, v6
; CHECK-NEXT:    buffer_store_dword v10, off, s[0:3], s32 offset:44 ; 4-byte Folded Spill
; CHECK-NEXT:    v_mov_b32_e32 v9, v7
; CHECK-NEXT:    buffer_store_dword v9, off, s[0:3], s32 offset:40 ; 4-byte Folded Spill
; CHECK-NEXT:    ; kill: def $vgpr0 killed $vgpr0 def $vgpr0_vgpr1_vgpr2_vgpr3_vgpr4_vgpr5_vgpr6_vgpr7 killed $exec
; CHECK-NEXT:    v_mov_b32_e32 v1, v15
; CHECK-NEXT:    v_mov_b32_e32 v2, v14
; CHECK-NEXT:    v_mov_b32_e32 v3, v13
; CHECK-NEXT:    v_mov_b32_e32 v4, v12
; CHECK-NEXT:    v_mov_b32_e32 v5, v11
; CHECK-NEXT:    v_mov_b32_e32 v6, v10
; CHECK-NEXT:    v_mov_b32_e32 v7, v9
; CHECK-NEXT:    buffer_store_dword v0, off, s[0:3], s32 offset:8 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v1, off, s[0:3], s32 offset:12 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v2, off, s[0:3], s32 offset:16 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v3, off, s[0:3], s32 offset:20 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v4, off, s[0:3], s32 offset:24 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v5, off, s[0:3], s32 offset:28 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v6, off, s[0:3], s32 offset:32 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v7, off, s[0:3], s32 offset:36 ; 4-byte Folded Spill
; CHECK-NEXT:    s_mov_b32 s8, 0
; CHECK-NEXT:    s_mov_b32 s4, s8
; CHECK-NEXT:    s_mov_b32 s5, s8
; CHECK-NEXT:    s_mov_b32 s6, s8
; CHECK-NEXT:    s_mov_b32 s7, s8
; CHECK-NEXT:    v_writelane_b32 v8, s4, 0
; CHECK-NEXT:    v_writelane_b32 v8, s5, 1
; CHECK-NEXT:    v_writelane_b32 v8, s6, 2
; CHECK-NEXT:    v_writelane_b32 v8, s7, 3
; CHECK-NEXT:    s_mov_b32 s6, 0
; CHECK-NEXT:    s_mov_b32 s4, s6
; CHECK-NEXT:    s_mov_b32 s5, s6
; CHECK-NEXT:    v_mov_b32_e32 v0, s4
; CHECK-NEXT:    v_mov_b32_e32 v1, s5
; CHECK-NEXT:    buffer_store_dword v0, off, s[0:3], s32 ; 4-byte Folded Spill
; CHECK-NEXT:    buffer_store_dword v1, off, s[0:3], s32 offset:4 ; 4-byte Folded Spill
; CHECK-NEXT:    s_mov_b32 s4, exec_lo
; CHECK-NEXT:    v_writelane_b32 v8, s4, 4
; CHECK-NEXT:  .LBB0_1: ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    buffer_load_dword v9, off, s[0:3], s32 offset:8 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v10, off, s[0:3], s32 offset:12 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v11, off, s[0:3], s32 offset:16 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v12, off, s[0:3], s32 offset:20 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v13, off, s[0:3], s32 offset:24 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v14, off, s[0:3], s32 offset:28 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v15, off, s[0:3], s32 offset:32 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v16, off, s[0:3], s32 offset:36 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v0, off, s[0:3], s32 offset:40 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v1, off, s[0:3], s32 offset:44 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v2, off, s[0:3], s32 offset:48 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v3, off, s[0:3], s32 offset:52 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v4, off, s[0:3], s32 offset:56 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v5, off, s[0:3], s32 offset:60 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v6, off, s[0:3], s32 offset:64 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v7, off, s[0:3], s32 offset:68 ; 4-byte Folded Reload
; CHECK-NEXT:    s_waitcnt vmcnt(0)
; CHECK-NEXT:    v_readfirstlane_b32 s12, v7
; CHECK-NEXT:    v_readfirstlane_b32 s10, v6
; CHECK-NEXT:    v_readfirstlane_b32 s9, v5
; CHECK-NEXT:    v_readfirstlane_b32 s8, v4
; CHECK-NEXT:    v_readfirstlane_b32 s7, v3
; CHECK-NEXT:    v_readfirstlane_b32 s6, v2
; CHECK-NEXT:    v_readfirstlane_b32 s5, v1
; CHECK-NEXT:    v_readfirstlane_b32 s4, v0
; CHECK-NEXT:    ; kill: def $sgpr12 killed $sgpr12 def $sgpr12_sgpr13_sgpr14_sgpr15_sgpr16_sgpr17_sgpr18_sgpr19
; CHECK-NEXT:    s_mov_b32 s13, s10
; CHECK-NEXT:    s_mov_b32 s14, s9
; CHECK-NEXT:    s_mov_b32 s15, s8
; CHECK-NEXT:    s_mov_b32 s16, s7
; CHECK-NEXT:    s_mov_b32 s17, s6
; CHECK-NEXT:    s_mov_b32 s18, s5
; CHECK-NEXT:    s_mov_b32 s19, s4
; CHECK-NEXT:    v_writelane_b32 v8, s12, 5
; CHECK-NEXT:    v_writelane_b32 v8, s13, 6
; CHECK-NEXT:    v_writelane_b32 v8, s14, 7
; CHECK-NEXT:    v_writelane_b32 v8, s15, 8
; CHECK-NEXT:    v_writelane_b32 v8, s16, 9
; CHECK-NEXT:    v_writelane_b32 v8, s17, 10
; CHECK-NEXT:    v_writelane_b32 v8, s18, 11
; CHECK-NEXT:    v_writelane_b32 v8, s19, 12
; CHECK-NEXT:    v_mov_b32_e32 v6, v9
; CHECK-NEXT:    v_mov_b32_e32 v7, v10
; CHECK-NEXT:    v_mov_b32_e32 v4, v11
; CHECK-NEXT:    v_mov_b32_e32 v5, v12
; CHECK-NEXT:    v_mov_b32_e32 v2, v13
; CHECK-NEXT:    v_mov_b32_e32 v3, v14
; CHECK-NEXT:    v_mov_b32_e32 v0, v15
; CHECK-NEXT:    v_mov_b32_e32 v1, v16
; CHECK-NEXT:    s_mov_b64 s[4:5], s[12:13]
; CHECK-NEXT:    s_mov_b64 s[10:11], s[14:15]
; CHECK-NEXT:    s_mov_b64 s[8:9], s[16:17]
; CHECK-NEXT:    s_mov_b64 s[6:7], s[18:19]
; CHECK-NEXT:    v_cmp_eq_u64_e64 s4, s[4:5], v[6:7]
; CHECK-NEXT:    v_cmp_eq_u64_e64 s5, s[10:11], v[4:5]
; CHECK-NEXT:    s_and_b32 s4, s4, s5
; CHECK-NEXT:    v_cmp_eq_u64_e64 s5, s[8:9], v[2:3]
; CHECK-NEXT:    s_and_b32 s4, s4, s5
; CHECK-NEXT:    v_cmp_eq_u64_e64 s5, s[6:7], v[0:1]
; CHECK-NEXT:    s_and_b32 s4, s4, s5
; CHECK-NEXT:    s_and_saveexec_b32 s4, s4
; CHECK-NEXT:    v_writelane_b32 v8, s4, 13
; CHECK-NEXT:  ; %bb.2: ; in Loop: Header=BB0_1 Depth=1
; CHECK-NEXT:    buffer_load_dword v0, off, s[0:3], s32 ; 4-byte Folded Reload
; CHECK-NEXT:    buffer_load_dword v1, off, s[0:3], s32 offset:4 ; 4-byte Folded Reload
; CHECK-NEXT:    v_readlane_b32 s4, v8, 13
; CHECK-NEXT:    v_readlane_b32 s8, v8, 5
; CHECK-NEXT:    v_readlane_b32 s9, v8, 6
; CHECK-NEXT:    v_readlane_b32 s10, v8, 7
; CHECK-NEXT:    v_readlane_b32 s11, v8, 8
; CHECK-NEXT:    v_readlane_b32 s12, v8, 9
; CHECK-NEXT:    v_readlane_b32 s13, v8, 10
; CHECK-NEXT:    v_readlane_b32 s14, v8, 11
; CHECK-NEXT:    v_readlane_b32 s15, v8, 12
; CHECK-NEXT:    v_readlane_b32 s16, v8, 0
; CHECK-NEXT:    v_readlane_b32 s17, v8, 1
; CHECK-NEXT:    v_readlane_b32 s18, v8, 2
; CHECK-NEXT:    v_readlane_b32 s19, v8, 3
; CHECK-NEXT:    s_waitcnt vmcnt(0)
; CHECK-NEXT:    image_sample v0, v[0:1], s[8:15], s[16:19] dmask:0x1 dim:SQ_RSRC_IMG_2D
; CHECK-NEXT:    s_waitcnt vmcnt(0)
; CHECK-NEXT:    buffer_store_dword v0, off, s[0:3], s32 offset:72 ; 4-byte Folded Spill
; CHECK-NEXT:    s_xor_b32 exec_lo, exec_lo, s4
; CHECK-NEXT:    s_cbranch_execnz .LBB0_1
; CHECK-NEXT:  ; %bb.3:
; CHECK-NEXT:    v_readlane_b32 s4, v8, 4
; CHECK-NEXT:    s_mov_b32 exec_lo, s4
; CHECK-NEXT:  ; %bb.4:
; CHECK-NEXT:    buffer_load_dword v0, off, s[0:3], s32 offset:72 ; 4-byte Folded Reload
; CHECK-NEXT:    ; implicit-def: $sgpr4
; CHECK-NEXT:    v_mov_b32_e32 v1, s4
; CHECK-NEXT:    v_mov_b32_e32 v2, s4
; CHECK-NEXT:    v_mov_b32_e32 v3, s4
; CHECK-NEXT:    s_xor_saveexec_b32 s4, -1
; CHECK-NEXT:    buffer_load_dword v8, off, s[0:3], s32 offset:76 ; 4-byte Folded Reload
; CHECK-NEXT:    s_mov_b32 exec_lo, s4
; CHECK-NEXT:    s_waitcnt vmcnt(0)
; CHECK-NEXT:    s_waitcnt_vscnt null, 0x0
; CHECK-NEXT:    s_setpc_b64 s[30:31]
bb:
  %ret = tail call <4 x float> @llvm.amdgcn.image.sample.2d.v4f32.f32(i32 1, float 0.000000e+00, float 0.000000e+00, <8 x i32> %vgpr_srd, <4 x i32> zeroinitializer, i1 false, i32 0, i32 0)
  ret <4 x float> %ret
}

declare <4 x float> @llvm.amdgcn.image.sample.2d.v4f32.f32(i32 immarg, float, float, <8 x i32>, <4 x i32>, i1 immarg, i32 immarg, i32 immarg) #0

attributes #0 = { nounwind readonly willreturn }
