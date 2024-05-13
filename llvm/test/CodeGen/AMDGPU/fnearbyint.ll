; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -march=amdgcn -verify-machineinstrs < %s | FileCheck -check-prefixes=SICI,SI %s
; RUN: llc -march=amdgcn -mcpu=bonaire -verify-machineinstrs < %s | FileCheck -check-prefixes=SICI,CI %s
; RUN: llc -march=amdgcn -mcpu=tonga -verify-machineinstrs < %s | FileCheck -check-prefixes=VI %s

declare half @llvm.nearbyint.f16(half) #0
declare float @llvm.nearbyint.f32(float) #0
declare <2 x float> @llvm.nearbyint.v2f32(<2 x float>) #0
declare <4 x float> @llvm.nearbyint.v4f32(<4 x float>) #0
declare double @llvm.nearbyint.f64(double) #0
declare <2 x double> @llvm.nearbyint.v2f64(<2 x double>) #0
declare <4 x double> @llvm.nearbyint.v4f64(<4 x double>) #0

define amdgpu_kernel void @fnearbyint_f16(ptr addrspace(1) %out, half %in) #1 {
; SI-LABEL: fnearbyint_f16:
; SI:       ; %bb.0:
; SI-NEXT:    s_load_dword s4, s[0:1], 0xb
; SI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x9
; SI-NEXT:    s_mov_b32 s3, 0xf000
; SI-NEXT:    s_mov_b32 s2, -1
; SI-NEXT:    s_waitcnt lgkmcnt(0)
; SI-NEXT:    v_cvt_f32_f16_e32 v0, s4
; SI-NEXT:    v_rndne_f32_e32 v0, v0
; SI-NEXT:    v_cvt_f16_f32_e32 v0, v0
; SI-NEXT:    buffer_store_short v0, off, s[0:3], 0
; SI-NEXT:    s_endpgm
;
; CI-LABEL: fnearbyint_f16:
; CI:       ; %bb.0:
; CI-NEXT:    s_load_dword s2, s[0:1], 0xb
; CI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x9
; CI-NEXT:    s_mov_b32 s3, 0xf000
; CI-NEXT:    s_waitcnt lgkmcnt(0)
; CI-NEXT:    v_cvt_f32_f16_e32 v0, s2
; CI-NEXT:    s_mov_b32 s2, -1
; CI-NEXT:    v_rndne_f32_e32 v0, v0
; CI-NEXT:    v_cvt_f16_f32_e32 v0, v0
; CI-NEXT:    buffer_store_short v0, off, s[0:3], 0
; CI-NEXT:    s_endpgm
;
; VI-LABEL: fnearbyint_f16:
; VI:       ; %bb.0:
; VI-NEXT:    s_load_dword s2, s[0:1], 0x2c
; VI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x24
; VI-NEXT:    s_waitcnt lgkmcnt(0)
; VI-NEXT:    v_rndne_f16_e32 v2, s2
; VI-NEXT:    v_mov_b32_e32 v0, s0
; VI-NEXT:    v_mov_b32_e32 v1, s1
; VI-NEXT:    flat_store_short v[0:1], v2
; VI-NEXT:    s_endpgm
  %1 = call half @llvm.nearbyint.f16(half %in)
  store half %1, ptr addrspace(1) %out
  ret void
}

define amdgpu_kernel void @fnearbyint_f32(ptr addrspace(1) %out, float %in) #1 {
; SICI-LABEL: fnearbyint_f32:
; SICI:       ; %bb.0: ; %entry
; SICI-NEXT:    s_load_dword s4, s[0:1], 0xb
; SICI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x9
; SICI-NEXT:    s_mov_b32 s3, 0xf000
; SICI-NEXT:    s_mov_b32 s2, -1
; SICI-NEXT:    s_waitcnt lgkmcnt(0)
; SICI-NEXT:    v_rndne_f32_e32 v0, s4
; SICI-NEXT:    buffer_store_dword v0, off, s[0:3], 0
; SICI-NEXT:    s_endpgm
;
; VI-LABEL: fnearbyint_f32:
; VI:       ; %bb.0: ; %entry
; VI-NEXT:    s_load_dword s2, s[0:1], 0x2c
; VI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x24
; VI-NEXT:    s_waitcnt lgkmcnt(0)
; VI-NEXT:    v_rndne_f32_e32 v2, s2
; VI-NEXT:    v_mov_b32_e32 v0, s0
; VI-NEXT:    v_mov_b32_e32 v1, s1
; VI-NEXT:    flat_store_dword v[0:1], v2
; VI-NEXT:    s_endpgm
entry:
  %0 = call float @llvm.nearbyint.f32(float %in)
  store float %0, ptr addrspace(1) %out
  ret void
}

define amdgpu_kernel void @fnearbyint_v2f32(ptr addrspace(1) %out, <2 x float> %in) #1 {
; SICI-LABEL: fnearbyint_v2f32:
; SICI:       ; %bb.0: ; %entry
; SICI-NEXT:    s_load_dwordx4 s[0:3], s[0:1], 0x9
; SICI-NEXT:    s_mov_b32 s7, 0xf000
; SICI-NEXT:    s_mov_b32 s6, -1
; SICI-NEXT:    s_waitcnt lgkmcnt(0)
; SICI-NEXT:    s_mov_b32 s4, s0
; SICI-NEXT:    s_mov_b32 s5, s1
; SICI-NEXT:    v_rndne_f32_e32 v1, s3
; SICI-NEXT:    v_rndne_f32_e32 v0, s2
; SICI-NEXT:    buffer_store_dwordx2 v[0:1], off, s[4:7], 0
; SICI-NEXT:    s_endpgm
;
; VI-LABEL: fnearbyint_v2f32:
; VI:       ; %bb.0: ; %entry
; VI-NEXT:    s_load_dwordx4 s[0:3], s[0:1], 0x24
; VI-NEXT:    s_waitcnt lgkmcnt(0)
; VI-NEXT:    v_mov_b32_e32 v3, s1
; VI-NEXT:    v_rndne_f32_e32 v1, s3
; VI-NEXT:    v_rndne_f32_e32 v0, s2
; VI-NEXT:    v_mov_b32_e32 v2, s0
; VI-NEXT:    flat_store_dwordx2 v[2:3], v[0:1]
; VI-NEXT:    s_endpgm
entry:
  %0 = call <2 x float> @llvm.nearbyint.v2f32(<2 x float> %in)
  store <2 x float> %0, ptr addrspace(1) %out
  ret void
}

define amdgpu_kernel void @fnearbyint_v4f32(ptr addrspace(1) %out, <4 x float> %in) #1 {
; SICI-LABEL: fnearbyint_v4f32:
; SICI:       ; %bb.0: ; %entry
; SICI-NEXT:    s_load_dwordx4 s[4:7], s[0:1], 0xd
; SICI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x9
; SICI-NEXT:    s_mov_b32 s3, 0xf000
; SICI-NEXT:    s_mov_b32 s2, -1
; SICI-NEXT:    s_waitcnt lgkmcnt(0)
; SICI-NEXT:    v_rndne_f32_e32 v3, s7
; SICI-NEXT:    v_rndne_f32_e32 v2, s6
; SICI-NEXT:    v_rndne_f32_e32 v1, s5
; SICI-NEXT:    v_rndne_f32_e32 v0, s4
; SICI-NEXT:    buffer_store_dwordx4 v[0:3], off, s[0:3], 0
; SICI-NEXT:    s_endpgm
;
; VI-LABEL: fnearbyint_v4f32:
; VI:       ; %bb.0: ; %entry
; VI-NEXT:    s_load_dwordx4 s[4:7], s[0:1], 0x34
; VI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x24
; VI-NEXT:    s_waitcnt lgkmcnt(0)
; VI-NEXT:    v_rndne_f32_e32 v3, s7
; VI-NEXT:    v_mov_b32_e32 v5, s1
; VI-NEXT:    v_rndne_f32_e32 v2, s6
; VI-NEXT:    v_rndne_f32_e32 v1, s5
; VI-NEXT:    v_rndne_f32_e32 v0, s4
; VI-NEXT:    v_mov_b32_e32 v4, s0
; VI-NEXT:    flat_store_dwordx4 v[4:5], v[0:3]
; VI-NEXT:    s_endpgm
entry:
  %0 = call <4 x float> @llvm.nearbyint.v4f32(<4 x float> %in)
  store <4 x float> %0, ptr addrspace(1) %out
  ret void
}

define amdgpu_kernel void @nearbyint_f64(ptr addrspace(1) %out, double %in) {
; SI-LABEL: nearbyint_f64:
; SI:       ; %bb.0: ; %entry
; SI-NEXT:    s_load_dwordx4 s[0:3], s[0:1], 0x9
; SI-NEXT:    s_mov_b32 s7, 0xf000
; SI-NEXT:    s_mov_b32 s6, -1
; SI-NEXT:    s_brev_b32 s8, -2
; SI-NEXT:    v_mov_b32_e32 v1, 0x43300000
; SI-NEXT:    v_mov_b32_e32 v0, 0
; SI-NEXT:    v_mov_b32_e32 v2, -1
; SI-NEXT:    v_mov_b32_e32 v3, 0x432fffff
; SI-NEXT:    s_waitcnt lgkmcnt(0)
; SI-NEXT:    s_mov_b32 s4, s0
; SI-NEXT:    s_mov_b32 s5, s1
; SI-NEXT:    v_mov_b32_e32 v6, s3
; SI-NEXT:    v_bfi_b32 v1, s8, v1, v6
; SI-NEXT:    v_mov_b32_e32 v7, s2
; SI-NEXT:    v_add_f64 v[4:5], s[2:3], v[0:1]
; SI-NEXT:    v_add_f64 v[0:1], v[4:5], -v[0:1]
; SI-NEXT:    v_cmp_gt_f64_e64 vcc, |s[2:3]|, v[2:3]
; SI-NEXT:    v_cndmask_b32_e32 v1, v1, v6, vcc
; SI-NEXT:    v_cndmask_b32_e32 v0, v0, v7, vcc
; SI-NEXT:    buffer_store_dwordx2 v[0:1], off, s[4:7], 0
; SI-NEXT:    s_endpgm
;
; CI-LABEL: nearbyint_f64:
; CI:       ; %bb.0: ; %entry
; CI-NEXT:    s_load_dwordx4 s[0:3], s[0:1], 0x9
; CI-NEXT:    s_waitcnt lgkmcnt(0)
; CI-NEXT:    v_rndne_f64_e32 v[0:1], s[2:3]
; CI-NEXT:    s_mov_b32 s3, 0xf000
; CI-NEXT:    s_mov_b32 s2, -1
; CI-NEXT:    buffer_store_dwordx2 v[0:1], off, s[0:3], 0
; CI-NEXT:    s_endpgm
;
; VI-LABEL: nearbyint_f64:
; VI:       ; %bb.0: ; %entry
; VI-NEXT:    s_load_dwordx4 s[0:3], s[0:1], 0x24
; VI-NEXT:    s_waitcnt lgkmcnt(0)
; VI-NEXT:    v_rndne_f64_e32 v[0:1], s[2:3]
; VI-NEXT:    v_mov_b32_e32 v2, s0
; VI-NEXT:    v_mov_b32_e32 v3, s1
; VI-NEXT:    flat_store_dwordx2 v[2:3], v[0:1]
; VI-NEXT:    s_endpgm
entry:
  %0 = call double @llvm.nearbyint.f64(double %in)
  store double %0, ptr addrspace(1) %out
  ret void
}
define amdgpu_kernel void @nearbyint_v2f64(ptr addrspace(1) %out, <2 x double> %in) {
; SI-LABEL: nearbyint_v2f64:
; SI:       ; %bb.0: ; %entry
; SI-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x9
; SI-NEXT:    s_load_dwordx4 s[0:3], s[0:1], 0xd
; SI-NEXT:    s_mov_b32 s7, 0xf000
; SI-NEXT:    s_mov_b32 s6, -1
; SI-NEXT:    s_brev_b32 s10, -2
; SI-NEXT:    v_mov_b32_e32 v6, 0x43300000
; SI-NEXT:    s_mov_b32 s9, 0x432fffff
; SI-NEXT:    v_mov_b32_e32 v0, 0
; SI-NEXT:    s_mov_b32 s8, s6
; SI-NEXT:    v_mov_b32_e32 v4, s8
; SI-NEXT:    v_mov_b32_e32 v5, s9
; SI-NEXT:    s_waitcnt lgkmcnt(0)
; SI-NEXT:    v_mov_b32_e32 v7, s3
; SI-NEXT:    v_bfi_b32 v1, s10, v6, v7
; SI-NEXT:    v_mov_b32_e32 v8, s2
; SI-NEXT:    v_mov_b32_e32 v9, s1
; SI-NEXT:    v_mov_b32_e32 v10, s0
; SI-NEXT:    v_add_f64 v[2:3], s[2:3], v[0:1]
; SI-NEXT:    v_add_f64 v[2:3], v[2:3], -v[0:1]
; SI-NEXT:    v_bfi_b32 v1, s10, v6, v9
; SI-NEXT:    v_cmp_gt_f64_e64 vcc, |s[2:3]|, v[4:5]
; SI-NEXT:    v_cndmask_b32_e32 v3, v3, v7, vcc
; SI-NEXT:    v_cndmask_b32_e32 v2, v2, v8, vcc
; SI-NEXT:    v_add_f64 v[6:7], s[0:1], v[0:1]
; SI-NEXT:    v_add_f64 v[0:1], v[6:7], -v[0:1]
; SI-NEXT:    v_cmp_gt_f64_e64 vcc, |s[0:1]|, v[4:5]
; SI-NEXT:    v_cndmask_b32_e32 v1, v1, v9, vcc
; SI-NEXT:    v_cndmask_b32_e32 v0, v0, v10, vcc
; SI-NEXT:    buffer_store_dwordx4 v[0:3], off, s[4:7], 0
; SI-NEXT:    s_endpgm
;
; CI-LABEL: nearbyint_v2f64:
; CI:       ; %bb.0: ; %entry
; CI-NEXT:    s_load_dwordx4 s[4:7], s[0:1], 0xd
; CI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x9
; CI-NEXT:    s_mov_b32 s3, 0xf000
; CI-NEXT:    s_mov_b32 s2, -1
; CI-NEXT:    s_waitcnt lgkmcnt(0)
; CI-NEXT:    v_rndne_f64_e32 v[2:3], s[6:7]
; CI-NEXT:    v_rndne_f64_e32 v[0:1], s[4:5]
; CI-NEXT:    buffer_store_dwordx4 v[0:3], off, s[0:3], 0
; CI-NEXT:    s_endpgm
;
; VI-LABEL: nearbyint_v2f64:
; VI:       ; %bb.0: ; %entry
; VI-NEXT:    s_load_dwordx4 s[4:7], s[0:1], 0x34
; VI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x24
; VI-NEXT:    s_waitcnt lgkmcnt(0)
; VI-NEXT:    v_rndne_f64_e32 v[2:3], s[6:7]
; VI-NEXT:    v_rndne_f64_e32 v[0:1], s[4:5]
; VI-NEXT:    v_mov_b32_e32 v5, s1
; VI-NEXT:    v_mov_b32_e32 v4, s0
; VI-NEXT:    flat_store_dwordx4 v[4:5], v[0:3]
; VI-NEXT:    s_endpgm
entry:
  %0 = call <2 x double> @llvm.nearbyint.v2f64(<2 x double> %in)
  store <2 x double> %0, ptr addrspace(1) %out
  ret void
}

define amdgpu_kernel void @nearbyint_v4f64(ptr addrspace(1) %out, <4 x double> %in) {
; SI-LABEL: nearbyint_v4f64:
; SI:       ; %bb.0: ; %entry
; SI-NEXT:    s_load_dwordx2 s[8:9], s[0:1], 0x9
; SI-NEXT:    s_load_dwordx8 s[0:7], s[0:1], 0x11
; SI-NEXT:    s_mov_b32 s11, 0xf000
; SI-NEXT:    s_mov_b32 s10, -1
; SI-NEXT:    s_brev_b32 s14, -2
; SI-NEXT:    v_mov_b32_e32 v10, 0x43300000
; SI-NEXT:    s_mov_b32 s13, 0x432fffff
; SI-NEXT:    v_mov_b32_e32 v4, 0
; SI-NEXT:    s_mov_b32 s12, s10
; SI-NEXT:    v_mov_b32_e32 v8, s12
; SI-NEXT:    v_mov_b32_e32 v9, s13
; SI-NEXT:    s_waitcnt lgkmcnt(0)
; SI-NEXT:    v_mov_b32_e32 v2, s3
; SI-NEXT:    v_bfi_b32 v5, s14, v10, v2
; SI-NEXT:    v_mov_b32_e32 v6, s2
; SI-NEXT:    v_mov_b32_e32 v7, s1
; SI-NEXT:    v_mov_b32_e32 v11, s0
; SI-NEXT:    v_mov_b32_e32 v12, s7
; SI-NEXT:    v_mov_b32_e32 v13, s6
; SI-NEXT:    v_mov_b32_e32 v14, s5
; SI-NEXT:    v_mov_b32_e32 v15, s4
; SI-NEXT:    v_add_f64 v[0:1], s[2:3], v[4:5]
; SI-NEXT:    v_add_f64 v[0:1], v[0:1], -v[4:5]
; SI-NEXT:    v_bfi_b32 v5, s14, v10, v7
; SI-NEXT:    v_cmp_gt_f64_e64 vcc, |s[2:3]|, v[8:9]
; SI-NEXT:    v_cndmask_b32_e32 v3, v1, v2, vcc
; SI-NEXT:    v_cndmask_b32_e32 v2, v0, v6, vcc
; SI-NEXT:    v_add_f64 v[0:1], s[0:1], v[4:5]
; SI-NEXT:    v_add_f64 v[0:1], v[0:1], -v[4:5]
; SI-NEXT:    v_bfi_b32 v5, s14, v10, v12
; SI-NEXT:    v_cmp_gt_f64_e64 vcc, |s[0:1]|, v[8:9]
; SI-NEXT:    v_cndmask_b32_e32 v1, v1, v7, vcc
; SI-NEXT:    v_cndmask_b32_e32 v0, v0, v11, vcc
; SI-NEXT:    v_add_f64 v[6:7], s[6:7], v[4:5]
; SI-NEXT:    v_add_f64 v[6:7], v[6:7], -v[4:5]
; SI-NEXT:    v_bfi_b32 v5, s14, v10, v14
; SI-NEXT:    v_cmp_gt_f64_e64 vcc, |s[6:7]|, v[8:9]
; SI-NEXT:    v_cndmask_b32_e32 v7, v7, v12, vcc
; SI-NEXT:    v_cndmask_b32_e32 v6, v6, v13, vcc
; SI-NEXT:    v_add_f64 v[10:11], s[4:5], v[4:5]
; SI-NEXT:    v_add_f64 v[4:5], v[10:11], -v[4:5]
; SI-NEXT:    v_cmp_gt_f64_e64 vcc, |s[4:5]|, v[8:9]
; SI-NEXT:    v_cndmask_b32_e32 v5, v5, v14, vcc
; SI-NEXT:    v_cndmask_b32_e32 v4, v4, v15, vcc
; SI-NEXT:    buffer_store_dwordx4 v[4:7], off, s[8:11], 0 offset:16
; SI-NEXT:    buffer_store_dwordx4 v[0:3], off, s[8:11], 0
; SI-NEXT:    s_endpgm
;
; CI-LABEL: nearbyint_v4f64:
; CI:       ; %bb.0: ; %entry
; CI-NEXT:    s_load_dwordx8 s[4:11], s[0:1], 0x11
; CI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x9
; CI-NEXT:    s_mov_b32 s3, 0xf000
; CI-NEXT:    s_mov_b32 s2, -1
; CI-NEXT:    s_waitcnt lgkmcnt(0)
; CI-NEXT:    v_rndne_f64_e32 v[6:7], s[10:11]
; CI-NEXT:    v_rndne_f64_e32 v[4:5], s[8:9]
; CI-NEXT:    v_rndne_f64_e32 v[2:3], s[6:7]
; CI-NEXT:    v_rndne_f64_e32 v[0:1], s[4:5]
; CI-NEXT:    buffer_store_dwordx4 v[4:7], off, s[0:3], 0 offset:16
; CI-NEXT:    buffer_store_dwordx4 v[0:3], off, s[0:3], 0
; CI-NEXT:    s_endpgm
;
; VI-LABEL: nearbyint_v4f64:
; VI:       ; %bb.0: ; %entry
; VI-NEXT:    s_load_dwordx8 s[4:11], s[0:1], 0x44
; VI-NEXT:    s_load_dwordx2 s[0:1], s[0:1], 0x24
; VI-NEXT:    s_waitcnt lgkmcnt(0)
; VI-NEXT:    v_rndne_f64_e32 v[6:7], s[10:11]
; VI-NEXT:    v_rndne_f64_e32 v[4:5], s[8:9]
; VI-NEXT:    v_rndne_f64_e32 v[2:3], s[6:7]
; VI-NEXT:    v_rndne_f64_e32 v[0:1], s[4:5]
; VI-NEXT:    s_add_u32 s2, s0, 16
; VI-NEXT:    s_addc_u32 s3, s1, 0
; VI-NEXT:    v_mov_b32_e32 v11, s3
; VI-NEXT:    v_mov_b32_e32 v9, s1
; VI-NEXT:    v_mov_b32_e32 v10, s2
; VI-NEXT:    v_mov_b32_e32 v8, s0
; VI-NEXT:    flat_store_dwordx4 v[10:11], v[4:7]
; VI-NEXT:    flat_store_dwordx4 v[8:9], v[0:3]
; VI-NEXT:    s_endpgm
entry:
  %0 = call <4 x double> @llvm.nearbyint.v4f64(<4 x double> %in)
  store <4 x double> %0, ptr addrspace(1) %out
  ret void
}

attributes #0 = { nounwind readonly }
attributes #1 = { nounwind }
