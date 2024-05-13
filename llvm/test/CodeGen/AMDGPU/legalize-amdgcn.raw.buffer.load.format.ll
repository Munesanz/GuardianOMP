; NOTE: Assertions have been autogenerated by utils/update_mir_test_checks.py UTC_ARGS: --version 2
; RUN: llc -march=amdgcn -mcpu=gfx908 -stop-after=si-fix-sgpr-copies -verify-machineinstrs < %s | FileCheck -check-prefix=GFX908 %s

; Natural mapping
define float @raw_buffer_load_format_f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset(<4 x i32> %rsrc, i32 %voffset, i32 %soffset) {
  ; GFX908-LABEL: name: raw_buffer_load_format_f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   successors: %bb.1(0x80000000)
  ; GFX908-NEXT:   liveins: $vgpr0, $vgpr1, $vgpr2, $vgpr3, $vgpr4, $vgpr5
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:vgpr_32 = COPY $vgpr5
  ; GFX908-NEXT:   [[COPY1:%[0-9]+]]:vgpr_32 = COPY $vgpr4
  ; GFX908-NEXT:   [[COPY2:%[0-9]+]]:vgpr_32 = COPY $vgpr3
  ; GFX908-NEXT:   [[COPY3:%[0-9]+]]:vgpr_32 = COPY $vgpr2
  ; GFX908-NEXT:   [[COPY4:%[0-9]+]]:vgpr_32 = COPY $vgpr1
  ; GFX908-NEXT:   [[COPY5:%[0-9]+]]:vgpr_32 = COPY $vgpr0
  ; GFX908-NEXT:   [[DEF:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF1:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF2:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF3:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[REG_SEQUENCE:%[0-9]+]]:vreg_128 = REG_SEQUENCE [[COPY5]], %subreg.sub0, [[COPY4]], %subreg.sub1, [[COPY3]], %subreg.sub2, [[COPY2]], %subreg.sub3
  ; GFX908-NEXT:   [[DEF4:%[0-9]+]]:sreg_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[S_MOV_B64_:%[0-9]+]]:sreg_64_xexec = S_MOV_B64 $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.1:
  ; GFX908-NEXT:   successors: %bb.2(0x80000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub0, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_1:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub1, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE1:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE1]], [[REG_SEQUENCE]].sub0_sub1, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_2:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub2, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_3:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub3, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE2:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_2]], %subreg.sub0, [[V_READFIRSTLANE_B32_3]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_1:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE2]], [[REG_SEQUENCE]].sub2_sub3, implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[V_CMP_EQ_U64_e64_]], [[V_CMP_EQ_U64_e64_1]], implicit-def $scc
  ; GFX908-NEXT:   [[REG_SEQUENCE3:%[0-9]+]]:sgpr_128 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1, [[V_READFIRSTLANE_B32_2]], %subreg.sub2, [[V_READFIRSTLANE_B32_3]], %subreg.sub3
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_4:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[V_CMP_EQ_U32_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U32_e64 [[V_READFIRSTLANE_B32_4]], [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_1:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[S_AND_B64_]], [[V_CMP_EQ_U32_e64_]], implicit-def $scc
  ; GFX908-NEXT:   [[S_AND_SAVEEXEC_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_SAVEEXEC_B64 killed [[S_AND_B64_1]], implicit-def $exec, implicit-def $scc, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.2:
  ; GFX908-NEXT:   successors: %bb.1(0x40000000), %bb.3(0x40000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[BUFFER_LOAD_FORMAT_X_OFFEN:%[0-9]+]]:vgpr_32 = BUFFER_LOAD_FORMAT_X_OFFEN [[COPY1]], killed [[REG_SEQUENCE3]], killed [[V_READFIRSTLANE_B32_4]], 0, 0, 0, implicit $exec :: (dereferenceable load (s32), align 1, addrspace 7)
  ; GFX908-NEXT:   $exec = S_XOR_B64_term $exec, [[S_AND_SAVEEXEC_B64_]], implicit-def $scc
  ; GFX908-NEXT:   SI_WATERFALL_LOOP %bb.1, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.3:
  ; GFX908-NEXT:   $exec = S_MOV_B64 [[S_MOV_B64_]]
  ; GFX908-NEXT:   $vgpr0 = COPY [[BUFFER_LOAD_FORMAT_X_OFFEN]]
  ; GFX908-NEXT:   SI_RETURN implicit $vgpr0
  %val = call float @llvm.amdgcn.raw.buffer.load.format.f32(<4 x i32> %rsrc, i32 %voffset, i32 %soffset, i32 0)
  ret float %val
}

define <2 x float> @raw_buffer_load_format_v2f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset(<4 x i32> %rsrc, i32 %voffset, i32 %soffset) {
  ; GFX908-LABEL: name: raw_buffer_load_format_v2f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   successors: %bb.1(0x80000000)
  ; GFX908-NEXT:   liveins: $vgpr0, $vgpr1, $vgpr2, $vgpr3, $vgpr4, $vgpr5
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:vgpr_32 = COPY $vgpr5
  ; GFX908-NEXT:   [[COPY1:%[0-9]+]]:vgpr_32 = COPY $vgpr4
  ; GFX908-NEXT:   [[COPY2:%[0-9]+]]:vgpr_32 = COPY $vgpr3
  ; GFX908-NEXT:   [[COPY3:%[0-9]+]]:vgpr_32 = COPY $vgpr2
  ; GFX908-NEXT:   [[COPY4:%[0-9]+]]:vgpr_32 = COPY $vgpr1
  ; GFX908-NEXT:   [[COPY5:%[0-9]+]]:vgpr_32 = COPY $vgpr0
  ; GFX908-NEXT:   [[DEF:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF1:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF2:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF3:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[REG_SEQUENCE:%[0-9]+]]:vreg_128 = REG_SEQUENCE [[COPY5]], %subreg.sub0, [[COPY4]], %subreg.sub1, [[COPY3]], %subreg.sub2, [[COPY2]], %subreg.sub3
  ; GFX908-NEXT:   [[DEF4:%[0-9]+]]:sreg_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[S_MOV_B64_:%[0-9]+]]:sreg_64_xexec = S_MOV_B64 $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.1:
  ; GFX908-NEXT:   successors: %bb.2(0x80000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub0, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_1:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub1, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE1:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE1]], [[REG_SEQUENCE]].sub0_sub1, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_2:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub2, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_3:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub3, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE2:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_2]], %subreg.sub0, [[V_READFIRSTLANE_B32_3]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_1:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE2]], [[REG_SEQUENCE]].sub2_sub3, implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[V_CMP_EQ_U64_e64_]], [[V_CMP_EQ_U64_e64_1]], implicit-def $scc
  ; GFX908-NEXT:   [[REG_SEQUENCE3:%[0-9]+]]:sgpr_128 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1, [[V_READFIRSTLANE_B32_2]], %subreg.sub2, [[V_READFIRSTLANE_B32_3]], %subreg.sub3
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_4:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[V_CMP_EQ_U32_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U32_e64 [[V_READFIRSTLANE_B32_4]], [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_1:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[S_AND_B64_]], [[V_CMP_EQ_U32_e64_]], implicit-def $scc
  ; GFX908-NEXT:   [[S_AND_SAVEEXEC_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_SAVEEXEC_B64 killed [[S_AND_B64_1]], implicit-def $exec, implicit-def $scc, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.2:
  ; GFX908-NEXT:   successors: %bb.1(0x40000000), %bb.3(0x40000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[BUFFER_LOAD_FORMAT_XY_OFFEN:%[0-9]+]]:vreg_64 = BUFFER_LOAD_FORMAT_XY_OFFEN [[COPY1]], killed [[REG_SEQUENCE3]], killed [[V_READFIRSTLANE_B32_4]], 0, 0, 0, implicit $exec :: (dereferenceable load (s64), align 1, addrspace 7)
  ; GFX908-NEXT:   $exec = S_XOR_B64_term $exec, [[S_AND_SAVEEXEC_B64_]], implicit-def $scc
  ; GFX908-NEXT:   SI_WATERFALL_LOOP %bb.1, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.3:
  ; GFX908-NEXT:   $exec = S_MOV_B64 [[S_MOV_B64_]]
  ; GFX908-NEXT:   [[COPY6:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XY_OFFEN]].sub0
  ; GFX908-NEXT:   [[COPY7:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XY_OFFEN]].sub1
  ; GFX908-NEXT:   $vgpr0 = COPY [[COPY6]]
  ; GFX908-NEXT:   $vgpr1 = COPY [[COPY7]]
  ; GFX908-NEXT:   SI_RETURN implicit $vgpr0, implicit $vgpr1
  %val = call <2 x float> @llvm.amdgcn.raw.buffer.load.format.v2f32(<4 x i32> %rsrc, i32 %voffset, i32 %soffset, i32 0)
  ret <2 x float> %val
}

define <3 x float> @raw_buffer_load_format_v3f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset(<4 x i32> %rsrc, i32 %voffset, i32 %soffset) {
  ; GFX908-LABEL: name: raw_buffer_load_format_v3f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   successors: %bb.1(0x80000000)
  ; GFX908-NEXT:   liveins: $vgpr0, $vgpr1, $vgpr2, $vgpr3, $vgpr4, $vgpr5
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:vgpr_32 = COPY $vgpr5
  ; GFX908-NEXT:   [[COPY1:%[0-9]+]]:vgpr_32 = COPY $vgpr4
  ; GFX908-NEXT:   [[COPY2:%[0-9]+]]:vgpr_32 = COPY $vgpr3
  ; GFX908-NEXT:   [[COPY3:%[0-9]+]]:vgpr_32 = COPY $vgpr2
  ; GFX908-NEXT:   [[COPY4:%[0-9]+]]:vgpr_32 = COPY $vgpr1
  ; GFX908-NEXT:   [[COPY5:%[0-9]+]]:vgpr_32 = COPY $vgpr0
  ; GFX908-NEXT:   [[DEF:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF1:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF2:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF3:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[REG_SEQUENCE:%[0-9]+]]:vreg_128 = REG_SEQUENCE [[COPY5]], %subreg.sub0, [[COPY4]], %subreg.sub1, [[COPY3]], %subreg.sub2, [[COPY2]], %subreg.sub3
  ; GFX908-NEXT:   [[DEF4:%[0-9]+]]:sreg_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[S_MOV_B64_:%[0-9]+]]:sreg_64_xexec = S_MOV_B64 $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.1:
  ; GFX908-NEXT:   successors: %bb.2(0x80000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub0, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_1:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub1, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE1:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE1]], [[REG_SEQUENCE]].sub0_sub1, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_2:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub2, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_3:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub3, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE2:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_2]], %subreg.sub0, [[V_READFIRSTLANE_B32_3]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_1:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE2]], [[REG_SEQUENCE]].sub2_sub3, implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[V_CMP_EQ_U64_e64_]], [[V_CMP_EQ_U64_e64_1]], implicit-def $scc
  ; GFX908-NEXT:   [[REG_SEQUENCE3:%[0-9]+]]:sgpr_128 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1, [[V_READFIRSTLANE_B32_2]], %subreg.sub2, [[V_READFIRSTLANE_B32_3]], %subreg.sub3
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_4:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[V_CMP_EQ_U32_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U32_e64 [[V_READFIRSTLANE_B32_4]], [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_1:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[S_AND_B64_]], [[V_CMP_EQ_U32_e64_]], implicit-def $scc
  ; GFX908-NEXT:   [[S_AND_SAVEEXEC_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_SAVEEXEC_B64 killed [[S_AND_B64_1]], implicit-def $exec, implicit-def $scc, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.2:
  ; GFX908-NEXT:   successors: %bb.1(0x40000000), %bb.3(0x40000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[BUFFER_LOAD_FORMAT_XYZ_OFFEN:%[0-9]+]]:vreg_96 = BUFFER_LOAD_FORMAT_XYZ_OFFEN [[COPY1]], killed [[REG_SEQUENCE3]], killed [[V_READFIRSTLANE_B32_4]], 0, 0, 0, implicit $exec :: (dereferenceable load (s96), align 1, addrspace 7)
  ; GFX908-NEXT:   $exec = S_XOR_B64_term $exec, [[S_AND_SAVEEXEC_B64_]], implicit-def $scc
  ; GFX908-NEXT:   SI_WATERFALL_LOOP %bb.1, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.3:
  ; GFX908-NEXT:   $exec = S_MOV_B64 [[S_MOV_B64_]]
  ; GFX908-NEXT:   [[COPY6:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZ_OFFEN]].sub0
  ; GFX908-NEXT:   [[COPY7:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZ_OFFEN]].sub1
  ; GFX908-NEXT:   [[COPY8:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZ_OFFEN]].sub2
  ; GFX908-NEXT:   $vgpr0 = COPY [[COPY6]]
  ; GFX908-NEXT:   $vgpr1 = COPY [[COPY7]]
  ; GFX908-NEXT:   $vgpr2 = COPY [[COPY8]]
  ; GFX908-NEXT:   SI_RETURN implicit $vgpr0, implicit $vgpr1, implicit $vgpr2
  %val = call <3 x float> @llvm.amdgcn.raw.buffer.load.format.v3f32(<4 x i32> %rsrc, i32 %voffset, i32 %soffset, i32 0)
  ret <3 x float> %val
}

define <4 x float> @raw_buffer_load_format_v4f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset(<4 x i32> %rsrc, i32 %voffset, i32 %soffset) {
  ; GFX908-LABEL: name: raw_buffer_load_format_v4f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   successors: %bb.1(0x80000000)
  ; GFX908-NEXT:   liveins: $vgpr0, $vgpr1, $vgpr2, $vgpr3, $vgpr4, $vgpr5
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:vgpr_32 = COPY $vgpr5
  ; GFX908-NEXT:   [[COPY1:%[0-9]+]]:vgpr_32 = COPY $vgpr4
  ; GFX908-NEXT:   [[COPY2:%[0-9]+]]:vgpr_32 = COPY $vgpr3
  ; GFX908-NEXT:   [[COPY3:%[0-9]+]]:vgpr_32 = COPY $vgpr2
  ; GFX908-NEXT:   [[COPY4:%[0-9]+]]:vgpr_32 = COPY $vgpr1
  ; GFX908-NEXT:   [[COPY5:%[0-9]+]]:vgpr_32 = COPY $vgpr0
  ; GFX908-NEXT:   [[DEF:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF1:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF2:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF3:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[REG_SEQUENCE:%[0-9]+]]:vreg_128 = REG_SEQUENCE [[COPY5]], %subreg.sub0, [[COPY4]], %subreg.sub1, [[COPY3]], %subreg.sub2, [[COPY2]], %subreg.sub3
  ; GFX908-NEXT:   [[DEF4:%[0-9]+]]:sreg_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[S_MOV_B64_:%[0-9]+]]:sreg_64_xexec = S_MOV_B64 $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.1:
  ; GFX908-NEXT:   successors: %bb.2(0x80000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub0, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_1:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub1, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE1:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE1]], [[REG_SEQUENCE]].sub0_sub1, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_2:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub2, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_3:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub3, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE2:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_2]], %subreg.sub0, [[V_READFIRSTLANE_B32_3]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_1:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE2]], [[REG_SEQUENCE]].sub2_sub3, implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[V_CMP_EQ_U64_e64_]], [[V_CMP_EQ_U64_e64_1]], implicit-def $scc
  ; GFX908-NEXT:   [[REG_SEQUENCE3:%[0-9]+]]:sgpr_128 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1, [[V_READFIRSTLANE_B32_2]], %subreg.sub2, [[V_READFIRSTLANE_B32_3]], %subreg.sub3
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_4:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[V_CMP_EQ_U32_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U32_e64 [[V_READFIRSTLANE_B32_4]], [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_1:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[S_AND_B64_]], [[V_CMP_EQ_U32_e64_]], implicit-def $scc
  ; GFX908-NEXT:   [[S_AND_SAVEEXEC_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_SAVEEXEC_B64 killed [[S_AND_B64_1]], implicit-def $exec, implicit-def $scc, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.2:
  ; GFX908-NEXT:   successors: %bb.1(0x40000000), %bb.3(0x40000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[BUFFER_LOAD_FORMAT_XYZW_OFFEN:%[0-9]+]]:vreg_128 = BUFFER_LOAD_FORMAT_XYZW_OFFEN [[COPY1]], killed [[REG_SEQUENCE3]], killed [[V_READFIRSTLANE_B32_4]], 0, 0, 0, implicit $exec :: (dereferenceable load (s128), align 1, addrspace 7)
  ; GFX908-NEXT:   $exec = S_XOR_B64_term $exec, [[S_AND_SAVEEXEC_B64_]], implicit-def $scc
  ; GFX908-NEXT:   SI_WATERFALL_LOOP %bb.1, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.3:
  ; GFX908-NEXT:   $exec = S_MOV_B64 [[S_MOV_B64_]]
  ; GFX908-NEXT:   [[COPY6:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub0
  ; GFX908-NEXT:   [[COPY7:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub1
  ; GFX908-NEXT:   [[COPY8:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub2
  ; GFX908-NEXT:   [[COPY9:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub3
  ; GFX908-NEXT:   $vgpr0 = COPY [[COPY6]]
  ; GFX908-NEXT:   $vgpr1 = COPY [[COPY7]]
  ; GFX908-NEXT:   $vgpr2 = COPY [[COPY8]]
  ; GFX908-NEXT:   $vgpr3 = COPY [[COPY9]]
  ; GFX908-NEXT:   SI_RETURN implicit $vgpr0, implicit $vgpr1, implicit $vgpr2, implicit $vgpr3
  %val = call <4 x float> @llvm.amdgcn.raw.buffer.load.format.v4f32(<4 x i32> %rsrc, i32 %voffset, i32 %soffset, i32 0)
  ret <4 x float> %val
}

; Waterfall for rsrc and soffset, copy for voffset
define float @raw_buffer_load_format_f32__vgpr_rsrc__sgpr_voffset__vgpr_soffset(<4 x i32> %rsrc, i32 %voffset, i32 %soffset) {
  ; GFX908-LABEL: name: raw_buffer_load_format_f32__vgpr_rsrc__sgpr_voffset__vgpr_soffset
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   successors: %bb.1(0x80000000)
  ; GFX908-NEXT:   liveins: $vgpr0, $vgpr1, $vgpr2, $vgpr3, $vgpr4, $vgpr5
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:vgpr_32 = COPY $vgpr5
  ; GFX908-NEXT:   [[COPY1:%[0-9]+]]:vgpr_32 = COPY $vgpr4
  ; GFX908-NEXT:   [[COPY2:%[0-9]+]]:vgpr_32 = COPY $vgpr3
  ; GFX908-NEXT:   [[COPY3:%[0-9]+]]:vgpr_32 = COPY $vgpr2
  ; GFX908-NEXT:   [[COPY4:%[0-9]+]]:vgpr_32 = COPY $vgpr1
  ; GFX908-NEXT:   [[COPY5:%[0-9]+]]:vgpr_32 = COPY $vgpr0
  ; GFX908-NEXT:   [[DEF:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF1:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF2:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF3:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[REG_SEQUENCE:%[0-9]+]]:vreg_128 = REG_SEQUENCE [[COPY5]], %subreg.sub0, [[COPY4]], %subreg.sub1, [[COPY3]], %subreg.sub2, [[COPY2]], %subreg.sub3
  ; GFX908-NEXT:   [[DEF4:%[0-9]+]]:sreg_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[S_MOV_B64_:%[0-9]+]]:sreg_64_xexec = S_MOV_B64 $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.1:
  ; GFX908-NEXT:   successors: %bb.2(0x80000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub0, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_1:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub1, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE1:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE1]], [[REG_SEQUENCE]].sub0_sub1, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_2:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub2, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_3:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub3, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE2:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_2]], %subreg.sub0, [[V_READFIRSTLANE_B32_3]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_1:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE2]], [[REG_SEQUENCE]].sub2_sub3, implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[V_CMP_EQ_U64_e64_]], [[V_CMP_EQ_U64_e64_1]], implicit-def $scc
  ; GFX908-NEXT:   [[REG_SEQUENCE3:%[0-9]+]]:sgpr_128 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1, [[V_READFIRSTLANE_B32_2]], %subreg.sub2, [[V_READFIRSTLANE_B32_3]], %subreg.sub3
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_4:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[V_CMP_EQ_U32_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U32_e64 [[V_READFIRSTLANE_B32_4]], [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_1:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[S_AND_B64_]], [[V_CMP_EQ_U32_e64_]], implicit-def $scc
  ; GFX908-NEXT:   [[S_AND_SAVEEXEC_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_SAVEEXEC_B64 killed [[S_AND_B64_1]], implicit-def $exec, implicit-def $scc, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.2:
  ; GFX908-NEXT:   successors: %bb.1(0x40000000), %bb.3(0x40000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[BUFFER_LOAD_FORMAT_X_OFFEN:%[0-9]+]]:vgpr_32 = BUFFER_LOAD_FORMAT_X_OFFEN [[COPY1]], killed [[REG_SEQUENCE3]], killed [[V_READFIRSTLANE_B32_4]], 0, 0, 0, implicit $exec :: (dereferenceable load (s32), align 1, addrspace 7)
  ; GFX908-NEXT:   $exec = S_XOR_B64_term $exec, [[S_AND_SAVEEXEC_B64_]], implicit-def $scc
  ; GFX908-NEXT:   SI_WATERFALL_LOOP %bb.1, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.3:
  ; GFX908-NEXT:   $exec = S_MOV_B64 [[S_MOV_B64_]]
  ; GFX908-NEXT:   $vgpr0 = COPY [[BUFFER_LOAD_FORMAT_X_OFFEN]]
  ; GFX908-NEXT:   SI_RETURN implicit $vgpr0
  %val = call float @llvm.amdgcn.raw.buffer.load.format.f32(<4 x i32> %rsrc, i32 %voffset, i32 %soffset, i32 0)
  ret float %val
}

define <4 x float> @raw_buffer_load_format_v4f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset_voffset_add_4095(<4 x i32> %rsrc, i32 %voffset.base, i32 %soffset) {
  ; GFX908-LABEL: name: raw_buffer_load_format_v4f32__sgpr_rsrc__vgpr_voffset__sgpr_soffset_voffset_add_4095
  ; GFX908: bb.0 (%ir-block.0):
  ; GFX908-NEXT:   successors: %bb.1(0x80000000)
  ; GFX908-NEXT:   liveins: $vgpr0, $vgpr1, $vgpr2, $vgpr3, $vgpr4, $vgpr5
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[COPY:%[0-9]+]]:vgpr_32 = COPY $vgpr5
  ; GFX908-NEXT:   [[COPY1:%[0-9]+]]:vgpr_32 = COPY $vgpr4
  ; GFX908-NEXT:   [[COPY2:%[0-9]+]]:vgpr_32 = COPY $vgpr3
  ; GFX908-NEXT:   [[COPY3:%[0-9]+]]:vgpr_32 = COPY $vgpr2
  ; GFX908-NEXT:   [[COPY4:%[0-9]+]]:vgpr_32 = COPY $vgpr1
  ; GFX908-NEXT:   [[COPY5:%[0-9]+]]:vgpr_32 = COPY $vgpr0
  ; GFX908-NEXT:   [[DEF:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF1:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF2:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[DEF3:%[0-9]+]]:sgpr_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[REG_SEQUENCE:%[0-9]+]]:vreg_128 = REG_SEQUENCE [[COPY5]], %subreg.sub0, [[COPY4]], %subreg.sub1, [[COPY3]], %subreg.sub2, [[COPY2]], %subreg.sub3
  ; GFX908-NEXT:   [[DEF4:%[0-9]+]]:sreg_32 = IMPLICIT_DEF
  ; GFX908-NEXT:   [[S_MOV_B64_:%[0-9]+]]:sreg_64_xexec = S_MOV_B64 $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.1:
  ; GFX908-NEXT:   successors: %bb.2(0x80000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub0, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_1:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub1, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE1:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE1]], [[REG_SEQUENCE]].sub0_sub1, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_2:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub2, implicit $exec
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_3:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[REG_SEQUENCE]].sub3, implicit $exec
  ; GFX908-NEXT:   [[REG_SEQUENCE2:%[0-9]+]]:sgpr_64 = REG_SEQUENCE [[V_READFIRSTLANE_B32_2]], %subreg.sub0, [[V_READFIRSTLANE_B32_3]], %subreg.sub1
  ; GFX908-NEXT:   [[V_CMP_EQ_U64_e64_1:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U64_e64 [[REG_SEQUENCE2]], [[REG_SEQUENCE]].sub2_sub3, implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[V_CMP_EQ_U64_e64_]], [[V_CMP_EQ_U64_e64_1]], implicit-def $scc
  ; GFX908-NEXT:   [[REG_SEQUENCE3:%[0-9]+]]:sgpr_128 = REG_SEQUENCE [[V_READFIRSTLANE_B32_]], %subreg.sub0, [[V_READFIRSTLANE_B32_1]], %subreg.sub1, [[V_READFIRSTLANE_B32_2]], %subreg.sub2, [[V_READFIRSTLANE_B32_3]], %subreg.sub3
  ; GFX908-NEXT:   [[V_READFIRSTLANE_B32_4:%[0-9]+]]:sgpr_32 = V_READFIRSTLANE_B32 [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[V_CMP_EQ_U32_e64_:%[0-9]+]]:sreg_64_xexec = V_CMP_EQ_U32_e64 [[V_READFIRSTLANE_B32_4]], [[COPY]], implicit $exec
  ; GFX908-NEXT:   [[S_AND_B64_1:%[0-9]+]]:sreg_64_xexec = S_AND_B64 [[S_AND_B64_]], [[V_CMP_EQ_U32_e64_]], implicit-def $scc
  ; GFX908-NEXT:   [[S_AND_SAVEEXEC_B64_:%[0-9]+]]:sreg_64_xexec = S_AND_SAVEEXEC_B64 killed [[S_AND_B64_1]], implicit-def $exec, implicit-def $scc, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.2:
  ; GFX908-NEXT:   successors: %bb.1(0x40000000), %bb.3(0x40000000)
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT:   [[BUFFER_LOAD_FORMAT_XYZW_OFFEN:%[0-9]+]]:vreg_128 = BUFFER_LOAD_FORMAT_XYZW_OFFEN [[COPY1]], killed [[REG_SEQUENCE3]], killed [[V_READFIRSTLANE_B32_4]], 4095, 0, 0, implicit $exec :: (dereferenceable load (s128), align 1, addrspace 7)
  ; GFX908-NEXT:   $exec = S_XOR_B64_term $exec, [[S_AND_SAVEEXEC_B64_]], implicit-def $scc
  ; GFX908-NEXT:   SI_WATERFALL_LOOP %bb.1, implicit $exec
  ; GFX908-NEXT: {{  $}}
  ; GFX908-NEXT: bb.3:
  ; GFX908-NEXT:   $exec = S_MOV_B64 [[S_MOV_B64_]]
  ; GFX908-NEXT:   [[COPY6:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub0
  ; GFX908-NEXT:   [[COPY7:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub1
  ; GFX908-NEXT:   [[COPY8:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub2
  ; GFX908-NEXT:   [[COPY9:%[0-9]+]]:vgpr_32 = COPY [[BUFFER_LOAD_FORMAT_XYZW_OFFEN]].sub3
  ; GFX908-NEXT:   $vgpr0 = COPY [[COPY6]]
  ; GFX908-NEXT:   $vgpr1 = COPY [[COPY7]]
  ; GFX908-NEXT:   $vgpr2 = COPY [[COPY8]]
  ; GFX908-NEXT:   $vgpr3 = COPY [[COPY9]]
  ; GFX908-NEXT:   SI_RETURN implicit $vgpr0, implicit $vgpr1, implicit $vgpr2, implicit $vgpr3
  %voffset = add i32 %voffset.base, 4095
  %val = call <4 x float> @llvm.amdgcn.raw.buffer.load.format.v4f32(<4 x i32> %rsrc, i32 %voffset, i32 %soffset, i32 0)
  ret <4 x float> %val
}

declare float @llvm.amdgcn.raw.buffer.load.format.f32(<4 x i32>, i32, i32, i32 immarg) #0
declare <2 x float> @llvm.amdgcn.raw.buffer.load.format.v2f32(<4 x i32>, i32, i32, i32 immarg) #0
declare <3 x float> @llvm.amdgcn.raw.buffer.load.format.v3f32(<4 x i32>, i32, i32, i32 immarg) #0
declare <4 x float> @llvm.amdgcn.raw.buffer.load.format.v4f32(<4 x i32>, i32, i32, i32 immarg) #0

attributes #0 = { nounwind readonly }
