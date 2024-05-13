; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -mtriple=amdgcn-amd-amdhsa -mcpu=hawaii -atomic-expand %s | FileCheck -check-prefix=GCN %s
; RUN: opt -S -mtriple=amdgcn-amd-amdhsa -mcpu=gfx900 -atomic-expand %s | FileCheck -check-prefix=GCN %s

define float @test_atomicrmw_fmax_f32_flat(ptr %ptr, float %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f32_flat(
; GCN-NEXT:    [[TMP1:%.*]] = load float, ptr [[PTR:%.*]], align 4
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi float [ [[TMP1]], [[TMP0:%.*]] ], [ [[TMP7:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[TMP2:%.*]] = call float @llvm.maxnum.f32(float [[LOADED]], float [[VALUE:%.*]])
; GCN-NEXT:    [[TMP4:%.*]] = bitcast float [[TMP2]] to i32
; GCN-NEXT:    [[TMP5:%.*]] = bitcast float [[LOADED]] to i32
; GCN-NEXT:    [[TMP6:%.*]] = cmpxchg ptr [[PTR]], i32 [[TMP5]], i32 [[TMP4]] seq_cst seq_cst, align 4
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i32, i1 } [[TMP6]], 1
; GCN-NEXT:    [[NEWLOADED:%.*]] = extractvalue { i32, i1 } [[TMP6]], 0
; GCN-NEXT:    [[TMP7]] = bitcast i32 [[NEWLOADED]] to float
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    ret float [[TMP7]]
;
  %res = atomicrmw fmax ptr %ptr, float %value seq_cst
  ret float %res
}

define float @test_atomicrmw_fmax_f32_global(ptr addrspace(1) %ptr, float %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f32_global(
; GCN-NEXT:    [[TMP1:%.*]] = load float, ptr addrspace(1) [[PTR:%.*]], align 4
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi float [ [[TMP1]], [[TMP0:%.*]] ], [ [[TMP7:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[TMP2:%.*]] = call float @llvm.maxnum.f32(float [[LOADED]], float [[VALUE:%.*]])
; GCN-NEXT:    [[TMP4:%.*]] = bitcast float [[TMP2]] to i32
; GCN-NEXT:    [[TMP5:%.*]] = bitcast float [[LOADED]] to i32
; GCN-NEXT:    [[TMP6:%.*]] = cmpxchg ptr addrspace(1) [[PTR]], i32 [[TMP5]], i32 [[TMP4]] seq_cst seq_cst, align 4
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i32, i1 } [[TMP6]], 1
; GCN-NEXT:    [[NEWLOADED:%.*]] = extractvalue { i32, i1 } [[TMP6]], 0
; GCN-NEXT:    [[TMP7]] = bitcast i32 [[NEWLOADED]] to float
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    ret float [[TMP7]]
;
  %res = atomicrmw fmax ptr addrspace(1) %ptr, float %value seq_cst
  ret float %res
}

define float @test_atomicrmw_fmax_f32_local(ptr addrspace(3) %ptr, float %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f32_local(
; GCN-NEXT:    [[TMP1:%.*]] = load float, ptr addrspace(3) [[PTR:%.*]], align 4
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi float [ [[TMP1]], [[TMP0:%.*]] ], [ [[TMP7:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[TMP2:%.*]] = call float @llvm.maxnum.f32(float [[LOADED]], float [[VALUE:%.*]])
; GCN-NEXT:    [[TMP4:%.*]] = bitcast float [[TMP2]] to i32
; GCN-NEXT:    [[TMP5:%.*]] = bitcast float [[LOADED]] to i32
; GCN-NEXT:    [[TMP6:%.*]] = cmpxchg ptr addrspace(3) [[PTR]], i32 [[TMP5]], i32 [[TMP4]] seq_cst seq_cst, align 4
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i32, i1 } [[TMP6]], 1
; GCN-NEXT:    [[NEWLOADED:%.*]] = extractvalue { i32, i1 } [[TMP6]], 0
; GCN-NEXT:    [[TMP7]] = bitcast i32 [[NEWLOADED]] to float
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    ret float [[TMP7]]
;
  %res = atomicrmw fmax ptr addrspace(3) %ptr, float %value seq_cst
  ret float %res
}

define half @test_atomicrmw_fmax_f16_flat(ptr %ptr, half %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f16_flat(
; GCN-NEXT:    [[ALIGNEDADDR:%.*]] = call ptr @llvm.ptrmask.p0.i64(ptr [[PTR:%.*]], i64 -4)
; GCN-NEXT:    [[TMP1:%.*]] = ptrtoint ptr [[PTR]] to i64
; GCN-NEXT:    [[PTRLSB:%.*]] = and i64 [[TMP1]], 3
; GCN-NEXT:    [[TMP2:%.*]] = shl i64 [[PTRLSB]], 3
; GCN-NEXT:    [[SHIFTAMT:%.*]] = trunc i64 [[TMP2]] to i32
; GCN-NEXT:    [[MASK:%.*]] = shl i32 65535, [[SHIFTAMT]]
; GCN-NEXT:    [[INV_MASK:%.*]] = xor i32 [[MASK]], -1
; GCN-NEXT:    [[TMP3:%.*]] = load i32, ptr [[ALIGNEDADDR]], align 4
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi i32 [ [[TMP3]], [[TMP0:%.*]] ], [ [[NEWLOADED:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[SHIFTED:%.*]] = lshr i32 [[LOADED]], [[SHIFTAMT]]
; GCN-NEXT:    [[EXTRACTED:%.*]] = trunc i32 [[SHIFTED]] to i16
; GCN-NEXT:    [[TMP4:%.*]] = bitcast i16 [[EXTRACTED]] to half
; GCN-NEXT:    [[TMP5:%.*]] = call half @llvm.maxnum.f16(half [[TMP4]], half [[VALUE:%.*]])
; GCN-NEXT:    [[TMP6:%.*]] = bitcast half [[TMP5]] to i16
; GCN-NEXT:    [[EXTENDED:%.*]] = zext i16 [[TMP6]] to i32
; GCN-NEXT:    [[SHIFTED2:%.*]] = shl nuw i32 [[EXTENDED]], [[SHIFTAMT]]
; GCN-NEXT:    [[UNMASKED:%.*]] = and i32 [[LOADED]], [[INV_MASK]]
; GCN-NEXT:    [[INSERTED:%.*]] = or i32 [[UNMASKED]], [[SHIFTED2]]
; GCN-NEXT:    [[TMP7:%.*]] = cmpxchg ptr [[ALIGNEDADDR]], i32 [[LOADED]], i32 [[INSERTED]] seq_cst seq_cst, align 4
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i32, i1 } [[TMP7]], 1
; GCN-NEXT:    [[NEWLOADED]] = extractvalue { i32, i1 } [[TMP7]], 0
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    [[SHIFTED3:%.*]] = lshr i32 [[NEWLOADED]], [[SHIFTAMT]]
; GCN-NEXT:    [[EXTRACTED4:%.*]] = trunc i32 [[SHIFTED3]] to i16
; GCN-NEXT:    [[TMP8:%.*]] = bitcast i16 [[EXTRACTED4]] to half
; GCN-NEXT:    ret half [[TMP8]]
;
  %res = atomicrmw fmax ptr %ptr, half %value seq_cst
  ret half %res
}

define half @test_atomicrmw_fmax_f16_global(ptr addrspace(1) %ptr, half %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f16_global(
; GCN-NEXT:    [[ALIGNEDADDR:%.*]] = call ptr addrspace(1) @llvm.ptrmask.p1.i64(ptr addrspace(1) [[PTR:%.*]], i64 -4)
; GCN-NEXT:    [[TMP1:%.*]] = ptrtoint ptr addrspace(1) [[PTR]] to i64
; GCN-NEXT:    [[PTRLSB:%.*]] = and i64 [[TMP1]], 3
; GCN-NEXT:    [[TMP2:%.*]] = shl i64 [[PTRLSB]], 3
; GCN-NEXT:    [[SHIFTAMT:%.*]] = trunc i64 [[TMP2]] to i32
; GCN-NEXT:    [[MASK:%.*]] = shl i32 65535, [[SHIFTAMT]]
; GCN-NEXT:    [[INV_MASK:%.*]] = xor i32 [[MASK]], -1
; GCN-NEXT:    [[TMP3:%.*]] = load i32, ptr addrspace(1) [[ALIGNEDADDR]], align 4
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi i32 [ [[TMP3]], [[TMP0:%.*]] ], [ [[NEWLOADED:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[SHIFTED:%.*]] = lshr i32 [[LOADED]], [[SHIFTAMT]]
; GCN-NEXT:    [[EXTRACTED:%.*]] = trunc i32 [[SHIFTED]] to i16
; GCN-NEXT:    [[TMP4:%.*]] = bitcast i16 [[EXTRACTED]] to half
; GCN-NEXT:    [[TMP5:%.*]] = call half @llvm.maxnum.f16(half [[TMP4]], half [[VALUE:%.*]])
; GCN-NEXT:    [[TMP6:%.*]] = bitcast half [[TMP5]] to i16
; GCN-NEXT:    [[EXTENDED:%.*]] = zext i16 [[TMP6]] to i32
; GCN-NEXT:    [[SHIFTED2:%.*]] = shl nuw i32 [[EXTENDED]], [[SHIFTAMT]]
; GCN-NEXT:    [[UNMASKED:%.*]] = and i32 [[LOADED]], [[INV_MASK]]
; GCN-NEXT:    [[INSERTED:%.*]] = or i32 [[UNMASKED]], [[SHIFTED2]]
; GCN-NEXT:    [[TMP7:%.*]] = cmpxchg ptr addrspace(1) [[ALIGNEDADDR]], i32 [[LOADED]], i32 [[INSERTED]] seq_cst seq_cst, align 4
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i32, i1 } [[TMP7]], 1
; GCN-NEXT:    [[NEWLOADED]] = extractvalue { i32, i1 } [[TMP7]], 0
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    [[SHIFTED3:%.*]] = lshr i32 [[NEWLOADED]], [[SHIFTAMT]]
; GCN-NEXT:    [[EXTRACTED4:%.*]] = trunc i32 [[SHIFTED3]] to i16
; GCN-NEXT:    [[TMP8:%.*]] = bitcast i16 [[EXTRACTED4]] to half
; GCN-NEXT:    ret half [[TMP8]]
;
  %res = atomicrmw fmax ptr addrspace(1) %ptr, half %value seq_cst
  ret half %res
}

define half @test_atomicrmw_fmax_f16_global_align4(ptr addrspace(1) %ptr, half %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f16_global_align4(
; GCN-NEXT:    [[TMP1:%.*]] = load i32, ptr addrspace(1) [[PTR:%.*]], align 4
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi i32 [ [[TMP1]], [[TMP0:%.*]] ], [ [[NEWLOADED:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[EXTRACTED:%.*]] = trunc i32 [[LOADED]] to i16
; GCN-NEXT:    [[TMP2:%.*]] = bitcast i16 [[EXTRACTED]] to half
; GCN-NEXT:    [[TMP3:%.*]] = call half @llvm.maxnum.f16(half [[TMP2]], half [[VALUE:%.*]])
; GCN-NEXT:    [[TMP4:%.*]] = bitcast half [[TMP3]] to i16
; GCN-NEXT:    [[EXTENDED:%.*]] = zext i16 [[TMP4]] to i32
; GCN-NEXT:    [[UNMASKED:%.*]] = and i32 [[LOADED]], -65536
; GCN-NEXT:    [[INSERTED:%.*]] = or i32 [[UNMASKED]], [[EXTENDED]]
; GCN-NEXT:    [[TMP5:%.*]] = cmpxchg ptr addrspace(1) [[PTR]], i32 [[LOADED]], i32 [[INSERTED]] seq_cst seq_cst, align 4
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i32, i1 } [[TMP5]], 1
; GCN-NEXT:    [[NEWLOADED]] = extractvalue { i32, i1 } [[TMP5]], 0
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    [[EXTRACTED1:%.*]] = trunc i32 [[NEWLOADED]] to i16
; GCN-NEXT:    [[TMP6:%.*]] = bitcast i16 [[EXTRACTED1]] to half
; GCN-NEXT:    ret half [[TMP6]]
;
  %res = atomicrmw fmax ptr addrspace(1) %ptr, half %value seq_cst, align 4
  ret half %res
}

define half @test_atomicrmw_fmax_f16_local(ptr addrspace(3) %ptr, half %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f16_local(
; GCN-NEXT:    [[ALIGNEDADDR:%.*]] = call ptr addrspace(3) @llvm.ptrmask.p3.i64(ptr addrspace(3) [[PTR:%.*]], i64 -4)
; GCN-NEXT:    [[TMP1:%.*]] = ptrtoint ptr addrspace(3) [[PTR]] to i64
; GCN-NEXT:    [[PTRLSB:%.*]] = and i64 [[TMP1]], 3
; GCN-NEXT:    [[TMP2:%.*]] = shl i64 [[PTRLSB]], 3
; GCN-NEXT:    [[SHIFTAMT:%.*]] = trunc i64 [[TMP2]] to i32
; GCN-NEXT:    [[MASK:%.*]] = shl i32 65535, [[SHIFTAMT]]
; GCN-NEXT:    [[INV_MASK:%.*]] = xor i32 [[MASK]], -1
; GCN-NEXT:    [[TMP3:%.*]] = load i32, ptr addrspace(3) [[ALIGNEDADDR]], align 4
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi i32 [ [[TMP3]], [[TMP0:%.*]] ], [ [[NEWLOADED:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[SHIFTED:%.*]] = lshr i32 [[LOADED]], [[SHIFTAMT]]
; GCN-NEXT:    [[EXTRACTED:%.*]] = trunc i32 [[SHIFTED]] to i16
; GCN-NEXT:    [[TMP4:%.*]] = bitcast i16 [[EXTRACTED]] to half
; GCN-NEXT:    [[TMP5:%.*]] = call half @llvm.maxnum.f16(half [[TMP4]], half [[VALUE:%.*]])
; GCN-NEXT:    [[TMP6:%.*]] = bitcast half [[TMP5]] to i16
; GCN-NEXT:    [[EXTENDED:%.*]] = zext i16 [[TMP6]] to i32
; GCN-NEXT:    [[SHIFTED2:%.*]] = shl nuw i32 [[EXTENDED]], [[SHIFTAMT]]
; GCN-NEXT:    [[UNMASKED:%.*]] = and i32 [[LOADED]], [[INV_MASK]]
; GCN-NEXT:    [[INSERTED:%.*]] = or i32 [[UNMASKED]], [[SHIFTED2]]
; GCN-NEXT:    [[TMP7:%.*]] = cmpxchg ptr addrspace(3) [[ALIGNEDADDR]], i32 [[LOADED]], i32 [[INSERTED]] seq_cst seq_cst, align 4
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i32, i1 } [[TMP7]], 1
; GCN-NEXT:    [[NEWLOADED]] = extractvalue { i32, i1 } [[TMP7]], 0
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    [[SHIFTED3:%.*]] = lshr i32 [[NEWLOADED]], [[SHIFTAMT]]
; GCN-NEXT:    [[EXTRACTED4:%.*]] = trunc i32 [[SHIFTED3]] to i16
; GCN-NEXT:    [[TMP8:%.*]] = bitcast i16 [[EXTRACTED4]] to half
; GCN-NEXT:    ret half [[TMP8]]
;
  %res = atomicrmw fmax ptr addrspace(3) %ptr, half %value seq_cst
  ret half %res
}

define double @test_atomicrmw_fmax_f64_flat(ptr %ptr, double %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f64_flat(
; GCN-NEXT:    [[TMP1:%.*]] = load double, ptr [[PTR:%.*]], align 8
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi double [ [[TMP1]], [[TMP0:%.*]] ], [ [[TMP7:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[TMP2:%.*]] = call double @llvm.maxnum.f64(double [[LOADED]], double [[VALUE:%.*]])
; GCN-NEXT:    [[TMP4:%.*]] = bitcast double [[TMP2]] to i64
; GCN-NEXT:    [[TMP5:%.*]] = bitcast double [[LOADED]] to i64
; GCN-NEXT:    [[TMP6:%.*]] = cmpxchg ptr [[PTR]], i64 [[TMP5]], i64 [[TMP4]] seq_cst seq_cst, align 8
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i64, i1 } [[TMP6]], 1
; GCN-NEXT:    [[NEWLOADED:%.*]] = extractvalue { i64, i1 } [[TMP6]], 0
; GCN-NEXT:    [[TMP7]] = bitcast i64 [[NEWLOADED]] to double
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    ret double [[TMP7]]
;
  %res = atomicrmw fmax ptr %ptr, double %value seq_cst
  ret double %res
}

define double @test_atomicrmw_fmax_f64_global(ptr addrspace(1) %ptr, double %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f64_global(
; GCN-NEXT:    [[TMP1:%.*]] = load double, ptr addrspace(1) [[PTR:%.*]], align 8
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi double [ [[TMP1]], [[TMP0:%.*]] ], [ [[TMP7:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[TMP2:%.*]] = call double @llvm.maxnum.f64(double [[LOADED]], double [[VALUE:%.*]])
; GCN-NEXT:    [[TMP4:%.*]] = bitcast double [[TMP2]] to i64
; GCN-NEXT:    [[TMP5:%.*]] = bitcast double [[LOADED]] to i64
; GCN-NEXT:    [[TMP6:%.*]] = cmpxchg ptr addrspace(1) [[PTR]], i64 [[TMP5]], i64 [[TMP4]] seq_cst seq_cst, align 8
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i64, i1 } [[TMP6]], 1
; GCN-NEXT:    [[NEWLOADED:%.*]] = extractvalue { i64, i1 } [[TMP6]], 0
; GCN-NEXT:    [[TMP7]] = bitcast i64 [[NEWLOADED]] to double
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    ret double [[TMP7]]
;
  %res = atomicrmw fmax ptr addrspace(1) %ptr, double %value seq_cst
  ret double %res
}

define double @test_atomicrmw_fmax_f64_local(ptr addrspace(3) %ptr, double %value) {
; GCN-LABEL: @test_atomicrmw_fmax_f64_local(
; GCN-NEXT:    [[TMP1:%.*]] = load double, ptr addrspace(3) [[PTR:%.*]], align 8
; GCN-NEXT:    br label [[ATOMICRMW_START:%.*]]
; GCN:       atomicrmw.start:
; GCN-NEXT:    [[LOADED:%.*]] = phi double [ [[TMP1]], [[TMP0:%.*]] ], [ [[TMP7:%.*]], [[ATOMICRMW_START]] ]
; GCN-NEXT:    [[TMP2:%.*]] = call double @llvm.maxnum.f64(double [[LOADED]], double [[VALUE:%.*]])
; GCN-NEXT:    [[TMP4:%.*]] = bitcast double [[TMP2]] to i64
; GCN-NEXT:    [[TMP5:%.*]] = bitcast double [[LOADED]] to i64
; GCN-NEXT:    [[TMP6:%.*]] = cmpxchg ptr addrspace(3) [[PTR]], i64 [[TMP5]], i64 [[TMP4]] seq_cst seq_cst, align 8
; GCN-NEXT:    [[SUCCESS:%.*]] = extractvalue { i64, i1 } [[TMP6]], 1
; GCN-NEXT:    [[NEWLOADED:%.*]] = extractvalue { i64, i1 } [[TMP6]], 0
; GCN-NEXT:    [[TMP7]] = bitcast i64 [[NEWLOADED]] to double
; GCN-NEXT:    br i1 [[SUCCESS]], label [[ATOMICRMW_END:%.*]], label [[ATOMICRMW_START]]
; GCN:       atomicrmw.end:
; GCN-NEXT:    ret double [[TMP7]]
;
  %res = atomicrmw fmax ptr addrspace(3) %ptr, double %value seq_cst
  ret double %res
}
