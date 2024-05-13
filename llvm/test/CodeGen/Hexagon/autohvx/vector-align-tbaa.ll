; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -mtriple=hexagon -S -hexagon-vc -instcombine < %s | FileCheck %s

; Check that Hexagon Vector Combine propagates (TBAA) metadata to the
; generated output. (Use instcombine to clean the output up a bit.)

target datalayout = "e-m:e-p:32:32:32-a:0-n16:32-i64:64:64-i32:32:32-i16:16:16-i1:8:8-f32:32:32-f64:64:64-v32:32:32-v64:64:64-v512:512:512-v1024:1024:1024-v2048:2048:2048"
target triple = "hexagon"

; Two unaligned loads, both with the same TBAA tag.
;
define <64 x i16> @f0(ptr %a0, i32 %a1) #0 {
; CHECK-LABEL: @f0(
; CHECK-NEXT:  b0:
; CHECK-NEXT:    [[V0:%.*]] = add i32 [[A1:%.*]], 64
; CHECK-NEXT:    [[V1:%.*]] = getelementptr i16, ptr [[A0:%.*]], i32 [[V0]]
; CHECK-NEXT:    [[PTI:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ADD:%.*]] = and i32 [[PTI]], -128
; CHECK-NEXT:    [[ITP:%.*]] = inttoptr i32 [[ADD]] to ptr
; CHECK-NEXT:    [[PTI1:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ALD13:%.*]] = load <32 x i32>, ptr [[ITP]], align 128, !tbaa [[TBAA0:![0-9]+]]
; CHECK-NEXT:    [[GEP:%.*]] = getelementptr i8, ptr [[ITP]], i32 128
; CHECK-NEXT:    [[ALD2:%.*]] = load <128 x i8>, ptr [[GEP]], align 128, !tbaa [[TBAA0]]
; CHECK-NEXT:    [[GEP3:%.*]] = getelementptr i8, ptr [[ITP]], i32 256
; CHECK-NEXT:    [[ALD414:%.*]] = load <32 x i32>, ptr [[GEP3]], align 128, !tbaa [[TBAA0]]
; CHECK-NEXT:    [[CST:%.*]] = bitcast <128 x i8> [[ALD2]] to <32 x i32>
; CHECK-NEXT:    [[CUP:%.*]] = call <32 x i32> @llvm.hexagon.V6.valignb.128B(<32 x i32> [[CST]], <32 x i32> [[ALD13]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST11:%.*]] = bitcast <32 x i32> [[CUP]] to <64 x i16>
; CHECK-NEXT:    [[CST8:%.*]] = bitcast <128 x i8> [[ALD2]] to <32 x i32>
; CHECK-NEXT:    [[CUP9:%.*]] = call <32 x i32> @llvm.hexagon.V6.valignb.128B(<32 x i32> [[ALD414]], <32 x i32> [[CST8]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST12:%.*]] = bitcast <32 x i32> [[CUP9]] to <64 x i16>
; CHECK-NEXT:    [[V8:%.*]] = add <64 x i16> [[CST11]], [[CST12]]
; CHECK-NEXT:    ret <64 x i16> [[V8]]
;
b0:
  %v0 = add i32 %a1, 64
  %v1 = getelementptr i16, ptr %a0, i32 %v0
  %v3 = load <64 x i16>, ptr %v1, align 2, !tbaa !0
  %v4 = add i32 %a1, 128
  %v5 = getelementptr i16, ptr %a0, i32 %v4
  %v7 = load <64 x i16>, ptr %v5, align 2, !tbaa !0
  %v8 = add <64 x i16> %v3, %v7
  ret <64 x i16> %v8
}

; Two unaligned loads, only one with a TBAA tag.
;
define <64 x i16> @f1(ptr %a0, i32 %a1) #0 {
; CHECK-LABEL: @f1(
; CHECK-NEXT:  b0:
; CHECK-NEXT:    [[V0:%.*]] = add i32 [[A1:%.*]], 64
; CHECK-NEXT:    [[V1:%.*]] = getelementptr i16, ptr [[A0:%.*]], i32 [[V0]]
; CHECK-NEXT:    [[PTI:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ADD:%.*]] = and i32 [[PTI]], -128
; CHECK-NEXT:    [[ITP:%.*]] = inttoptr i32 [[ADD]] to ptr
; CHECK-NEXT:    [[PTI1:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ALD13:%.*]] = load <32 x i32>, ptr [[ITP]], align 128, !tbaa [[TBAA0]]
; CHECK-NEXT:    [[GEP:%.*]] = getelementptr i8, ptr [[ITP]], i32 128
; CHECK-NEXT:    [[ALD2:%.*]] = load <128 x i8>, ptr [[GEP]], align 128
; CHECK-NEXT:    [[GEP3:%.*]] = getelementptr i8, ptr [[ITP]], i32 256
; CHECK-NEXT:    [[ALD414:%.*]] = load <32 x i32>, ptr [[GEP3]], align 128
; CHECK-NEXT:    [[CST:%.*]] = bitcast <128 x i8> [[ALD2]] to <32 x i32>
; CHECK-NEXT:    [[CUP:%.*]] = call <32 x i32> @llvm.hexagon.V6.valignb.128B(<32 x i32> [[CST]], <32 x i32> [[ALD13]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST11:%.*]] = bitcast <32 x i32> [[CUP]] to <64 x i16>
; CHECK-NEXT:    [[CST8:%.*]] = bitcast <128 x i8> [[ALD2]] to <32 x i32>
; CHECK-NEXT:    [[CUP9:%.*]] = call <32 x i32> @llvm.hexagon.V6.valignb.128B(<32 x i32> [[ALD414]], <32 x i32> [[CST8]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST12:%.*]] = bitcast <32 x i32> [[CUP9]] to <64 x i16>
; CHECK-NEXT:    [[V8:%.*]] = add <64 x i16> [[CST11]], [[CST12]]
; CHECK-NEXT:    ret <64 x i16> [[V8]]
;
b0:
  %v0 = add i32 %a1, 64
  %v1 = getelementptr i16, ptr %a0, i32 %v0
  %v3 = load <64 x i16>, ptr %v1, align 2, !tbaa !0
  %v4 = add i32 %a1, 128
  %v5 = getelementptr i16, ptr %a0, i32 %v4
  %v7 = load <64 x i16>, ptr %v5, align 2
  %v8 = add <64 x i16> %v3, %v7
  ret <64 x i16> %v8
}

; Two unaligned loads, with different TBAA tags.
;
define <64 x i16> @f2(ptr %a0, i32 %a1) #0 {
; CHECK-LABEL: @f2(
; CHECK-NEXT:  b0:
; CHECK-NEXT:    [[V0:%.*]] = add i32 [[A1:%.*]], 64
; CHECK-NEXT:    [[V1:%.*]] = getelementptr i16, ptr [[A0:%.*]], i32 [[V0]]
; CHECK-NEXT:    [[PTI:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ADD:%.*]] = and i32 [[PTI]], -128
; CHECK-NEXT:    [[ITP:%.*]] = inttoptr i32 [[ADD]] to ptr
; CHECK-NEXT:    [[PTI1:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ALD13:%.*]] = load <32 x i32>, ptr [[ITP]], align 128, !tbaa [[TBAA0]]
; CHECK-NEXT:    [[GEP:%.*]] = getelementptr i8, ptr [[ITP]], i32 128
; CHECK-NEXT:    [[ALD2:%.*]] = load <128 x i8>, ptr [[GEP]], align 128
; CHECK-NEXT:    [[GEP3:%.*]] = getelementptr i8, ptr [[ITP]], i32 256
; CHECK-NEXT:    [[ALD414:%.*]] = load <32 x i32>, ptr [[GEP3]], align 128, !tbaa [[TBAA3:![0-9]+]]
; CHECK-NEXT:    [[CST:%.*]] = bitcast <128 x i8> [[ALD2]] to <32 x i32>
; CHECK-NEXT:    [[CUP:%.*]] = call <32 x i32> @llvm.hexagon.V6.valignb.128B(<32 x i32> [[CST]], <32 x i32> [[ALD13]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST11:%.*]] = bitcast <32 x i32> [[CUP]] to <64 x i16>
; CHECK-NEXT:    [[CST8:%.*]] = bitcast <128 x i8> [[ALD2]] to <32 x i32>
; CHECK-NEXT:    [[CUP9:%.*]] = call <32 x i32> @llvm.hexagon.V6.valignb.128B(<32 x i32> [[ALD414]], <32 x i32> [[CST8]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST12:%.*]] = bitcast <32 x i32> [[CUP9]] to <64 x i16>
; CHECK-NEXT:    [[V8:%.*]] = add <64 x i16> [[CST11]], [[CST12]]
; CHECK-NEXT:    ret <64 x i16> [[V8]]
;
b0:
  %v0 = add i32 %a1, 64
  %v1 = getelementptr i16, ptr %a0, i32 %v0
  %v3 = load <64 x i16>, ptr %v1, align 2, !tbaa !0
  %v4 = add i32 %a1, 128
  %v5 = getelementptr i16, ptr %a0, i32 %v4
  %v7 = load <64 x i16>, ptr %v5, align 2, !tbaa !3
  %v8 = add <64 x i16> %v3, %v7
  ret <64 x i16> %v8
}

; Two unaligned stores, both with the same TBAA tag.
;
define void @f3(ptr %a0, i32 %a1, <64 x i16> %a2, <64 x i16> %a3) #0 {
; CHECK-LABEL: @f3(
; CHECK-NEXT:  b0:
; CHECK-NEXT:    [[V0:%.*]] = add i32 [[A1:%.*]], 64
; CHECK-NEXT:    [[V1:%.*]] = getelementptr i16, ptr [[A0:%.*]], i32 [[V0]]
; CHECK-NEXT:    [[PTI:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ADD:%.*]] = and i32 [[PTI]], -128
; CHECK-NEXT:    [[ITP:%.*]] = inttoptr i32 [[ADD]] to ptr
; CHECK-NEXT:    [[PTI1:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[CST3:%.*]] = bitcast <64 x i16> [[A2:%.*]] to <32 x i32>
; CHECK-NEXT:    [[CUP:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> [[CST3]], <32 x i32> undef, i32 [[PTI1]])
; CHECK-NEXT:    [[CST4:%.*]] = bitcast <32 x i32> [[CUP]] to <128 x i8>
; CHECK-NEXT:    [[CUP5:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, <32 x i32> zeroinitializer, i32 [[PTI1]])
; CHECK-NEXT:    [[CST6:%.*]] = bitcast <32 x i32> [[CUP5]] to <128 x i8>
; CHECK-NEXT:    [[CST7:%.*]] = bitcast <64 x i16> [[A3:%.*]] to <32 x i32>
; CHECK-NEXT:    [[CST8:%.*]] = bitcast <64 x i16> [[A2]] to <32 x i32>
; CHECK-NEXT:    [[CUP9:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> [[CST7]], <32 x i32> [[CST8]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST10:%.*]] = bitcast <32 x i32> [[CUP9]] to <128 x i8>
; CHECK-NEXT:    [[CUP11:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, <32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, i32 [[PTI1]])
; CHECK-NEXT:    [[CST12:%.*]] = bitcast <32 x i32> [[CUP11]] to <128 x i8>
; CHECK-NEXT:    [[CST13:%.*]] = bitcast <64 x i16> [[A3]] to <32 x i32>
; CHECK-NEXT:    [[CUP14:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> undef, <32 x i32> [[CST13]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST15:%.*]] = bitcast <32 x i32> [[CUP14]] to <128 x i8>
; CHECK-NEXT:    [[CUP16:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> zeroinitializer, <32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, i32 [[PTI1]])
; CHECK-NEXT:    [[CST17:%.*]] = bitcast <32 x i32> [[CUP16]] to <128 x i8>
; CHECK-NEXT:    [[TRN:%.*]] = trunc <128 x i8> [[CST6]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST4]], ptr [[ITP]], i32 128, <128 x i1> [[TRN]]), !tbaa [[TBAA5:![0-9]+]]
; CHECK-NEXT:    [[GEP:%.*]] = getelementptr i8, ptr [[ITP]], i32 128
; CHECK-NEXT:    [[TRN18:%.*]] = trunc <128 x i8> [[CST12]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST10]], ptr [[GEP]], i32 128, <128 x i1> [[TRN18]]), !tbaa [[TBAA5]]
; CHECK-NEXT:    [[GEP19:%.*]] = getelementptr i8, ptr [[ITP]], i32 256
; CHECK-NEXT:    [[TRN20:%.*]] = trunc <128 x i8> [[CST17]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST15]], ptr [[GEP19]], i32 128, <128 x i1> [[TRN20]]), !tbaa [[TBAA5]]
; CHECK-NEXT:    ret void
;
b0:
  %v0 = add i32 %a1, 64
  %v1 = getelementptr i16, ptr %a0, i32 %v0
  store <64 x i16> %a2, ptr %v1, align 2, !tbaa !5
  %v3 = add i32 %a1, 128
  %v4 = getelementptr i16, ptr %a0, i32 %v3
  store <64 x i16> %a3, ptr %v4, align 2, !tbaa !5
  ret void
}

; Two unaligned stores, only one with a TBAA tag.
;
define void @f4(ptr %a0, i32 %a1, <64 x i16> %a2, <64 x i16> %a3) #0 {
; CHECK-LABEL: @f4(
; CHECK-NEXT:  b0:
; CHECK-NEXT:    [[V0:%.*]] = add i32 [[A1:%.*]], 64
; CHECK-NEXT:    [[V1:%.*]] = getelementptr i16, ptr [[A0:%.*]], i32 [[V0]]
; CHECK-NEXT:    [[PTI:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ADD:%.*]] = and i32 [[PTI]], -128
; CHECK-NEXT:    [[ITP:%.*]] = inttoptr i32 [[ADD]] to ptr
; CHECK-NEXT:    [[PTI1:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[CST3:%.*]] = bitcast <64 x i16> [[A2:%.*]] to <32 x i32>
; CHECK-NEXT:    [[CUP:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> [[CST3]], <32 x i32> undef, i32 [[PTI1]])
; CHECK-NEXT:    [[CST4:%.*]] = bitcast <32 x i32> [[CUP]] to <128 x i8>
; CHECK-NEXT:    [[CUP5:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, <32 x i32> zeroinitializer, i32 [[PTI1]])
; CHECK-NEXT:    [[CST6:%.*]] = bitcast <32 x i32> [[CUP5]] to <128 x i8>
; CHECK-NEXT:    [[CST7:%.*]] = bitcast <64 x i16> [[A3:%.*]] to <32 x i32>
; CHECK-NEXT:    [[CST8:%.*]] = bitcast <64 x i16> [[A2]] to <32 x i32>
; CHECK-NEXT:    [[CUP9:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> [[CST7]], <32 x i32> [[CST8]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST10:%.*]] = bitcast <32 x i32> [[CUP9]] to <128 x i8>
; CHECK-NEXT:    [[CUP11:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, <32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, i32 [[PTI1]])
; CHECK-NEXT:    [[CST12:%.*]] = bitcast <32 x i32> [[CUP11]] to <128 x i8>
; CHECK-NEXT:    [[CST13:%.*]] = bitcast <64 x i16> [[A3]] to <32 x i32>
; CHECK-NEXT:    [[CUP14:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> undef, <32 x i32> [[CST13]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST15:%.*]] = bitcast <32 x i32> [[CUP14]] to <128 x i8>
; CHECK-NEXT:    [[CUP16:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> zeroinitializer, <32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, i32 [[PTI1]])
; CHECK-NEXT:    [[CST17:%.*]] = bitcast <32 x i32> [[CUP16]] to <128 x i8>
; CHECK-NEXT:    [[TRN:%.*]] = trunc <128 x i8> [[CST6]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST4]], ptr [[ITP]], i32 128, <128 x i1> [[TRN]])
; CHECK-NEXT:    [[GEP:%.*]] = getelementptr i8, ptr [[ITP]], i32 128
; CHECK-NEXT:    [[TRN18:%.*]] = trunc <128 x i8> [[CST12]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST10]], ptr [[GEP]], i32 128, <128 x i1> [[TRN18]])
; CHECK-NEXT:    [[GEP19:%.*]] = getelementptr i8, ptr [[ITP]], i32 256
; CHECK-NEXT:    [[TRN20:%.*]] = trunc <128 x i8> [[CST17]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST15]], ptr [[GEP19]], i32 128, <128 x i1> [[TRN20]]), !tbaa [[TBAA5]]
; CHECK-NEXT:    ret void
;
b0:
  %v0 = add i32 %a1, 64
  %v1 = getelementptr i16, ptr %a0, i32 %v0
  store <64 x i16> %a2, ptr %v1, align 2
  %v3 = add i32 %a1, 128
  %v4 = getelementptr i16, ptr %a0, i32 %v3
  store <64 x i16> %a3, ptr %v4, align 2, !tbaa !5
  ret void
}

; Two unaligned store, with different TBAA tags.
;
define void @f5(ptr %a0, i32 %a1, <64 x i16> %a2, <64 x i16> %a3) #0 {
; CHECK-LABEL: @f5(
; CHECK-NEXT:  b0:
; CHECK-NEXT:    [[V0:%.*]] = add i32 [[A1:%.*]], 64
; CHECK-NEXT:    [[V1:%.*]] = getelementptr i16, ptr [[A0:%.*]], i32 [[V0]]
; CHECK-NEXT:    [[PTI:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[ADD:%.*]] = and i32 [[PTI]], -128
; CHECK-NEXT:    [[ITP:%.*]] = inttoptr i32 [[ADD]] to ptr
; CHECK-NEXT:    [[PTI1:%.*]] = ptrtoint ptr [[V1]] to i32
; CHECK-NEXT:    [[CST3:%.*]] = bitcast <64 x i16> [[A2:%.*]] to <32 x i32>
; CHECK-NEXT:    [[CUP:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> [[CST3]], <32 x i32> undef, i32 [[PTI1]])
; CHECK-NEXT:    [[CST4:%.*]] = bitcast <32 x i32> [[CUP]] to <128 x i8>
; CHECK-NEXT:    [[CUP5:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, <32 x i32> zeroinitializer, i32 [[PTI1]])
; CHECK-NEXT:    [[CST6:%.*]] = bitcast <32 x i32> [[CUP5]] to <128 x i8>
; CHECK-NEXT:    [[CST7:%.*]] = bitcast <64 x i16> [[A3:%.*]] to <32 x i32>
; CHECK-NEXT:    [[CST8:%.*]] = bitcast <64 x i16> [[A2]] to <32 x i32>
; CHECK-NEXT:    [[CUP9:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> [[CST7]], <32 x i32> [[CST8]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST10:%.*]] = bitcast <32 x i32> [[CUP9]] to <128 x i8>
; CHECK-NEXT:    [[CUP11:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, <32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, i32 [[PTI1]])
; CHECK-NEXT:    [[CST12:%.*]] = bitcast <32 x i32> [[CUP11]] to <128 x i8>
; CHECK-NEXT:    [[CST13:%.*]] = bitcast <64 x i16> [[A3]] to <32 x i32>
; CHECK-NEXT:    [[CUP14:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> undef, <32 x i32> [[CST13]], i32 [[PTI1]])
; CHECK-NEXT:    [[CST15:%.*]] = bitcast <32 x i32> [[CUP14]] to <128 x i8>
; CHECK-NEXT:    [[CUP16:%.*]] = call <32 x i32> @llvm.hexagon.V6.vlalignb.128B(<32 x i32> zeroinitializer, <32 x i32> <i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1, i32 -1>, i32 [[PTI1]])
; CHECK-NEXT:    [[CST17:%.*]] = bitcast <32 x i32> [[CUP16]] to <128 x i8>
; CHECK-NEXT:    [[TRN:%.*]] = trunc <128 x i8> [[CST6]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST4]], ptr [[ITP]], i32 128, <128 x i1> [[TRN]]), !tbaa [[TBAA5]]
; CHECK-NEXT:    [[GEP:%.*]] = getelementptr i8, ptr [[ITP]], i32 128
; CHECK-NEXT:    [[TRN18:%.*]] = trunc <128 x i8> [[CST12]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST10]], ptr [[GEP]], i32 128, <128 x i1> [[TRN18]])
; CHECK-NEXT:    [[GEP19:%.*]] = getelementptr i8, ptr [[ITP]], i32 256
; CHECK-NEXT:    [[TRN20:%.*]] = trunc <128 x i8> [[CST17]] to <128 x i1>
; CHECK-NEXT:    call void @llvm.masked.store.v128i8.p0(<128 x i8> [[CST15]], ptr [[GEP19]], i32 128, <128 x i1> [[TRN20]]), !tbaa [[TBAA7:![0-9]+]]
; CHECK-NEXT:    ret void
;
b0:
  %v0 = add i32 %a1, 64
  %v1 = getelementptr i16, ptr %a0, i32 %v0
  store <64 x i16> %a2, ptr %v1, align 2, !tbaa !5
  %v3 = add i32 %a1, 128
  %v4 = getelementptr i16, ptr %a0, i32 %v3
  store <64 x i16> %a3, ptr %v4, align 2, !tbaa !7
  ret void
}

attributes #0 = { nounwind "target-cpu"="hexagonv66" "target-features"="+hvx,+hvx-length128b" }

!0 = !{!1, !1, i64 0}
!1 = !{!"load type 1", !2}
!2 = !{!"Simple C/C++ TBAA"}
!3 = !{!4, !4, i64 0}
!4 = !{!"load type 2", !2}
!5 = !{!6, !6, i64 0}
!6 = !{!"store type 1", !2}
!7 = !{!8, !8, i64 0}
!8 = !{!"store type 2", !2}
