; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes='lower-matrix-intrinsics' -S < %s | FileCheck %s


define <4 x float> @multiply_2x2(<4 x float> %a, <4 x float> %b) {
; CHECK-LABEL: @multiply_2x2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SPLIT:%.*]] = shufflevector <4 x float> [[A:%.*]], <4 x float> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT1:%.*]] = shufflevector <4 x float> [[A]], <4 x float> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[SPLIT2:%.*]] = shufflevector <4 x float> [[B:%.*]], <4 x float> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT3:%.*]] = shufflevector <4 x float> [[B]], <4 x float> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[BLOCK:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP0:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT:%.*]] = insertelement <1 x float> poison, float [[TMP0]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP1:%.*]] = fmul <1 x float> [[BLOCK]], [[SPLAT_SPLAT]]
; CHECK-NEXT:    [[BLOCK4:%.*]] = shufflevector <2 x float> [[SPLIT1]], <2 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP2:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT5:%.*]] = insertelement <1 x float> poison, float [[TMP2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT6:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT5]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP3:%.*]] = fmul <1 x float> [[BLOCK4]], [[SPLAT_SPLAT6]]
; CHECK-NEXT:    [[TMP4:%.*]] = fadd <1 x float> [[TMP1]], [[TMP3]]
; CHECK-NEXT:    [[TMP5:%.*]] = shufflevector <1 x float> [[TMP4]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP6:%.*]] = shufflevector <2 x float> undef, <2 x float> [[TMP5]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK7:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP7:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT8:%.*]] = insertelement <1 x float> poison, float [[TMP7]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT9:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT8]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP8:%.*]] = fmul <1 x float> [[BLOCK7]], [[SPLAT_SPLAT9]]
; CHECK-NEXT:    [[BLOCK10:%.*]] = shufflevector <2 x float> [[SPLIT1]], <2 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP9:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT11:%.*]] = insertelement <1 x float> poison, float [[TMP9]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT12:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT11]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP10:%.*]] = fmul <1 x float> [[BLOCK10]], [[SPLAT_SPLAT12]]
; CHECK-NEXT:    [[TMP11:%.*]] = fadd <1 x float> [[TMP8]], [[TMP10]]
; CHECK-NEXT:    [[TMP12:%.*]] = shufflevector <1 x float> [[TMP11]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP13:%.*]] = shufflevector <2 x float> [[TMP6]], <2 x float> [[TMP12]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[BLOCK13:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP14:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT14:%.*]] = insertelement <1 x float> poison, float [[TMP14]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT15:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT14]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP15:%.*]] = fmul <1 x float> [[BLOCK13]], [[SPLAT_SPLAT15]]
; CHECK-NEXT:    [[BLOCK16:%.*]] = shufflevector <2 x float> [[SPLIT1]], <2 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP16:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT17:%.*]] = insertelement <1 x float> poison, float [[TMP16]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT18:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT17]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP17:%.*]] = fmul <1 x float> [[BLOCK16]], [[SPLAT_SPLAT18]]
; CHECK-NEXT:    [[TMP18:%.*]] = fadd <1 x float> [[TMP15]], [[TMP17]]
; CHECK-NEXT:    [[TMP19:%.*]] = shufflevector <1 x float> [[TMP18]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP20:%.*]] = shufflevector <2 x float> undef, <2 x float> [[TMP19]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK19:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP21:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT20:%.*]] = insertelement <1 x float> poison, float [[TMP21]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT21:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT20]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP22:%.*]] = fmul <1 x float> [[BLOCK19]], [[SPLAT_SPLAT21]]
; CHECK-NEXT:    [[BLOCK22:%.*]] = shufflevector <2 x float> [[SPLIT1]], <2 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP23:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT23:%.*]] = insertelement <1 x float> poison, float [[TMP23]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT24:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT23]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP24:%.*]] = fmul <1 x float> [[BLOCK22]], [[SPLAT_SPLAT24]]
; CHECK-NEXT:    [[TMP25:%.*]] = fadd <1 x float> [[TMP22]], [[TMP24]]
; CHECK-NEXT:    [[TMP26:%.*]] = shufflevector <1 x float> [[TMP25]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP27:%.*]] = shufflevector <2 x float> [[TMP20]], <2 x float> [[TMP26]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[TMP28:%.*]] = shufflevector <2 x float> [[TMP13]], <2 x float> [[TMP27]], <4 x i32> <i32 0, i32 1, i32 2, i32 3>
; CHECK-NEXT:    ret <4 x float> [[TMP28]]
;
entry:
  %c = call <4 x float> @llvm.matrix.multiply.v4f32.v4f32.v4f32(<4 x float> %a, <4 x float> %b, i32 2, i32 2, i32 2)
  ret <4 x float> %c
}

declare <4 x float> @llvm.matrix.multiply.v4f32.v4f32.v4f32(<4 x float>, <4 x float>, i32, i32, i32)

define <4 x float> @multiply_1x2(<2 x float> %a, <2 x float> %b) {
; CHECK-LABEL: @multiply_1x2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SPLIT:%.*]] = shufflevector <2 x float> [[A:%.*]], <2 x float> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT1:%.*]] = shufflevector <2 x float> [[B:%.*]], <2 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[SPLIT2:%.*]] = shufflevector <2 x float> [[B]], <2 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[BLOCK:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP0:%.*]] = extractelement <1 x float> [[SPLIT1]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT:%.*]] = insertelement <1 x float> poison, float [[TMP0]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP1:%.*]] = fmul <1 x float> [[BLOCK]], [[SPLAT_SPLAT]]
; CHECK-NEXT:    [[TMP2:%.*]] = shufflevector <1 x float> [[TMP1]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP3:%.*]] = shufflevector <2 x float> undef, <2 x float> [[TMP2]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK3:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP4:%.*]] = extractelement <1 x float> [[SPLIT1]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT4:%.*]] = insertelement <1 x float> poison, float [[TMP4]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT5:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT4]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP5:%.*]] = fmul <1 x float> [[BLOCK3]], [[SPLAT_SPLAT5]]
; CHECK-NEXT:    [[TMP6:%.*]] = shufflevector <1 x float> [[TMP5]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP7:%.*]] = shufflevector <2 x float> [[TMP3]], <2 x float> [[TMP6]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[BLOCK6:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP8:%.*]] = extractelement <1 x float> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT7:%.*]] = insertelement <1 x float> poison, float [[TMP8]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT8:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT7]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP9:%.*]] = fmul <1 x float> [[BLOCK6]], [[SPLAT_SPLAT8]]
; CHECK-NEXT:    [[TMP10:%.*]] = shufflevector <1 x float> [[TMP9]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP11:%.*]] = shufflevector <2 x float> undef, <2 x float> [[TMP10]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK9:%.*]] = shufflevector <2 x float> [[SPLIT]], <2 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP12:%.*]] = extractelement <1 x float> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT10:%.*]] = insertelement <1 x float> poison, float [[TMP12]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT11:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT10]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP13:%.*]] = fmul <1 x float> [[BLOCK9]], [[SPLAT_SPLAT11]]
; CHECK-NEXT:    [[TMP14:%.*]] = shufflevector <1 x float> [[TMP13]], <1 x float> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP15:%.*]] = shufflevector <2 x float> [[TMP11]], <2 x float> [[TMP14]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[TMP16:%.*]] = shufflevector <2 x float> [[TMP7]], <2 x float> [[TMP15]], <4 x i32> <i32 0, i32 1, i32 2, i32 3>
; CHECK-NEXT:    ret <4 x float> [[TMP16]]
;
entry:
  %c = call <4 x float> @llvm.matrix.multiply.v4f32.v2f32.v2f32(<2 x float> %a, <2 x float> %b, i32 2, i32 1, i32 2)
  ret <4 x float> %c
}

declare <4 x float> @llvm.matrix.multiply.v4f32.v2f32.v2f32(<2 x float>, <2 x float>, i32, i32, i32)

define <9 x float> @multiply_2x3(<6 x float> %a, <6 x float> %b) {
; CHECK-LABEL: @multiply_2x3(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SPLIT:%.*]] = shufflevector <6 x float> [[A:%.*]], <6 x float> poison, <3 x i32> <i32 0, i32 1, i32 2>
; CHECK-NEXT:    [[SPLIT1:%.*]] = shufflevector <6 x float> [[A]], <6 x float> poison, <3 x i32> <i32 3, i32 4, i32 5>
; CHECK-NEXT:    [[SPLIT2:%.*]] = shufflevector <6 x float> [[B:%.*]], <6 x float> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT3:%.*]] = shufflevector <6 x float> [[B]], <6 x float> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[SPLIT4:%.*]] = shufflevector <6 x float> [[B]], <6 x float> poison, <2 x i32> <i32 4, i32 5>
; CHECK-NEXT:    [[BLOCK:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP0:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT:%.*]] = insertelement <1 x float> poison, float [[TMP0]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP1:%.*]] = fmul <1 x float> [[BLOCK]], [[SPLAT_SPLAT]]
; CHECK-NEXT:    [[BLOCK5:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP2:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT6:%.*]] = insertelement <1 x float> poison, float [[TMP2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT7:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT6]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP3:%.*]] = fmul <1 x float> [[BLOCK5]], [[SPLAT_SPLAT7]]
; CHECK-NEXT:    [[TMP4:%.*]] = fadd <1 x float> [[TMP1]], [[TMP3]]
; CHECK-NEXT:    [[TMP5:%.*]] = shufflevector <1 x float> [[TMP4]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP6:%.*]] = shufflevector <3 x float> undef, <3 x float> [[TMP5]], <3 x i32> <i32 3, i32 1, i32 2>
; CHECK-NEXT:    [[BLOCK8:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP7:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT9:%.*]] = insertelement <1 x float> poison, float [[TMP7]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT10:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT9]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP8:%.*]] = fmul <1 x float> [[BLOCK8]], [[SPLAT_SPLAT10]]
; CHECK-NEXT:    [[BLOCK11:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP9:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT12:%.*]] = insertelement <1 x float> poison, float [[TMP9]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT13:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT12]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP10:%.*]] = fmul <1 x float> [[BLOCK11]], [[SPLAT_SPLAT13]]
; CHECK-NEXT:    [[TMP11:%.*]] = fadd <1 x float> [[TMP8]], [[TMP10]]
; CHECK-NEXT:    [[TMP12:%.*]] = shufflevector <1 x float> [[TMP11]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP13:%.*]] = shufflevector <3 x float> [[TMP6]], <3 x float> [[TMP12]], <3 x i32> <i32 0, i32 3, i32 2>
; CHECK-NEXT:    [[BLOCK14:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> <i32 2>
; CHECK-NEXT:    [[TMP14:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT15:%.*]] = insertelement <1 x float> poison, float [[TMP14]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT16:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT15]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP15:%.*]] = fmul <1 x float> [[BLOCK14]], [[SPLAT_SPLAT16]]
; CHECK-NEXT:    [[BLOCK17:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> <i32 2>
; CHECK-NEXT:    [[TMP16:%.*]] = extractelement <2 x float> [[SPLIT2]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT18:%.*]] = insertelement <1 x float> poison, float [[TMP16]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT19:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT18]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP17:%.*]] = fmul <1 x float> [[BLOCK17]], [[SPLAT_SPLAT19]]
; CHECK-NEXT:    [[TMP18:%.*]] = fadd <1 x float> [[TMP15]], [[TMP17]]
; CHECK-NEXT:    [[TMP19:%.*]] = shufflevector <1 x float> [[TMP18]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP20:%.*]] = shufflevector <3 x float> [[TMP13]], <3 x float> [[TMP19]], <3 x i32> <i32 0, i32 1, i32 3>
; CHECK-NEXT:    [[BLOCK20:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP21:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT21:%.*]] = insertelement <1 x float> poison, float [[TMP21]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT22:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT21]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP22:%.*]] = fmul <1 x float> [[BLOCK20]], [[SPLAT_SPLAT22]]
; CHECK-NEXT:    [[BLOCK23:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP23:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT24:%.*]] = insertelement <1 x float> poison, float [[TMP23]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT25:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT24]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP24:%.*]] = fmul <1 x float> [[BLOCK23]], [[SPLAT_SPLAT25]]
; CHECK-NEXT:    [[TMP25:%.*]] = fadd <1 x float> [[TMP22]], [[TMP24]]
; CHECK-NEXT:    [[TMP26:%.*]] = shufflevector <1 x float> [[TMP25]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP27:%.*]] = shufflevector <3 x float> undef, <3 x float> [[TMP26]], <3 x i32> <i32 3, i32 1, i32 2>
; CHECK-NEXT:    [[BLOCK26:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP28:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT27:%.*]] = insertelement <1 x float> poison, float [[TMP28]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT28:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT27]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP29:%.*]] = fmul <1 x float> [[BLOCK26]], [[SPLAT_SPLAT28]]
; CHECK-NEXT:    [[BLOCK29:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP30:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT30:%.*]] = insertelement <1 x float> poison, float [[TMP30]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT31:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT30]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP31:%.*]] = fmul <1 x float> [[BLOCK29]], [[SPLAT_SPLAT31]]
; CHECK-NEXT:    [[TMP32:%.*]] = fadd <1 x float> [[TMP29]], [[TMP31]]
; CHECK-NEXT:    [[TMP33:%.*]] = shufflevector <1 x float> [[TMP32]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP34:%.*]] = shufflevector <3 x float> [[TMP27]], <3 x float> [[TMP33]], <3 x i32> <i32 0, i32 3, i32 2>
; CHECK-NEXT:    [[BLOCK32:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> <i32 2>
; CHECK-NEXT:    [[TMP35:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT33:%.*]] = insertelement <1 x float> poison, float [[TMP35]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT34:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT33]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP36:%.*]] = fmul <1 x float> [[BLOCK32]], [[SPLAT_SPLAT34]]
; CHECK-NEXT:    [[BLOCK35:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> <i32 2>
; CHECK-NEXT:    [[TMP37:%.*]] = extractelement <2 x float> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT36:%.*]] = insertelement <1 x float> poison, float [[TMP37]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT37:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT36]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP38:%.*]] = fmul <1 x float> [[BLOCK35]], [[SPLAT_SPLAT37]]
; CHECK-NEXT:    [[TMP39:%.*]] = fadd <1 x float> [[TMP36]], [[TMP38]]
; CHECK-NEXT:    [[TMP40:%.*]] = shufflevector <1 x float> [[TMP39]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP41:%.*]] = shufflevector <3 x float> [[TMP34]], <3 x float> [[TMP40]], <3 x i32> <i32 0, i32 1, i32 3>
; CHECK-NEXT:    [[BLOCK38:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP42:%.*]] = extractelement <2 x float> [[SPLIT4]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT39:%.*]] = insertelement <1 x float> poison, float [[TMP42]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT40:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT39]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP43:%.*]] = fmul <1 x float> [[BLOCK38]], [[SPLAT_SPLAT40]]
; CHECK-NEXT:    [[BLOCK41:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP44:%.*]] = extractelement <2 x float> [[SPLIT4]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT42:%.*]] = insertelement <1 x float> poison, float [[TMP44]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT43:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT42]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP45:%.*]] = fmul <1 x float> [[BLOCK41]], [[SPLAT_SPLAT43]]
; CHECK-NEXT:    [[TMP46:%.*]] = fadd <1 x float> [[TMP43]], [[TMP45]]
; CHECK-NEXT:    [[TMP47:%.*]] = shufflevector <1 x float> [[TMP46]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP48:%.*]] = shufflevector <3 x float> undef, <3 x float> [[TMP47]], <3 x i32> <i32 3, i32 1, i32 2>
; CHECK-NEXT:    [[BLOCK44:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP49:%.*]] = extractelement <2 x float> [[SPLIT4]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT45:%.*]] = insertelement <1 x float> poison, float [[TMP49]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT46:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT45]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP50:%.*]] = fmul <1 x float> [[BLOCK44]], [[SPLAT_SPLAT46]]
; CHECK-NEXT:    [[BLOCK47:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP51:%.*]] = extractelement <2 x float> [[SPLIT4]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT48:%.*]] = insertelement <1 x float> poison, float [[TMP51]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT49:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT48]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP52:%.*]] = fmul <1 x float> [[BLOCK47]], [[SPLAT_SPLAT49]]
; CHECK-NEXT:    [[TMP53:%.*]] = fadd <1 x float> [[TMP50]], [[TMP52]]
; CHECK-NEXT:    [[TMP54:%.*]] = shufflevector <1 x float> [[TMP53]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP55:%.*]] = shufflevector <3 x float> [[TMP48]], <3 x float> [[TMP54]], <3 x i32> <i32 0, i32 3, i32 2>
; CHECK-NEXT:    [[BLOCK50:%.*]] = shufflevector <3 x float> [[SPLIT]], <3 x float> poison, <1 x i32> <i32 2>
; CHECK-NEXT:    [[TMP56:%.*]] = extractelement <2 x float> [[SPLIT4]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT51:%.*]] = insertelement <1 x float> poison, float [[TMP56]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT52:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT51]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP57:%.*]] = fmul <1 x float> [[BLOCK50]], [[SPLAT_SPLAT52]]
; CHECK-NEXT:    [[BLOCK53:%.*]] = shufflevector <3 x float> [[SPLIT1]], <3 x float> poison, <1 x i32> <i32 2>
; CHECK-NEXT:    [[TMP58:%.*]] = extractelement <2 x float> [[SPLIT4]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT54:%.*]] = insertelement <1 x float> poison, float [[TMP58]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT55:%.*]] = shufflevector <1 x float> [[SPLAT_SPLATINSERT54]], <1 x float> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP59:%.*]] = fmul <1 x float> [[BLOCK53]], [[SPLAT_SPLAT55]]
; CHECK-NEXT:    [[TMP60:%.*]] = fadd <1 x float> [[TMP57]], [[TMP59]]
; CHECK-NEXT:    [[TMP61:%.*]] = shufflevector <1 x float> [[TMP60]], <1 x float> poison, <3 x i32> <i32 0, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP62:%.*]] = shufflevector <3 x float> [[TMP55]], <3 x float> [[TMP61]], <3 x i32> <i32 0, i32 1, i32 3>
; CHECK-NEXT:    [[TMP63:%.*]] = shufflevector <3 x float> [[TMP20]], <3 x float> [[TMP41]], <6 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5>
; CHECK-NEXT:    [[TMP64:%.*]] = shufflevector <3 x float> [[TMP62]], <3 x float> poison, <6 x i32> <i32 0, i32 1, i32 2, i32 poison, i32 poison, i32 poison>
; CHECK-NEXT:    [[TMP65:%.*]] = shufflevector <6 x float> [[TMP63]], <6 x float> [[TMP64]], <9 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8>
; CHECK-NEXT:    ret <9 x float> [[TMP65]]
;
entry:
  %c = call <9 x float> @llvm.matrix.multiply.v6f32.v6f32.v6f32(<6 x float> %a, <6 x float> %b, i32 3, i32 2, i32 3)
  ret <9 x float> %c
}

declare <9 x float> @llvm.matrix.multiply.v6f32.v6f32.v6f32(<6 x float>, <6 x float>, i32, i32, i32)
