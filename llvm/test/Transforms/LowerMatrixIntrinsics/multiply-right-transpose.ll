; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes='lower-matrix-intrinsics' -S < %s | FileCheck %s

define <4 x double> @multiply_right_transpose_2x2(<4 x double> %a, <4 x double> %b) {
; CHECK-LABEL: @multiply_right_transpose_2x2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SPLIT:%.*]] = shufflevector <4 x double> [[A:%.*]], <4 x double> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT1:%.*]] = shufflevector <4 x double> [[A]], <4 x double> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[SPLIT2:%.*]] = shufflevector <4 x double> [[B:%.*]], <4 x double> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT3:%.*]] = shufflevector <4 x double> [[B]], <4 x double> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[BLOCK:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP0:%.*]] = extractelement <2 x double> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT:%.*]] = insertelement <1 x double> poison, double [[TMP0]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP1:%.*]] = fmul <1 x double> [[BLOCK]], [[SPLAT_SPLAT]]
; CHECK-NEXT:    [[BLOCK4:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP2:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT5:%.*]] = insertelement <1 x double> poison, double [[TMP2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT6:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT5]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP3:%.*]] = fmul <1 x double> [[BLOCK4]], [[SPLAT_SPLAT6]]
; CHECK-NEXT:    [[TMP4:%.*]] = fadd <1 x double> [[TMP1]], [[TMP3]]
; CHECK-NEXT:    [[TMP5:%.*]] = shufflevector <1 x double> [[TMP4]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP6:%.*]] = shufflevector <2 x double> undef, <2 x double> [[TMP5]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK7:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP7:%.*]] = extractelement <2 x double> [[SPLIT2]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT8:%.*]] = insertelement <1 x double> poison, double [[TMP7]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT9:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT8]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP8:%.*]] = fmul <1 x double> [[BLOCK7]], [[SPLAT_SPLAT9]]
; CHECK-NEXT:    [[BLOCK10:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP9:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT11:%.*]] = insertelement <1 x double> poison, double [[TMP9]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT12:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT11]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP10:%.*]] = fmul <1 x double> [[BLOCK10]], [[SPLAT_SPLAT12]]
; CHECK-NEXT:    [[TMP11:%.*]] = fadd <1 x double> [[TMP8]], [[TMP10]]
; CHECK-NEXT:    [[TMP12:%.*]] = shufflevector <1 x double> [[TMP11]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP13:%.*]] = shufflevector <2 x double> [[TMP6]], <2 x double> [[TMP12]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[BLOCK13:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP14:%.*]] = extractelement <2 x double> [[SPLIT2]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT14:%.*]] = insertelement <1 x double> poison, double [[TMP14]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT15:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT14]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP15:%.*]] = fmul <1 x double> [[BLOCK13]], [[SPLAT_SPLAT15]]
; CHECK-NEXT:    [[BLOCK16:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP16:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT17:%.*]] = insertelement <1 x double> poison, double [[TMP16]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT18:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT17]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP17:%.*]] = fmul <1 x double> [[BLOCK16]], [[SPLAT_SPLAT18]]
; CHECK-NEXT:    [[TMP18:%.*]] = fadd <1 x double> [[TMP15]], [[TMP17]]
; CHECK-NEXT:    [[TMP19:%.*]] = shufflevector <1 x double> [[TMP18]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP20:%.*]] = shufflevector <2 x double> undef, <2 x double> [[TMP19]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK19:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP21:%.*]] = extractelement <2 x double> [[SPLIT2]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT20:%.*]] = insertelement <1 x double> poison, double [[TMP21]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT21:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT20]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP22:%.*]] = fmul <1 x double> [[BLOCK19]], [[SPLAT_SPLAT21]]
; CHECK-NEXT:    [[BLOCK22:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP23:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT23:%.*]] = insertelement <1 x double> poison, double [[TMP23]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT24:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT23]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP24:%.*]] = fmul <1 x double> [[BLOCK22]], [[SPLAT_SPLAT24]]
; CHECK-NEXT:    [[TMP25:%.*]] = fadd <1 x double> [[TMP22]], [[TMP24]]
; CHECK-NEXT:    [[TMP26:%.*]] = shufflevector <1 x double> [[TMP25]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP27:%.*]] = shufflevector <2 x double> [[TMP20]], <2 x double> [[TMP26]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[TMP28:%.*]] = shufflevector <2 x double> [[TMP13]], <2 x double> [[TMP27]], <4 x i32> <i32 0, i32 1, i32 2, i32 3>
; CHECK-NEXT:    ret <4 x double> [[TMP28]]
;
entry:
  %bt = call <4 x double> @llvm.matrix.transpose.v4f64(<4 x double> %b, i32 2, i32 2)
  %c = call <4 x double> @llvm.matrix.multiply.v4f64.v4f64.v4f64(<4 x double> %a, <4 x double> %bt, i32 2, i32 2, i32 2)
  ret <4 x double> %c
}

; Lower transpose if not all uses are folded.
define <4 x double> @multiply_right_transpose_2x3x2(<6 x double> %a, <6 x double> %b, ptr %p) {
; CHECK-LABEL: @multiply_right_transpose_2x3x2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[SPLIT39:%.*]] = shufflevector <6 x double> [[B:%.*]], <6 x double> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT40:%.*]] = shufflevector <6 x double> [[B]], <6 x double> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[SPLIT41:%.*]] = shufflevector <6 x double> [[B]], <6 x double> poison, <2 x i32> <i32 4, i32 5>
; CHECK-NEXT:    [[TMP0:%.*]] = extractelement <2 x double> [[SPLIT39]], i64 0
; CHECK-NEXT:    [[TMP1:%.*]] = insertelement <3 x double> poison, double [[TMP0]], i64 0
; CHECK-NEXT:    [[TMP2:%.*]] = extractelement <2 x double> [[SPLIT40]], i64 0
; CHECK-NEXT:    [[TMP3:%.*]] = insertelement <3 x double> [[TMP1]], double [[TMP2]], i64 1
; CHECK-NEXT:    [[TMP4:%.*]] = extractelement <2 x double> [[SPLIT41]], i64 0
; CHECK-NEXT:    [[TMP5:%.*]] = insertelement <3 x double> [[TMP3]], double [[TMP4]], i64 2
; CHECK-NEXT:    [[TMP6:%.*]] = extractelement <2 x double> [[SPLIT39]], i64 1
; CHECK-NEXT:    [[TMP7:%.*]] = insertelement <3 x double> poison, double [[TMP6]], i64 0
; CHECK-NEXT:    [[TMP8:%.*]] = extractelement <2 x double> [[SPLIT40]], i64 1
; CHECK-NEXT:    [[TMP9:%.*]] = insertelement <3 x double> [[TMP7]], double [[TMP8]], i64 1
; CHECK-NEXT:    [[TMP10:%.*]] = extractelement <2 x double> [[SPLIT41]], i64 1
; CHECK-NEXT:    [[TMP11:%.*]] = insertelement <3 x double> [[TMP9]], double [[TMP10]], i64 2
; CHECK-NEXT:    store <3 x double> [[TMP5]], ptr [[P:%.*]], align 16
; CHECK-NEXT:    [[VEC_GEP:%.*]] = getelementptr double, ptr [[P]], i64 3
; CHECK-NEXT:    store <3 x double> [[TMP11]], ptr [[VEC_GEP]], align 8
; CHECK-NEXT:    [[SPLIT:%.*]] = shufflevector <6 x double> [[A:%.*]], <6 x double> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT1:%.*]] = shufflevector <6 x double> [[A]], <6 x double> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[SPLIT2:%.*]] = shufflevector <6 x double> [[A]], <6 x double> poison, <2 x i32> <i32 4, i32 5>
; CHECK-NEXT:    [[SPLIT3:%.*]] = shufflevector <6 x double> [[B]], <6 x double> poison, <2 x i32> <i32 0, i32 1>
; CHECK-NEXT:    [[SPLIT4:%.*]] = shufflevector <6 x double> [[B]], <6 x double> poison, <2 x i32> <i32 2, i32 3>
; CHECK-NEXT:    [[SPLIT5:%.*]] = shufflevector <6 x double> [[B]], <6 x double> poison, <2 x i32> <i32 4, i32 5>
; CHECK-NEXT:    [[BLOCK:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP12:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT:%.*]] = insertelement <1 x double> poison, double [[TMP12]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP13:%.*]] = fmul <1 x double> [[BLOCK]], [[SPLAT_SPLAT]]
; CHECK-NEXT:    [[BLOCK6:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP14:%.*]] = extractelement <2 x double> [[SPLIT4]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT7:%.*]] = insertelement <1 x double> poison, double [[TMP14]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT8:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT7]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP15:%.*]] = fmul <1 x double> [[BLOCK6]], [[SPLAT_SPLAT8]]
; CHECK-NEXT:    [[TMP16:%.*]] = fadd <1 x double> [[TMP13]], [[TMP15]]
; CHECK-NEXT:    [[BLOCK9:%.*]] = shufflevector <2 x double> [[SPLIT2]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP17:%.*]] = extractelement <2 x double> [[SPLIT5]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT10:%.*]] = insertelement <1 x double> poison, double [[TMP17]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT11:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT10]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP18:%.*]] = fmul <1 x double> [[BLOCK9]], [[SPLAT_SPLAT11]]
; CHECK-NEXT:    [[TMP19:%.*]] = fadd <1 x double> [[TMP16]], [[TMP18]]
; CHECK-NEXT:    [[TMP20:%.*]] = shufflevector <1 x double> [[TMP19]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP21:%.*]] = shufflevector <2 x double> undef, <2 x double> [[TMP20]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK12:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP22:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT13:%.*]] = insertelement <1 x double> poison, double [[TMP22]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT14:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT13]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP23:%.*]] = fmul <1 x double> [[BLOCK12]], [[SPLAT_SPLAT14]]
; CHECK-NEXT:    [[BLOCK15:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP24:%.*]] = extractelement <2 x double> [[SPLIT4]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT16:%.*]] = insertelement <1 x double> poison, double [[TMP24]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT17:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT16]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP25:%.*]] = fmul <1 x double> [[BLOCK15]], [[SPLAT_SPLAT17]]
; CHECK-NEXT:    [[TMP26:%.*]] = fadd <1 x double> [[TMP23]], [[TMP25]]
; CHECK-NEXT:    [[BLOCK18:%.*]] = shufflevector <2 x double> [[SPLIT2]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP27:%.*]] = extractelement <2 x double> [[SPLIT5]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLATINSERT19:%.*]] = insertelement <1 x double> poison, double [[TMP27]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT20:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT19]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP28:%.*]] = fmul <1 x double> [[BLOCK18]], [[SPLAT_SPLAT20]]
; CHECK-NEXT:    [[TMP29:%.*]] = fadd <1 x double> [[TMP26]], [[TMP28]]
; CHECK-NEXT:    [[TMP30:%.*]] = shufflevector <1 x double> [[TMP29]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP31:%.*]] = shufflevector <2 x double> [[TMP21]], <2 x double> [[TMP30]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[BLOCK21:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP32:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT22:%.*]] = insertelement <1 x double> poison, double [[TMP32]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT23:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT22]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP33:%.*]] = fmul <1 x double> [[BLOCK21]], [[SPLAT_SPLAT23]]
; CHECK-NEXT:    [[BLOCK24:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP34:%.*]] = extractelement <2 x double> [[SPLIT4]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT25:%.*]] = insertelement <1 x double> poison, double [[TMP34]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT26:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT25]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP35:%.*]] = fmul <1 x double> [[BLOCK24]], [[SPLAT_SPLAT26]]
; CHECK-NEXT:    [[TMP36:%.*]] = fadd <1 x double> [[TMP33]], [[TMP35]]
; CHECK-NEXT:    [[BLOCK27:%.*]] = shufflevector <2 x double> [[SPLIT2]], <2 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP37:%.*]] = extractelement <2 x double> [[SPLIT5]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT28:%.*]] = insertelement <1 x double> poison, double [[TMP37]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT29:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT28]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP38:%.*]] = fmul <1 x double> [[BLOCK27]], [[SPLAT_SPLAT29]]
; CHECK-NEXT:    [[TMP39:%.*]] = fadd <1 x double> [[TMP36]], [[TMP38]]
; CHECK-NEXT:    [[TMP40:%.*]] = shufflevector <1 x double> [[TMP39]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP41:%.*]] = shufflevector <2 x double> undef, <2 x double> [[TMP40]], <2 x i32> <i32 2, i32 1>
; CHECK-NEXT:    [[BLOCK30:%.*]] = shufflevector <2 x double> [[SPLIT]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP42:%.*]] = extractelement <2 x double> [[SPLIT3]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT31:%.*]] = insertelement <1 x double> poison, double [[TMP42]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT32:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT31]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP43:%.*]] = fmul <1 x double> [[BLOCK30]], [[SPLAT_SPLAT32]]
; CHECK-NEXT:    [[BLOCK33:%.*]] = shufflevector <2 x double> [[SPLIT1]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP44:%.*]] = extractelement <2 x double> [[SPLIT4]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT34:%.*]] = insertelement <1 x double> poison, double [[TMP44]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT35:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT34]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP45:%.*]] = fmul <1 x double> [[BLOCK33]], [[SPLAT_SPLAT35]]
; CHECK-NEXT:    [[TMP46:%.*]] = fadd <1 x double> [[TMP43]], [[TMP45]]
; CHECK-NEXT:    [[BLOCK36:%.*]] = shufflevector <2 x double> [[SPLIT2]], <2 x double> poison, <1 x i32> <i32 1>
; CHECK-NEXT:    [[TMP47:%.*]] = extractelement <2 x double> [[SPLIT5]], i64 1
; CHECK-NEXT:    [[SPLAT_SPLATINSERT37:%.*]] = insertelement <1 x double> poison, double [[TMP47]], i64 0
; CHECK-NEXT:    [[SPLAT_SPLAT38:%.*]] = shufflevector <1 x double> [[SPLAT_SPLATINSERT37]], <1 x double> poison, <1 x i32> zeroinitializer
; CHECK-NEXT:    [[TMP48:%.*]] = fmul <1 x double> [[BLOCK36]], [[SPLAT_SPLAT38]]
; CHECK-NEXT:    [[TMP49:%.*]] = fadd <1 x double> [[TMP46]], [[TMP48]]
; CHECK-NEXT:    [[TMP50:%.*]] = shufflevector <1 x double> [[TMP49]], <1 x double> poison, <2 x i32> <i32 0, i32 poison>
; CHECK-NEXT:    [[TMP51:%.*]] = shufflevector <2 x double> [[TMP41]], <2 x double> [[TMP50]], <2 x i32> <i32 0, i32 2>
; CHECK-NEXT:    [[TMP52:%.*]] = shufflevector <2 x double> [[TMP31]], <2 x double> [[TMP51]], <4 x i32> <i32 0, i32 1, i32 2, i32 3>
; CHECK-NEXT:    ret <4 x double> [[TMP52]]
;
entry:
  %bt = call <6 x double> @llvm.matrix.transpose.v6f64(<6 x double> %b, i32 2, i32 3)
  store <6 x double> %bt, ptr %p, align 16
  %c = call <4 x double> @llvm.matrix.multiply.v4f64.v6f64.v6f64(<6 x double> %a, <6 x double> %bt, i32 2, i32 3, i32 2)
  ret <4 x double> %c
}


declare <4 x double> @llvm.matrix.multiply.v4f64.v4f64.v4f64(<4 x double>, <4 x double>, i32, i32, i32)
declare <4 x double> @llvm.matrix.multiply.v4f64.v6f64.v6f64(<6 x double>, <6 x double>, i32, i32, i32)
declare <4 x double> @llvm.matrix.transpose.v4f64(<4 x double>, i32, i32)
declare <6 x double> @llvm.matrix.transpose.v6f64(<6 x double>, i32, i32)
