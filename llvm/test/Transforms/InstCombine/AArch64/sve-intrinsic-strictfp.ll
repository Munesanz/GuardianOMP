; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --check-attributes --check-globals
; RUN: opt -S -passes=inline,instcombine < %s | FileCheck %s

target triple = "aarch64-unknown-linux-gnu"

; TODO: We can only lower to constrained intrinsics when the necessary code
; generation support for scalable vector strict operations exists.
define <vscale x 2 x double> @replace_fadd_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #0 {
; CHECK: Function Attrs: strictfp
; CHECK-LABEL: @replace_fadd_intrinsic_double_strictfp(
; CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #[[ATTR2:[0-9]+]]
; CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 2 x double> @llvm.aarch64.sve.fadd.nxv2f64(<vscale x 2 x i1> [[TMP1]], <vscale x 2 x double> [[A:%.*]], <vscale x 2 x double> [[B:%.*]]) #[[ATTR2]]
; CHECK-NEXT:    ret <vscale x 2 x double> [[TMP2]]
;
  %1 = tail call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #1
  %2 = tail call <vscale x 2 x double> @llvm.aarch64.sve.fadd.nxv2f64(<vscale x 2 x i1> %1, <vscale x 2 x double> %a, <vscale x 2 x double> %b) #1
  ret <vscale x 2 x double> %2
}

; NOTE: IRBuilder::CreateBinOp doesn't emit constrained operations directly so
; rely on function inlining to showcase the problematic transformation.
define <vscale x 2 x double> @call_replace_fadd_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #0 {
; CHECK: Function Attrs: strictfp
; CHECK-LABEL: @call_replace_fadd_intrinsic_double_strictfp(
; CHECK-NEXT:    [[TMP1:%.*]] = call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #[[ATTR2]]
; CHECK-NEXT:    [[TMP2:%.*]] = call <vscale x 2 x double> @llvm.aarch64.sve.fadd.nxv2f64(<vscale x 2 x i1> [[TMP1]], <vscale x 2 x double> [[A:%.*]], <vscale x 2 x double> [[B:%.*]]) #[[ATTR2]]
; CHECK-NEXT:    ret <vscale x 2 x double> [[TMP2]]
;
  %1 = call <vscale x 2 x double> @replace_fadd_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #1
  ret <vscale x 2 x double> %1
}

; TODO: We can only lower to constrained intrinsics when the necessary code
; generation support for scalable vector strict operations exists.
define <vscale x 2 x double> @replace_fmul_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #0 {
; CHECK: Function Attrs: strictfp
; CHECK-LABEL: @replace_fmul_intrinsic_double_strictfp(
; CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #[[ATTR2]]
; CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 2 x double> @llvm.aarch64.sve.fmul.nxv2f64(<vscale x 2 x i1> [[TMP1]], <vscale x 2 x double> [[A:%.*]], <vscale x 2 x double> [[B:%.*]]) #[[ATTR2]]
; CHECK-NEXT:    ret <vscale x 2 x double> [[TMP2]]
;
  %1 = tail call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #1
  %2 = tail call <vscale x 2 x double> @llvm.aarch64.sve.fmul.nxv2f64(<vscale x 2 x i1> %1, <vscale x 2 x double> %a, <vscale x 2 x double> %b) #1
  ret <vscale x 2 x double> %2
}

; NOTE: IRBuilder::CreateBinOp doesn't emit constrained operations directly so
; rely on function inlining to showcase the problematic transformation.
define <vscale x 2 x double> @call_replace_fmul_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #0 {
; CHECK: Function Attrs: strictfp
; CHECK-LABEL: @call_replace_fmul_intrinsic_double_strictfp(
; CHECK-NEXT:    [[TMP1:%.*]] = call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #[[ATTR2]]
; CHECK-NEXT:    [[TMP2:%.*]] = call <vscale x 2 x double> @llvm.aarch64.sve.fmul.nxv2f64(<vscale x 2 x i1> [[TMP1]], <vscale x 2 x double> [[A:%.*]], <vscale x 2 x double> [[B:%.*]]) #[[ATTR2]]
; CHECK-NEXT:    ret <vscale x 2 x double> [[TMP2]]
;
  %1 = call <vscale x 2 x double> @replace_fmul_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #1
  ret <vscale x 2 x double> %1
}

; TODO: We can only lower to constrained intrinsics when the necessary code
; generation support for scalable vector strict operations exists.
define <vscale x 2 x double> @replace_fsub_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #0 {
; CHECK: Function Attrs: strictfp
; CHECK-LABEL: @replace_fsub_intrinsic_double_strictfp(
; CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #[[ATTR2]]
; CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 2 x double> @llvm.aarch64.sve.fsub.nxv2f64(<vscale x 2 x i1> [[TMP1]], <vscale x 2 x double> [[A:%.*]], <vscale x 2 x double> [[B:%.*]]) #[[ATTR2]]
; CHECK-NEXT:    ret <vscale x 2 x double> [[TMP2]]
;
  %1 = tail call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #1
  %2 = tail call <vscale x 2 x double> @llvm.aarch64.sve.fsub.nxv2f64(<vscale x 2 x i1> %1, <vscale x 2 x double> %a, <vscale x 2 x double> %b) #1
  ret <vscale x 2 x double> %2
}

; NOTE: IRBuilder::CreateBinOp doesn't emit constrained operations directly so
; rely on function inlining to showcase the problematic transformation.
define <vscale x 2 x double> @call_replace_fsub_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #0 {
; CHECK: Function Attrs: strictfp
; CHECK-LABEL: @call_replace_fsub_intrinsic_double_strictfp(
; CHECK-NEXT:    [[TMP1:%.*]] = call <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32 31) #[[ATTR2]]
; CHECK-NEXT:    [[TMP2:%.*]] = call <vscale x 2 x double> @llvm.aarch64.sve.fsub.nxv2f64(<vscale x 2 x i1> [[TMP1]], <vscale x 2 x double> [[A:%.*]], <vscale x 2 x double> [[B:%.*]]) #[[ATTR2]]
; CHECK-NEXT:    ret <vscale x 2 x double> [[TMP2]]
;
  %1 = call <vscale x 2 x double> @replace_fsub_intrinsic_double_strictfp(<vscale x 2 x double> %a, <vscale x 2 x double> %b) #1
  ret <vscale x 2 x double> %1
}

declare <vscale x 2 x double> @llvm.aarch64.sve.fadd.nxv2f64(<vscale x 2 x i1>, <vscale x 2 x double>, <vscale x 2 x double>)
declare <vscale x 2 x double> @llvm.aarch64.sve.fmul.nxv2f64(<vscale x 2 x i1>, <vscale x 2 x double>, <vscale x 2 x double>)
declare <vscale x 2 x double> @llvm.aarch64.sve.fsub.nxv2f64(<vscale x 2 x i1>, <vscale x 2 x double>, <vscale x 2 x double>)

declare <vscale x 2 x i1> @llvm.aarch64.sve.ptrue.nxv2i1(i32)

attributes #0 = { "target-features"="+sve" strictfp }
attributes #1 = { strictfp }
;.
; CHECK: attributes #[[ATTR0:[0-9]+]] = { strictfp "target-features"="+sve" }
; CHECK: attributes #[[ATTR1:[0-9]+]] = { nocallback nofree nosync nounwind willreturn memory(none) }
; CHECK: attributes #[[ATTR2]] = { strictfp }
;.
