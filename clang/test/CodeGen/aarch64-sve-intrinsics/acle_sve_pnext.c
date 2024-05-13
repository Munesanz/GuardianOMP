// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: aarch64-registered-target
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sve -S -disable-O0-optnone -Werror -Wall -emit-llvm -o - %s | opt -S -passes=mem2reg,tailcallelim | FileCheck %s
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sve -S -disable-O0-optnone -Werror -Wall -emit-llvm -o - -x c++ %s | opt -S -passes=mem2reg,tailcallelim | FileCheck %s -check-prefix=CPP-CHECK
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sve -S -disable-O0-optnone -Werror -o /dev/null %s
#include <arm_sve.h>

// CHECK-LABEL: @test_svpnext_b8(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.pnext.nxv16i1(<vscale x 16 x i1> [[PG:%.*]], <vscale x 16 x i1> [[OP:%.*]])
// CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
// CPP-CHECK-LABEL: @_Z15test_svpnext_b8u10__SVBool_tu10__SVBool_t(
// CPP-CHECK-NEXT:  entry:
// CPP-CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.pnext.nxv16i1(<vscale x 16 x i1> [[PG:%.*]], <vscale x 16 x i1> [[OP:%.*]])
// CPP-CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP0]]
//
svbool_t test_svpnext_b8(svbool_t pg, svbool_t op)
{
  return svpnext_b8(pg, op);
}

// CHECK-LABEL: @test_svpnext_b16(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv8i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv8i1(<vscale x 16 x i1> [[OP:%.*]])
// CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.pnext.nxv8i1(<vscale x 8 x i1> [[TMP0]], <vscale x 8 x i1> [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv8i1(<vscale x 8 x i1> [[TMP2]])
// CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP3]]
//
// CPP-CHECK-LABEL: @_Z16test_svpnext_b16u10__SVBool_tu10__SVBool_t(
// CPP-CHECK-NEXT:  entry:
// CPP-CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv8i1(<vscale x 16 x i1> [[PG:%.*]])
// CPP-CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv8i1(<vscale x 16 x i1> [[OP:%.*]])
// CPP-CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.pnext.nxv8i1(<vscale x 8 x i1> [[TMP0]], <vscale x 8 x i1> [[TMP1]])
// CPP-CHECK-NEXT:    [[TMP3:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv8i1(<vscale x 8 x i1> [[TMP2]])
// CPP-CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP3]]
//
svbool_t test_svpnext_b16(svbool_t pg, svbool_t op)
{
  return svpnext_b16(pg, op);
}

// CHECK-LABEL: @test_svpnext_b32(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv4i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv4i1(<vscale x 16 x i1> [[OP:%.*]])
// CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.pnext.nxv4i1(<vscale x 4 x i1> [[TMP0]], <vscale x 4 x i1> [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv4i1(<vscale x 4 x i1> [[TMP2]])
// CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP3]]
//
// CPP-CHECK-LABEL: @_Z16test_svpnext_b32u10__SVBool_tu10__SVBool_t(
// CPP-CHECK-NEXT:  entry:
// CPP-CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv4i1(<vscale x 16 x i1> [[PG:%.*]])
// CPP-CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv4i1(<vscale x 16 x i1> [[OP:%.*]])
// CPP-CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.pnext.nxv4i1(<vscale x 4 x i1> [[TMP0]], <vscale x 4 x i1> [[TMP1]])
// CPP-CHECK-NEXT:    [[TMP3:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv4i1(<vscale x 4 x i1> [[TMP2]])
// CPP-CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP3]]
//
svbool_t test_svpnext_b32(svbool_t pg, svbool_t op)
{
  return svpnext_b32(pg, op);
}

// CHECK-LABEL: @test_svpnext_b64(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv2i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv2i1(<vscale x 16 x i1> [[OP:%.*]])
// CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.pnext.nxv2i1(<vscale x 2 x i1> [[TMP0]], <vscale x 2 x i1> [[TMP1]])
// CHECK-NEXT:    [[TMP3:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv2i1(<vscale x 2 x i1> [[TMP2]])
// CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP3]]
//
// CPP-CHECK-LABEL: @_Z16test_svpnext_b64u10__SVBool_tu10__SVBool_t(
// CPP-CHECK-NEXT:  entry:
// CPP-CHECK-NEXT:    [[TMP0:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv2i1(<vscale x 16 x i1> [[PG:%.*]])
// CPP-CHECK-NEXT:    [[TMP1:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv2i1(<vscale x 16 x i1> [[OP:%.*]])
// CPP-CHECK-NEXT:    [[TMP2:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.pnext.nxv2i1(<vscale x 2 x i1> [[TMP0]], <vscale x 2 x i1> [[TMP1]])
// CPP-CHECK-NEXT:    [[TMP3:%.*]] = tail call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv2i1(<vscale x 2 x i1> [[TMP2]])
// CPP-CHECK-NEXT:    ret <vscale x 16 x i1> [[TMP3]]
//
svbool_t test_svpnext_b64(svbool_t pg, svbool_t op)
{
  return svpnext_b64(pg, op);
}
