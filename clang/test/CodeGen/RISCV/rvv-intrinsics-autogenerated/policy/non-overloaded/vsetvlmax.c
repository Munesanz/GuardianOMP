// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// REQUIRES: riscv-registered-target
// RUN: %clang_cc1 -triple riscv64 -target-feature +v -disable-O0-optnone \
// RUN:   -emit-llvm %s -o - | opt -S -passes=mem2reg | \
// RUN:   FileCheck --check-prefix=CHECK-RV64 %s

#include <riscv_vector.h>

// CHECK-RV64-LABEL: @test_vsetvlmax_e8mf8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 0, i64 5)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e8mf8() {
  return __riscv_vsetvlmax_e8mf8();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e8mf4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 0, i64 6)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e8mf4() {
  return __riscv_vsetvlmax_e8mf4();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e8mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 0, i64 7)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e8mf2() {
  return __riscv_vsetvlmax_e8mf2();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e8m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 0, i64 0)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e8m1() {
  return __riscv_vsetvlmax_e8m1();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e8m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 0, i64 1)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e8m2() {
  return __riscv_vsetvlmax_e8m2();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e8m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 0, i64 2)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e8m4() {
  return __riscv_vsetvlmax_e8m4();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e8m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 0, i64 3)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e8m8() {
  return __riscv_vsetvlmax_e8m8();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e16mf4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 1, i64 6)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e16mf4() {
  return __riscv_vsetvlmax_e16mf4();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e16mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 1, i64 7)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e16mf2() {
  return __riscv_vsetvlmax_e16mf2();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e16m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 1, i64 0)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e16m1() {
  return __riscv_vsetvlmax_e16m1();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e16m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 1, i64 1)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e16m2() {
  return __riscv_vsetvlmax_e16m2();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e16m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 1, i64 2)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e16m4() {
  return __riscv_vsetvlmax_e16m4();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e16m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 1, i64 3)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e16m8() {
  return __riscv_vsetvlmax_e16m8();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e32mf2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 2, i64 7)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e32mf2() {
  return __riscv_vsetvlmax_e32mf2();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e32m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 2, i64 0)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e32m1() {
  return __riscv_vsetvlmax_e32m1();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e32m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 2, i64 1)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e32m2() {
  return __riscv_vsetvlmax_e32m2();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e32m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 2, i64 2)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e32m4() {
  return __riscv_vsetvlmax_e32m4();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e32m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 2, i64 3)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e32m8() {
  return __riscv_vsetvlmax_e32m8();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e64m1(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 3, i64 0)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e64m1() {
  return __riscv_vsetvlmax_e64m1();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e64m2(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 3, i64 1)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e64m2() {
  return __riscv_vsetvlmax_e64m2();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e64m4(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 3, i64 2)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e64m4() {
  return __riscv_vsetvlmax_e64m4();
}

// CHECK-RV64-LABEL: @test_vsetvlmax_e64m8(
// CHECK-RV64-NEXT:  entry:
// CHECK-RV64-NEXT:    [[TMP0:%.*]] = call i64 @llvm.riscv.vsetvlimax.i64(i64 3, i64 3)
// CHECK-RV64-NEXT:    ret i64 [[TMP0]]
//
size_t test_vsetvlmax_e64m8() {
  return __riscv_vsetvlmax_e64m8();
}

