// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs --prefix-filecheck-ir-name _
// RUN: %clang_cc1 -fopenmp-simd -O1 -x c -triple x86_64-apple-darwin10 -emit-llvm %s -o - | FileCheck %s --check-prefix=CHECK

int j;
int *u;

void loop(int n) {
  int i;
#pragma omp parallel master taskloop simd linear(j)
  for (i = 0; i < n; ++i) {
    ++j;
    u = &j;
  }
}
// CHECK-LABEL: define {{[^@]+}}@loop
// CHECK-SAME: (i32 noundef [[N:%.*]]) local_unnamed_addr #[[ATTR0:[0-9]+]] {
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[J:%.*]] = alloca i32, align 4
// CHECK-NEXT:    [[CMP:%.*]] = icmp sgt i32 [[N]], 0
// CHECK-NEXT:    br i1 [[CMP]], label [[SIMD_IF_THEN:%.*]], label [[SIMD_IF_END:%.*]]
// CHECK:       simd.if.then:
// CHECK-NEXT:    [[TMP0:%.*]] = load i32, ptr @j, align 4, !tbaa [[TBAA2:![0-9]+]]
// CHECK-NEXT:    call void @llvm.lifetime.start.p0(i64 4, ptr nonnull [[J]]) #[[ATTR2:[0-9]+]]
// CHECK-NEXT:    store ptr [[J]], ptr @u, align 8, !tbaa [[TBAA6:![0-9]+]], !llvm.access.group [[ACC_GRP8:![0-9]+]]
// CHECK-NEXT:    [[INC_LE:%.*]] = add i32 [[TMP0]], [[N]]
// CHECK-NEXT:    store i32 [[INC_LE]], ptr [[J]], align 4, !tbaa [[TBAA2]]
// CHECK-NEXT:    store i32 [[INC_LE]], ptr @j, align 4, !tbaa [[TBAA2]]
// CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 4, ptr nonnull [[J]]) #[[ATTR2]]
// CHECK-NEXT:    br label [[SIMD_IF_END]]
// CHECK:       simd.if.end:
// CHECK-NEXT:    ret void
//
