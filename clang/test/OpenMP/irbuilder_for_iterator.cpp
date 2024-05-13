// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs --replace-value-regex "__omp_offloading_[0-9a-z]+_[0-9a-z]+" "reduction_size[.].+[.]" "pl_cond[.].+[.|,]" --prefix-filecheck-ir-name _
// RUN: %clang_cc1 -fopenmp-enable-irbuilder -verify -fopenmp -fopenmp-version=50 -x c++ -triple x86_64-unknown-unknown -emit-llvm %s -o - | FileCheck %s
// expected-no-diagnostics

#ifndef HEADER
#define HEADER

struct MyIterator {
  MyIterator(unsigned pos);
  MyIterator(const MyIterator &other);
  const MyIterator &operator=(const MyIterator &that);
  MyIterator &operator++();
  int operator-(const MyIterator &that) const;
  MyIterator &operator+=(unsigned a);
  MyIterator operator+(unsigned a) const;
  bool operator==(const MyIterator &that) const;
  bool operator!=(const MyIterator &that) const;
  unsigned operator*() const;
};

extern "C" void workshareloop_iterator(float *a, float *b, float *c) {
#pragma omp for
  for (MyIterator it = MyIterator(7); it != MyIterator(41); ++it) {
    unsigned i = *it;
    a[i] = b[i] * c[i];
  }
}

#endif // HEADER
// CHECK-LABEL: define {{[^@]+}}@workshareloop_iterator
// CHECK-SAME: (ptr noundef [[A:%.*]], ptr noundef [[B:%.*]], ptr noundef [[C:%.*]]) #[[ATTR0:[0-9]+]] {
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[A_ADDR:%.*]] = alloca ptr, align 8
// CHECK-NEXT:    [[B_ADDR:%.*]] = alloca ptr, align 8
// CHECK-NEXT:    [[C_ADDR:%.*]] = alloca ptr, align 8
// CHECK-NEXT:    [[IT:%.*]] = alloca [[STRUCT_MYITERATOR:%.*]], align 1
// CHECK-NEXT:    [[AGG_CAPTURED:%.*]] = alloca [[STRUCT_ANON:%.*]], align 8
// CHECK-NEXT:    [[AGG_CAPTURED1:%.*]] = alloca [[STRUCT_ANON_0:%.*]], align 1
// CHECK-NEXT:    [[DOTCOUNT_ADDR:%.*]] = alloca i64, align 8
// CHECK-NEXT:    [[I:%.*]] = alloca i32, align 4
// CHECK-NEXT:    [[P_LASTITER:%.*]] = alloca i32, align 4
// CHECK-NEXT:    [[P_LOWERBOUND:%.*]] = alloca i64, align 8
// CHECK-NEXT:    [[P_UPPERBOUND:%.*]] = alloca i64, align 8
// CHECK-NEXT:    [[P_STRIDE:%.*]] = alloca i64, align 8
// CHECK-NEXT:    store ptr [[A]], ptr [[A_ADDR]], align 8
// CHECK-NEXT:    store ptr [[B]], ptr [[B_ADDR]], align 8
// CHECK-NEXT:    store ptr [[C]], ptr [[C_ADDR]], align 8
// CHECK-NEXT:    call void @_ZN10MyIteratorC1Ej(ptr noundef nonnull align 1 dereferenceable(1) [[IT]], i32 noundef 7)
// CHECK-NEXT:    [[TMP0:%.*]] = getelementptr inbounds [[STRUCT_ANON]], ptr [[AGG_CAPTURED]], i32 0, i32 0
// CHECK-NEXT:    store ptr [[IT]], ptr [[TMP0]], align 8
// CHECK-NEXT:    [[TMP1:%.*]] = getelementptr inbounds [[STRUCT_ANON_0]], ptr [[AGG_CAPTURED1]], i32 0, i32 0
// CHECK-NEXT:    call void @_ZN10MyIteratorC1ERKS_(ptr noundef nonnull align 1 dereferenceable(1) [[TMP1]], ptr noundef nonnull align 1 dereferenceable(1) [[IT]])
// CHECK-NEXT:    call void @__captured_stmt(ptr [[DOTCOUNT_ADDR]], ptr [[AGG_CAPTURED]])
// CHECK-NEXT:    [[DOTCOUNT:%.*]] = load i64, ptr [[DOTCOUNT_ADDR]], align 8
// CHECK-NEXT:    br label [[OMP_LOOP_PREHEADER:%.*]]
// CHECK:       omp_loop.preheader:
// CHECK-NEXT:    store i64 0, ptr [[P_LOWERBOUND]], align 8
// CHECK-NEXT:    [[TMP2:%.*]] = sub i64 [[DOTCOUNT]], 1
// CHECK-NEXT:    store i64 [[TMP2]], ptr [[P_UPPERBOUND]], align 8
// CHECK-NEXT:    store i64 1, ptr [[P_STRIDE]], align 8
// CHECK-NEXT:    [[OMP_GLOBAL_THREAD_NUM:%.*]] = call i32 @__kmpc_global_thread_num(ptr @[[GLOB1:[0-9]+]])
// CHECK-NEXT:    call void @__kmpc_for_static_init_8u(ptr @[[GLOB1]], i32 [[OMP_GLOBAL_THREAD_NUM]], i32 34, ptr [[P_LASTITER]], ptr [[P_LOWERBOUND]], ptr [[P_UPPERBOUND]], ptr [[P_STRIDE]], i64 1, i64 0)
// CHECK-NEXT:    [[TMP3:%.*]] = load i64, ptr [[P_LOWERBOUND]], align 8
// CHECK-NEXT:    [[TMP4:%.*]] = load i64, ptr [[P_UPPERBOUND]], align 8
// CHECK-NEXT:    [[TMP5:%.*]] = sub i64 [[TMP4]], [[TMP3]]
// CHECK-NEXT:    [[TMP6:%.*]] = add i64 [[TMP5]], 1
// CHECK-NEXT:    br label [[OMP_LOOP_HEADER:%.*]]
// CHECK:       omp_loop.header:
// CHECK-NEXT:    [[OMP_LOOP_IV:%.*]] = phi i64 [ 0, [[OMP_LOOP_PREHEADER]] ], [ [[OMP_LOOP_NEXT:%.*]], [[OMP_LOOP_INC:%.*]] ]
// CHECK-NEXT:    br label [[OMP_LOOP_COND:%.*]]
// CHECK:       omp_loop.cond:
// CHECK-NEXT:    [[OMP_LOOP_CMP:%.*]] = icmp ult i64 [[OMP_LOOP_IV]], [[TMP6]]
// CHECK-NEXT:    br i1 [[OMP_LOOP_CMP]], label [[OMP_LOOP_BODY:%.*]], label [[OMP_LOOP_EXIT:%.*]]
// CHECK:       omp_loop.body:
// CHECK-NEXT:    [[TMP7:%.*]] = add i64 [[OMP_LOOP_IV]], [[TMP3]]
// CHECK-NEXT:    call void @__captured_stmt.1(ptr [[IT]], i64 [[TMP7]], ptr [[AGG_CAPTURED1]])
// CHECK-NEXT:    [[CALL:%.*]] = call noundef i32 @_ZNK10MyIteratordeEv(ptr noundef nonnull align 1 dereferenceable(1) [[IT]])
// CHECK-NEXT:    store i32 [[CALL]], ptr [[I]], align 4
// CHECK-NEXT:    [[TMP8:%.*]] = load ptr, ptr [[B_ADDR]], align 8
// CHECK-NEXT:    [[TMP9:%.*]] = load i32, ptr [[I]], align 4
// CHECK-NEXT:    [[IDXPROM:%.*]] = zext i32 [[TMP9]] to i64
// CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds float, ptr [[TMP8]], i64 [[IDXPROM]]
// CHECK-NEXT:    [[TMP10:%.*]] = load float, ptr [[ARRAYIDX]], align 4
// CHECK-NEXT:    [[TMP11:%.*]] = load ptr, ptr [[C_ADDR]], align 8
// CHECK-NEXT:    [[TMP12:%.*]] = load i32, ptr [[I]], align 4
// CHECK-NEXT:    [[IDXPROM2:%.*]] = zext i32 [[TMP12]] to i64
// CHECK-NEXT:    [[ARRAYIDX3:%.*]] = getelementptr inbounds float, ptr [[TMP11]], i64 [[IDXPROM2]]
// CHECK-NEXT:    [[TMP13:%.*]] = load float, ptr [[ARRAYIDX3]], align 4
// CHECK-NEXT:    [[MUL:%.*]] = fmul float [[TMP10]], [[TMP13]]
// CHECK-NEXT:    [[TMP14:%.*]] = load ptr, ptr [[A_ADDR]], align 8
// CHECK-NEXT:    [[TMP15:%.*]] = load i32, ptr [[I]], align 4
// CHECK-NEXT:    [[IDXPROM4:%.*]] = zext i32 [[TMP15]] to i64
// CHECK-NEXT:    [[ARRAYIDX5:%.*]] = getelementptr inbounds float, ptr [[TMP14]], i64 [[IDXPROM4]]
// CHECK-NEXT:    store float [[MUL]], ptr [[ARRAYIDX5]], align 4
// CHECK-NEXT:    br label [[OMP_LOOP_INC]]
// CHECK:       omp_loop.inc:
// CHECK-NEXT:    [[OMP_LOOP_NEXT]] = add nuw i64 [[OMP_LOOP_IV]], 1
// CHECK-NEXT:    br label [[OMP_LOOP_HEADER]]
// CHECK:       omp_loop.exit:
// CHECK-NEXT:    call void @__kmpc_for_static_fini(ptr @[[GLOB1]], i32 [[OMP_GLOBAL_THREAD_NUM]])
// CHECK-NEXT:    [[OMP_GLOBAL_THREAD_NUM6:%.*]] = call i32 @__kmpc_global_thread_num(ptr @[[GLOB1]])
// CHECK-NEXT:    call void @__kmpc_barrier(ptr @[[GLOB2:[0-9]+]], i32 [[OMP_GLOBAL_THREAD_NUM6]])
// CHECK-NEXT:    br label [[OMP_LOOP_AFTER:%.*]]
// CHECK:       omp_loop.after:
// CHECK-NEXT:    ret void
//
//
// CHECK-LABEL: define {{[^@]+}}@__captured_stmt
// CHECK-SAME: (ptr noundef nonnull align 8 dereferenceable(8) [[DISTANCE:%.*]], ptr noalias noundef [[__CONTEXT:%.*]]) #[[ATTR2:[0-9]+]] {
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[DISTANCE_ADDR:%.*]] = alloca ptr, align 8
// CHECK-NEXT:    [[__CONTEXT_ADDR:%.*]] = alloca ptr, align 8
// CHECK-NEXT:    [[DOTSTART:%.*]] = alloca [[STRUCT_MYITERATOR:%.*]], align 1
// CHECK-NEXT:    [[DOTSTOP:%.*]] = alloca [[STRUCT_MYITERATOR]], align 1
// CHECK-NEXT:    [[DOTSTEP:%.*]] = alloca i64, align 8
// CHECK-NEXT:    store ptr [[DISTANCE]], ptr [[DISTANCE_ADDR]], align 8
// CHECK-NEXT:    store ptr [[__CONTEXT]], ptr [[__CONTEXT_ADDR]], align 8
// CHECK-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[__CONTEXT_ADDR]], align 8
// CHECK-NEXT:    [[TMP1:%.*]] = getelementptr inbounds [[STRUCT_ANON:%.*]], ptr [[TMP0]], i32 0, i32 0
// CHECK-NEXT:    [[TMP2:%.*]] = load ptr, ptr [[TMP1]], align 8
// CHECK-NEXT:    call void @_ZN10MyIteratorC1ERKS_(ptr noundef nonnull align 1 dereferenceable(1) [[DOTSTART]], ptr noundef nonnull align 1 dereferenceable(1) [[TMP2]])
// CHECK-NEXT:    call void @_ZN10MyIteratorC1Ej(ptr noundef nonnull align 1 dereferenceable(1) [[DOTSTOP]], i32 noundef 41)
// CHECK-NEXT:    store i64 1, ptr [[DOTSTEP]], align 8
// CHECK-NEXT:    [[TMP3:%.*]] = load i64, ptr [[DOTSTEP]], align 8
// CHECK-NEXT:    [[CMP:%.*]] = icmp ult i64 [[TMP3]], 0
// CHECK-NEXT:    br i1 [[CMP]], label [[COND_TRUE:%.*]], label [[COND_FALSE:%.*]]
// CHECK:       cond.true:
// CHECK-NEXT:    [[CALL:%.*]] = call noundef i32 @_ZNK10MyIteratormiERKS_(ptr noundef nonnull align 1 dereferenceable(1) [[DOTSTART]], ptr noundef nonnull align 1 dereferenceable(1) [[DOTSTOP]])
// CHECK-NEXT:    [[CONV:%.*]] = sext i32 [[CALL]] to i64
// CHECK-NEXT:    [[TMP4:%.*]] = load i64, ptr [[DOTSTEP]], align 8
// CHECK-NEXT:    [[SUB:%.*]] = sub i64 0, [[TMP4]]
// CHECK-NEXT:    [[DIV:%.*]] = udiv i64 [[CONV]], [[SUB]]
// CHECK-NEXT:    br label [[COND_END:%.*]]
// CHECK:       cond.false:
// CHECK-NEXT:    [[CALL1:%.*]] = call noundef i32 @_ZNK10MyIteratormiERKS_(ptr noundef nonnull align 1 dereferenceable(1) [[DOTSTOP]], ptr noundef nonnull align 1 dereferenceable(1) [[DOTSTART]])
// CHECK-NEXT:    [[CONV2:%.*]] = sext i32 [[CALL1]] to i64
// CHECK-NEXT:    [[TMP5:%.*]] = load i64, ptr [[DOTSTEP]], align 8
// CHECK-NEXT:    [[DIV3:%.*]] = udiv i64 [[CONV2]], [[TMP5]]
// CHECK-NEXT:    br label [[COND_END]]
// CHECK:       cond.end:
// CHECK-NEXT:    [[COND:%.*]] = phi i64 [ [[DIV]], [[COND_TRUE]] ], [ [[DIV3]], [[COND_FALSE]] ]
// CHECK-NEXT:    [[TMP6:%.*]] = load ptr, ptr [[DISTANCE_ADDR]], align 8
// CHECK-NEXT:    store i64 [[COND]], ptr [[TMP6]], align 8
// CHECK-NEXT:    ret void
//
//
// CHECK-LABEL: define {{[^@]+}}@__captured_stmt.1
// CHECK-SAME: (ptr noundef nonnull align 1 dereferenceable(1) [[LOOPVAR:%.*]], i64 noundef [[LOGICAL:%.*]], ptr noalias noundef [[__CONTEXT:%.*]]) #[[ATTR2]] {
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[LOOPVAR_ADDR:%.*]] = alloca ptr, align 8
// CHECK-NEXT:    [[LOGICAL_ADDR:%.*]] = alloca i64, align 8
// CHECK-NEXT:    [[__CONTEXT_ADDR:%.*]] = alloca ptr, align 8
// CHECK-NEXT:    [[REF_TMP:%.*]] = alloca [[STRUCT_MYITERATOR:%.*]], align 1
// CHECK-NEXT:    store ptr [[LOOPVAR]], ptr [[LOOPVAR_ADDR]], align 8
// CHECK-NEXT:    store i64 [[LOGICAL]], ptr [[LOGICAL_ADDR]], align 8
// CHECK-NEXT:    store ptr [[__CONTEXT]], ptr [[__CONTEXT_ADDR]], align 8
// CHECK-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[__CONTEXT_ADDR]], align 8
// CHECK-NEXT:    [[TMP1:%.*]] = getelementptr inbounds [[STRUCT_ANON_0:%.*]], ptr [[TMP0]], i32 0, i32 0
// CHECK-NEXT:    [[TMP2:%.*]] = load i64, ptr [[LOGICAL_ADDR]], align 8
// CHECK-NEXT:    [[MUL:%.*]] = mul i64 1, [[TMP2]]
// CHECK-NEXT:    [[CONV:%.*]] = trunc i64 [[MUL]] to i32
// CHECK-NEXT:    call void @_ZNK10MyIteratorplEj(ptr sret([[STRUCT_MYITERATOR]]) align 1 [[REF_TMP]], ptr noundef nonnull align 1 dereferenceable(1) [[TMP1]], i32 noundef [[CONV]])
// CHECK-NEXT:    [[TMP3:%.*]] = load ptr, ptr [[LOOPVAR_ADDR]], align 8
// CHECK-NEXT:    [[CALL:%.*]] = call noundef nonnull align 1 dereferenceable(1) ptr @_ZN10MyIteratoraSERKS_(ptr noundef nonnull align 1 dereferenceable(1) [[TMP3]], ptr noundef nonnull align 1 dereferenceable(1) [[REF_TMP]])
// CHECK-NEXT:    ret void
//
