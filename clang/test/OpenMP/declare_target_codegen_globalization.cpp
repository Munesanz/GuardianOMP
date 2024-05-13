// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py UTC_ARGS: --function-signature --include-generated-funcs --replace-value-regex "__omp_offloading_[0-9a-z]+_[0-9a-z]+" "reduction_size[.].+[.]" "pl_cond[.].+[.|,]" --prefix-filecheck-ir-name _
// RUN: %clang_cc1 -verify -fopenmp -x c++ -triple powerpc64le-unknown-unknown -fopenmp-targets=nvptx64-nvidia-cuda -emit-llvm-bc %s -o %t-ppc-host.bc
// RUN: %clang_cc1 -verify -fopenmp -x c++ -triple nvptx64-nvidia-cuda -fopenmp-targets=nvptx64-nvidia-cuda -emit-llvm %s -fopenmp-is-device -fopenmp-host-ir-file-path %t-ppc-host.bc -o - -disable-llvm-optzns | FileCheck %s --check-prefix=CHECK1
// expected-no-diagnostics

int foo(int &a) { return a; }

int bar() {
  int a;
  return foo(a);
}


int maini1() {
  int a;
#pragma omp target parallel map(from:a)
  {
    int b;
    a = foo(b) + bar();
  }
  return a;
}

// parallel region


// CHECK1-LABEL: define {{[^@]+}}@{{__omp_offloading_[0-9a-z]+_[0-9a-z]+}}__Z6maini1v_l16
// CHECK1-SAME: (ptr noundef nonnull align 4 dereferenceable(4) [[A:%.*]]) #[[ATTR0:[0-9]+]] {
// CHECK1-NEXT:  entry:
// CHECK1-NEXT:    [[A_ADDR:%.*]] = alloca ptr, align 8
// CHECK1-NEXT:    [[CAPTURED_VARS_ADDRS:%.*]] = alloca [1 x ptr], align 8
// CHECK1-NEXT:    store ptr [[A]], ptr [[A_ADDR]], align 8
// CHECK1-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[A_ADDR]], align 8
// CHECK1-NEXT:    [[TMP1:%.*]] = call i32 @__kmpc_target_init(ptr @[[GLOB1:[0-9]+]], i8 2, i1 false)
// CHECK1-NEXT:    [[EXEC_USER_CODE:%.*]] = icmp eq i32 [[TMP1]], -1
// CHECK1-NEXT:    br i1 [[EXEC_USER_CODE]], label [[USER_CODE_ENTRY:%.*]], label [[WORKER_EXIT:%.*]]
// CHECK1:       user_code.entry:
// CHECK1-NEXT:    [[TMP2:%.*]] = call i32 @__kmpc_global_thread_num(ptr @[[GLOB1]])
// CHECK1-NEXT:    [[TMP3:%.*]] = getelementptr inbounds [1 x ptr], ptr [[CAPTURED_VARS_ADDRS]], i64 0, i64 0
// CHECK1-NEXT:    store ptr [[TMP0]], ptr [[TMP3]], align 8
// CHECK1-NEXT:    call void @__kmpc_parallel_51(ptr @[[GLOB1]], i32 [[TMP2]], i32 1, i32 -1, i32 -1, ptr @{{__omp_offloading_[0-9a-z]+_[0-9a-z]+}}__Z6maini1v_l16_omp_outlined, ptr null, ptr [[CAPTURED_VARS_ADDRS]], i64 1)
// CHECK1-NEXT:    call void @__kmpc_target_deinit(ptr @[[GLOB1]], i8 2)
// CHECK1-NEXT:    ret void
// CHECK1:       worker.exit:
// CHECK1-NEXT:    ret void
//
//
// CHECK1-LABEL: define {{[^@]+}}@{{__omp_offloading_[0-9a-z]+_[0-9a-z]+}}__Z6maini1v_l16_omp_outlined
// CHECK1-SAME: (ptr noalias noundef [[DOTGLOBAL_TID_:%.*]], ptr noalias noundef [[DOTBOUND_TID_:%.*]], ptr noundef nonnull align 4 dereferenceable(4) [[A:%.*]]) #[[ATTR1:[0-9]+]] {
// CHECK1-NEXT:  entry:
// CHECK1-NEXT:    [[DOTGLOBAL_TID__ADDR:%.*]] = alloca ptr, align 8
// CHECK1-NEXT:    [[DOTBOUND_TID__ADDR:%.*]] = alloca ptr, align 8
// CHECK1-NEXT:    [[A_ADDR:%.*]] = alloca ptr, align 8
// CHECK1-NEXT:    [[B:%.*]] = alloca i32, align 4
// CHECK1-NEXT:    store ptr [[DOTGLOBAL_TID_]], ptr [[DOTGLOBAL_TID__ADDR]], align 8
// CHECK1-NEXT:    store ptr [[DOTBOUND_TID_]], ptr [[DOTBOUND_TID__ADDR]], align 8
// CHECK1-NEXT:    store ptr [[A]], ptr [[A_ADDR]], align 8
// CHECK1-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[A_ADDR]], align 8
// CHECK1-NEXT:    [[CALL:%.*]] = call noundef i32 @_Z3fooRi(ptr noundef nonnull align 4 dereferenceable(4) [[B]]) #[[ATTR7:[0-9]+]]
// CHECK1-NEXT:    [[CALL1:%.*]] = call noundef i32 @_Z3barv() #[[ATTR7]]
// CHECK1-NEXT:    [[ADD:%.*]] = add nsw i32 [[CALL]], [[CALL1]]
// CHECK1-NEXT:    store i32 [[ADD]], ptr [[TMP0]], align 4
// CHECK1-NEXT:    ret void
//
//
// CHECK1-LABEL: define {{[^@]+}}@_Z3fooRi
// CHECK1-SAME: (ptr noundef nonnull align 4 dereferenceable(4) [[A:%.*]]) #[[ATTR2:[0-9]+]] {
// CHECK1-NEXT:  entry:
// CHECK1-NEXT:    [[A_ADDR:%.*]] = alloca ptr, align 8
// CHECK1-NEXT:    store ptr [[A]], ptr [[A_ADDR]], align 8
// CHECK1-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[A_ADDR]], align 8
// CHECK1-NEXT:    [[TMP1:%.*]] = load i32, ptr [[TMP0]], align 4
// CHECK1-NEXT:    ret i32 [[TMP1]]
//
//
// CHECK1-LABEL: define {{[^@]+}}@_Z3barv
// CHECK1-SAME: () #[[ATTR2]] {
// CHECK1-NEXT:  entry:
// CHECK1-NEXT:    [[A:%.*]] = call align 8 ptr @__kmpc_alloc_shared(i64 4)
// CHECK1-NEXT:    [[CALL:%.*]] = call noundef i32 @_Z3fooRi(ptr noundef nonnull align 4 dereferenceable(4) [[A]]) #[[ATTR7]]
// CHECK1-NEXT:    call void @__kmpc_free_shared(ptr [[A]], i64 4)
// CHECK1-NEXT:    ret i32 [[CALL]]
//
