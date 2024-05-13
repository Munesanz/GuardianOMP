; RUN: opt -mtriple amdgcn-- -passes='print<uniformity>' -disable-output %s 2>&1 | FileCheck %s

; CHECK: DIVERGENT: %orig = atomicrmw xchg ptr %ptr, i32 %val seq_cst
define amdgpu_kernel void @test1(ptr %ptr, i32 %val) #0 {
  %orig = atomicrmw xchg ptr %ptr, i32 %val seq_cst
  store i32 %orig, ptr %ptr
  ret void
}

; CHECK: DIVERGENT: %orig = cmpxchg ptr %ptr, i32 %cmp, i32 %new seq_cst seq_cst
define amdgpu_kernel void @test2(ptr %ptr, i32 %cmp, i32 %new) {
  %orig = cmpxchg ptr %ptr, i32 %cmp, i32 %new seq_cst seq_cst
  %val = extractvalue { i32, i1 } %orig, 0
  store i32 %val, ptr %ptr
  ret void
}

; CHECK: DIVERGENT: %ret = call i32 @llvm.amdgcn.atomic.inc.i32.p1(ptr addrspace(1) %ptr, i32 %val, i32 0, i32 0, i1 false)
define i32 @test_atomic_inc_i32(ptr addrspace(1) %ptr, i32 %val) #0 {
  %ret = call i32 @llvm.amdgcn.atomic.inc.i32.p1(ptr addrspace(1) %ptr, i32 %val, i32 0, i32 0, i1 false)
  ret i32 %ret
}

; CHECK: DIVERGENT: %ret = call i64 @llvm.amdgcn.atomic.inc.i64.p1(ptr addrspace(1) %ptr, i64 %val, i32 0, i32 0, i1 false)
define i64 @test_atomic_inc_i64(ptr addrspace(1) %ptr, i64 %val) #0 {
  %ret = call i64 @llvm.amdgcn.atomic.inc.i64.p1(ptr addrspace(1) %ptr, i64 %val, i32 0, i32 0, i1 false)
  ret i64 %ret
}

; CHECK: DIVERGENT: %ret = call i32 @llvm.amdgcn.atomic.dec.i32.p1(ptr addrspace(1) %ptr, i32 %val, i32 0, i32 0, i1 false)
define i32 @test_atomic_dec_i32(ptr addrspace(1) %ptr, i32 %val) #0 {
  %ret = call i32 @llvm.amdgcn.atomic.dec.i32.p1(ptr addrspace(1) %ptr, i32 %val, i32 0, i32 0, i1 false)
  ret i32 %ret
}

; CHECK: DIVERGENT: %ret = call i64 @llvm.amdgcn.atomic.dec.i64.p1(ptr addrspace(1) %ptr, i64 %val, i32 0, i32 0, i1 false)
define i64 @test_atomic_dec_i64(ptr addrspace(1) %ptr, i64 %val) #0 {
  %ret = call i64 @llvm.amdgcn.atomic.dec.i64.p1(ptr addrspace(1) %ptr, i64 %val, i32 0, i32 0, i1 false)
  ret i64 %ret
}

declare i32 @llvm.amdgcn.atomic.inc.i32.p1(ptr addrspace(1) nocapture, i32, i32, i32, i1) #1
declare i64 @llvm.amdgcn.atomic.inc.i64.p1(ptr addrspace(1) nocapture, i64, i32, i32, i1) #1
declare i32 @llvm.amdgcn.atomic.dec.i32.p1(ptr addrspace(1) nocapture, i32, i32, i32, i1) #1
declare i64 @llvm.amdgcn.atomic.dec.i64.p1(ptr addrspace(1) nocapture, i64, i32, i32, i1) #1

; CHECK: DIVERGENT: %ret = call i32 @llvm.amdgcn.global.atomic.csub.p1(ptr addrspace(1) %ptr, i32 %val)
define amdgpu_kernel void @test_atomic_csub_i32(ptr addrspace(1) %ptr, i32 %val) #0 {
  %ret = call i32 @llvm.amdgcn.global.atomic.csub.p1(ptr addrspace(1) %ptr, i32 %val)
  store i32 %ret, ptr addrspace(1) %ptr, align 4
  ret void
}

declare i32 @llvm.amdgcn.global.atomic.csub.p1(ptr addrspace(1) nocapture, i32) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nounwind willreturn }
