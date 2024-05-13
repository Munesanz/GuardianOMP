; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -O3 -mtriple=aarch64 -mattr=+sme -S < %s | FileCheck %s

; Test PHI nodes are allowed with opaque scalable types.
define target("aarch64.svcount") @test_alloca_store_reload(target("aarch64.svcount") %val0, target("aarch64.svcount") %val1, ptr %iptr, ptr %pptr, i64 %N) nounwind {
; CHECK-LABEL: @test_alloca_store_reload(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    store i64 0, ptr [[IPTR:%.*]], align 4
; CHECK-NEXT:    store target("aarch64.svcount") [[VAL0:%.*]], ptr [[PPTR:%.*]], align 2
; CHECK-NEXT:    [[I1_PEEL:%.*]] = icmp eq i64 [[N:%.*]], 0
; CHECK-NEXT:    br i1 [[I1_PEEL]], label [[LOOP_EXIT:%.*]], label [[LOOP_BODY:%.*]]
; CHECK:       loop.body:
; CHECK-NEXT:    [[IND:%.*]] = phi i64 [ [[IND_NEXT:%.*]], [[LOOP_BODY]] ], [ 1, [[ENTRY:%.*]] ]
; CHECK-NEXT:    [[IPTR_GEP:%.*]] = getelementptr i64, ptr [[IPTR]], i64 [[IND]]
; CHECK-NEXT:    store i64 [[IND]], ptr [[IPTR_GEP]], align 4
; CHECK-NEXT:    store target("aarch64.svcount") [[VAL1:%.*]], ptr [[PPTR]], align 2
; CHECK-NEXT:    [[IND_NEXT]] = add i64 [[IND]], 1
; CHECK-NEXT:    [[I1:%.*]] = icmp eq i64 [[IND]], [[N]]
; CHECK-NEXT:    br i1 [[I1]], label [[LOOP_EXIT]], label [[LOOP_BODY]], !llvm.loop [[LOOP0:![0-9]+]]
; CHECK:       loop.exit:
; CHECK-NEXT:    [[PHI_LCSSA:%.*]] = phi target("aarch64.svcount") [ [[VAL0]], [[ENTRY]] ], [ [[VAL1]], [[LOOP_BODY]] ]
; CHECK-NEXT:    ret target("aarch64.svcount") [[PHI_LCSSA]]
;
entry:
  br label %loop.body

loop.body:
  %ind = phi i64 [0, %entry], [%ind.next, %loop.body]
  %phi = phi target("aarch64.svcount") [%val0, %entry], [%val1, %loop.body]
  %iptr.gep = getelementptr i64, ptr %iptr, i64 %ind
  store i64 %ind, ptr %iptr.gep
  store target("aarch64.svcount") %phi, ptr %pptr
  %ind.next = add i64 %ind, 1
  %i1 = icmp eq i64 %ind, %N
  br i1 %i1, label %loop.exit, label %loop.body

loop.exit:
  ret target("aarch64.svcount") %phi
}
