; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --check-attributes --check-globals
; RUN: opt -aa-pipeline=basic-aa -passes=attributor -attributor-manifest-internal  -attributor-max-iterations-verify -attributor-annotate-decl-cs -attributor-max-iterations=2 -S < %s | FileCheck %s --check-prefixes=CHECK,TUNIT
; RUN: opt -aa-pipeline=basic-aa -passes=attributor-cgscc -attributor-manifest-internal  -attributor-annotate-decl-cs -S < %s | FileCheck %s --check-prefixes=CHECK,CGSCC

%struct.test.b = type { i32, i32 }
%struct.test.a = type { %struct.test.b, i32, ptr}

define void @foo(ptr %ptr) {
; TUNIT: Function Attrs: nofree norecurse nosync nounwind willreturn memory(none)
; TUNIT-LABEL: define {{[^@]+}}@foo
; TUNIT-SAME: (ptr nocapture nofree readnone [[PTR:%.*]]) #[[ATTR0:[0-9]+]] {
; TUNIT-NEXT:  entry:
; TUNIT-NEXT:    [[TMP0:%.*]] = alloca [[STRUCT_TEST_A:%.*]], align 8
; TUNIT-NEXT:    br label [[CALL_BR:%.*]]
; TUNIT:       call.br:
; TUNIT-NEXT:    [[TMP1:%.*]] = getelementptr inbounds [[STRUCT_TEST_A]], ptr [[TMP0]], i64 0, i32 2
; TUNIT-NEXT:    tail call void @bar(ptr noalias nocapture nofree noundef nonnull readonly byval([[STRUCT_TEST_A]]) align 8 dereferenceable(24) [[TMP0]]) #[[ATTR2:[0-9]+]]
; TUNIT-NEXT:    ret void
;
; CGSCC: Function Attrs: nofree nosync nounwind willreturn memory(none)
; CGSCC-LABEL: define {{[^@]+}}@foo
; CGSCC-SAME: (ptr nocapture nofree writeonly [[PTR:%.*]]) #[[ATTR0:[0-9]+]] {
; CGSCC-NEXT:  entry:
; CGSCC-NEXT:    [[TMP0:%.*]] = alloca [[STRUCT_TEST_A:%.*]], align 8
; CGSCC-NEXT:    br label [[CALL_BR:%.*]]
; CGSCC:       call.br:
; CGSCC-NEXT:    [[TMP1:%.*]] = getelementptr inbounds [[STRUCT_TEST_A]], ptr [[TMP0]], i64 0, i32 2
; CGSCC-NEXT:    store ptr [[PTR]], ptr [[TMP1]], align 8
; CGSCC-NEXT:    tail call void @bar(ptr noalias nocapture nofree noundef nonnull readnone byval([[STRUCT_TEST_A]]) align 8 dereferenceable(24) [[TMP0]]) #[[ATTR2:[0-9]+]]
; CGSCC-NEXT:    ret void
;
entry:
  %0 = alloca %struct.test.a, align 8
  br label %call.br

call.br:
  %1 = getelementptr inbounds %struct.test.a, ptr %0, i64 0, i32 2
  store ptr %ptr, ptr %1
  tail call void @bar(ptr noundef byval(%struct.test.a) align 8 %0)
  ret void
}

define void @bar(ptr noundef byval(%struct.test.a) align 8 %dev) {
; CHECK: Function Attrs: nofree norecurse nosync nounwind willreturn memory(argmem: write)
; CHECK-LABEL: define {{[^@]+}}@bar
; CHECK-SAME: (ptr noalias nocapture nofree noundef nonnull writeonly byval([[STRUCT_TEST_A:%.*]]) align 8 dereferenceable(24) [[DEV:%.*]]) #[[ATTR1:[0-9]+]] {
; CHECK-NEXT:    [[TMP1:%.*]] = getelementptr inbounds [[STRUCT_TEST_B:%.*]], ptr [[DEV]], i64 0, i32 1
; CHECK-NEXT:    store i32 1, ptr [[TMP1]], align 4
; CHECK-NEXT:    ret void
;
  %1 = getelementptr inbounds %struct.test.b, ptr %dev, i64 0, i32 1
  store i32 1, ptr %1
  ret void
}
;.
; TUNIT: attributes #[[ATTR0]] = { nofree norecurse nosync nounwind willreturn memory(none) }
; TUNIT: attributes #[[ATTR1]] = { nofree norecurse nosync nounwind willreturn memory(argmem: write) }
; TUNIT: attributes #[[ATTR2]] = { nofree nosync nounwind willreturn }
;.
; CGSCC: attributes #[[ATTR0]] = { nofree nosync nounwind willreturn memory(none) }
; CGSCC: attributes #[[ATTR1]] = { nofree norecurse nosync nounwind willreturn memory(argmem: write) }
; CGSCC: attributes #[[ATTR2]] = { nounwind willreturn }
;.
