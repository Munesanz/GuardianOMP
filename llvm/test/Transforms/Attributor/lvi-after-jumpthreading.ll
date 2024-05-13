; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --check-attributes --check-globals
; RUN: opt -aa-pipeline=basic-aa -passes=attributor -attributor-manifest-internal  -attributor-max-iterations-verify -attributor-annotate-decl-cs -attributor-max-iterations=6 -S < %s | FileCheck %s --check-prefixes=CHECK,TUNIT
; RUN: opt -aa-pipeline=basic-aa -passes=attributor-cgscc -attributor-manifest-internal  -attributor-annotate-decl-cs -S < %s | FileCheck %s --check-prefixes=CHECK,CGSCC

define i8 @test1(i32 %a, i32 %length) {
; CHECK: Function Attrs: nofree norecurse nosync nounwind willreturn memory(none)
; CHECK-LABEL: define {{[^@]+}}@test1
; CHECK-SAME: (i32 [[A:%.*]], i32 [[LENGTH:%.*]]) #[[ATTR0:[0-9]+]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i32 [ 0, [[ENTRY:%.*]] ], [ [[IV_NEXT:%.*]], [[BACKEDGE:%.*]] ]
; CHECK-NEXT:    [[CND:%.*]] = icmp sge i32 [[IV]], 0
; CHECK-NEXT:    br i1 [[CND]], label [[BACKEDGE]], label [[EXIT:%.*]]
; CHECK:       backedge:
; CHECK-NEXT:    [[IV_NEXT]] = add nsw i32 [[IV]], 1
; CHECK-NEXT:    [[CONT:%.*]] = icmp slt i32 [[IV_NEXT]], 400
; CHECK-NEXT:    br i1 [[CONT]], label [[LOOP]], label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    ret i8 0
;
entry:
  br label %loop

loop:
  %iv = phi i32 [0, %entry], [%iv.next, %backedge]
  %cnd = icmp sge i32 %iv, 0
  br i1 %cnd, label %backedge, label %exit

backedge:
  %iv.next = add nsw i32 %iv, 1
  %cont = icmp slt i32 %iv.next, 400
  br i1 %cont, label %loop, label %exit

exit:
  ret i8 0
}

define i8 @test2(i32 %n) {
; CHECK: Function Attrs: nofree norecurse nosync nounwind willreturn memory(none)
; CHECK-LABEL: define {{[^@]+}}@test2
; CHECK-SAME: (i32 [[N:%.*]]) #[[ATTR0]] {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[IV:%.*]] = phi i32 [ 0, [[ENTRY:%.*]] ], [ [[IV_NEXT:%.*]], [[BACKEDGE:%.*]] ]
; CHECK-NEXT:    [[IV2:%.*]] = phi i32 [ [[N]], [[ENTRY]] ], [ [[IV2_NEXT:%.*]], [[BACKEDGE]] ]
; CHECK-NEXT:    [[CND1:%.*]] = icmp sge i32 [[IV]], 0
; CHECK-NEXT:    [[CND2:%.*]] = icmp sgt i32 [[IV2]], 0
; CHECK-NEXT:    [[CND:%.*]] = and i1 [[CND1]], [[CND2]]
; CHECK-NEXT:    br i1 [[CND]], label [[BACKEDGE]], label [[EXIT:%.*]]
; CHECK:       backedge:
; CHECK-NEXT:    [[IV_NEXT]] = add nsw i32 [[IV]], 1
; CHECK-NEXT:    [[IV2_NEXT]] = sub nsw i32 [[IV2]], 1
; CHECK-NEXT:    [[CONT1:%.*]] = icmp slt i32 [[IV_NEXT]], 400
; CHECK-NEXT:    [[CONT2:%.*]] = icmp sgt i32 [[IV2_NEXT]], 0
; CHECK-NEXT:    [[CONT:%.*]] = and i1 [[CONT1]], [[CONT2]]
; CHECK-NEXT:    br i1 [[CONT]], label [[LOOP]], label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    ret i8 0
;
entry:
  br label %loop

loop:
  %iv = phi i32 [0, %entry], [%iv.next, %backedge]
  %iv2 = phi i32 [%n, %entry], [%iv2.next, %backedge]

  %cnd1 = icmp sge i32 %iv, 0
  %cnd2 = icmp sgt i32 %iv2, 0
  %cnd = and i1 %cnd1, %cnd2
  br i1 %cnd, label %backedge, label %exit

backedge:
  %iv.next = add nsw i32 %iv, 1
  %iv2.next = sub nsw i32 %iv2, 1
  %cont1 = icmp slt i32 %iv.next, 400
  %cont2 = icmp sgt i32 %iv2.next, 0
  %cont = and i1 %cont1, %cont2
  br i1 %cont, label %loop, label %exit

exit:
  ret i8 0
}

; Merging cont block into do block.
define i32 @test3(i32 %i, i1 %f, i32 %n) {
; CHECK-LABEL: define {{[^@]+}}@test3
; CHECK-SAME: (i32 [[I:%.*]], i1 [[F:%.*]], i32 [[N:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[C:%.*]] = icmp ne i32 [[I]], -2134
; CHECK-NEXT:    br i1 [[C]], label [[DO:%.*]], label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    [[C1:%.*]] = icmp ne i32 [[I]], -42
; CHECK-NEXT:    br i1 [[C1]], label [[EXIT2:%.*]], label [[EXIT]]
; CHECK:       cont:
; CHECK-NEXT:    [[COND_3:%.*]] = icmp sgt i32 [[I]], [[N]]
; CHECK-NEXT:    br i1 [[COND_3]], label [[EXIT2]], label [[EXIT]]
; CHECK:       do:
; CHECK-NEXT:    [[COND_0:%.*]] = icmp sgt i32 [[I]], 0
; CHECK-NEXT:    [[CONSUME:%.*]] = call i32 @consume(i1 [[COND_0]])
; CHECK-NEXT:    [[COND:%.*]] = icmp eq i32 [[I]], 0
; CHECK-NEXT:    call void (i1, ...) @llvm.experimental.guard(i1 [[COND]]) [ "deopt"() ]
; CHECK-NEXT:    [[COND_2:%.*]] = icmp sgt i32 [[I]], 0
; CHECK-NEXT:    br i1 [[COND_2]], label [[EXIT]], label [[CONT:%.*]]
; CHECK:       exit2:
; CHECK-NEXT:    ret i32 30
;
entry:
  %c = icmp ne i32 %i, -2134
  br i1 %c, label %do, label %exit

exit:
  %c1 = icmp ne i32 %i, -42
  br i1 %c1, label %exit2, label %exit

; Here cont is merged to do and i is any value except -2134.
; i is not the single value: zero.
cont:
  %cond.3 = icmp sgt i32 %i, %n
  br i1 %cond.3, label %exit2, label %exit

do:
  %cond.0 = icmp sgt i32 %i, 0
  %consume = call i32 @consume(i1 %cond.0)
  %cond = icmp eq i32 %i, 0
  call void (i1, ...) @llvm.experimental.guard(i1 %cond) [ "deopt"() ]
  %cond.2 = icmp sgt i32 %i, 0
  br i1 %cond.2, label %exit, label %cont

exit2:
; LatticeVal for: 'i32 %i' is: constantrange<-2134, 1>
  ret i32 30
}

; FIXME: We should be able to merge cont into do.
; FIXME: COND should be replaced with false. This will be fixed by improving LVI.
define i32 @test4(i32 %i, i1 %f, i32 %n) {
; CHECK-LABEL: define {{[^@]+}}@test4
; CHECK-SAME: (i32 [[I:%.*]], i1 [[F:%.*]], i32 [[N:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[C:%.*]] = icmp ne i32 [[I]], -2134
; CHECK-NEXT:    br i1 [[C]], label [[DO:%.*]], label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    [[C1:%.*]] = icmp ne i32 [[I]], -42
; CHECK-NEXT:    br i1 [[C1]], label [[EXIT2:%.*]], label [[EXIT]]
; CHECK:       cont:
; CHECK-NEXT:    call void @dummy(i1 [[F]]) #[[ATTR2:[0-9]+]]
; CHECK-NEXT:    br label [[EXIT2]]
; CHECK:       do:
; CHECK-NEXT:    call void @dummy(i1 [[F]]) #[[ATTR2]]
; CHECK-NEXT:    [[CONSUME:%.*]] = call i32 @exit()
; CHECK-NEXT:    call void @llvm.assume(i1 noundef [[F]])
; CHECK-NEXT:    [[COND:%.*]] = icmp eq i1 [[F]], false
; CHECK-NEXT:    br i1 [[COND]], label [[EXIT]], label [[CONT:%.*]]
; CHECK:       exit2:
; CHECK-NEXT:    ret i32 30
;
entry:
  %c = icmp ne i32 %i, -2134
  br i1 %c, label %do, label %exit

exit:                                             ; preds = %do, %cont, %exit, %entry
  %c1 = icmp ne i32 %i, -42
  br i1 %c1, label %exit2, label %exit

cont:                                             ; preds = %do
  call void @dummy(i1 %f)
  br label %exit2

do:                                               ; preds = %entry
  call void @dummy(i1 %f)
  %consume = call i32 @exit()
  call void @llvm.assume(i1 %f)
  %cond = icmp eq i1 %f, false
  br i1 %cond, label %exit, label %cont

exit2:                                            ; preds = %cont, %exit
  ret i32 30
}

declare i32 @exit()
declare i32 @consume(i1)
declare void @llvm.assume(i1) nounwind
declare void @dummy(i1) nounwind
declare void @llvm.experimental.guard(i1, ...)
;.
; CHECK: attributes #[[ATTR0]] = { nofree norecurse nosync nounwind willreturn memory(none) }
; CHECK: attributes #[[ATTR1:[0-9]+]] = { nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite) }
; CHECK: attributes #[[ATTR2]] = { nounwind }
; CHECK: attributes #[[ATTR3:[0-9]+]] = { nocallback nofree nosync willreturn }
;.
;; NOTE: These prefixes are unused and the list is autogenerated. Do not add tests below this line:
; CGSCC: {{.*}}
; TUNIT: {{.*}}
