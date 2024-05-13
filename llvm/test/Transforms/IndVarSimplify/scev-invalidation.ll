; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -passes=indvars -verify-scev < %s | FileCheck %s

define void @test_pr54434() {
; CHECK-LABEL: @test_pr54434(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[FOR_COND:%.*]]
; CHECK:       for.cond:
; CHECK-NEXT:    br i1 false, label [[FOR_COND92_PREHEADER:%.*]], label [[FOR_END106:%.*]]
; CHECK:       for.cond92.preheader:
; CHECK-NEXT:    br label [[FOR_COND92:%.*]]
; CHECK:       for.cond92:
; CHECK-NEXT:    br i1 false, label [[FOR_BODY94:%.*]], label [[FOR_END:%.*]]
; CHECK:       for.body94:
; CHECK-NEXT:    br label [[FOR_COND92]]
; CHECK:       for.end:
; CHECK-NEXT:    br label [[FOR_COND]]
; CHECK:       for.end106:
; CHECK-NEXT:    ret void
;
entry:
  br label %for.cond

for.cond:                                         ; preds = %for.end, %entry
  %0 = phi i32 [ %inc105, %for.end ], [ 0, %entry ]
  %cmp = icmp sge i32 %0, 1
  br i1 %cmp, label %for.cond92, label %for.end106

for.cond92:                                       ; preds = %for.body94, %for.cond
  %1 = phi i16 [ %inc, %for.body94 ], [ 0, %for.cond ]
  %cmp93 = icmp slt i16 %1, 1
  br i1 %cmp93, label %for.body94, label %for.end

for.body94:                                       ; preds = %for.cond92
  %inc = add nsw i16 %1, 1
  br label %for.cond92

for.end:                                          ; preds = %for.cond92
  %inc105 = add nsw i32 %0, 1
  br label %for.cond

for.end106:                                       ; preds = %for.cond
  ret void
}

define i32 @test_pr58439(i32 %a) {
; CHECK-LABEL: @test_pr58439(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    br i1 false, label [[LOOP]], label [[EXIT:%.*]]
; CHECK:       exit:
; CHECK-NEXT:    [[C_EXT_LCSSA:%.*]] = phi i32 [ 0, [[LOOP]] ]
; CHECK-NEXT:    [[OR:%.*]] = or i32 [[A:%.*]], 1
; CHECK-NEXT:    [[RES:%.*]] = add i32 [[C_EXT_LCSSA]], [[OR]]
; CHECK-NEXT:    ret i32 [[RES]]
;
entry:
  %or = or i32 %a, 1
  br label %loop

loop:
  %iv = phi i32 [ 1, %entry ], [ %iv.next, %loop ]
  %iv.next = add i32 %iv, 1
  %c.1 = icmp eq i32 %iv.next, %or
  %c.ext = zext i1 %c.1 to i32
  br i1 false, label %loop, label %exit

exit:
  %res = add i32 %c.ext, %or
  ret i32 %res
}

define i8 @l(i32 %inc, i1 %tobool.not.i) {
; CHECK-LABEL: @l(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[OUTER_HEADER:%.*]]
; CHECK:       outer.header:
; CHECK-NEXT:    br label [[INNER:%.*]]
; CHECK:       inner:
; CHECK-NEXT:    [[C_05_I:%.*]] = phi i32 [ [[INC_I:%.*]], [[INNER]] ], [ 0, [[OUTER_HEADER]] ]
; CHECK-NEXT:    [[INC_I]] = add nuw nsw i32 [[C_05_I]], 1
; CHECK-NEXT:    [[CMP_I:%.*]] = icmp ugt i32 [[C_05_I]], 0
; CHECK-NEXT:    [[OR_COND_I:%.*]] = select i1 [[CMP_I]], i1 true, i1 [[TOBOOL_NOT_I:%.*]]
; CHECK-NEXT:    br i1 [[OR_COND_I]], label [[OUTER_LATCH:%.*]], label [[INNER]]
; CHECK:       outer.latch:
; CHECK-NEXT:    [[C_05_I_LCSSA:%.*]] = phi i32 [ [[C_05_I]], [[INNER]] ]
; CHECK-NEXT:    [[LCSSA:%.*]] = phi i32 [ 0, [[INNER]] ]
; CHECK-NEXT:    [[AND:%.*]] = and i32 1, [[INC:%.*]]
; CHECK-NEXT:    [[TMP0:%.*]] = trunc i32 [[AND]] to i8
; CHECK-NEXT:    [[TMP1:%.*]] = trunc i32 [[C_05_I_LCSSA]] to i8
; CHECK-NEXT:    [[TMP2:%.*]] = sub i8 [[TMP0]], [[TMP1]]
; CHECK-NEXT:    [[TOBOOL_NOT:%.*]] = icmp eq i8 [[TMP2]], 0
; CHECK-NEXT:    br i1 [[TOBOOL_NOT]], label [[OUTER_HEADER]], label [[IF_THEN:%.*]]
; CHECK:       if.then:
; CHECK-NEXT:    ret i8 0
;
entry:
  br label %outer.header

outer.header:                                         ; preds = %h.exit, %entry
  %outer.iv = phi i16 [ 0, %entry ], [ %outer.iv.next, %outer.latch ]
  %and = and i32 1, %inc
  %conv = sext i16 %outer.iv to i32
  br label %inner

inner:                                     ; preds = %while.body.i, %for.cond
  %c.05.i = phi i32 [ %inc.i, %inner ], [ 0, %outer.header ]
  %i.addr.04.i = phi i32 [ 0, %inner ], [ %conv, %outer.header ]
  %inc.i = add nsw i32 %c.05.i, 1
  %cmp.i = icmp sgt i32 %c.05.i, 0
  %or.cond.i = select i1 %cmp.i, i1 true, i1 %tobool.not.i
  br i1 %or.cond.i, label %outer.latch, label %inner

outer.latch:                                           ; preds = %while.body.i
  %lcssa = phi i32 [ 0, %inner ]
  %0 = trunc i32 %and to i8
  %1 = trunc i32 %c.05.i to i8
  %2 = sub i8 %0, %1
  %tobool.not = icmp eq i8 %2, 0
  %outer.iv.next = add i16 %outer.iv, 1
  br i1 %tobool.not, label %outer.header, label %if.then

if.then:                                          ; preds = %h.exit
  ret i8 0
}
