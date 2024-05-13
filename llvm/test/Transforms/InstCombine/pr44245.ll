; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -passes=instcombine -instcombine-infinite-loop-threshold=2 < %s | FileCheck %s

; This used to cause on infinite instcombine loop.

define void @test(i1 %c) {
; CHECK-LABEL: @test(
; CHECK-NEXT:  bb16:
; CHECK-NEXT:    br i1 [[C:%.*]], label [[BB17:%.*]], label [[BB24:%.*]]
; CHECK:       bb17:
; CHECK-NEXT:    [[I:%.*]] = phi ptr [ [[DOTIN1:%.*]], [[BB47:%.*]] ], [ undef, [[BB16:%.*]] ]
; CHECK-NEXT:    store ptr [[I]], ptr undef, align 8
; CHECK-NEXT:    ret void
; CHECK:       bb24:
; CHECK-NEXT:    br i1 [[C]], label [[BB44:%.*]], label [[BB49:%.*]]
; CHECK:       bb44:
; CHECK-NEXT:    [[TMP46:%.*]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb47:
; CHECK-NEXT:    [[DOTIN1]] = phi ptr [ [[DOTIN:%.*]], [[BB150:%.*]] ], [ [[TMP122:%.*]], [[BB119:%.*]] ], [ [[TMP103:%.*]], [[BB101:%.*]] ], [ [[TMP93:%.*]], [[BB91:%.*]] ], [ [[TMP83:%.*]], [[BB81:%.*]] ], [ [[TMP70:%.*]], [[BB67:%.*]] ], [ [[TMP58:%.*]], [[BB56:%.*]] ], [ [[TMP46]], [[BB44]] ]
; CHECK-NEXT:    br label [[BB17]]
; CHECK:       bb49:
; CHECK-NEXT:    br i1 [[C]], label [[BB56]], label [[BB59:%.*]]
; CHECK:       bb56:
; CHECK-NEXT:    [[TMP58]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb59:
; CHECK-NEXT:    br i1 [[C]], label [[BB67]], label [[BB71:%.*]]
; CHECK:       bb67:
; CHECK-NEXT:    [[TMP70]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb71:
; CHECK-NEXT:    br i1 [[C]], label [[BB81]], label [[BB84:%.*]]
; CHECK:       bb81:
; CHECK-NEXT:    [[TMP83]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb84:
; CHECK-NEXT:    br i1 [[C]], label [[BB91]], label [[BB94:%.*]]
; CHECK:       bb91:
; CHECK-NEXT:    [[TMP93]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb94:
; CHECK-NEXT:    br i1 [[C]], label [[BB101]], label [[BB104:%.*]]
; CHECK:       bb101:
; CHECK-NEXT:    [[TMP103]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb104:
; CHECK-NEXT:    br i1 [[C]], label [[BB119]], label [[BB123:%.*]]
; CHECK:       bb119:
; CHECK-NEXT:    [[TMP122]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb123:
; CHECK-NEXT:    br i1 [[C]], label [[BB147:%.*]], label [[BB152:%.*]]
; CHECK:       bb147:
; CHECK-NEXT:    [[TMP149:%.*]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    br label [[BB150]]
; CHECK:       bb150:
; CHECK-NEXT:    [[DOTIN]] = phi ptr [ [[TMP184:%.*]], [[BB152]] ], [ [[TMP149]], [[BB147]] ]
; CHECK-NEXT:    br label [[BB47]]
; CHECK:       bb152:
; CHECK-NEXT:    [[TMP184]] = load ptr, ptr inttoptr (i64 16 to ptr), align 16
; CHECK-NEXT:    store i1 true, ptr poison, align 1
; CHECK-NEXT:    br label [[BB150]]
;
bb16:
  br i1 %c, label %bb17, label %bb24

bb17:                                             ; preds = %bb47, %bb16
  %i = phi ptr [ %.in1, %bb47 ], [ undef, %bb16 ]
  store ptr %i, ptr undef, align 8
  ret void

bb24:                                             ; preds = %bb16
  br i1 %c, label %bb44, label %bb49

bb44:                                             ; preds = %bb24
  %tmp46 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb47

bb47:                                             ; preds = %bb150, %bb119, %bb101, %bb91, %bb81, %bb67, %bb56, %bb44
  %.in1 = phi ptr [ %.in, %bb150 ], [ %tmp122, %bb119 ], [ %tmp103, %bb101 ], [ %tmp93, %bb91 ], [ %tmp83, %bb81 ], [ %tmp70, %bb67 ], [ %tmp58, %bb56 ], [ %tmp46, %bb44 ]
  br label %bb17

bb49:                                             ; preds = %bb24
  br i1 %c, label %bb56, label %bb59

bb56:                                             ; preds = %bb49
  %tmp58 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb47

bb59:                                             ; preds = %bb49
  br i1 %c, label %bb67, label %bb71

bb67:                                             ; preds = %bb59
  %tmp70 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb47

bb71:                                             ; preds = %bb59
  br i1 %c, label %bb81, label %bb84

bb81:                                             ; preds = %bb71
  %tmp83 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb47

bb84:                                             ; preds = %bb71
  br i1 %c, label %bb91, label %bb94

bb91:                                             ; preds = %bb84
  %tmp93 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb47

bb94:                                             ; preds = %bb84
  br i1 %c, label %bb101, label %bb104

bb101:                                            ; preds = %bb94
  %tmp103 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb47

bb104:                                            ; preds = %bb94
  br i1 %c, label %bb119, label %bb123

bb119:                                            ; preds = %bb104
  %tmp122 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb47

bb123:                                            ; preds = %bb104
  br i1 %c, label %bb147, label %bb152

bb147:                                            ; preds = %bb123
  %tmp149 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  br label %bb150

bb150:                                            ; preds = %bb152, %bb147
  %.in = phi ptr [ %tmp184, %bb152 ], [ %tmp149, %bb147 ]
  br label %bb47

bb152:                                            ; preds = %bb123
  %tmp184 = load ptr, ptr inttoptr (i64 16 to ptr), align 16
  call void undef()
  br label %bb150
}


; This used to cause an instcombine loop when the problem above was
; addressed in a non-robust fashion.
%type_1 = type {}
%type_2 = type {}
%type_3 = type {}

define void @test_2(i1 %c) local_unnamed_addr {
; CHECK-LABEL: @test_2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[WHILE_COND:%.*]]
; CHECK:       while.cond:
; CHECK-NEXT:    br label [[FOR_COND:%.*]]
; CHECK:       for.cond:
; CHECK-NEXT:    br i1 [[C:%.*]], label [[COND_TRUE133:%.*]], label [[COND_FALSE138:%.*]]
; CHECK:       cond.true133:
; CHECK-NEXT:    br label [[COND_END144:%.*]]
; CHECK:       cond.false138:
; CHECK-NEXT:    store ptr poison, ptr null, align 4294967296
; CHECK-NEXT:    br label [[COND_END144]]
; CHECK:       cond.end144:
; CHECK-NEXT:    br label [[WHILE_COND]]
;
entry:
  br label %while.cond

while.cond:                                       ; preds = %cond.end144, %entry
  %link.0 = phi ptr [ undef, %entry ], [ %cond145, %cond.end144 ]
  br label %for.cond

for.cond:                                         ; preds = %while.cond
  br i1 %c, label %cond.true133, label %cond.false138

cond.true133:                                     ; preds = %for.cond
  %i = load ptr, ptr undef, align 8
  br label %cond.end144

cond.false138:                                    ; preds = %for.cond
  %i1 = load ptr, ptr undef, align 8
  br label %cond.end144

cond.end144:                                      ; preds = %cond.false138, %cond.true133
  %cond145 = phi ptr [ %i, %cond.true133 ], [ %i1, %cond.false138 ]
  br label %while.cond
}
