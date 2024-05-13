; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=tailcallelim -verify-dom-info -S | FileCheck %s

; the test was generated from the following C++ source:
;
; int zoo ( S p1 );
;
; int foo ( int count, S p1 ) {
;   if ( count > 10 )
;     return zoo(p1);
;
;   // After TRE: temporarily variable created for passing byvalue parameter
;   // p1 could be used when zoo(p1) is called.
;   return foo(count+1, p1);
; }

; this test checks that value of ByValue operand AGG_TMP_I of call site foo()
; is copied into temporarily variable AGG_TMP_I1(byVal value holder) and
; later the value from AGG_TMP_I1 is copied into function argument P1 before
; new iteration started.

%struct.S = type { i32, i32, float, %struct.B }
%struct.B = type { i32, float }

; Function Attrs: uwtable
define dso_local i32 @_Z3fooi1S(i32 %count, ptr nocapture readonly byval(%struct.S) align 8 %p1) local_unnamed_addr #0 {
; CHECK-LABEL: @_Z3fooi1S(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[AGG_TMP_I1:%.*]] = alloca [[STRUCT_S:%.*]], align 8
; CHECK-NEXT:    [[AGG_TMP_I:%.*]] = alloca [[STRUCT_S]], align 8
; CHECK-NEXT:    [[AGG_TMP14:%.*]] = alloca [[STRUCT_S]], align 8
; CHECK-NEXT:    [[AGG_TMP:%.*]] = alloca [[STRUCT_S]], align 8
; CHECK-NEXT:    [[AGG_TMP1:%.*]] = alloca [[STRUCT_S]], align 8
; CHECK-NEXT:    br label [[TAILRECURSE:%.*]]
; CHECK:       tailrecurse:
; CHECK-NEXT:    [[COUNT_TR:%.*]] = phi i32 [ [[COUNT:%.*]], [[ENTRY:%.*]] ], [ [[ADD:%.*]], [[IF_END:%.*]] ]
; CHECK-NEXT:    [[CMP:%.*]] = icmp sgt i32 [[COUNT_TR]], 10
; CHECK-NEXT:    br i1 [[CMP]], label [[IF_THEN:%.*]], label [[IF_END]]
; CHECK:       if.then:
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) [[AGG_TMP]], ptr nonnull align 8 dereferenceable(20) [[P1:%.*]], i64 20, i1 false)
; CHECK-NEXT:    [[CALL:%.*]] = tail call i32 @_Z3zoo1S(ptr nonnull byval(%struct.S) align 8 [[AGG_TMP]])
; CHECK-NEXT:    br label [[RETURN:%.*]]
; CHECK:       if.end:
; CHECK-NEXT:    [[ADD]] = add nsw i32 [[COUNT_TR]], 1
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) [[AGG_TMP1]], ptr nonnull align 8 dereferenceable(20) [[P1]], i64 20, i1 false)
; CHECK-NEXT:    call void @llvm.lifetime.start.p0(i64 20, ptr nonnull [[AGG_TMP14]])
; CHECK-NEXT:    call void @llvm.lifetime.start.p0(i64 20, ptr nonnull [[AGG_TMP_I]])
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) [[AGG_TMP14]], ptr nonnull align 8 dereferenceable(20) [[AGG_TMP1]], i64 20, i1 false)
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) [[AGG_TMP_I]], ptr nonnull align 8 dereferenceable(20) [[AGG_TMP14]], i64 20, i1 false)
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 8 [[AGG_TMP_I1]], ptr align 8 [[AGG_TMP_I]], i64 20, i1 false)
; CHECK-NEXT:    call void @llvm.memcpy.p0.p0.i64(ptr align 8 [[P1]], ptr align 8 [[AGG_TMP_I1]], i64 20, i1 false)
; CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 20, ptr nonnull [[AGG_TMP14]])
; CHECK-NEXT:    call void @llvm.lifetime.end.p0(i64 20, ptr nonnull [[AGG_TMP_I]])
; CHECK-NEXT:    br label [[TAILRECURSE]]
; CHECK:       return:
; CHECK-NEXT:    ret i32 [[CALL]]
;
entry:
  %agg.tmp.i = alloca %struct.S, align 8
  %agg.tmp14 = alloca %struct.S, align 8
  %agg.tmp = alloca %struct.S, align 8
  %agg.tmp1 = alloca %struct.S, align 8
  %cmp = icmp sgt i32 %count, 10
  br i1 %cmp, label %if.then, label %if.end

if.then:                                          ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) %agg.tmp, ptr nonnull align 8 dereferenceable(20) %p1, i64 20, i1 false)
  %call = call i32 @_Z3zoo1S(ptr nonnull byval(%struct.S) align 8 %agg.tmp)
  br label %return

if.end:                                           ; preds = %entry
  %add = add nsw i32 %count, 1
  call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) %agg.tmp1, ptr nonnull align 8 dereferenceable(20) %p1, i64 20, i1 false)
  call void @llvm.lifetime.start.p0(i64 20, ptr nonnull %agg.tmp14)
  call void @llvm.lifetime.start.p0(i64 20, ptr nonnull %agg.tmp.i)
  call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) %agg.tmp14, ptr nonnull align 8 dereferenceable(20) %agg.tmp1, i64 20, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 8 dereferenceable(20) %agg.tmp.i, ptr nonnull align 8 dereferenceable(20) %agg.tmp14, i64 20, i1 false)
  %call.i = call i32 @_Z3fooi1S(i32 %add, ptr nonnull byval(%struct.S) align 8 %agg.tmp.i)
  call void @llvm.lifetime.end.p0(i64 20, ptr nonnull %agg.tmp14)
  call void @llvm.lifetime.end.p0(i64 20, ptr nonnull %agg.tmp.i)
  br label %return

return:                                           ; preds = %if.end, %if.then
  %retval.0 = phi i32 [ %call, %if.then ], [ %call.i, %if.end ]
  ret i32 %retval.0
}

declare dso_local i32 @_Z3zoo1S(ptr byval(%struct.S) align 8) local_unnamed_addr #1

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture) #2

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture) #2

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #2

attributes #0 = { uwtable }
attributes #1 = { uwtable }
attributes #2 = { argmemonly nounwind willreturn }
