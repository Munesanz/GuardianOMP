; RUN: opt -S -aa-pipeline=basic-aa,tbaa -passes=gvn < %s | FileCheck -check-prefix=BASICAA %s
; RUN: opt -S -aa-pipeline=tbaa -passes=gvn < %s | FileCheck %s
; rdar://8875631, rdar://8875069

; BasicAA should notice that the store stores to the entire %u object,
; so the %tmp5 load is PartialAlias with the store and suppress TBAA.
; Without BasicAA, TBAA should say that %tmp5 is NoAlias with the store.

target datalayout = "e-p:64:64:64"

%union.anon = type { double }

@u = global %union.anon { double -2.500000e-01 }, align 8
@endianness_test = global i64 1, align 8

define i32 @signbit(double %x) nounwind {
; BASICAA: ret i32 %tmp5.lobit
; CHECK:   ret i32 0
entry:
  %u = alloca %union.anon, align 8
  store double %x, ptr %u, align 8, !tbaa !0
  %tmp2 = load i32, ptr @endianness_test, align 8, !tbaa !3
  %idxprom = sext i32 %tmp2 to i64
  %arrayidx = getelementptr inbounds [2 x i32], ptr %u, i64 0, i64 %idxprom
  %tmp5 = load i32, ptr %arrayidx, align 4, !tbaa !3
  %tmp5.lobit = lshr i32 %tmp5, 31
  ret i32 %tmp5.lobit
}

!0 = !{!4, !4, i64 0}
!1 = !{!"omnipotent char", !2}
!2 = !{!"Simple C/C++ TBAA"}
!3 = !{!5, !5, i64 0}
!4 = !{!"double", !1}
!5 = !{!"int", !1}
