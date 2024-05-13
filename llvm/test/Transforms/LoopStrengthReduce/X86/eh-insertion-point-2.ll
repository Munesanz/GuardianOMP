; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S -loop-reduce < %s | FileCheck %s

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

declare void @maybe_throws()
declare void @use1(i1)

define void @is_not_42(ptr %baseptr, ptr %finalptr) local_unnamed_addr align 2 personality ptr undef {
; CHECK-LABEL: @is_not_42(
; CHECK-NEXT:  preheader:
; CHECK-NEXT:    br label [[HEADER:%.*]]
; CHECK:       header:
; CHECK-NEXT:    [[PTR:%.*]] = phi ptr [ [[INCPTR:%.*]], [[LATCH:%.*]] ], [ [[BASEPTR:%.*]], [[PREHEADER:%.*]] ]
; CHECK-NEXT:    invoke void @maybe_throws()
; CHECK-NEXT:    to label [[LATCH]] unwind label [[LPAD:%.*]]
; CHECK:       lpad:
; CHECK-NEXT:    [[TMP0:%.*]] = landingpad { ptr, i32 }
; CHECK-NEXT:    catch ptr inttoptr (i64 42 to ptr)
; CHECK-NEXT:    [[PTR_IS_NOT_42:%.*]] = icmp ne ptr [[PTR]], inttoptr (i64 42 to ptr)
; CHECK-NEXT:    call void @use1(i1 [[PTR_IS_NOT_42]])
; CHECK-NEXT:    ret void
; CHECK:       latch:
; CHECK-NEXT:    [[INCPTR]] = getelementptr inbounds i8, ptr [[PTR]], i64 1
; CHECK-NEXT:    br label [[HEADER]]
;
preheader:
  br label %header

header:
  %ptr = phi ptr [ %incptr, %latch ], [ %baseptr, %preheader ]
  invoke void @maybe_throws() to label %latch unwind label %lpad

lpad:
  landingpad { ptr, i32 } catch ptr inttoptr (i64 42 to ptr)
  %ptr_is_not_42 = icmp ne ptr %ptr, inttoptr (i64 42 to ptr)
  call void @use1(i1 %ptr_is_not_42)
  ret void

latch:
  %incptr = getelementptr inbounds i8, ptr %ptr, i64 1
  br label %header
}
