; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -passes=instcombine -S < %s | FileCheck %s

define i1 @ugt_vscale64_x_32() vscale_range(1,16) {
; CHECK-LABEL: @ugt_vscale64_x_32(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i1 false
;
entry:
  %vscale = call i64 @llvm.vscale.i64()
  %num_els = shl i64 %vscale, 5
  %res = icmp ugt i64 %num_els, 1024
  ret i1 %res
}

define i1 @ugt_vscale64_x_31() vscale_range(1,16) {
; CHECK-LABEL: @ugt_vscale64_x_31(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i1 false
;
entry:
  %vscale = call i64 @llvm.vscale.i64()
  %num_els = mul i64 %vscale, 31
  %res = icmp ugt i64 %num_els, 1024
  ret i1 %res
}

define i1 @ugt_vscale16_x_32() vscale_range(1,16) {
; CHECK-LABEL: @ugt_vscale16_x_32(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i1 false
;
entry:
  %vscale = call i16 @llvm.vscale.i16()
  %num_els = shl i16 %vscale, 5
  %res = icmp ugt i16 %num_els, 1024
  ret i1 %res
}

define i1 @ult_vscale16() vscale_range(1,16) {
; CHECK-LABEL: @ult_vscale16(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i1 false
;
entry:
  %vscale = call i16 @llvm.vscale.i16()
  %res = icmp ult i16 1024, %vscale
  ret i1 %res
}

define i1 @ule_vscale64() vscale_range(1,16) {
; CHECK-LABEL: @ule_vscale64(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i1 false
;
entry:
  %vscale = call i64 @llvm.vscale.i64()
  %res = icmp ule i64 1024, %vscale
  ret i1 %res
}

define i1 @ueq_vscale64_range4_4() vscale_range(4,4) {
; CHECK-LABEL: @ueq_vscale64_range4_4(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i1 true
;
entry:
  %vscale = call i64 @llvm.vscale.i64()
  %res = icmp eq i64 %vscale, 4
  ret i1 %res
}

define i1 @ne_vscale64_x_32() vscale_range(1,16) {
; CHECK-LABEL: @ne_vscale64_x_32(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    ret i1 true
;
entry:
  %vscale = call i64 @llvm.vscale.i64()
  %num_els = mul i64 %vscale, 32
  %res = icmp ne i64 %num_els, 39488
  ret i1 %res
}

define i1 @vscale_ule_max() vscale_range(5,10) {
; CHECK-LABEL: @vscale_ule_max(
; CHECK-NEXT:    ret i1 true
;
  %vscale = call i16 @llvm.vscale.i16()
  %res = icmp ule i16 %vscale, 10
  ret i1 %res
}

define i1 @vscale_ult_max() vscale_range(5,10) {
; CHECK-LABEL: @vscale_ult_max(
; CHECK-NEXT:    [[VSCALE:%.*]] = call i16 @llvm.vscale.i16()
; CHECK-NEXT:    [[RES:%.*]] = icmp ult i16 [[VSCALE]], 10
; CHECK-NEXT:    ret i1 [[RES]]
;
  %vscale = call i16 @llvm.vscale.i16()
  %res = icmp ult i16 %vscale, 10
  ret i1 %res
}

define i1 @vscale_uge_min() vscale_range(5,10) {
; CHECK-LABEL: @vscale_uge_min(
; CHECK-NEXT:    ret i1 true
;
  %vscale = call i16 @llvm.vscale.i16()
  %res = icmp uge i16 %vscale, 5
  ret i1 %res
}

define i1 @vscale_ugt_min() vscale_range(5,10) {
; CHECK-LABEL: @vscale_ugt_min(
; CHECK-NEXT:    [[VSCALE:%.*]] = call i16 @llvm.vscale.i16()
; CHECK-NEXT:    [[RES:%.*]] = icmp ugt i16 [[VSCALE]], 5
; CHECK-NEXT:    ret i1 [[RES]]
;
  %vscale = call i16 @llvm.vscale.i16()
  %res = icmp ugt i16 %vscale, 5
  ret i1 %res
}

define i1 @vscale_uge_no_max() vscale_range(5) {
; CHECK-LABEL: @vscale_uge_no_max(
; CHECK-NEXT:    ret i1 true
;
  %vscale = call i8 @llvm.vscale.i8()
  %res = icmp uge i8 %vscale, 5
  ret i1 %res
}

define i1 @vscale_ugt_no_max() vscale_range(5) {
; CHECK-LABEL: @vscale_ugt_no_max(
; CHECK-NEXT:    ret i1 false
;
  %vscale = call i8 @llvm.vscale.i8()
  %res = icmp ugt i8 %vscale, 5
  ret i1 %res
}

define i1 @vscale_uge_max_overflow() vscale_range(5,256) {
; CHECK-LABEL: @vscale_uge_max_overflow(
; CHECK-NEXT:    ret i1 true
;
  %vscale = call i8 @llvm.vscale.i8()
  %res = icmp uge i8 %vscale, 5
  ret i1 %res
}

define i1 @vscale_ugt_max_overflow() vscale_range(5,256) {
; CHECK-LABEL: @vscale_ugt_max_overflow(
; CHECK-NEXT:    [[VSCALE:%.*]] = call i8 @llvm.vscale.i8()
; CHECK-NEXT:    [[RES:%.*]] = icmp ugt i8 [[VSCALE]], 5
; CHECK-NEXT:    ret i1 [[RES]]
;
  %vscale = call i8 @llvm.vscale.i8()
  %res = icmp ugt i8 %vscale, 5
  ret i1 %res
}

define i1 @vscale_eq_min_overflow() vscale_range(256,300) {
; CHECK-LABEL: @vscale_eq_min_overflow(
; CHECK-NEXT:    ret i1 true
;
  %vscale = call i8 @llvm.vscale.i8()
  %res = icmp eq i8 %vscale, 42
  ret i1 %res
}

define i1 @vscale_ult_min_overflow() vscale_range(256,300) {
; CHECK-LABEL: @vscale_ult_min_overflow(
; CHECK-NEXT:    ret i1 true
;
  %vscale = call i8 @llvm.vscale.i8()
  %res = icmp ult i8 %vscale, 42
  ret i1 %res
}

define i1 @vscale_ugt_min_overflow() vscale_range(256,300) {
; CHECK-LABEL: @vscale_ugt_min_overflow(
; CHECK-NEXT:    ret i1 true
;
  %vscale = call i8 @llvm.vscale.i8()
  %res = icmp ugt i8 %vscale, 42
  ret i1 %res
}

declare i8 @llvm.vscale.i8()
declare i16 @llvm.vscale.i16()
declare i32 @llvm.vscale.i32()
declare i64 @llvm.vscale.i64()
