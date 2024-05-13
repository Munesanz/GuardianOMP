; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -passes=ipsccp -S | FileCheck %s

define internal i32 @test1a(i32 %A, i32 %b) {
; CHECK-LABEL: @test1a(
; CHECK-NEXT:    [[X:%.*]] = add i32 [[A:%.*]], 1
; CHECK-NEXT:    [[C:%.*]] = icmp eq i32 [[X]], [[B:%.*]]
; CHECK-NEXT:    br i1 [[C]], label [[BB_TRUE:%.*]], label [[BB_FALSE:%.*]]
; CHECK:       bb.true:
; CHECK-NEXT:    [[R:%.*]] = call i32 @test1a(i32 [[X]], i32 [[B]])
; CHECK-NEXT:    ret i32 [[R]]
; CHECK:       bb.false:
; CHECK-NEXT:    ret i32 [[A]]
;
  %X = add i32 %A, 1
  %c = icmp eq i32 %X, %b
  br i1 %c, label %bb.true, label %bb.false

bb.true:
  %r = call i32 @test1a(i32 %X, i32 %b)
  ret i32 %r

bb.false:
  ret i32 %A
}

define i32 @test1b(i32 %b) {
; CHECK-LABEL: @test1b(
; CHECK-NEXT:    [[X:%.*]] = call i32 @test1a(i32 17, i32 [[B:%.*]])
; CHECK-NEXT:    ret i32 [[X]]
;
  %X = call i32 @test1a( i32 17, i32 %b)
  ret i32 %X
}

@Getopt.optind = internal global i32 1, align 4

define i32 @test2(i32 %a) {
; CHECK-LABEL: @test2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[LV:%.*]] = load i32, ptr @Getopt.optind, align 4
; CHECK-NEXT:    [[ADD:%.*]] = add i32 [[LV]], 1
; CHECK-NEXT:    store i32 [[ADD]], ptr @Getopt.optind, align 4
; CHECK-NEXT:    [[C:%.*]] = icmp eq i32 [[ADD]], [[A:%.*]]
; CHECK-NEXT:    br i1 [[C]], label [[EXIT:%.*]], label [[LOOP]]
; CHECK:       exit:
; CHECK-NEXT:    ret i32 [[ADD]]
;
entry:
  br label %loop

loop:
  %lv = load i32, ptr @Getopt.optind, align 4
  %add = add i32 %lv, 1
  store i32 %add, ptr @Getopt.optind
  %c = icmp eq i32 %add, %a
  br i1 %c, label %exit, label %loop

exit:
  ret i32 %add
}


define internal i32 @test3a(i32 %a) {
; CHECK-LABEL: @test3a(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[RES:%.*]] = add i32 [[A:%.*]], 1
; CHECK-NEXT:    [[C:%.*]] = icmp ult i32 [[RES]], 1000
; CHECK-NEXT:    br i1 [[C]], label [[BB_TRUE:%.*]], label [[BB_FALSE:%.*]]
; CHECK:       bb.true:
; CHECK-NEXT:    ret i32 [[RES]]
; CHECK:       bb.false:
; CHECK-NEXT:    ret i32 0
;
entry:
  %res = add i32 %a, 1
  %c = icmp ult i32 %res, 1000
  br i1 %c, label %bb.true, label %bb.false

bb.true:
  ret i32 %res

bb.false:
  ret i32 0
}

define i32 @test3b(i32 %a) {
; CHECK-LABEL: @test3b(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[V1:%.*]] = call i32 @test3a(i32 0)
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    [[V2:%.*]] = call i32 @test3a(i32 [[V1]])
; CHECK-NEXT:    [[V3:%.*]] = add i32 [[V2]], 1
; CHECK-NEXT:    [[V4:%.*]] = call i32 @test3a(i32 [[V3]])
; CHECK-NEXT:    [[C:%.*]] = icmp eq i32 [[V4]], [[A:%.*]]
; CHECK-NEXT:    br i1 [[C]], label [[EXIT:%.*]], label [[LOOP]]
; CHECK:       exit:
; CHECK-NEXT:    ret i32 [[V4]]
;
entry:
  %v1 = call i32 @test3a(i32 0)
  br label %loop

loop:
  %v2 = call i32 @test3a(i32 %v1)
  %v3 = add i32 %v2, 1
  %v4 = call i32 @test3a(i32 %v3)
  %c = icmp eq i32 %v4, %a
  br i1 %c, label %exit, label %loop

exit:
  ret i32 %v4
}

%struct.S = type { i32, i32 }

; Check for a range extension cycle through a  struct argument.
define internal i32 @test4a(%struct.S %s) {
; CHECK-LABEL: @test4a(
; CHECK-NEXT:    [[A:%.*]] = extractvalue [[STRUCT_S:%.*]] %s, 0
; CHECK-NEXT:    [[B:%.*]] = extractvalue [[STRUCT_S]] %s, 1
; CHECK-NEXT:    [[X:%.*]] = add i32 [[A]], 1
; CHECK-NEXT:    [[C:%.*]] = icmp eq i32 [[X]], [[B]]
; CHECK-NEXT:    br i1 [[C]], label [[BB_TRUE:%.*]], label [[BB_FALSE:%.*]]
; CHECK:       bb.true:
; CHECK-NEXT:    [[S2:%.*]] = insertvalue [[STRUCT_S]] %s, i32 [[X]], 0
; CHECK-NEXT:    [[R:%.*]] = call i32 @test4a(%struct.S [[S2]])
; CHECK-NEXT:    ret i32 [[R]]
; CHECK:       bb.false:
; CHECK-NEXT:    ret i32 [[A]]
;
  %a = extractvalue %struct.S %s, 0
  %b = extractvalue %struct.S %s, 1

  %x = add i32 %a, 1
  %c = icmp eq i32 %x, %b
  br i1 %c, label %bb.true, label %bb.false

bb.true:
  %s2 = insertvalue %struct.S %s, i32 %x, 0
  %r = call i32 @test4a(%struct.S %s2)
  ret i32 %r

bb.false:
  ret i32 %a
}

define i32 @test4b(i32 %b) {
; CHECK-LABEL: @test4b(
; CHECK-NEXT:    [[S2:%.*]] = insertvalue [[STRUCT_S:%.*]] { i32 17, i32 undef }, i32 [[B:%.*]], 1
; CHECK-NEXT:    [[X:%.*]] = call i32 @test4a(%struct.S [[S2]])
; CHECK-NEXT:    ret i32 [[X]]
;
  %s1 = insertvalue %struct.S undef, i32 17, 0
  %s2 = insertvalue %struct.S %s1, i32 %b, 1
  %X = call i32 @test4a(%struct.S %s2)
  ret i32 %X
}

; Check for a range extension cycle through a returned value.

define internal i32 @test5a(ptr %arg, i32 %arg1, i32 %arg2) {
; CHECK-LABEL: @test5a(
; CHECK-NEXT:  bb:
; CHECK-NEXT:    [[TMP:%.*]] = icmp eq ptr [[ARG:%.*]], null
; CHECK-NEXT:    br i1 [[TMP]], label [[BB6:%.*]], label [[BB3:%.*]]
; CHECK:       bb3:
; CHECK-NEXT:    [[TMP4:%.*]] = tail call i32 @test5a(ptr [[ARG]], i32 0, i32 -1)
; CHECK-NEXT:    [[TMP5:%.*]] = add nsw i32 [[TMP4]], -1
; CHECK-NEXT:    ret i32 [[TMP5]]
; CHECK:       bb6:
; CHECK-NEXT:    ret i32 0
;
bb:
  %tmp = icmp eq ptr %arg, null
  br i1 %tmp, label %bb6, label %bb3

bb3:                                              ; preds = %bb
  %tmp4 = tail call i32 @test5a(ptr %arg, i32 %arg1, i32 %arg2)
  %tmp5 = add nsw i32 %tmp4, %arg2
  ret i32 %tmp5

bb6:                                              ; preds = %bb
  ret i32 %arg1
}

define void @test5b(ptr %ptr) {
; CHECK-LABEL: @test5b(
; CHECK-NEXT:  bb:
; CHECK-NEXT:    [[TMP:%.*]] = tail call i32 @test5a(ptr [[PTR:%.*]], i32 0, i32 -1)
; CHECK-NEXT:    ret void
;
bb:
  %tmp = tail call i32 @test5a(ptr %ptr, i32 0, i32 -1)
  ret void
}

%struct = type { i32, i32 }

define internal %struct @test6a(ptr %arg, i32 %arg1, i32 %arg2) {
; CHECK-LABEL: @test6a(
; CHECK-NEXT:  bb:
; CHECK-NEXT:    [[TMP:%.*]] = icmp eq ptr [[ARG:%.*]], null
; CHECK-NEXT:    br i1 [[TMP]], label [[BB6:%.*]], label [[BB3:%.*]]
; CHECK:       bb3:
; CHECK-NEXT:    [[S1:%.*]] = tail call [[STRUCT:%.*]] @test6a(ptr [[ARG]], i32 0, i32 -1)
; CHECK-NEXT:    [[TMP4:%.*]] = extractvalue [[STRUCT]] %s1, 0
; CHECK-NEXT:    [[TMP5:%.*]] = add nsw i32 [[TMP4]], -1
; CHECK-NEXT:    [[S2:%.*]] = insertvalue [[STRUCT]] %s1, i32 [[TMP5]], 0
; CHECK-NEXT:    ret [[STRUCT]] %s2
; CHECK:       bb6:
; CHECK-NEXT:    ret [[STRUCT]] { i32 0, i32 undef }
;
bb:
  %tmp = icmp eq ptr %arg, null
  br i1 %tmp, label %bb6, label %bb3

bb3:                                              ; preds = %bb
  %s1 = tail call %struct @test6a(ptr %arg, i32 %arg1, i32 %arg2)
  %tmp4 = extractvalue %struct %s1, 0
  %tmp5 = add nsw i32 %tmp4, %arg2
  %s2 = insertvalue %struct %s1, i32 %tmp5, 0
  ret %struct %s2

bb6:                                              ; preds = %bb
  %s3 = insertvalue %struct undef, i32 %arg1, 0
  ret %struct %s3
}

define void @test6b(ptr %ptr) {
; CHECK-LABEL: @test6b(
; CHECK-NEXT:  bb:
; CHECK-NEXT:    [[TMP:%.*]] = tail call [[STRUCT:%.*]] @test6a(ptr [[PTR:%.*]], i32 0, i32 -1)
; CHECK-NEXT:    ret void
;
bb:
  %tmp = tail call %struct @test6a(ptr %ptr, i32 0, i32 -1)
  ret void
}