; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 2
; RUN: llc -verify-machineinstrs -mcpu=pwr8 -mtriple=powerpc64le-unknown-unknown \
; RUN:   -ppc-asm-full-reg-names < %s | FileCheck %s --check-prefix=64BIT
; RUN: llc -verify-machineinstrs -mcpu=pwr8 -mtriple=powerpc64-unknown-unknown \
; RUN:   -ppc-asm-full-reg-names < %s | FileCheck %s --check-prefix=64BIT
; RUN: llc -O3 -mcpu=pwr8 -mtriple powerpc-ibm-aix -verify-machineinstrs \
; RUN:   -ppc-asm-full-reg-names < %s | FileCheck --check-prefix=32BIT %s
; RUN: llc -O3 -mcpu=pwr8 -mtriple powerpc64-ibm-aix -verify-machineinstrs \
; RUN:   -ppc-asm-full-reg-names < %s | FileCheck --check-prefix=64BIT %s


define dso_local i64 @test_xor(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_xor:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r4, 0(r3)
; 64BIT-NEXT:    lbz r3, 1(r3)
; 64BIT-NEXT:    xor r3, r3, r4
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_xor:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r5, 0(r4)
; 32BIT-NEXT:    lbz r4, 1(r4)
; 32BIT-NEXT:    xor r4, r4, r5
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i8, ptr %inp, i64 1
  %1 = load i8, ptr %arrayidx1, align 1
  %xor5 = xor i8 %1, %0
  %conv3 = zext i8 %xor5 to i64
  ret i64 %conv3
}

define dso_local i64 @test_xor2(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_xor2:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r4, 0(r3)
; 64BIT-NEXT:    lbz r5, 1(r3)
; 64BIT-NEXT:    lbz r3, 2(r3)
; 64BIT-NEXT:    xor r4, r5, r4
; 64BIT-NEXT:    xor r3, r4, r3
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_xor2:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r5, 0(r4)
; 32BIT-NEXT:    lbz r6, 1(r4)
; 32BIT-NEXT:    lbz r4, 2(r4)
; 32BIT-NEXT:    xor r5, r6, r5
; 32BIT-NEXT:    xor r4, r5, r4
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i8, ptr %inp, i64 1
  %1 = load i8, ptr %arrayidx1, align 1
  %xor9 = xor i8 %1, %0
  %arrayidx3 = getelementptr inbounds i8, ptr %inp, i64 2
  %2 = load i8, ptr %arrayidx3, align 1
  %xor510 = xor i8 %xor9, %2
  %conv6 = zext i8 %xor510 to i64
  ret i64 %conv6
}

define dso_local i64 @test_or(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_or:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r4, 0(r3)
; 64BIT-NEXT:    lbz r3, 1(r3)
; 64BIT-NEXT:    or r3, r3, r4
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_or:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r5, 0(r4)
; 32BIT-NEXT:    lbz r4, 1(r4)
; 32BIT-NEXT:    or r4, r4, r5
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i8, ptr %inp, i64 1
  %1 = load i8, ptr %arrayidx1, align 1
  %or5 = or i8 %1, %0
  %conv3 = zext i8 %or5 to i64
  ret i64 %conv3
}

define dso_local i64 @test_or2(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_or2:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r4, 0(r3)
; 64BIT-NEXT:    lbz r5, 1(r3)
; 64BIT-NEXT:    lbz r3, 2(r3)
; 64BIT-NEXT:    or r4, r5, r4
; 64BIT-NEXT:    or r3, r4, r3
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_or2:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r5, 0(r4)
; 32BIT-NEXT:    lbz r6, 1(r4)
; 32BIT-NEXT:    lbz r4, 2(r4)
; 32BIT-NEXT:    or r5, r6, r5
; 32BIT-NEXT:    or r4, r5, r4
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i8, ptr %inp, i64 1
  %1 = load i8, ptr %arrayidx1, align 1
  %or9 = or i8 %1, %0
  %arrayidx3 = getelementptr inbounds i8, ptr %inp, i64 2
  %2 = load i8, ptr %arrayidx3, align 1
  %or510 = or i8 %or9, %2
  %conv6 = zext i8 %or510 to i64
  ret i64 %conv6
}

define dso_local i64 @test_and(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_and:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r4, 0(r3)
; 64BIT-NEXT:    lbz r3, 1(r3)
; 64BIT-NEXT:    and r3, r3, r4
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_and:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r5, 0(r4)
; 32BIT-NEXT:    lbz r4, 1(r4)
; 32BIT-NEXT:    and r4, r4, r5
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i8, ptr %inp, i64 1
  %1 = load i8, ptr %arrayidx1, align 1
  %and5 = and i8 %1, %0
  %conv3 = zext i8 %and5 to i64
  ret i64 %conv3
}

define dso_local i64 @test_and2(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_and2:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r4, 0(r3)
; 64BIT-NEXT:    lbz r5, 1(r3)
; 64BIT-NEXT:    lbz r3, 2(r3)
; 64BIT-NEXT:    and r4, r5, r4
; 64BIT-NEXT:    and r3, r4, r3
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_and2:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r5, 0(r4)
; 32BIT-NEXT:    lbz r6, 1(r4)
; 32BIT-NEXT:    lbz r4, 2(r4)
; 32BIT-NEXT:    and r5, r6, r5
; 32BIT-NEXT:    and r4, r5, r4
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i8, ptr %inp, i64 1
  %1 = load i8, ptr %arrayidx1, align 1
  %and9 = and i8 %1, %0
  %arrayidx3 = getelementptr inbounds i8, ptr %inp, i64 2
  %2 = load i8, ptr %arrayidx3, align 1
  %and510 = and i8 %and9, %2
  %conv6 = zext i8 %and510 to i64
  ret i64 %conv6
}

define dso_local i64 @test_mixed(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_mixed:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r4, 0(r3)
; 64BIT-NEXT:    lbz r5, 1(r3)
; 64BIT-NEXT:    lbz r6, 2(r3)
; 64BIT-NEXT:    lbz r3, 3(r3)
; 64BIT-NEXT:    and r4, r5, r4
; 64BIT-NEXT:    xor r4, r4, r6
; 64BIT-NEXT:    or r3, r4, r3
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_mixed:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r5, 0(r4)
; 32BIT-NEXT:    lbz r6, 1(r4)
; 32BIT-NEXT:    lbz r7, 2(r4)
; 32BIT-NEXT:    lbz r4, 3(r4)
; 32BIT-NEXT:    and r5, r6, r5
; 32BIT-NEXT:    xor r5, r5, r7
; 32BIT-NEXT:    or r4, r5, r4
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i8, ptr %inp, i64 1
  %1 = load i8, ptr %arrayidx1, align 1
  %and11 = and i8 %1, %0
  %arrayidx3 = getelementptr inbounds i8, ptr %inp, i64 2
  %2 = load i8, ptr %arrayidx3, align 1
  %xor12 = xor i8 %and11, %2
  %arrayidx5 = getelementptr inbounds i8, ptr %inp, i64 3
  %3 = load i8, ptr %arrayidx5, align 1
  %or13 = or i8 %xor12, %3
  %conv7 = zext i8 %or13 to i64
  ret i64 %conv7
}

define dso_local i64 @test_mixedtype(ptr nocapture noundef readonly %inp, ptr nocapture noundef readonly %inp2) local_unnamed_addr #0 {
; 64BIT-LABEL: test_mixedtype:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r5, 0(r3)
; 64BIT-NEXT:    lhz r6, 2(r4)
; 64BIT-NEXT:    lbz r3, 2(r3)
; 64BIT-NEXT:    lhz r4, 6(r4)
; 64BIT-NEXT:    and r5, r6, r5
; 64BIT-NEXT:    xor r3, r5, r3
; 64BIT-NEXT:    or r3, r3, r4
; 64BIT-NEXT:    clrldi r3, r3, 48
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_mixedtype:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    lbz r5, 0(r3)
; 32BIT-NEXT:    lhz r6, 2(r4)
; 32BIT-NEXT:    lbz r3, 2(r3)
; 32BIT-NEXT:    lhz r4, 6(r4)
; 32BIT-NEXT:    and r5, r6, r5
; 32BIT-NEXT:    xor r3, r5, r3
; 32BIT-NEXT:    or r3, r3, r4
; 32BIT-NEXT:    clrlwi r4, r3, 16
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %arrayidx1 = getelementptr inbounds i16, ptr %inp2, i64 1
  %1 = load i16, ptr %arrayidx1, align 2
  %2 = zext i8 %0 to i16
  %3 = and i16 %1, %2
  %arrayidx3 = getelementptr inbounds i8, ptr %inp, i64 2
  %4 = load i8, ptr %arrayidx3, align 1
  %5 = zext i8 %4 to i16
  %6 = xor i16 %3, %5
  %arrayidx5 = getelementptr inbounds i16, ptr %inp2, i64 3
  %7 = load i16, ptr %arrayidx5, align 2
  %or10 = or i16 %6, %7
  %conv7 = zext i16 %or10 to i64
  ret i64 %conv7
}

define dso_local i64 @test_load(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_load:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lbz r3, 0(r3)
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_load:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lbz r4, 0(r4)
; 32BIT-NEXT:    blr
entry:
  %0 = load i8, ptr %inp, align 1
  %conv = zext i8 %0 to i64
  ret i64 %conv
}

define dso_local i64 @test_and32(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_and32:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lwz r4, 0(r3)
; 64BIT-NEXT:    lwz r3, 4(r3)
; 64BIT-NEXT:    and r3, r3, r4
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_and32:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    mr r4, r3
; 32BIT-NEXT:    li r3, 0
; 32BIT-NEXT:    lwz r5, 0(r4)
; 32BIT-NEXT:    lwz r4, 4(r4)
; 32BIT-NEXT:    and r4, r4, r5
; 32BIT-NEXT:    blr
entry:
  %0 = load i32, ptr %inp, align 4
  %arrayidx1 = getelementptr inbounds i32, ptr %inp, i64 1
  %1 = load i32, ptr %arrayidx1, align 4
  %and = and i32 %1, %0
  %conv = zext i32 %and to i64
  ret i64 %conv
}

define dso_local zeroext i8 @test_needsclear(ptr nocapture noundef readonly %inp) local_unnamed_addr #0 {
; 64BIT-LABEL: test_needsclear:
; 64BIT:       # %bb.0: # %entry
; 64BIT-NEXT:    lwz r4, 0(r3)
; 64BIT-NEXT:    lwz r3, 4(r3)
; 64BIT-NEXT:    and r3, r3, r4
; 64BIT-NEXT:    clrldi r3, r3, 56
; 64BIT-NEXT:    blr
;
; 32BIT-LABEL: test_needsclear:
; 32BIT:       # %bb.0: # %entry
; 32BIT-NEXT:    lbz r4, 3(r3)
; 32BIT-NEXT:    lbz r3, 7(r3)
; 32BIT-NEXT:    and r3, r3, r4
; 32BIT-NEXT:    blr
entry:
  %0 = load i32, ptr %inp, align 4
  %arrayidx1 = getelementptr inbounds i32, ptr %inp, i64 1
  %1 = load i32, ptr %arrayidx1, align 4
  %and = and i32 %1, %0
  %conv = trunc i32 %and to i8
  ret i8 %conv
}

attributes #0 = {  nounwind  }
