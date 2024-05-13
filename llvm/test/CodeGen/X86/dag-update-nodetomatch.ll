; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown-linux-gnu | FileCheck %s

%struct.i = type { i32, i24 }
%struct.m = type { %struct.i }

@a = local_unnamed_addr global i32 0, align 4
@b = local_unnamed_addr global i16 0, align 2
@c = local_unnamed_addr global i16 0, align 2
@e = local_unnamed_addr global i16 0, align 2
@l = local_unnamed_addr global %struct.i zeroinitializer, align 4
@k = local_unnamed_addr global %struct.m zeroinitializer, align 4

@x0 = local_unnamed_addr global double 0.000000e+00, align 8
@x1 = local_unnamed_addr global i32 0, align 4
@x2 = local_unnamed_addr global i32 0, align 4
@x3 = local_unnamed_addr global i32 0, align 4
@x4 = local_unnamed_addr global i32 0, align 4
@x5 = local_unnamed_addr global ptr null, align 8

; Check that compiler does not crash.
; Test for PR30775
define void @_Z1nv() local_unnamed_addr {
; CHECK-LABEL: _Z1nv:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    movq k@GOTPCREL(%rip), %rax
; CHECK-NEXT:    movl 4(%rax), %edx
; CHECK-NEXT:    movq c@GOTPCREL(%rip), %rax
; CHECK-NEXT:    movswl (%rax), %ecx
; CHECK-NEXT:    movq b@GOTPCREL(%rip), %rax
; CHECK-NEXT:    movswl (%rax), %edi
; CHECK-NEXT:    movq a@GOTPCREL(%rip), %rsi
; CHECK-NEXT:    movl (%rsi), %esi
; CHECK-NEXT:    movq l@GOTPCREL(%rip), %r8
; CHECK-NEXT:    movl (%r8), %r8d
; CHECK-NEXT:    movl %r8d, %r9d
; CHECK-NEXT:    shll $7, %r9d
; CHECK-NEXT:    sarl $7, %r9d
; CHECK-NEXT:    negl %r9d
; CHECK-NEXT:    testl %esi, %esi
; CHECK-NEXT:    cmovel %esi, %r9d
; CHECK-NEXT:    movzwl %dx, %r10d
; CHECK-NEXT:    leal (%rcx,%r10,2), %ecx
; CHECK-NEXT:    addl %edi, %ecx
; CHECK-NEXT:    cmpl %r9d, %ecx
; CHECK-NEXT:    sete %dil
; CHECK-NEXT:    testl $33554431, %r8d # imm = 0x1FFFFFF
; CHECK-NEXT:    sete %r8b
; CHECK-NEXT:    orb %dil, %r8b
; CHECK-NEXT:    movzbl %r8b, %edi
; CHECK-NEXT:    movq e@GOTPCREL(%rip), %r8
; CHECK-NEXT:    movw %di, (%r8)
; CHECK-NEXT:    notl %ecx
; CHECK-NEXT:    shrl $31, %ecx
; CHECK-NEXT:    addl %edx, %ecx
; CHECK-NEXT:    # kill: def $cl killed $cl killed $ecx
; CHECK-NEXT:    sarl %cl, %esi
; CHECK-NEXT:    movw %si, (%rax)
; CHECK-NEXT:    retq
entry:
  %bf.load = load i32, ptr getelementptr inbounds (%struct.m, ptr @k, i64 0, i32 0, i32 1), align 4
  %0 = load i16, ptr @c, align 2
  %conv = sext i16 %0 to i32
  %1 = load i16, ptr @b, align 2
  %conv1 = sext i16 %1 to i32
  %2 = load i32, ptr @a, align 4
  %tobool = icmp ne i32 %2, 0
  %bf.load3 = load i32, ptr @l, align 4
  %bf.shl = shl i32 %bf.load3, 7
  %bf.ashr = ashr exact i32 %bf.shl, 7
  %bf.clear = shl i32 %bf.load, 1
  %factor = and i32 %bf.clear, 131070
  %add13 = add nsw i32 %factor, %conv
  %add15 = add nsw i32 %add13, %conv1
  %bf.ashr.op = sub nsw i32 0, %bf.ashr
  %add28 = select i1 %tobool, i32 %bf.ashr.op, i32 0
  %tobool29 = icmp eq i32 %add15, %add28
  %phitmp = icmp eq i32 %bf.ashr, 0
  %.phitmp = or i1 %phitmp, %tobool29
  %conv37 = zext i1 %.phitmp to i16
  store i16 %conv37, ptr @e, align 2
  %bf.clear39 = and i32 %bf.load, 65535
  %factor53 = shl nuw nsw i32 %bf.clear39, 1
  %add46 = add nsw i32 %factor53, %conv
  %add48 = add nsw i32 %add46, %conv1
  %add48.lobit = lshr i32 %add48, 31
  %add48.lobit.not = xor i32 %add48.lobit, 1
  %add51 = add nuw nsw i32 %add48.lobit.not, %bf.clear39
  %shr = ashr i32 %2, %add51
  %conv52 = trunc i32 %shr to i16
  store i16 %conv52, ptr @b, align 2
  ret void
}

; Test for PR31536
define void @_Z2x6v() local_unnamed_addr {
; CHECK-LABEL: _Z2x6v:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    pushq %rbp
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    pushq %r15
; CHECK-NEXT:    .cfi_def_cfa_offset 24
; CHECK-NEXT:    pushq %r14
; CHECK-NEXT:    .cfi_def_cfa_offset 32
; CHECK-NEXT:    pushq %r13
; CHECK-NEXT:    .cfi_def_cfa_offset 40
; CHECK-NEXT:    pushq %r12
; CHECK-NEXT:    .cfi_def_cfa_offset 48
; CHECK-NEXT:    pushq %rbx
; CHECK-NEXT:    .cfi_def_cfa_offset 56
; CHECK-NEXT:    .cfi_offset %rbx, -56
; CHECK-NEXT:    .cfi_offset %r12, -48
; CHECK-NEXT:    .cfi_offset %r13, -40
; CHECK-NEXT:    .cfi_offset %r14, -32
; CHECK-NEXT:    .cfi_offset %r15, -24
; CHECK-NEXT:    .cfi_offset %rbp, -16
; CHECK-NEXT:    movq x1@GOTPCREL(%rip), %rax
; CHECK-NEXT:    movl (%rax), %esi
; CHECK-NEXT:    andl $511, %esi # imm = 0x1FF
; CHECK-NEXT:    leaq 1(%rsi), %rax
; CHECK-NEXT:    movq x4@GOTPCREL(%rip), %rcx
; CHECK-NEXT:    movl %eax, (%rcx)
; CHECK-NEXT:    movq x3@GOTPCREL(%rip), %rcx
; CHECK-NEXT:    movl (%rcx), %edx
; CHECK-NEXT:    testl %edx, %edx
; CHECK-NEXT:    je .LBB1_18
; CHECK-NEXT:  # %bb.1: # %for.cond1thread-pre-split.lr.ph
; CHECK-NEXT:    movq x5@GOTPCREL(%rip), %rcx
; CHECK-NEXT:    movq (%rcx), %rdi
; CHECK-NEXT:    movl %edx, %ecx
; CHECK-NEXT:    notl %ecx
; CHECK-NEXT:    leaq 8(,%rcx,8), %rcx
; CHECK-NEXT:    imulq %rax, %rcx
; CHECK-NEXT:    addq %rdi, %rcx
; CHECK-NEXT:    movq %rcx, {{[-0-9]+}}(%r{{[sb]}}p) # 8-byte Spill
; CHECK-NEXT:    movq x2@GOTPCREL(%rip), %r9
; CHECK-NEXT:    movl (%r9), %ecx
; CHECK-NEXT:    leal 8(,%rsi,8), %r8d
; CHECK-NEXT:    movq %r8, {{[-0-9]+}}(%r{{[sb]}}p) # 8-byte Spill
; CHECK-NEXT:    leaq 8(%rdi), %r8
; CHECK-NEXT:    movq %r8, {{[-0-9]+}}(%r{{[sb]}}p) # 8-byte Spill
; CHECK-NEXT:    leaq 32(%rdi), %rbx
; CHECK-NEXT:    leaq 8(,%rsi,8), %r14
; CHECK-NEXT:    xorl %r15d, %r15d
; CHECK-NEXT:    movq x0@GOTPCREL(%rip), %r12
; CHECK-NEXT:    movq %rdi, %r13
; CHECK-NEXT:    jmp .LBB1_2
; CHECK-NEXT:    .p2align 4, 0x90
; CHECK-NEXT:  .LBB1_15: # %for.cond1.for.inc3_crit_edge
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    movl %ecx, (%r9)
; CHECK-NEXT:  .LBB1_16: # %for.inc3
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    incq %r15
; CHECK-NEXT:    addq %r14, %rbx
; CHECK-NEXT:    incl %edx
; CHECK-NEXT:    leaq (%r13,%rax,8), %r13
; CHECK-NEXT:    je .LBB1_17
; CHECK-NEXT:  .LBB1_2: # %for.cond1thread-pre-split
; CHECK-NEXT:    # =>This Loop Header: Depth=1
; CHECK-NEXT:    # Child Loop BB1_12 Depth 2
; CHECK-NEXT:    # Child Loop BB1_14 Depth 2
; CHECK-NEXT:    testl %ecx, %ecx
; CHECK-NEXT:    jns .LBB1_16
; CHECK-NEXT:  # %bb.3: # %for.body2.preheader
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    movslq %ecx, %rbp
; CHECK-NEXT:    testq %rbp, %rbp
; CHECK-NEXT:    movq $-1, %rsi
; CHECK-NEXT:    cmovnsq %rbp, %rsi
; CHECK-NEXT:    subq %rbp, %rsi
; CHECK-NEXT:    incq %rsi
; CHECK-NEXT:    cmpq $4, %rsi
; CHECK-NEXT:    jb .LBB1_14
; CHECK-NEXT:  # %bb.4: # %min.iters.checked
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    movq %rsi, %rcx
; CHECK-NEXT:    andq $-4, %rcx
; CHECK-NEXT:    je .LBB1_14
; CHECK-NEXT:  # %bb.5: # %vector.memcheck
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    movq {{[-0-9]+}}(%r{{[sb]}}p), %r10 # 8-byte Reload
; CHECK-NEXT:    imulq %r15, %r10
; CHECK-NEXT:    leaq (%rdi,%r10), %r11
; CHECK-NEXT:    leaq (%r11,%rbp,8), %r8
; CHECK-NEXT:    testq %rbp, %rbp
; CHECK-NEXT:    movq $-1, %r11
; CHECK-NEXT:    cmovnsq %rbp, %r11
; CHECK-NEXT:    cmpq %r12, %r8
; CHECK-NEXT:    jae .LBB1_7
; CHECK-NEXT:  # %bb.6: # %vector.memcheck
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    addq {{[-0-9]+}}(%r{{[sb]}}p), %r10 # 8-byte Folded Reload
; CHECK-NEXT:    leaq (%r10,%r11,8), %r8
; CHECK-NEXT:    cmpq %r12, %r8
; CHECK-NEXT:    ja .LBB1_14
; CHECK-NEXT:  .LBB1_7: # %vector.body.preheader
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    leaq -4(%rcx), %r8
; CHECK-NEXT:    movq %r8, %r11
; CHECK-NEXT:    shrq $2, %r11
; CHECK-NEXT:    btl $2, %r8d
; CHECK-NEXT:    jb .LBB1_8
; CHECK-NEXT:  # %bb.9: # %vector.body.prol.preheader
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    movq {{.*#+}} xmm0 = mem[0],zero
; CHECK-NEXT:    pshufd {{.*#+}} xmm0 = xmm0[0,1,0,1]
; CHECK-NEXT:    movdqu %xmm0, (%r13,%rbp,8)
; CHECK-NEXT:    movdqu %xmm0, 16(%r13,%rbp,8)
; CHECK-NEXT:    movl $4, %r10d
; CHECK-NEXT:    testq %r11, %r11
; CHECK-NEXT:    jne .LBB1_11
; CHECK-NEXT:    jmp .LBB1_13
; CHECK-NEXT:  .LBB1_8: # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    xorl %r10d, %r10d
; CHECK-NEXT:    testq %r11, %r11
; CHECK-NEXT:    je .LBB1_13
; CHECK-NEXT:  .LBB1_11: # %vector.body.preheader.new
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    movq {{.*#+}} xmm0 = mem[0],zero
; CHECK-NEXT:    pshufd {{.*#+}} xmm0 = xmm0[0,1,0,1]
; CHECK-NEXT:    movq %r10, %r11
; CHECK-NEXT:    subq %rcx, %r11
; CHECK-NEXT:    addq %rbp, %r10
; CHECK-NEXT:    leaq (%rbx,%r10,8), %r10
; CHECK-NEXT:    .p2align 4, 0x90
; CHECK-NEXT:  .LBB1_12: # %vector.body
; CHECK-NEXT:    # Parent Loop BB1_2 Depth=1
; CHECK-NEXT:    # => This Inner Loop Header: Depth=2
; CHECK-NEXT:    movdqu %xmm0, -32(%r10)
; CHECK-NEXT:    movdqu %xmm0, -16(%r10)
; CHECK-NEXT:    movdqu %xmm0, (%r10)
; CHECK-NEXT:    movdqu %xmm0, 16(%r10)
; CHECK-NEXT:    addq $64, %r10
; CHECK-NEXT:    addq $8, %r11
; CHECK-NEXT:    jne .LBB1_12
; CHECK-NEXT:  .LBB1_13: # %middle.block
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    addq %rcx, %rbp
; CHECK-NEXT:    cmpq %rcx, %rsi
; CHECK-NEXT:    movq %rbp, %rcx
; CHECK-NEXT:    je .LBB1_15
; CHECK-NEXT:    .p2align 4, 0x90
; CHECK-NEXT:  .LBB1_14: # %for.body2
; CHECK-NEXT:    # Parent Loop BB1_2 Depth=1
; CHECK-NEXT:    # => This Inner Loop Header: Depth=2
; CHECK-NEXT:    movq (%r12), %rcx
; CHECK-NEXT:    movq %rcx, (%r13,%rbp,8)
; CHECK-NEXT:    leaq 1(%rbp), %rcx
; CHECK-NEXT:    cmpq $-1, %rbp
; CHECK-NEXT:    movq %rcx, %rbp
; CHECK-NEXT:    jl .LBB1_14
; CHECK-NEXT:    jmp .LBB1_15
; CHECK-NEXT:  .LBB1_17: # %for.cond.for.end5_crit_edge
; CHECK-NEXT:    movq x5@GOTPCREL(%rip), %rax
; CHECK-NEXT:    movq {{[-0-9]+}}(%r{{[sb]}}p), %rcx # 8-byte Reload
; CHECK-NEXT:    movq %rcx, (%rax)
; CHECK-NEXT:    movq x3@GOTPCREL(%rip), %rax
; CHECK-NEXT:    movl $0, (%rax)
; CHECK-NEXT:  .LBB1_18: # %for.end5
; CHECK-NEXT:    popq %rbx
; CHECK-NEXT:    .cfi_def_cfa_offset 48
; CHECK-NEXT:    popq %r12
; CHECK-NEXT:    .cfi_def_cfa_offset 40
; CHECK-NEXT:    popq %r13
; CHECK-NEXT:    .cfi_def_cfa_offset 32
; CHECK-NEXT:    popq %r14
; CHECK-NEXT:    .cfi_def_cfa_offset 24
; CHECK-NEXT:    popq %r15
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    popq %rbp
; CHECK-NEXT:    .cfi_def_cfa_offset 8
; CHECK-NEXT:    retq
entry:
  %0 = load i32, ptr @x1, align 4
  %and = and i32 %0, 511
  %add = add nuw nsw i32 %and, 1
  store i32 %add, ptr @x4, align 4
  %.pr = load i32, ptr @x3, align 4
  %tobool8 = icmp eq i32 %.pr, 0
  br i1 %tobool8, label %for.end5, label %for.cond1thread-pre-split.lr.ph

for.cond1thread-pre-split.lr.ph:                  ; preds = %entry
  %idx.ext13 = zext i32 %add to i64
  %x5.promoted = load ptr, ptr @x5, align 8
  %1 = xor i32 %.pr, -1
  %2 = zext i32 %1 to i64
  %3 = shl nuw nsw i64 %2, 3
  %4 = add nuw nsw i64 %3, 8
  %5 = mul nuw nsw i64 %4, %idx.ext13
  %uglygep = getelementptr i8, ptr %x5.promoted, i64 %5
  %.pr6.pre = load i32, ptr @x2, align 4
  %6 = shl nuw nsw i32 %and, 3
  %addconv = add nuw nsw i32 %6, 8
  %7 = zext i32 %addconv to i64
  %scevgep15 = getelementptr double, ptr %x5.promoted, i64 1
  br label %for.cond1thread-pre-split

for.cond1thread-pre-split:                        ; preds = %for.cond1thread-pre-split.lr.ph, %for.inc3
  %indvar = phi i64 [ 0, %for.cond1thread-pre-split.lr.ph ], [ %indvar.next, %for.inc3 ]
  %.pr6 = phi i32 [ %.pr6.pre, %for.cond1thread-pre-split.lr.ph ], [ %.pr611, %for.inc3 ]
  %8 = phi ptr [ %x5.promoted, %for.cond1thread-pre-split.lr.ph ], [ %add.ptr, %for.inc3 ]
  %9 = phi i32 [ %.pr, %for.cond1thread-pre-split.lr.ph ], [ %inc4, %for.inc3 ]
  %10 = mul i64 %7, %indvar
  %uglygep14 = getelementptr i8, ptr %x5.promoted, i64 %10
  %uglygep17 = getelementptr i8, ptr %scevgep15, i64 %10
  %cmp7 = icmp slt i32 %.pr6, 0
  br i1 %cmp7, label %for.body2.preheader, label %for.inc3

for.body2.preheader:                              ; preds = %for.cond1thread-pre-split
  %11 = sext i32 %.pr6 to i64
  %12 = sext i32 %.pr6 to i64
  %13 = icmp sgt i64 %12, -1
  %smax = select i1 %13, i64 %12, i64 -1
  %14 = add nsw i64 %smax, 1
  %15 = sub nsw i64 %14, %12
  %min.iters.check = icmp ult i64 %15, 4
  br i1 %min.iters.check, label %for.body2.preheader21, label %min.iters.checked

min.iters.checked:                                ; preds = %for.body2.preheader
  %n.vec = and i64 %15, -4
  %cmp.zero = icmp eq i64 %n.vec, 0
  br i1 %cmp.zero, label %for.body2.preheader21, label %vector.memcheck

vector.memcheck:                                  ; preds = %min.iters.checked
  %16 = shl nsw i64 %11, 3
  %scevgep = getelementptr i8, ptr %uglygep14, i64 %16
  %17 = icmp sgt i64 %11, -1
  %smax18 = select i1 %17, i64 %11, i64 -1
  %18 = shl nsw i64 %smax18, 3
  %scevgep19 = getelementptr i8, ptr %uglygep17, i64 %18
  %bound0 = icmp ult ptr %scevgep, @x0
  %bound1 = icmp ugt ptr %scevgep19, @x0
  %memcheck.conflict = and i1 %bound0, %bound1
  %ind.end = add nsw i64 %11, %n.vec
  br i1 %memcheck.conflict, label %for.body2.preheader21, label %vector.body.preheader

vector.body.preheader:                            ; preds = %vector.memcheck
  %19 = add nsw i64 %n.vec, -4
  %20 = lshr exact i64 %19, 2
  %21 = and i64 %20, 1
  %lcmp.mod = icmp eq i64 %21, 0
  br i1 %lcmp.mod, label %vector.body.prol.preheader, label %vector.body.prol.loopexit.unr-lcssa

vector.body.prol.preheader:                       ; preds = %vector.body.preheader
  br label %vector.body.prol

vector.body.prol:                                 ; preds = %vector.body.prol.preheader
  %22 = load i64, ptr @x0, align 8
  %23 = insertelement <2 x i64> undef, i64 %22, i32 0
  %24 = shufflevector <2 x i64> %23, <2 x i64> undef, <2 x i32> zeroinitializer
  %25 = insertelement <2 x i64> undef, i64 %22, i32 0
  %26 = shufflevector <2 x i64> %25, <2 x i64> undef, <2 x i32> zeroinitializer
  %27 = getelementptr inbounds double, ptr %8, i64 %11
  store <2 x i64> %24, ptr %27, align 8
  %28 = getelementptr double, ptr %27, i64 2
  store <2 x i64> %26, ptr %28, align 8
  br label %vector.body.prol.loopexit.unr-lcssa

vector.body.prol.loopexit.unr-lcssa:              ; preds = %vector.body.preheader, %vector.body.prol
  %index.unr.ph = phi i64 [ 4, %vector.body.prol ], [ 0, %vector.body.preheader ]
  br label %vector.body.prol.loopexit

vector.body.prol.loopexit:                        ; preds = %vector.body.prol.loopexit.unr-lcssa
  %29 = icmp eq i64 %20, 0
  br i1 %29, label %middle.block, label %vector.body.preheader.new

vector.body.preheader.new:                        ; preds = %vector.body.prol.loopexit
  %30 = load i64, ptr @x0, align 8
  %31 = insertelement <2 x i64> undef, i64 %30, i32 0
  %32 = shufflevector <2 x i64> %31, <2 x i64> undef, <2 x i32> zeroinitializer
  %33 = insertelement <2 x i64> undef, i64 %30, i32 0
  %34 = shufflevector <2 x i64> %33, <2 x i64> undef, <2 x i32> zeroinitializer
  %35 = load i64, ptr @x0, align 8
  %36 = insertelement <2 x i64> undef, i64 %35, i32 0
  %37 = shufflevector <2 x i64> %36, <2 x i64> undef, <2 x i32> zeroinitializer
  %38 = insertelement <2 x i64> undef, i64 %35, i32 0
  %39 = shufflevector <2 x i64> %38, <2 x i64> undef, <2 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.body.preheader.new
  %index = phi i64 [ %index.unr.ph, %vector.body.preheader.new ], [ %index.next.1, %vector.body ]
  %40 = add i64 %11, %index
  %41 = getelementptr inbounds double, ptr %8, i64 %40
  store <2 x i64> %32, ptr %41, align 8
  %42 = getelementptr double, ptr %41, i64 2
  store <2 x i64> %34, ptr %42, align 8
  %index.next = add i64 %index, 4
  %43 = add i64 %11, %index.next
  %44 = getelementptr inbounds double, ptr %8, i64 %43
  store <2 x i64> %37, ptr %44, align 8
  %45 = getelementptr double, ptr %44, i64 2
  store <2 x i64> %39, ptr %45, align 8
  %index.next.1 = add i64 %index, 8
  %46 = icmp eq i64 %index.next.1, %n.vec
  br i1 %46, label %middle.block.unr-lcssa, label %vector.body

middle.block.unr-lcssa:                           ; preds = %vector.body
  br label %middle.block

middle.block:                                     ; preds = %vector.body.prol.loopexit, %middle.block.unr-lcssa
  %cmp.n = icmp eq i64 %15, %n.vec
  br i1 %cmp.n, label %for.cond1.for.inc3_crit_edge, label %for.body2.preheader21

for.body2.preheader21:                            ; preds = %middle.block, %vector.memcheck, %min.iters.checked, %for.body2.preheader
  %indvars.iv.ph = phi i64 [ %11, %vector.memcheck ], [ %11, %min.iters.checked ], [ %11, %for.body2.preheader ], [ %ind.end, %middle.block ]
  br label %for.body2

for.body2:                                        ; preds = %for.body2.preheader21, %for.body2
  %indvars.iv = phi i64 [ %indvars.iv.next, %for.body2 ], [ %indvars.iv.ph, %for.body2.preheader21 ]
  %47 = load i64, ptr @x0, align 8
  %arrayidx = getelementptr inbounds double, ptr %8, i64 %indvars.iv
  store i64 %47, ptr %arrayidx, align 8
  %indvars.iv.next = add nsw i64 %indvars.iv, 1
  %cmp = icmp slt i64 %indvars.iv, -1
  br i1 %cmp, label %for.body2, label %for.cond1.for.inc3_crit_edge.loopexit

for.cond1.for.inc3_crit_edge.loopexit:            ; preds = %for.body2
  br label %for.cond1.for.inc3_crit_edge

for.cond1.for.inc3_crit_edge:                     ; preds = %for.cond1.for.inc3_crit_edge.loopexit, %middle.block
  %indvars.iv.next.lcssa = phi i64 [ %ind.end, %middle.block ], [ %indvars.iv.next, %for.cond1.for.inc3_crit_edge.loopexit ]
  %48 = trunc i64 %indvars.iv.next.lcssa to i32
  store i32 %48, ptr @x2, align 4
  br label %for.inc3

for.inc3:                                         ; preds = %for.cond1.for.inc3_crit_edge, %for.cond1thread-pre-split
  %.pr611 = phi i32 [ %48, %for.cond1.for.inc3_crit_edge ], [ %.pr6, %for.cond1thread-pre-split ]
  %inc4 = add nsw i32 %9, 1
  %add.ptr = getelementptr inbounds double, ptr %8, i64 %idx.ext13
  %tobool = icmp eq i32 %inc4, 0
  %indvar.next = add i64 %indvar, 1
  br i1 %tobool, label %for.cond.for.end5_crit_edge, label %for.cond1thread-pre-split

for.cond.for.end5_crit_edge:                      ; preds = %for.inc3
  store ptr %uglygep, ptr @x5, align 8
  store i32 0, ptr @x3, align 4
  br label %for.end5

for.end5:                                         ; preds = %for.cond.for.end5_crit_edge, %entry
  ret void
}

