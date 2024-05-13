; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=x86_64-unknown-unknown -mcpu=x86-64 -mattr=sse -enable-unsafe-fp-math < %s | FileCheck %s

; The debug info in this test case was causing a crash because machine trace metrics
; did not correctly ignore debug instructions. The check lines ensure that the
; machine-combiner pass has run, reassociated the add operands, and therefore
; used machine trace metrics.

define void @PR24199(i32 %a0) {
; CHECK-LABEL: PR24199:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    pushq %rbx
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    subq $16, %rsp
; CHECK-NEXT:    .cfi_def_cfa_offset 32
; CHECK-NEXT:    .cfi_offset %rbx, -16
; CHECK-NEXT:    movl %edi, %ebx
; CHECK-NEXT:    xorl %eax, %eax
; CHECK-NEXT:    testb %al, %al
; CHECK-NEXT:    je .LBB0_2
; CHECK-NEXT:  # %bb.1:
; CHECK-NEXT:    movss {{.*#+}} xmm0 = mem[0],zero,zero,zero
; CHECK-NEXT:    jmp .LBB0_3
; CHECK-NEXT:  .LBB0_2: # %if.then
; CHECK-NEXT:    xorps %xmm0, %xmm0
; CHECK-NEXT:  .LBB0_3: # %if.end
; CHECK-NEXT:    movss %xmm0, {{[-0-9]+}}(%r{{[sb]}}p) # 4-byte Spill
; CHECK-NEXT:    callq foo@PLT
; CHECK-NEXT:    movss {{.*#+}} xmm0 = mem[0],zero,zero,zero
; CHECK-NEXT:    movss {{[-0-9]+}}(%r{{[sb]}}p), %xmm2 # 4-byte Reload
; CHECK-NEXT:    # xmm2 = mem[0],zero,zero,zero
; CHECK-NEXT:    mulss %xmm0, %xmm2
; CHECK-NEXT:    movss {{.*#+}} xmm1 = mem[0],zero,zero,zero
; CHECK-NEXT:    addss %xmm1, %xmm0
; CHECK-NEXT:    addss %xmm2, %xmm0
; CHECK-NEXT:    movss %xmm0, (%rax)
; CHECK-NEXT:    testl %ebx, %ebx
; CHECK-NEXT:    jne .LBB0_5
; CHECK-NEXT:  # %bb.4: # %if.end
; CHECK-NEXT:    xorps %xmm1, %xmm1
; CHECK-NEXT:  .LBB0_5: # %if.end
; CHECK-NEXT:    movss {{.*#+}} xmm0 = mem[0],zero,zero,zero
; CHECK-NEXT:    addss %xmm0, %xmm0
; CHECK-NEXT:    addss %xmm1, %xmm0
; CHECK-NEXT:    callq bar@PLT
; CHECK-NEXT:    addq $16, %rsp
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    popq %rbx
; CHECK-NEXT:    .cfi_def_cfa_offset 8
; CHECK-NEXT:    retq

entry:
  %i = alloca %struct.A, align 8
  %tobool = icmp ne i32 %a0, 0
  br i1 undef, label %if.end, label %if.then

if.then:
  br label %if.end

if.end:
  %h = phi float [ 0.0, %if.then ], [ 4.0, %entry ]
  call void @foo(ptr nonnull undef)
  tail call void @llvm.dbg.value(metadata ptr undef, i64 0, metadata !5, metadata !4), !dbg !6
  tail call void @llvm.dbg.value(metadata float %h, i64 0, metadata !5, metadata !4), !dbg !6
  %n0 = load float, ptr undef, align 4
  %mul = fmul fast float %n0, %h
  %add = fadd fast float %mul, 1.0
  tail call void @llvm.dbg.value(metadata ptr undef, i64 0, metadata !5, metadata !4), !dbg !6
  tail call void @llvm.dbg.value(metadata float %add, i64 0, metadata !5, metadata !4), !dbg !6
  %add.i = fadd fast float %add, %n0
  store float %add.i, ptr undef, align 4
  call void @llvm.lifetime.start.p0(i64 16, ptr %i)
  %n2 = load <2 x float>, ptr undef, align 8
  %conv = uitofp i1 %tobool to float
  %bitcast = extractelement <2 x float> %n2, i32 0
  %factor = fmul fast float %bitcast, 2.0
  %add3 = fadd fast float %factor, %conv
  call void @bar(float %add3)
  ret void
}

%struct.A = type { float, float }

declare void @bar(float)
declare void @foo(ptr)
declare void @llvm.lifetime.start.p0(i64, ptr nocapture)
declare void @llvm.dbg.value(metadata, i64, metadata, metadata)

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus, file: !1, isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "24199.cpp", directory: "/bin")
!2 = !{i32 2, !"Debug Info Version", i32 3}
!3 = distinct !DISubprogram(linkageName: "foo", file: !1, line: 18, isLocal: false, isDefinition: true, scopeLine: 18, unit: !0)
!4 = !DIExpression()
!5 = !DILocalVariable(name: "this", arg: 1, scope: !3, flags: DIFlagArtificial | DIFlagObjectPointer)
!6 = !DILocation(line: 0, scope: !3)


