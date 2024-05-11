	.text
	.def	@feat.00;
	.scl	3;
	.type	0;
	.endef
	.globl	@feat.00
.set @feat.00, 0
	.section	newworld,"dr"
	.asciz	"New World coming soon"
.Lsec_end0:
	.text
	.file	"Substitution.cpp"
	.def	"?f@@YA?A?<auto>@@XZ";
	.scl	2;
	.type	32;
	.endef
	.section	llvmmsvc,"xr"
	.globl	"?f@@YA?A?<auto>@@XZ"           # -- Begin function ?f@@YA?A?<auto>@@XZ
	.p2align	4, 0x90
"?f@@YA?A?<auto>@@XZ":                  # @"?f@@YA?A?<auto>@@XZ"
.seh_proc "?f@@YA?A?<auto>@@XZ"
	.p2align	0, 0x90
# %bb.0:
	subq	$24, %rsp
	.seh_stackalloc 24
	.seh_endprologue
	movq	%rcx, (%rsp)                    # 8-byte Spill
	movq	%rcx, 8(%rsp)                   # 8-byte Spill
	xorl	%eax, %eax
                                        # kill: def $al killed $al killed $eax
	testb	%al, %al
	jne	.LBB0_2
	jmp	.LBB0_1
	.p2align	0, 0x90
.LBB0_1:
	movq	8(%rsp), %rax                   # 8-byte Reload
	movq	(%rsp), %rcx                    # 8-byte Reload
	movq	%rcx, 16(%rsp)
	movl	$1, (%rcx)
	movl	$2, 4(%rcx)
	movl	$3, 8(%rcx)
	addq	$24, %rsp
	retq
	.p2align	0, 0x90
.LBB0_2:
	movq	8(%rsp), %rax                   # 8-byte Reload
	#APP

	subq	$305419896, %rsp                # imm = 0x12345678

	#NO_APP
	addq	$24, %rsp
	retq
	.seh_endproc
                                        # -- End function
	.def	main;
	.scl	2;
	.type	32;
	.endef
	.globl	main                            # -- Begin function main
	.p2align	4, 0x90
main:                                   # @main
.seh_proc main
	.p2align	0, 0x90
# %bb.0:
	subq	$104, %rsp
	.seh_stackalloc 104
	.seh_endprologue
	movq	%rdx, 40(%rsp)                  # 8-byte Spill
	movl	%ecx, 48(%rsp)                  # 4-byte Spill
	xorl	%eax, %eax
                                        # kill: def $al killed $al killed $eax
	testb	%al, %al
	jne	.LBB1_2
	jmp	.LBB1_1
	.p2align	0, 0x90
.LBB1_1:
	movl	48(%rsp), %eax                  # 4-byte Reload
	movq	40(%rsp), %rcx                  # 8-byte Reload
	movl	$0, 100(%rsp)
	movq	%rcx, 88(%rsp)
	movl	%eax, 84(%rsp)
	movl	$0, 80(%rsp)
	movl	80(%rsp), %edx
	movl	%edx, %eax
	andl	$1, %eax
	xorl	$1, %edx
                                        # implicit-def: $rcx
	movl	%eax, %ecx
                                        # implicit-def: $rax
	movl	%edx, %eax
	leal	(%rax,%rcx,2), %eax
	movl	%eax, 76(%rsp)
	movl	76(%rsp), %eax
	movl	%eax, 68(%rsp)
	movl	80(%rsp), %eax
	movl	%eax, 64(%rsp)
	movl	$0, 72(%rsp)
	leaq	52(%rsp), %rcx
	callq	"?f@@YA?A?<auto>@@XZ"
	movl	68(%rsp), %eax
	addq	$104, %rsp
	retq
	.p2align	0, 0x90
.LBB1_2:
	#APP

	subq	$305419896, %rsp                # imm = 0x12345678

	#NO_APP
	xorl	%eax, %eax
	addq	$104, %rsp
	retq
	.seh_endproc
                                        # -- End function
	.section	.rdata,"dr",discard,llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53
	.globl	llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53 # @llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53
	.p2align	4, 0x0
llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53:
	.ascii	"Welcome to use llvm-msvc."

	.section	.drectve,"yni"
	.ascii	" /INCLUDE:llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53"
