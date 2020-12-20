
/* If user disable the ASM, such as avoiding bugs in ASM, donot compile it. */
#if !defined(MD_ST_NO_ASM)

/* 是否支持 .type .size 伪指令 */
#ifdef LINUX
#define DOT_TYPE_SIZE 1
#endif

/*
 * Portions created by SGI are Copyright (C) 2000 Silicon Graphics, Inc.
 * All Rights Reserved.
 */

#if defined(__ia64__)

    /*
     * The internal __jmp_buf layout is different from one used
     * by setjmp()/longjmp().
     *
     *       Offset   Description
     *       ------   -----------
     *       0x000    stack pointer (r12)
     *       0x008    gp (r1)
     *       0x010    caller's unat
     *       0x018    fpsr
     *       0x020    r4
     *       0x028    r5
     *       0x030    r6
     *       0x038    r7
     *       0x040    rp (b0)
     *       0x048    b1
     *       0x050    b2
     *       0x058    b3
     *       0x060    b4
     *       0x068    b5
     *       0x070    ar.pfs
     *       0x078    ar.lc
     *       0x080    pr
     *       0x088    ar.bsp
     *       0x090    ar.unat
     *       0x098    &__jmp_buf
     *       0x0a0    ar.rsc
     *       0x0a8    ar.rnat
     *       0x0b0     f2
     *       0x0c0     f3
     *       0x0d0     f4
     *       0x0e0     f5
     *       0x0f0    f16
     *       0x100    f17
     *       0x110    f18
     *       0x120    f19
     *       0x130    f20
     *       0x130    f21
     *       0x140    f22
     *       0x150    f23
     *       0x160    f24
     *       0x170    f25
     *       0x180    f26
     *       0x190    f27
     *       0x1a0    f28
     *       0x1b0    f29
     *       0x1c0    f30
     *       0x1d0    f31
     *
     * Note that the address of __jmp_buf is saved but not used: we assume
     * that the jmp_buf data structure is never moved around in memory.
     */

    /*
     * Implemented according to "IA-64 Software Conventions and Runtime
     * Architecture Guide", Chapter 10: "Context Management".
     */

    .text
    .psr abi64
    .psr lsb
    .lsb

    /* _st_md_cxt_save(__jmp_buf env) */
    .align 32
    .global _st_md_cxt_save
    .proc _st_md_cxt_save
    _st_md_cxt_save:
        alloc r14 = ar.pfs,1,0,0,0
        mov r16 = ar.unat
        ;;
        mov r17 = ar.fpsr
        mov r2 = in0
        add r3 = 8,in0
        ;;
        st8.spill.nta [r2] = sp,16    // r12 (sp)
        ;;
        st8.spill.nta [r3] = gp,16    // r1  (gp)
        ;;
        st8.nta [r2] = r16,16         // save caller's unat
        st8.nta [r3] = r17,16         // save fpsr
        add r8 = 0xb0,in0
        ;;   
        st8.spill.nta [r2] = r4,16    // r4
        ;;
        st8.spill.nta [r3] = r5,16    // r5
        add r9 = 0xc0,in0
        ;;
        stf.spill.nta [r8] = f2,32
        stf.spill.nta [r9] = f3,32
        mov r15 = rp
        ;;
        stf.spill.nta [r8] = f4,32
        stf.spill.nta [r9] = f5,32
        mov r17 = b1
        ;;
        stf.spill.nta [r8] = f16,32
        stf.spill.nta [r9] = f17,32
        mov r18 = b2
        ;;
        stf.spill.nta [r8] = f18,32
        stf.spill.nta [r9] = f19,32
        mov r19 = b3
        ;;
        stf.spill.nta [r8] = f20,32
        stf.spill.nta [r9] = f21,32
        mov r20 = b4
        ;;
        stf.spill.nta [r8] = f22,32
        stf.spill.nta [r9] = f23,32
        mov r21 = b5
        ;;
        stf.spill.nta [r8] = f24,32
        stf.spill.nta [r9] = f25,32
        mov r22 = ar.lc
        ;;
        stf.spill.nta [r8] = f26,32
        stf.spill.nta [r9] = f27,32
        mov r24 = pr
        ;;
        stf.spill.nta [r8] = f28,32
        stf.spill.nta [r9] = f29,32
        ;;
        stf.spill.nta [r8] = f30
        stf.spill.nta [r9] = f31

        st8.spill.nta [r2] = r6,16    // r6
        ;;
        st8.spill.nta [r3] = r7,16    // r7
        ;;
        mov r23 = ar.bsp
        mov r25 = ar.unat

        st8.nta [r2] = r15,16         // b0
        st8.nta [r3] = r17,16         // b1
        ;;
        st8.nta [r2] = r18,16         // b2
        st8.nta [r3] = r19,16         // b3
        mov r26 = ar.rsc
        ;;
        st8.nta [r2] = r20,16         // b4
        st8.nta [r3] = r21,16         // b5
        ;;
        st8.nta [r2] = r14,16         // ar.pfs
        st8.nta [r3] = r22,16         // ar.lc
        ;;
        st8.nta [r2] = r24,16         // pr
        st8.nta [r3] = r23,16         // ar.bsp
        ;;
        st8.nta [r2] = r25,16         // ar.unat
        st8.nta [r3] = in0,16         // &__jmp_buf (just in case)
        ;;
        st8.nta [r2] = r26            // ar.rsc
        ;;
        flushrs                       // flush dirty regs to backing store
        ;;
        and r27 = ~0x3,r26            // clear ar.rsc.mode
        ;;
        mov ar.rsc = r27              // put RSE in enforced lazy mode
        ;;
        mov r28 = ar.rnat
        ;;
        st8.nta [r3] = r28            // ar.rnat
        mov ar.rsc = r26              // restore ar.rsc
        ;;
        mov r8 = 0
        br.ret.sptk.few b0
    .endp _st_md_cxt_save


    /****************************************************************/

    /* _st_md_cxt_restore(__jmp_buf env, int val) */
    .global _st_md_cxt_restore
    .proc _st_md_cxt_restore
    _st_md_cxt_restore:
        alloc r8 = ar.pfs,2,0,0,0
        add r2 = 0x88,in0             // r2 <- &jmpbuf.ar_bsp
        mov r16 = ar.rsc
        ;;
        flushrs                       // flush dirty regs to backing store
        ;;
        and r17 = ~0x3,r16            // clear ar.rsc.mode
        ;;
        mov ar.rsc = r17              // put RSE in enforced lazy mode
        ;;
        invala                        // invalidate the ALAT
        ;;
        ld8 r23 = [r2],8              // r23 <- jmpbuf.ar_bsp
        ;;
        mov ar.bspstore = r23         // write BSPSTORE
        ld8 r25 = [r2],24             // r25 <- jmpbuf.ar_unat
        ;;
        ld8 r26 = [r2],-8             // r26 <- jmpbuf.ar_rnat
        ;;
        mov ar.rnat = r26             // write RNAT
        ld8 r27 = [r2]                // r27 <- jmpbuf.ar_rsc
        ;;
        mov ar.rsc = r27              // write RSE control
        mov r2 = in0
        ;;
        mov ar.unat = r25             // write ar.unat
        add r3 = 8,in0
        ;;
        ld8.fill.nta sp = [r2],16     // r12 (sp)
        ld8.fill.nta gp = [r3],16     // r1  (gp)
        ;;
        ld8.nta r16 = [r2],16         // caller's unat
        ld8.nta r17 = [r3],16         // fpsr
        ;;
        ld8.fill.nta r4 = [r2],16     // r4
        ld8.fill.nta r5 = [r3],16     // r5
        ;;
        ld8.fill.nta r6 = [r2],16     // r6
        ld8.fill.nta r7 = [r3],16     // r7
        ;;
        mov ar.unat = r16             // restore caller's unat
        mov ar.fpsr = r17             // restore fpsr
        ;;
        ld8.nta r16 = [r2],16         // b0
        ld8.nta r17 = [r3],16         // b1
        ;;
        ld8.nta r18 = [r2],16         // b2
        ld8.nta r19 = [r3],16         // b3
        ;;
        ld8.nta r20 = [r2],16         // b4
        ld8.nta r21 = [r3],16         // b5
        ;;
        ld8.nta r11 = [r2],16         // ar.pfs
        ld8.nta r22 = [r3],72         // ar.lc
        ;;
        ld8.nta r24 = [r2],48         // pr
        mov b0 = r16
        ;;
        ldf.fill.nta f2 = [r2],32
        ldf.fill.nta f3 = [r3],32
        mov b1 = r17
        ;;
        ldf.fill.nta f4 = [r2],32
        ldf.fill.nta f5 = [r3],32
        mov b2 = r18
        ;;
        ldf.fill.nta f16 = [r2],32
        ldf.fill.nta f17 = [r3],32
        mov b3 = r19
        ;;
        ldf.fill.nta f18 = [r2],32
        ldf.fill.nta f19 = [r3],32
        mov b4 = r20
        ;;
        ldf.fill.nta f20 = [r2],32
        ldf.fill.nta f21 = [r3],32
        mov b5 = r21
        ;;
        ldf.fill.nta f22 = [r2],32
        ldf.fill.nta f23 = [r3],32
        mov ar.lc = r22
        ;;
        ldf.fill.nta f24 = [r2],32
        ldf.fill.nta f25 = [r3],32
        cmp.eq p6,p7 = 0,in1
        ;;
        ldf.fill.nta f26 = [r2],32
        ldf.fill.nta f27 = [r3],32
        mov ar.pfs = r11
        ;;
        ldf.fill.nta f28 = [r2],32
        ldf.fill.nta f29 = [r3],32
        ;;
        ldf.fill.nta f30 = [r2]
        ldf.fill.nta f31 = [r3]
        (p6)    mov r8 = 1
        (p7)    mov r8 = in1

        mov pr = r24,-1
        br.ret.sptk.few b0
    .endp _st_md_cxt_restore

    /****************************************************************/









#elif defined(__i386__)
/* __jmp_buf layout: 按平台 setjmp.h 定义
 * #define MD_GET_SP            *((void**)jmp_buf + JB_SP)
 */
#ifdef _WIN32
/* #define _JBLEN  16
 * typedef int jmp_buf[_JBLEN];
 * uint32_t  Ebp, Ebx, Edi, Esi, Esp, Eip,
 * uint32_t Registration, TryLevel, Cookie
 * uint32_t UnwindFunc, UnwindData[6]
 */
    #define JB_BP  0
    #define JB_BX  1
    #define JB_DI  2
    #define JB_SI  3
    #define JB_SP  4
    #define JB_IP  5

#define _st_md_cxt_save __st_md_cxt_save
#define _st_md_cxt_restore __st_md_cxt_restore

#else /* TODO others */
    #define JB_BX  0
    #define JB_SI  1
    #define JB_DI  2
    #define JB_BP  3
    #define JB_SP  4
    #define JB_IP  5
#endif

    .file "md.S"
    .text

    /* _st_md_cxt_save(__jmp_buf env) */
    .globl _st_md_cxt_save
#ifdef DOT_TYPE_SIZE
    .type _st_md_cxt_save, @function
#endif
    .align 16
    _st_md_cxt_save:
    movl 4(%esp), %eax
    /* Save registers.  */
    movl %ebx, (JB_BX*4)(%eax)
    movl %esi, (JB_SI*4)(%eax)
    movl %edi, (JB_DI*4)(%eax)
    /* Save SP */
    leal 4(%esp), %ecx
    movl %ecx, (JB_SP*4)(%eax)
    /* Save PC we are returning to */
    movl 0(%esp), %ecx
    movl %ecx, (JB_IP*4)(%eax)
    /* Save caller frame pointer */
    movl %ebp, (JB_BP*4)(%eax)
    xorl %eax, %eax
    ret
#ifdef DOT_TYPE_SIZE
    .size _st_md_cxt_save, .-_st_md_cxt_save
#endif

    /****************************************************************/
    /* _st_md_cxt_restore(__jmp_buf env, int val) */
    .globl _st_md_cxt_restore
#ifdef DOT_TYPE_SIZE
    .type _st_md_cxt_restore, @function
#endif
    .align 16
    _st_md_cxt_restore:
    /* First argument is jmp_buf */
    movl 4(%esp), %ecx
    /* Second argument is return value */
    movl 8(%esp), %eax
    /* Set the return address */
    movl (JB_IP*4)(%ecx), %edx
    /*
     * Restore registers.
     */
    movl (JB_BX*4)(%ecx), %ebx
    movl (JB_SI*4)(%ecx), %esi
    movl (JB_DI*4)(%ecx), %edi
    movl (JB_BP*4)(%ecx), %ebp
    movl (JB_SP*4)(%ecx), %esp
    testl %eax, %eax
    jnz  1f
    incl %eax
    /* Jump to saved PC */
    1: jmp *%edx
#ifdef DOT_TYPE_SIZE
    .size _st_md_cxt_restore, .-_st_md_cxt_restore
#endif
    /****************************************************************/






#elif defined(__amd64__) || defined(__x86_64__)
/* 传参寄存器
 * WIN64: rcx，rdx，r8,r9
 *  UNIX: rdi，rsi，rdx，rcx，r8，r9
 */
#ifdef _WIN64
#define JB_ENV  %rcx
#else
#define JB_ENV  %rdi
#endif


/* __jmp_buf layout: 按平台 setjmp.h 定义
 * #define MD_GET_SP            *((void**)jmp_buf + JB_RSP)
 */
#if defined(DARWIN)
/* #define _JBLEN ((9 * 2) + 3 + 16)
 * typedef int jmp_buf[_JBLEN];
 * uint64_t  rflags, rip, rbp, rsp, rbx, r12, r13, r14, r15...
 * uint32_t  mxcsr, fp control word, sigmask... 
 * add 16 uint32_t for future expansion needs...
 */
    #define JB_RIP  1
    #define JB_RBP  2
    #define JB_RSP  3
    #define JB_RBX  4
    #define JB_R12  5
    #define JB_R13  6
    #define JB_R14  7
    #define JB_R15  8

#define _st_md_cxt_save __st_md_cxt_save
#define _st_md_cxt_restore __st_md_cxt_restore

#elif defined(_WIN64)
/* #define _JBLEN (11*8+4+2*2)/16 + 10)
 * typedef { unsigned __int64 Part[2]; } _JBTYPE;
 * typedef _JBTYPE jmp_buf[_JBLEN];
 * uint64_t  Frame, Rbx, Rsp, Rbp, Rsi, Rdi, R12, R13, R14, R15, Rip
 * uint32_t MxCsr
 * uint16_t FpCsr, Spare;
 * uint128_t Xmm6, Xmm7,....Xmm15
 */
    #define JB_RBX  1  
    #define JB_RSP  2
    #define JB_RBP  3
    #define JB_RSI  4
    #define JB_RDI  5
    #define JB_R12  6
    #define JB_R13  7
    #define JB_R14  8
    #define JB_R15  9
    #define JB_RIP  10

#else /* TODO others */
    #define JB_RBX  0
    #define JB_RBP  1
    #define JB_R12  2
    #define JB_R13  3
    #define JB_R14  4
    #define JB_R15  5
    #define JB_RSP  6
    #define JB_RIP  7
#endif

    .file "md.S"
    .text

    /* _st_md_cxt_save(__jmp_buf env) */
    .globl _st_md_cxt_save
#ifdef DOT_TYPE_SIZE
    .type _st_md_cxt_save,@function
#endif
    .align 16
    _st_md_cxt_save:
    /* Save registers.  */
    movq %rbx, (JB_RBX*8)(JB_ENV)
    movq %rbp, (JB_RBP*8)(JB_ENV)
    movq %r12, (JB_R12*8)(JB_ENV)
    movq %r13, (JB_R13*8)(JB_ENV)
    movq %r14, (JB_R14*8)(JB_ENV)
    movq %r15, (JB_R15*8)(JB_ENV)
#ifdef _WIN64
    movq %rsi, (JB_RSI*8)(JB_ENV)
    movq %rdi, (JB_RDI*8)(JB_ENV)
#endif
    /* Save SP */
    leaq 8(%rsp), %rdx
    movq %rdx, (JB_RSP*8)(JB_ENV)
    /* Save PC we are returning to */
    movq (%rsp), %rax
    movq %rax, (JB_RIP*8)(JB_ENV)
    xorq %rax, %rax
    ret
#ifdef DOT_TYPE_SIZE
    .size _st_md_cxt_save, .-_st_md_cxt_save
#endif

    /****************************************************************/
    /* _st_md_cxt_restore(__jmp_buf env, int val) */
    .globl _st_md_cxt_restore
#ifdef DOT_TYPE_SIZE
    .type _st_md_cxt_restore, @function
#endif
    .align 16
    _st_md_cxt_restore:
    /* Restore registers.  */
    movq (JB_RBX*8)(JB_ENV), %rbx
    movq (JB_RBP*8)(JB_ENV), %rbp
    movq (JB_R12*8)(JB_ENV), %r12
    movq (JB_R13*8)(JB_ENV), %r13
    movq (JB_R14*8)(JB_ENV), %r14
    movq (JB_R15*8)(JB_ENV), %r15
#ifdef _WIN64
    movq (JB_RSI*8)(JB_ENV), %rsi
    movq (JB_RDI*8)(JB_ENV), %rdi
#endif
    /* Set return value */
    test %esi, %esi
    mov $01, %eax
    cmove %eax, %esi
    mov %esi, %eax
    movq (JB_RIP*8)(JB_ENV), %rdx
    movq (JB_RSP*8)(JB_ENV), %rsp
    /* Jump to saved PC */
    jmpq *%rdx
#ifdef DOT_TYPE_SIZE
    .size _st_md_cxt_restore, .-_st_md_cxt_restore
#endif
    /****************************************************************/







#elif defined(__aarch64__)

    /****************************************************************/
    /* https://github.com/ossrs/srs/issues/1282#issuecomment-445539513 */

    #define JB_X19            0
    #define JB_X20            1
    #define JB_X21            2
    #define JB_X22            3
    #define JB_X23            4
    #define JB_X24            5
    #define JB_X25            6
    #define JB_X26            7
    #define JB_X27            8
    #define JB_X28            9
    #define JB_X29           10
    #define JB_LR            11
    #define JB_SP		 13

    #define JB_D8		 14
    #define JB_D9		 15
    #define JB_D10		 16
    #define JB_D11		 17
    #define JB_D12		 18
    #define JB_D13		 19
    #define JB_D14		 20
    #define JB_D15		 21

    	.file "md.S"
    	.text

    	/* _st_md_cxt_save(__jmp_buf env) */
    	.globl _st_md_cxt_save
    	.type _st_md_cxt_save, %function
    	.align 4
    _st_md_cxt_save:
    	stp	x19, x20, [x0, #JB_X19<<3]
    	stp	x21, x22, [x0, #JB_X21<<3]
    	stp	x23, x24, [x0, #JB_X23<<3]
    	stp	x25, x26, [x0, #JB_X25<<3]
    	stp	x27, x28, [x0, #JB_X27<<3]
    	stp	x29, x30, [x0, #JB_X29<<3]

    	stp	 d8,  d9, [x0, #JB_D8<<3]
    	stp	d10, d11, [x0, #JB_D10<<3]
    	stp	d12, d13, [x0, #JB_D12<<3]
    	stp	d14, d15, [x0, #JB_D14<<3]
    	mov	x2,  sp
    	str	x2,  [x0, #JB_SP<<3]

    	mov	x0, #0
    	ret
    	.size _st_md_cxt_save, .-_st_md_cxt_save

    /****************************************************************/

    	/* _st_md_cxt_restore(__jmp_buf env, int val) */
    	.globl _st_md_cxt_restore
    	.type _st_md_cxt_restore, %function
    	.align 4
    _st_md_cxt_restore:
    	ldp	x19, x20, [x0, #JB_X19<<3]
    	ldp	x21, x22, [x0, #JB_X21<<3]
    	ldp	x23, x24, [x0, #JB_X23<<3]
    	ldp	x25, x26, [x0, #JB_X25<<3]
    	ldp	x27, x28, [x0, #JB_X27<<3]

    	ldp	x29, x30, [x0, #JB_X29<<3]

    	ldp	 d8,  d9, [x0, #JB_D8<<3]
    	ldp	d10, d11, [x0, #JB_D10<<3]
    	ldp	d12, d13, [x0, #JB_D12<<3]
    	ldp	d14, d15, [x0, #JB_D14<<3]

    	ldr	x5, [x0, #JB_SP<<3]
    	mov	sp, x5

    	cmp	x1, #0
    	mov	x0, #1
    	csel	x0, x1, x0, ne
    	/* Use br instead of ret because ret is guaranteed to mispredict */
    	br	x30
    	.size _st_md_cxt_restore, .-_st_md_cxt_restore

    /****************************************************************/










#elif defined(__arm__)

    /****************************************************************/
    /* https://github.com/ossrs/srs/issues/1282#issuecomment-445539513 */

    /* Register list for a ldm/stm instruction to load/store
       the general registers from a __jmp_buf.  */
    # define JMP_BUF_REGLIST	{v1-v6, sl, fp, sp, lr}

    	.file "md.S"
    	.text

    	/* _st_md_cxt_save(__jmp_buf env) */
    	.globl _st_md_cxt_save
    	.type _st_md_cxt_save, %function
    	.align 2
    _st_md_cxt_save:
    	mov	ip, r0

    	/* Save registers */
    	stmia	ip!, JMP_BUF_REGLIST

    #ifdef __VFP_FP__
    	/* Store the VFP registers.  */
    	/* Following instruction is vstmia ip!, {d8-d15}.  */
    	stc	p11, cr8, [ip], #64
    #endif

    #ifdef __IWMMXT__
    	/* Save the call-preserved iWMMXt registers.  */
    	/* Following instructions are wstrd wr10, [ip], #8 (etc.)  */
    	stcl	p1, cr10, [r12], #8
    	stcl	p1, cr11, [r12], #8
    	stcl	p1, cr12, [r12], #8
    	stcl	p1, cr13, [r12], #8
    	stcl	p1, cr14, [r12], #8
    	stcl	p1, cr15, [r12], #8
    #endif

    	mov	r0, #0
    	bx	lr

    	.size _st_md_cxt_save, .-_st_md_cxt_save

    /****************************************************************/

    	/* _st_md_cxt_restore(__jmp_buf env, int val) */
    	.globl _st_md_cxt_restore
    	.type _st_md_cxt_restore, %function
    	.align 2
    _st_md_cxt_restore:
    	mov	ip, r0

    	/* Restore registers */
    	ldmia	ip!, JMP_BUF_REGLIST

    #ifdef __VFP_FP__
    	/* Restore the VFP registers.  */
    	/* Following instruction is vldmia ip!, {d8-d15}.  */
    	ldc	p11, cr8, [r12], #64
    #endif

    #ifdef __IWMMXT__
    	/* Restore the call-preserved iWMMXt registers.  */
    	/* Following instructions are wldrd wr10, [ip], #8 (etc.)  */
    	ldcl	p1, cr10, [r12], #8
    	ldcl	p1, cr11, [r12], #8
    	ldcl	p1, cr12, [r12], #8
    	ldcl	p1, cr13, [r12], #8
    	ldcl	p1, cr14, [r12], #8
    	ldcl	p1, cr15, [r12], #8
    #endif

    	movs	r0, r1		/* get the return value in place */
    	moveq	r0, #1		/* can't let setjmp() return zero! */
    	bx	lr

    	.size _st_md_cxt_restore, .-_st_md_cxt_restore

    /****************************************************************/

#endif

#endif
