/*
 *  S/390 helper routines
 *
 *  Copyright (c) 2009 Ulrich Hecht
 *  Copyright (c) 2009 Alexander Graf
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "exec.h"
#include "helpers.h"
#include <string.h>

/*****************************************************************************/
/* Softmmu support */
#if !defined (CONFIG_USER_ONLY)

#define MMUSUFFIX _mmu

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill (target_ulong addr, int is_write, int mmu_idx, void *retaddr)
{
    TranslationBlock *tb;
    CPUState *saved_env;
    unsigned long pc;
    int ret;

    /* XXX: hack to restore env in all cases, even if not called from
       generated code */
    saved_env = env;
    env = cpu_single_env;
    ret = cpu_s390x_handle_mmu_fault(env, addr, is_write, mmu_idx, 1);
    if (unlikely(ret != 0)) {
        if (likely(retaddr)) {
            /* now we have a real cpu fault */
            pc = (unsigned long)retaddr;
            tb = tb_find_pc(pc);
            if (likely(tb)) {
                /* the PC is inside the translated code. It means that we have
                   a virtual CPU fault */
                cpu_restore_state(tb, env, pc, NULL);
            }
        }
        /* XXX */
        /* helper_raise_exception_err(env->exception_index, env->error_code); */
    }
    env = saved_env;
}

#endif
/* #define DEBUG_HELPER */
#ifdef DEBUG_HELPER
#define HELPER_LOG(x...) qemu_log(x)
#else
#define HELPER_LOG(x...)
#endif

/* raise an exception */
void HELPER(exception)(uint32_t excp)
{
    HELPER_LOG("%s: exception %d\n", __FUNCTION__, excp);
    env->exception_index = excp;
    cpu_loop_exit();
}

/* and on array */
uint32_t HELPER(nc)(uint32_t l, uint32_t b, uint32_t d1, uint32_t d2)
{
    uint64_t dest = env->regs[b >> 4] + d1;
    uint64_t src = env->regs[b & 0xf] + d2;
    int i;
    unsigned char x;
    uint32_t cc = 0;
    HELPER_LOG("%s l %d b 0x%x d1 %d d2 %d\n", __FUNCTION__, l, b, d1, d2);
    for (i = 0; i <= l; i++) {
        x = ldub(dest + i) & ldub(src + i);
        if (x) cc = 1;
        stb(dest + i, x);
    }
    return cc;
}

/* xor on array */
uint32_t HELPER(xc)(uint32_t l, uint32_t b, uint32_t d1, uint32_t d2)
{
    uint64_t dest = env->regs[b >> 4] + d1;
    uint64_t src = env->regs[b & 0xf] + d2;
    int i;
    unsigned char x;
    uint32_t cc = 0;
    HELPER_LOG("%s l %d b 0x%x d1 %d d2 %d\n", __FUNCTION__, l, b, d1, d2);
    for (i = 0; i <= l; i++) {
        x = ldub(dest + i) ^ ldub(src + i);
        if (x) cc = 1;
        stb(dest + i, x);
    }
    return cc;
}

/* or on array */
uint32_t HELPER(oc)(uint32_t l, uint32_t b, uint32_t d1, uint32_t d2)
{
    uint64_t dest = env->regs[b >> 4] + d1;
    uint64_t src = env->regs[b & 0xf] + d2;
    int i;
    unsigned char x;
    uint32_t cc = 0;
    HELPER_LOG("%s l %d b 0x%x d1 %d d2 %d\n", __FUNCTION__, l, b, d1, d2);
    for (i = 0; i <= l; i++) {
        x = ldub(dest + i) | ldub(src + i);
        if (x) cc = 1;
        stb(dest + i, x);
    }
    return cc;
}

/* memcopy */
void HELPER(mvc)(uint32_t l, uint32_t b, uint32_t d1, uint32_t d2)
{
    uint64_t dest = env->regs[b >> 4] + d1;
    uint64_t src = env->regs[b & 0xf] + d2;
    int i;
    HELPER_LOG("%s l %d b 0x%x d1 %d d2 %d\n", __FUNCTION__, l, b, d1, d2);
    for (i = 0; i <= l; i++) {
        stb(dest + i, ldub(src + i));
    }
}

/* compare unsigned byte arrays */
uint32_t HELPER(clc)(uint32_t l, uint32_t b, uint32_t d1, uint32_t d2)
{
    uint64_t s1 = env->regs[b >> 4] + d1;
    uint64_t s2 = env->regs[b & 0xf] + d2;
    int i;
    unsigned char x,y;
    uint32_t cc;
    HELPER_LOG("%s l %d b 0x%x d1 %d d2 %d\n", __FUNCTION__, l, b, d1, d2);
    for (i = 0; i <= l; i++) {
        x = ldub(s1 + i);
        y = ldub(s2 + i);
        HELPER_LOG("%02x (%c)/%02x (%c) ", x, x, y, y);
        if (x < y) {
            cc = 1;
            goto done;
        } else if (x > y) {
            cc = 2;
            goto done;
        }
    }
    cc = 0;
done:
    HELPER_LOG("\n");
    return cc;
}

/* load multiple 64-bit registers from memory */
void HELPER(lmg)(uint32_t r1, uint32_t r3, uint32_t b2, int d2)
{
    uint64_t src = env->regs[b2] + d2;
    for (;;) {
        env->regs[r1] = ldq(src);
        src += 8;
        if (r1 == r3) break;
        r1 = (r1 + 1) & 15;
    }
}

/* store multiple 64-bit registers to memory */
void HELPER(stmg)(uint32_t r1, uint32_t r3, uint32_t b2, int d2)
{
    uint64_t dest = env->regs[b2] + d2;
    HELPER_LOG("%s: r1 %d r3 %d\n", __FUNCTION__, r1, r3);
    for (;;) {
        HELPER_LOG("storing r%d in 0x%lx\n", r1, dest);
        stq(dest, env->regs[r1]);
        dest += 8;
        if (r1 == r3) break;
        r1 = (r1 + 1) & 15;
    }
}

/* set condition code for signed 32-bit arithmetics */
uint32_t HELPER(set_cc_s32)(int32_t v)
{
    if (v < 0) return 1;
    else if (v > 0) return 2;
    else return 0;
}

/* set condition code for signed 64-bit arithmetics */
uint32_t HELPER(set_cc_s64)(int64_t v)
{
    if (v < 0) return 1;
    else if (v > 0) return 2;
    else return 0;
}

/* set condition code for signed 32-bit two's complement */
uint32_t HELPER(set_cc_comp_s32)(int32_t v)
{
    if ((uint32_t)v == 0x80000000UL) return 3;
    else if (v < 0) return 1;
    else if (v > 0) return 2;
    else return 0;
}

/* set condition code for signed 64-bit two's complement */
uint32_t HELPER(set_cc_comp_s64)(int64_t v)
{
    if ((uint64_t)v == 0x8000000000000000ULL) return 3;
    else if (v < 0) return 1;
    else if (v > 0) return 2;
    else return 0;
}

/* set negative/zero condition code for 32-bit logical op */
uint32_t HELPER(set_cc_nz_u32)(uint32_t v)
{
    if (v) return 1;
    else return 0;
}

/* set negative/zero condition code for 64-bit logical op */
uint32_t HELPER(set_cc_nz_u64)(uint64_t v)
{
    if (v) return 1;
    else return 0;
}

/* set condition code for insert character under mask insn */
uint32_t HELPER(set_cc_icm)(uint32_t mask, uint32_t val)
{
    HELPER_LOG("%s: mask 0x%x val %d\n", __FUNCTION__, mask, val);
    uint32_t cc;
    if (!val || !mask) cc = 0;
    else {
        while (mask != 1) {
            mask >>= 1;
            val >>= 8;
        }
        if (val & 0x80) cc = 1;
        else cc = 2;
    }
    return cc;
}

/* branch relative on 64-bit count (condition is computed inline, this only
   does the branch */
void HELPER(brctg)(uint64_t flag, uint64_t pc, int32_t offset)
{
    if (flag) {
        env->psw.addr = pc + offset;
    }
    else {
        env->psw.addr = pc + 4;
    }
    HELPER_LOG("%s: pc 0x%lx flag %ld psw.addr 0x%lx\n", __FUNCTION__, pc, flag,
             env->psw.addr);
}

/* branch relative on 32-bit count (condition is computed inline, this only
   does the branch */
void HELPER(brct)(uint32_t flag, uint64_t pc, int32_t offset)
{
    if (flag) {
        env->psw.addr = pc + offset;
    }
    else {
        env->psw.addr = pc + 4;
    }
    HELPER_LOG("%s: pc 0x%lx flag %d psw.addr 0x%lx\n", __FUNCTION__, pc, flag,
             env->psw.addr);
}

/* relative conditional branch with long displacement */
void HELPER(brcl)(uint32_t cc, uint32_t mask, uint64_t pc, int64_t offset)
{
    if ( mask & ( 1 << (3 - cc) ) ) {
        env->psw.addr = pc + offset;
    }
    else {
        env->psw.addr = pc + 6;
    }
    HELPER_LOG("%s: pc 0x%lx psw.addr 0x%lx\n", __FUNCTION__, pc, env->psw.addr);
}

/* conditional branch to register (register content is passed as target) */
void HELPER(bcr)(uint32_t cc, uint32_t mask, uint64_t target, uint64_t pc)
{
    if ( mask & ( 1 << (3 - cc) ) ) {
        env->psw.addr = target;
    }
    else {
        env->psw.addr = pc + 2;
    }
}

/* conditional branch to address (address is passed as target) */
void HELPER(bc)(uint32_t cc, uint32_t mask, uint64_t target, uint64_t pc)
{
    if ( mask & ( 1 << (3 - cc) ) ) {
        env->psw.addr = target;
    }
    else {
        env->psw.addr = pc + 4;
    }
    HELPER_LOG("%s: pc 0x%lx psw.addr 0x%lx r2 0x%lx r5 0x%lx\n", __FUNCTION__,
             pc, env->psw.addr, env->regs[2], env->regs[5]);
}

/* 64-bit unsigned comparison */
uint32_t HELPER(cmp_u64)(uint64_t o1, uint64_t o2)
{
    if (o1 < o2) return 1;
    else if (o1 > o2) return 2;
    else return 0;
}

/* 32-bit unsigned comparison */
uint32_t HELPER(cmp_u32)(uint32_t o1, uint32_t o2)
{
    HELPER_LOG("%s: o1 0x%x o2 0x%x\n", __FUNCTION__, o1, o2);
    if (o1 < o2) return 1;
    else if (o1 > o2) return 2;
    else return 0;
}

/* 64-bit signed comparison */
uint32_t HELPER(cmp_s64)(int64_t o1, int64_t o2)
{
    HELPER_LOG("%s: o1 %ld o2 %ld\n", __FUNCTION__, o1, o2);
    if (o1 < o2) return 1;
    else if (o1 > o2) return 2;
    else return 0;
}

/* 32-bit signed comparison */
uint32_t HELPER(cmp_s32)(int32_t o1, int32_t o2)
{
    if (o1 < o2) return 1;
    else if (o1 > o2) return 2;
    else return 0;
}

/* compare logical under mask */
uint32_t HELPER(clm)(uint32_t r1, uint32_t mask, uint64_t addr)
{
    uint8_t r,d;
    uint32_t cc;
    HELPER_LOG("%s: r1 0x%x mask 0x%x addr 0x%lx\n",__FUNCTION__,r1,mask,addr);
    cc = 0;
    while (mask) {
        if (mask & 8) {
            d = ldub(addr);
            r = (r1 & 0xff000000UL) >> 24;
            HELPER_LOG("mask 0x%x %02x/%02x (0x%lx) ", mask, r, d, addr);
            if (r < d) {
                cc = 1;
                break;
            }
            else if (r > d) {
                cc = 2;
                break;
            }
            addr++;
        }
        mask = (mask << 1) & 0xf;
        r1 <<= 8;
    }
    HELPER_LOG("\n");
    return cc;
}

/* store character under mask */
void HELPER(stcm)(uint32_t r1, uint32_t mask, uint64_t addr)
{
    uint8_t r;
    HELPER_LOG("%s: r1 0x%x mask 0x%x addr 0x%lx\n",__FUNCTION__,r1,mask,addr);
    while (mask) {
        if (mask & 8) {
            r = (r1 & 0xff000000UL) >> 24;
            stb(addr, r);
            HELPER_LOG("mask 0x%x %02x (0x%lx) ", mask, r, addr);
            addr++;
        }
        mask = (mask << 1) & 0xf;
        r1 <<= 8;
    }
    HELPER_LOG("\n");
}

/* 64/64 -> 128 unsigned multiplication */
void HELPER(mlg)(uint32_t r1, uint64_t v2)
{
#if TARGET_LONG_BITS == 64 && defined(__GNUC__) /* assuming 64-bit hosts have __uint128_t */
    __uint128_t res = (__uint128_t)env->regs[r1 + 1];
    res *= (__uint128_t)v2;
    env->regs[r1] = (uint64_t)(res >> 64);
    env->regs[r1 + 1] = (uint64_t)res;
#else
    mulu64(&env->regs[r1 + 1], &env->regs[r1], env->regs[r1 + 1], v2);
#endif
}

/* 128 -> 64/64 unsigned division */
void HELPER(dlg)(uint32_t r1, uint64_t v2)
{
#if TARGET_LONG_BITS == 64 && defined(__GNUC__) /* assuming 64-bit hosts have __uint128_t */
    __uint128_t dividend = (((__uint128_t)env->regs[r1]) << 64) | 
                           (env->regs[r1+1]);
    uint64_t divisor = v2;
    __uint128_t quotient = dividend / divisor;
    env->regs[r1+1] = quotient;
    __uint128_t remainder = dividend % divisor;
    env->regs[r1] = remainder;
    HELPER_LOG("%s: dividend 0x%016lx%016lx divisor 0x%lx quotient 0x%lx rem 0x%lx\n",
               __FUNCTION__, (uint64_t)(dividend >> 64), (uint64_t)dividend,
               divisor, (uint64_t)quotient, (uint64_t)remainder);
#else
    cpu_abort(env, "128 -> 64/64 division not implemented on this system\n");
#endif
}

/* set condition code for 64-bit signed addition */
uint32_t HELPER(set_cc_add64)(int64_t a1, int64_t a2, int64_t ar)
{
    if ((a1 > 0 && a2 > 0 && ar < 0) || (a1 < 0 && a2 < 0 && ar > 0)) {
        return 3; /* overflow */
    } else {
        if (ar < 0) return 1;
        else if (ar > 0) return 2;
        else return 0;
    }
}

/* set condition code for 64-bit unsigned addition */
uint32_t HELPER(set_cc_addu64)(uint64_t a1, uint64_t a2, uint64_t ar)
{
    if (ar == 0) {
        if (a1) return 2;
        else return 0;
    } else {
        if (ar < a1 || ar < a2) {
          return 3;
        } else {
          return 1;
        }
    }
}

/* set condition code for 32-bit signed addition */
uint32_t HELPER(set_cc_add32)(int32_t a1, int32_t a2, int32_t ar)
{
    if ((a1 > 0 && a2 > 0 && ar < 0) || (a1 < 0 && a2 < 0 && ar > 0)) {
        return 3; /* overflow */
    } else {
        if (ar < 0) return 1;
        else if (ar > 0) return 2;
        else return 0;
    }
}

/* set condition code for 32-bit unsigned addition */
uint32_t HELPER(set_cc_addu32)(uint32_t a1, uint32_t a2, uint32_t ar)
{
    if (ar == 0) {
        if (a1) return 2;
        else return 0;
    } else {
        if (ar < a1 || ar < a2) {
          return 3;
        } else {
          return 1;
        }
    }
}

/* set condition code for 64-bit signed subtraction */
uint32_t HELPER(set_cc_sub64)(int64_t s1, int64_t s2, int64_t sr)
{
    if ((s1 > 0 && s2 < 0 && sr < 0) || (s1 < 0 && s2 > 0 && sr > 0)) {
        return 3; /* overflow */
    } else {
        if (sr < 0) return 1;
        else if (sr > 0) return 2;
        else return 0;
    }
}

/* set condition code for 32-bit signed subtraction */
uint32_t HELPER(set_cc_sub32)(int32_t s1, int32_t s2, int32_t sr)
{
    if ((s1 > 0 && s2 < 0 && sr < 0) || (s1 < 0 && s2 > 0 && sr > 0)) {
        return 3; /* overflow */
    } else {
        if (sr < 0) return 1;
        else if (sr > 0) return 2;
        else return 0;
    }
}

/* set condition code for 32-bit unsigned subtraction */
uint32_t HELPER(set_cc_subu32)(uint32_t s1, uint32_t s2, uint32_t sr)
{
    if (sr == 0) return 2;
    else {
        if (s2 > s1) return 1;
        else return 3;
    }
}

/* set condition code for 64-bit unsigned subtraction */
uint32_t HELPER(set_cc_subu64)(uint64_t s1, uint64_t s2, uint64_t sr)
{
    if (sr == 0) return 2;
    else {
        if (s2 > s1) return 1;
        else return 3;
    }
}

/* search string (c is byte to search, r2 is string, r1 end of string) */
uint32_t HELPER(srst)(uint32_t c, uint32_t r1, uint32_t r2)
{
    HELPER_LOG("%s: c %d *r1 0x%lx *r2 0x%lx\n", __FUNCTION__, c, env->regs[r1],
             env->regs[r2]);
    uint64_t i;
    uint32_t cc;
    for (i = env->regs[r2]; i != env->regs[r1]; i++) {
        if (ldub(i) == c) {
            env->regs[r1] = i;
            cc = 1;
            return cc;
        }
    }
    cc = 2;
    return cc;
}

/* unsigned string compare (c is string terminator) */
uint32_t HELPER(clst)(uint32_t c, uint32_t r1, uint32_t r2)
{
    uint64_t s1 = env->regs[r1];
    uint64_t s2 = env->regs[r2];
    uint8_t v1, v2;
    uint32_t cc;
    c = c & 0xff;
#ifdef CONFIG_USER_ONLY
    if (!c) {
        HELPER_LOG("%s: comparing '%s' and '%s'\n",
                   __FUNCTION__, (char*)s1, (char*)s2);
    }
#endif
    for (;;) {
        v1 = ldub(s1);
        v2 = ldub(s2);
        if (v1 == c || v2 == c) break;
        if (v1 != v2) break;
        s1++; s2++;
    }
    
    if (v1 == v2) cc = 0;
    else {
        if (v1 < v2) cc = 1;
        else cc = 2;
        env->regs[r1] = s1;
        env->regs[r2] = s2;
    }
    return cc;
}

/* string copy (c is string terminator) */
uint32_t HELPER(mvst)(uint32_t c, uint32_t r1, uint32_t r2)
{
    uint64_t dest = env->regs[r1];
    uint64_t src = env->regs[r2];
    uint8_t v;
    c = c & 0xff;
#ifdef CONFIG_USER_ONLY
    if (!c) {
        HELPER_LOG("%s: copying '%s' to 0x%lx\n", __FUNCTION__, (char*)src, dest);
    }
#endif
    for (;;) {
        v = ldub(src);
        stb(dest, v);
        if (v == c) break;
        src++; dest++;
    }
    env->regs[r1] = dest;
    return 1;
}

/* compare and swap 64-bit */
uint32_t HELPER(csg)(uint32_t r1, uint64_t a2, uint32_t r3)
{
    /* FIXME: locking? */
    uint32_t cc;
    uint64_t v2 = ldq(a2);
    if (env->regs[r1] == v2) {
        cc = 0;
        stq(a2, env->regs[r3]);
    } else {
        cc = 1;
        env->regs[r1] = v2;
    }
    return cc;
}

/* compare double and swap 64-bit */
uint32_t HELPER(cdsg)(uint32_t r1, uint64_t a2, uint32_t r3)
{
    /* FIXME: locking? */
    uint32_t cc;
    __uint128_t v2 = (((__uint128_t)ldq(a2)) << 64) | (__uint128_t)ldq(a2 + 8);
    __uint128_t v1 = (((__uint128_t)env->regs[r1]) << 64) | (__uint128_t)env->regs[r1 + 1];
    if (v1 == v2) {
        cc = 0;
        stq(a2, env->regs[r3]);
        stq(a2 + 8, env->regs[r3 + 1]);
    } else {
        cc = 1;
        env->regs[r1] = v2 >> 64;
        env->regs[r1 + 1] = v2 & 0xffffffffffffffffULL;
    }
    return cc;
}

/* compare and swap 32-bit */
uint32_t HELPER(cs)(uint32_t r1, uint64_t a2, uint32_t r3)
{
    /* FIXME: locking? */
    uint32_t cc;
    HELPER_LOG("%s: r1 %d a2 0x%lx r3 %d\n", __FUNCTION__, r1, a2, r3);
    uint32_t v2 = ldl(a2);
    if (((uint32_t)env->regs[r1]) == v2) {
        cc = 0;
        stl(a2, (uint32_t)env->regs[r3]);
    } else {
        cc = 1;
        env->regs[r1] = (env->regs[r1] & 0xffffffff00000000ULL) | v2;
    }
    return cc;
}

/* execute instruction
   this instruction executes an insn modified with the contents of r1
   it does not change the executed instruction in memory
   it does not change the program counter
   in other words: tricky...
   currently implemented by interpreting the cases it is most commonly used in
 */
uint32_t HELPER(ex)(uint32_t cc, uint64_t v1, uint64_t addr, uint64_t ret)
{
    uint16_t insn = lduw(addr);
    HELPER_LOG("%s: v1 0x%lx addr 0x%lx insn 0x%x\n", __FUNCTION__, v1, addr,
             insn);
    if ((insn & 0xf0ff) == 0xd000) {
        uint32_t l, insn2, b, d1, d2;
        l = v1 & 0xff;
        insn2 = ldl_code(addr + 2);
        b = (((insn2 >> 28) & 0xf) << 4) | ((insn2 >> 12) & 0xf);
        d1 = (insn2 >> 16) & 0xfff;
        d2 = insn2 & 0xfff;
        switch (insn & 0xf00) {
        case 0x200: helper_mvc(l, b, d1, d2); return cc; break;
        case 0x500: return helper_clc(l, b, d1, d2); break;
        case 0x700: return helper_xc(l, b, d1, d2); break;
        default: goto abort; break;
        }
    }
    else if ((insn & 0xff00) == 0x0a00) {	/* supervisor call */
        HELPER_LOG("%s: svc %ld via execute\n", __FUNCTION__, (insn|v1) & 0xff);
        env->psw.addr = ret;
        helper_exception(EXCP_EXECUTE_SVC + ((insn | v1) & 0xff));
    }
    else {
abort:
        cpu_abort(env, "EXECUTE on instruction prefix 0x%x not implemented\n", insn);
    }
    return cc;
}

/* set condition code for test under mask */
uint32_t HELPER(tm)(uint32_t val, uint32_t mask)
{
    HELPER_LOG("%s: val 0x%x mask 0x%x\n", __FUNCTION__, val, mask);
    uint16_t r = val & mask;
    if (r == 0) return 0;
    else if (r == mask) return 3;
    else return 1;
}

/* set condition code for test under mask */
uint32_t HELPER(tmxx)(uint64_t val, uint32_t mask)
{
    uint16_t r = val & mask;
    HELPER_LOG("%s: val 0x%lx mask 0x%x r 0x%x\n", __FUNCTION__, val, mask, r);
    if (r == 0) return 0;
    else if (r == mask) return 3;
    else {
        while (!(mask & 0x8000)) {
            mask <<= 1;
            val <<= 1;
        }
        if (val & 0x8000) return 2;
        else return 1;
    }
}

/* absolute value 32-bit */
uint32_t HELPER(abs_i32)(uint32_t reg, int32_t val)
{
    uint32_t cc;
    if (val == 0x80000000UL) cc = 3;
    else if (val) cc = 1;
    else cc = 0;

    if (val < 0) {
        env->regs[reg] = -val;
    } else {
        env->regs[reg] = val;
    }
    return cc;
}

/* negative absolute value 32-bit */
uint32_t HELPER(nabs_i32)(uint32_t reg, int32_t val)
{
    uint32_t cc;
    if (val) cc = 1;
    else cc = 0;
    
    if (val < 0) {
        env->regs[reg] = (env->regs[reg] & 0xffffffff00000000ULL) | val;
    } else {
        env->regs[reg] = (env->regs[reg] & 0xffffffff00000000ULL) | ((uint32_t)-val);
    }
    return cc;
}

/* absolute value 64-bit */
uint32_t HELPER(abs_i64)(uint32_t reg, int64_t val)
{
    uint32_t cc;
    if (val == 0x8000000000000000ULL) cc = 3;
    else if (val) cc = 1;
    else cc = 0;
    
    if (val < 0) {
        env->regs[reg] = -val;
    } else {
        env->regs[reg] = val;
    }
    return cc;
}

/* negative absolute value 64-bit */
uint32_t HELPER(nabs_i64)(uint32_t reg, int64_t val)
{
    uint32_t cc;
    if (val) cc = 1;
    else cc = 0;

    if (val < 0) {
        env->regs[reg] = val;
    } else {
        env->regs[reg] = -val;
    }
    return cc;
}

/* add with carry 32-bit unsigned */
uint32_t HELPER(addc_u32)(uint32_t cc, uint32_t r1, uint32_t v2)
{
    uint32_t res;
    uint32_t v1 = env->regs[r1] & 0xffffffffUL;
    res = v1 + v2;
    if (cc & 2) res++;

    if (res == 0) {
        if (v1) cc = 2;
        else cc = 0;
    } else {
        if (res < v1 || res < v2) {
          cc = 3;
        } else {
          cc = 1;
        }
    }
    env->regs[r1] = (env->regs[r1] & 0xffffffff00000000ULL) | res;
    return cc;
}

/* CC for add with carry 64-bit unsigned (isn't this a duplicate of some other CC function?) */
uint32_t HELPER(set_cc_addc_u64)(uint64_t v1, uint64_t v2, uint64_t res)
{
    uint32_t cc;
    if (res == 0) {
        if (v1) cc = 2;
        else cc = 0;
    } else {
        if (res < v1 || res < v2) {
          cc = 3;
        } else {
          cc = 1;
        }
    }
    return cc;
}

/* store character under mask high
   operates on the upper half of r1 */
uint32_t HELPER(stcmh)(uint32_t r1, uint64_t address, uint32_t mask)
{
    int pos = 56; /* top of the upper half of r1 */
    
    while (mask) {
        if (mask & 8) {
            stb(address, (env->regs[r1] >> pos) & 0xff);
            address++;
        }
        mask = (mask << 1) & 0xf;
        pos -= 8;
    }
    return 0;
}

/* insert character under mask high
   same as icm, but operates on the upper half of r1 */
uint32_t HELPER(icmh)(uint32_t r1, uint64_t address, uint32_t mask)
{
    int pos = 56; /* top of the upper half of r1 */
    uint64_t rmask = 0xff00000000000000ULL;
    uint8_t val = 0;
    int ccd = 0;
    uint32_t cc;
    
    cc = 0;
    
    while (mask) {
        if (mask & 8) {
            env->regs[r1] &= ~rmask;
            val = ldub(address);
            if ((val & 0x80) && !ccd) cc = 1;
            ccd = 1;
            if (val && cc == 0) cc = 2;
            env->regs[r1] |= (uint64_t)val << pos;
            address++;
        }
        mask = (mask << 1) & 0xf;
        pos -= 8;
        rmask >>= 8;
    }
    return cc;
}

/* insert psw mask and condition code into r1 */
void HELPER(ipm)(uint32_t cc, uint32_t r1)
{
    uint64_t r = env->regs[r1];
    r &= 0xffffffff00ffffffULL;
    r |= (cc << 28) | ( (env->psw.mask >> 40) & 0xf );
    env->regs[r1] = r;
    HELPER_LOG("%s: cc %d psw.mask 0x%lx r1 0x%lx\n", __FUNCTION__, cc, env->psw.mask, r);
}

/* store access registers r1 to r3 in memory at a2 */
void HELPER(stam)(uint32_t r1, uint64_t a2, uint32_t r3)
{
    int i;
    for (i = r1; i != ((r3 + 1) & 15); i = (i + 1) & 15) {
        stl(a2, env->aregs[i]);
        a2 += 4;
    }
}

/* move long extended
   another memcopy insn with more bells and whistles */
uint32_t HELPER(mvcle)(uint32_t r1, uint64_t a2, uint32_t r3)
{
    uint64_t destlen = env->regs[r1 + 1];
    uint64_t dest = env->regs[r1];
    uint64_t srclen = env->regs[r3 + 1];
    uint64_t src = env->regs[r3];
    uint8_t pad = a2 & 0xff;
    uint8_t v;
    uint32_t cc;
    if (destlen == srclen) cc = 0;
    else if (destlen < srclen) cc = 1;
    else cc = 2;
    if (srclen > destlen) srclen = destlen;
    for(;destlen && srclen;src++,dest++,destlen--,srclen--) {
        v = ldub(src);
        stb(dest, v);
    }
    for(;destlen;dest++,destlen--) {
        stb(dest, pad);
    }
    env->regs[r1 + 1] = destlen;
    env->regs[r3 + 1] -= src - env->regs[r3]; /* can't use srclen here,
                                                 we trunc'ed it */
    env->regs[r1] = dest;
    env->regs[r3] = src;
    
    return cc;
}

/* compare logical long extended
   memcompare insn with padding */
uint32_t HELPER(clcle)(uint32_t r1, uint64_t a2, uint32_t r3)
{
    uint64_t destlen = env->regs[r1 + 1];
    uint64_t dest = env->regs[r1];
    uint64_t srclen = env->regs[r3 + 1];
    uint64_t src = env->regs[r3];
    uint8_t pad = a2 & 0xff;
    uint8_t v1 = 0,v2 = 0;
    uint32_t cc = 0;
    if (!(destlen || srclen)) return cc;
    if (srclen > destlen) srclen = destlen;
    for(;destlen || srclen;src++,dest++,destlen--,srclen--) {
        if (srclen) v1 = ldub(src);
        else v1 = pad;
        if (destlen) v2 = ldub(dest);
        else v2 = pad;
        if (v1 != v2) break;
    }

    env->regs[r1 + 1] = destlen;
    env->regs[r3 + 1] -= src - env->regs[r3]; /* can't use srclen here,
                                                 we trunc'ed it */
    env->regs[r1] = dest;
    env->regs[r3] = src;
    
    if (v1 < v2) cc = 1;
    else if (v1 > v2) cc = 2;
    
    return cc;
}

/* subtract unsigned v2 from v1 with borrow */
uint32_t HELPER(slb)(uint32_t cc, uint32_t r1, uint32_t v1, uint32_t v2)
{
    uint32_t res = v1 + (~v2) + (cc >> 1);
    env->regs[r1] = (env->regs[r1] & 0xffffffff00000000ULL) | res;
    if (cc & 2) { /* borrow */
        if (v1) return 1;
        else return 0;
    } else {
        if (v1) return 3;
        else return 2;
    }
}

/* subtract unsigned v2 from v1 with borrow */
uint32_t HELPER(slbg)(uint32_t cc, uint32_t r1, uint64_t v1, uint64_t v2)
{
    uint64_t res = v1 + (~v2) + (cc >> 1);
    env->regs[r1] = res;
    if (cc & 2) { /* borrow */
        if (v1) return 1;
        else return 0;
    } else {
        if (v1) return 3;
        else return 2;
    }
}

/* condition codes for binary FP ops */
static uint32_t set_cc_f32(float32 v1, float32 v2)
{
    if (float32_is_nan(v1) || float32_is_nan(v2)) return 3;
    else if (float32_eq(v1, v2, &env->fpu_status)) return 0;
    else if (float32_lt(v1, v2, &env->fpu_status)) return 1;
    else return 2;
}

static uint32_t set_cc_f64(float64 v1, float64 v2)
{
    if (float64_is_nan(v1) || float64_is_nan(v2)) return 3;
    else if (float64_eq(v1, v2, &env->fpu_status)) return 0;
    else if (float64_lt(v1, v2, &env->fpu_status)) return 1;
    else return 2;
}

/* condition codes for unary FP ops */
static uint32_t set_cc_nz_f32(float32 v)
{
    if (float32_is_nan(v)) return 3;
    else if (float32_is_zero(v)) return 0;
    else if (float32_is_neg(v)) return 1;
    else return 2;
}

static uint32_t set_cc_nz_f64(float64 v)
{
    if (float64_is_nan(v)) return 3;
    else if (float64_is_zero(v)) return 0;
    else if (float64_is_neg(v)) return 1;
    else return 2;
}

static uint32_t set_cc_nz_f128(float128 v)
{
    if (float128_is_nan(v)) return 3;
    else if (float128_is_zero(v)) return 0;
    else if (float128_is_neg(v)) return 1;
    else return 2;
}

/* convert 32-bit int to 64-bit float */
void HELPER(cdfbr)(uint32_t f1, int32_t v2)
{
    HELPER_LOG("%s: converting %d to f%d\n", __FUNCTION__, v2, f1);
    env->fregs[f1].d = int32_to_float64(v2, &env->fpu_status);
}

/* convert 32-bit int to 128-bit float */
void HELPER(cxfbr)(uint32_t f1, int32_t v2)
{
    CPU_QuadU v1;
    v1.q = int32_to_float128(v2, &env->fpu_status);
    env->fregs[f1].ll = v1.ll.upper;
    env->fregs[f1 + 2].ll = v1.ll.lower;
}

/* convert 64-bit int to 32-bit float */
void HELPER(cegbr)(uint32_t f1, int64_t v2)
{
    HELPER_LOG("%s: converting %ld to f%d\n", __FUNCTION__, v2, f1);
    env->fregs[f1].l.upper = int64_to_float32(v2, &env->fpu_status);
}

/* convert 64-bit int to 64-bit float */
void HELPER(cdgbr)(uint32_t f1, int64_t v2)
{
    HELPER_LOG("%s: converting %ld to f%d\n", __FUNCTION__, v2, f1);
    env->fregs[f1].d = int64_to_float64(v2, &env->fpu_status);
}

/* convert 64-bit int to 128-bit float */
void HELPER(cxgbr)(uint32_t f1, int64_t v2)
{
    CPU_QuadU x1;
    x1.q = int64_to_float128(v2, &env->fpu_status);
    HELPER_LOG("%s: converted %ld to 0x%lx and 0x%lx\n", __FUNCTION__, v2, x1.ll.upper, x1.l);
    env->fregs[f1].ll = x1.ll.upper;
    env->fregs[f1 + 2].ll = x1.ll.lower;
}

/* convert 32-bit int to 32-bit float */
void HELPER(cefbr)(uint32_t f1, int32_t v2)
{
    env->fregs[f1].l.upper = int32_to_float32(v2, &env->fpu_status);
    HELPER_LOG("%s: converting %d to 0x%d in f%d\n", __FUNCTION__, v2, env->fregs[f1].l.upper, f1);
}

/* 32-bit FP addition RR */
uint32_t HELPER(aebr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].l.upper = float32_add(env->fregs[f1].l.upper, env->fregs[f2].l.upper, &env->fpu_status);
    HELPER_LOG("%s: adding 0x%d resulting in 0x%d in f%d\n", __FUNCTION__, env->fregs[f2].l.upper, env->fregs[f1].l.upper, f1);
    return set_cc_nz_f32(env->fregs[f1].l.upper);
}

/* 64-bit FP addition RR */
uint32_t HELPER(adbr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].d = float64_add(env->fregs[f1].d, env->fregs[f2].d, &env->fpu_status);
    HELPER_LOG("%s: adding 0x%ld resulting in 0x%ld in f%d\n", __FUNCTION__, env->fregs[f2].d, env->fregs[f1].d, f1);
    return set_cc_nz_f64(env->fregs[f1].d);
}

/* 32-bit FP subtraction RR */
uint32_t HELPER(sebr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].l.upper = float32_sub(env->fregs[f1].l.upper, env->fregs[f2].l.upper, &env->fpu_status);
    HELPER_LOG("%s: adding 0x%d resulting in 0x%d in f%d\n", __FUNCTION__, env->fregs[f2].l.upper, env->fregs[f1].l.upper, f1);
    return set_cc_nz_f32(env->fregs[f1].l.upper);
}

/* 64-bit FP subtraction RR */
uint32_t HELPER(sdbr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].d = float64_sub(env->fregs[f1].d, env->fregs[f2].d, &env->fpu_status);
    HELPER_LOG("%s: subtracting 0x%ld resulting in 0x%ld in f%d\n", __FUNCTION__, env->fregs[f2].d, env->fregs[f1].d, f1);
    return set_cc_nz_f64(env->fregs[f1].d);
}

/* 32-bit FP division RR */
void HELPER(debr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].l.upper = float32_div(env->fregs[f1].l.upper, env->fregs[f2].l.upper, &env->fpu_status);
}

/* 128-bit FP division RR */
void HELPER(dxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU v1;
    v1.ll.upper = env->fregs[f1].ll;
    v1.ll.lower = env->fregs[f1 + 2].ll;
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    CPU_QuadU res;
    res.q = float128_div(v1.q, v2.q, &env->fpu_status);
    env->fregs[f1].ll = res.ll.upper;
    env->fregs[f1 + 2].ll = res.ll.lower;
}

/* 64-bit FP multiplication RR */
void HELPER(mdbr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].d = float64_mul(env->fregs[f1].d, env->fregs[f2].d, &env->fpu_status);
}

/* 128-bit FP multiplication RR */
void HELPER(mxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU v1;
    v1.ll.upper = env->fregs[f1].ll;
    v1.ll.lower = env->fregs[f1 + 2].ll;
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    CPU_QuadU res;
    res.q = float128_mul(v1.q, v2.q, &env->fpu_status);
    env->fregs[f1].ll = res.ll.upper;
    env->fregs[f1 + 2].ll = res.ll.lower;
}

/* convert 32-bit float to 64-bit float */
void HELPER(ldebr)(uint32_t r1, uint32_t r2)
{
    env->fregs[r1].d = float32_to_float64(env->fregs[r2].l.upper, &env->fpu_status);
}

/* convert 128-bit float to 64-bit float */
void HELPER(ldxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU x2;
    x2.ll.upper = env->fregs[f2].ll;
    x2.ll.lower = env->fregs[f2 + 2].ll;
    env->fregs[f1].d = float128_to_float64(x2.q, &env->fpu_status);
    HELPER_LOG("%s: to 0x%ld\n", __FUNCTION__, env->fregs[f1].d);
}

/* convert 64-bit float to 128-bit float */
void HELPER(lxdbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU res;
    res.q = float64_to_float128(env->fregs[f2].d, &env->fpu_status);
    env->fregs[f1].ll = res.ll.upper;
    env->fregs[f1 + 2].ll = res.ll.lower;
}

/* convert 64-bit float to 32-bit float */
void HELPER(ledbr)(uint32_t f1, uint32_t f2)
{
    float64 d2 = env->fregs[f2].d;
    env->fregs[f1].l.upper = float64_to_float32(d2, &env->fpu_status);
}

/* convert 128-bit float to 32-bit float */
void HELPER(lexbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU x2;
    x2.ll.upper = env->fregs[f2].ll;
    x2.ll.lower = env->fregs[f2 + 2].ll;
    env->fregs[f1].l.upper = float128_to_float32(x2.q, &env->fpu_status);
    HELPER_LOG("%s: to 0x%d\n", __FUNCTION__, env->fregs[f1].l.upper);
}

/* absolute value of 32-bit float */
uint32_t HELPER(lpebr)(uint32_t f1, uint32_t f2)
{
    float32 v1;
    float32 v2 = env->fregs[f2].d;
    v1 = float32_abs(v2);
    env->fregs[f1].d = v1;
    return set_cc_nz_f32(v1);
}

/* absolute value of 64-bit float */
uint32_t HELPER(lpdbr)(uint32_t f1, uint32_t f2)
{
    float64 v1;
    float64 v2 = env->fregs[f2].d;
    v1 = float64_abs(v2);
    env->fregs[f1].d = v1;
    return set_cc_nz_f64(v1);
}

/* absolute value of 128-bit float */
uint32_t HELPER(lpxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU v1;
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    v1.q = float128_abs(v2.q);
    env->fregs[f1].ll = v1.ll.upper;
    env->fregs[f1 + 2].ll = v1.ll.lower;
    return set_cc_nz_f128(v1.q);
}

/* load and test 64-bit float */
uint32_t HELPER(ltdbr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].d = env->fregs[f2].d;
    return set_cc_nz_f64(env->fregs[f1].d);
}

/* load and test 32-bit float */
uint32_t HELPER(ltebr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].l.upper = env->fregs[f2].l.upper;
    return set_cc_nz_f32(env->fregs[f1].l.upper);
}

/* load and test 128-bit float */
uint32_t HELPER(ltxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU x;
    x.ll.upper = env->fregs[f2].ll;
    x.ll.lower = env->fregs[f2 + 2].ll;
    env->fregs[f1].ll = x.ll.upper;
    env->fregs[f1 + 2].ll = x.ll.lower;
    return set_cc_nz_f128(x.q);
}

/* negative absolute of 32-bit float */
uint32_t HELPER(lcebr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].l.upper = float32_sub(float32_zero, env->fregs[f2].l.upper, &env->fpu_status);
    return set_cc_nz_f32(env->fregs[f1].l.upper);
}

/* negative absolute of 64-bit float */
uint32_t HELPER(lcdbr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].d = float64_sub(float64_zero, env->fregs[f2].d, &env->fpu_status);
    return set_cc_nz_f64(env->fregs[f1].d);
}

/* convert 64-bit float to 128-bit float */
uint32_t HELPER(lcxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU x1, x2;
    x2.ll.upper = env->fregs[f2].ll;
    x2.ll.lower = env->fregs[f2 + 2].ll;
    x1.q = float128_sub(float64_to_float128(float64_zero, &env->fpu_status), x2.q, &env->fpu_status);
    env->fregs[f1].ll = x1.ll.upper;
    env->fregs[f1 + 2].ll = x1.ll.lower;
    return set_cc_nz_f128(x1.q);
}

/* 32-bit FP compare RM */
uint32_t HELPER(ceb)(uint32_t f1, uint32_t val)
{
    float32 v1 = env->fregs[f1].l.upper;
    CPU_FloatU v2;
    v2.l = val;
    HELPER_LOG("%s: comparing 0x%d from f%d and 0x%d\n", __FUNCTION__, v1, f1, v2.f);
    return set_cc_f32(v1, v2.f);
}

/* 32-bit FP addition RM */
uint32_t HELPER(aeb)(uint32_t f1, uint32_t val)
{
    float32 v1 = env->fregs[f1].l.upper;
    CPU_FloatU v2;
    v2.l = val;
    HELPER_LOG("%s: adding 0x%d from f%d and 0x%d\n", __FUNCTION__, v1, f1, v2.f);
    env->fregs[f1].l.upper = float32_add(v1, v2.f, &env->fpu_status);
    return set_cc_nz_f32(env->fregs[f1].l.upper);
}

/* 32-bit FP division RM */
void HELPER(deb)(uint32_t f1, uint32_t val)
{
    float32 v1 = env->fregs[f1].l.upper;
    CPU_FloatU v2;
    v2.l = val;
    HELPER_LOG("%s: dividing 0x%d from f%d by 0x%d\n", __FUNCTION__, v1, f1, v2.f);
    env->fregs[f1].l.upper = float32_div(v1, v2.f, &env->fpu_status);
}

/* 32-bit FP multiplication RM */
void HELPER(meeb)(uint32_t f1, uint32_t val)
{
    float32 v1 = env->fregs[f1].l.upper;
    CPU_FloatU v2;
    v2.l = val;
    HELPER_LOG("%s: multiplying 0x%d from f%d and 0x%d\n", __FUNCTION__, v1, f1, v2.f);
    env->fregs[f1].l.upper = float32_mul(v1, v2.f, &env->fpu_status);
}

/* 32-bit FP compare RR */
uint32_t HELPER(cebr)(uint32_t f1, uint32_t f2)
{
    float32 v1 = env->fregs[f1].l.upper;
    float32 v2 = env->fregs[f2].l.upper;;
    HELPER_LOG("%s: comparing 0x%d from f%d and 0x%d\n", __FUNCTION__, v1, f1, v2);
    return set_cc_f32(v1, v2);
}

/* 64-bit FP compare RR */
uint32_t HELPER(cdbr)(uint32_t f1, uint32_t f2)
{
    float64 v1 = env->fregs[f1].d;
    float64 v2 = env->fregs[f2].d;;
    HELPER_LOG("%s: comparing 0x%ld from f%d and 0x%ld\n", __FUNCTION__, v1, f1, v2);
    return set_cc_f64(v1, v2);
}

/* 128-bit FP compare RR */
uint32_t HELPER(cxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU v1;
    v1.ll.upper = env->fregs[f1].ll;
    v1.ll.lower = env->fregs[f1 + 2].ll;
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    if (float128_is_nan(v1.q) || float128_is_nan(v2.q)) return 3;
    else if (float128_eq(v1.q, v2.q, &env->fpu_status)) return 0;
    else if (float128_lt(v1.q, v2.q, &env->fpu_status)) return 1;
    else return 2;
}

/* 64-bit FP compare RM */
uint32_t HELPER(cdb)(uint32_t f1, uint64_t a2)
{
    float64 v1 = env->fregs[f1].d;
    CPU_DoubleU v2;
    v2.ll = ldq(a2);
    HELPER_LOG("%s: comparing 0x%ld from f%d and 0x%lx\n", __FUNCTION__, v1, f1, v2.d);
    return set_cc_f64(v1, v2.d);
}

/* 64-bit FP addition RM */
uint32_t HELPER(adb)(uint32_t f1, uint64_t a2)
{
    float64 v1 = env->fregs[f1].d;
    CPU_DoubleU v2;
    v2.ll = ldq(a2);
    HELPER_LOG("%s: adding 0x%lx from f%d and 0x%lx\n", __FUNCTION__, v1, f1, v2.d);
    env->fregs[f1].d = v1 = float64_add(v1, v2.d, &env->fpu_status);
    return set_cc_nz_f64(v1);
}

/* 32-bit FP subtraction RM */
uint32_t HELPER(seb)(uint32_t f1, uint32_t val)
{
    float32 v1 = env->fregs[f1].l.upper;
    CPU_FloatU v2;
    v2.l = val;
    env->fregs[f1].l.upper = v1 = float32_sub(v1, v2.f, &env->fpu_status);
    return set_cc_nz_f32(v1);
}

/* 64-bit FP subtraction RM */
uint32_t HELPER(sdb)(uint32_t f1, uint64_t a2)
{
    float64 v1 = env->fregs[f1].d;
    CPU_DoubleU v2;
    v2.ll = ldq(a2);
    env->fregs[f1].d = v1 = float64_sub(v1, v2.d, &env->fpu_status);
    return set_cc_nz_f64(v1);
}

/* 64-bit FP multiplication RM */
void HELPER(mdb)(uint32_t f1, uint64_t a2)
{
    float64 v1 = env->fregs[f1].d;
    CPU_DoubleU v2;
    v2.ll = ldq(a2);
    HELPER_LOG("%s: multiplying 0x%lx from f%d and 0x%ld\n", __FUNCTION__, v1, f1, v2.d);
    env->fregs[f1].d = float64_mul(v1, v2.d, &env->fpu_status);
}

/* 64-bit FP division RM */
void HELPER(ddb)(uint32_t f1, uint64_t a2)
{
    float64 v1 = env->fregs[f1].d;
    CPU_DoubleU v2;
    v2.ll = ldq(a2);
    HELPER_LOG("%s: dividing 0x%lx from f%d by 0x%ld\n", __FUNCTION__, v1, f1, v2.d);
    env->fregs[f1].d = float64_div(v1, v2.d, &env->fpu_status);
}

static void set_round_mode(int m3)
{
    switch (m3) {
    case 0: break; /* current mode */
    case 1: /* biased round no nearest */
    case 4: /* round to nearest */
        set_float_rounding_mode(float_round_nearest_even, &env->fpu_status);
        break;
    case 5: /* round to zero */
        set_float_rounding_mode(float_round_to_zero, &env->fpu_status);
        break;
    case 6: /* round to +inf */
        set_float_rounding_mode(float_round_up, &env->fpu_status);
        break;
    case 7: /* round to -inf */
        set_float_rounding_mode(float_round_down, &env->fpu_status);
        break;
    }
}

/* convert 32-bit float to 64-bit int */
uint32_t HELPER(cgebr)(uint32_t r1, uint32_t f2, uint32_t m3)
{
    float32 v2 = env->fregs[f2].l.upper;
    set_round_mode(m3);
    env->regs[r1] = float32_to_int64(v2, &env->fpu_status);
    return set_cc_nz_f32(v2);
}

/* convert 64-bit float to 64-bit int */
uint32_t HELPER(cgdbr)(uint32_t r1, uint32_t f2, uint32_t m3)
{
    float64 v2 = env->fregs[f2].d;
    set_round_mode(m3);
    env->regs[r1] = float64_to_int64(v2, &env->fpu_status);
    return set_cc_nz_f64(v2);
}

/* convert 128-bit float to 64-bit int */
uint32_t HELPER(cgxbr)(uint32_t r1, uint32_t f2, uint32_t m3)
{
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    set_round_mode(m3);
    env->regs[r1] = float128_to_int64(v2.q, &env->fpu_status);
    if (float128_is_nan(v2.q)) return 3;
    else if (float128_is_zero(v2.q)) return 0;
    else if (float128_is_neg(v2.q)) return 1;
    else return 2;
}

/* convert 32-bit float to 32-bit int */
uint32_t HELPER(cfebr)(uint32_t r1, uint32_t f2, uint32_t m3)
{
    float32 v2 = env->fregs[f2].l.upper;
    set_round_mode(m3);
    env->regs[r1] = (env->regs[r1] & 0xffffffff00000000ULL) | float32_to_int32(v2, &env->fpu_status);
    return set_cc_nz_f32(v2);
}

/* convert 64-bit float to 32-bit int */
uint32_t HELPER(cfdbr)(uint32_t r1, uint32_t f2, uint32_t m3)
{
    float64 v2 = env->fregs[f2].d;
    set_round_mode(m3);
    env->regs[r1] = (env->regs[r1] & 0xffffffff00000000ULL) | float64_to_int32(v2, &env->fpu_status);
    return set_cc_nz_f64(v2);
}

/* convert 128-bit float to 32-bit int */
uint32_t HELPER(cfxbr)(uint32_t r1, uint32_t f2, uint32_t m3)
{
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    env->regs[r1] = (env->regs[r1] & 0xffffffff00000000ULL) | float128_to_int32(v2.q, &env->fpu_status);
    return set_cc_nz_f128(v2.q);
}

/* load 32-bit FP zero */
void HELPER(lzer)(uint32_t f1)
{
    env->fregs[f1].l.upper = float32_zero;
}

/* load 64-bit FP zero */
void HELPER(lzdr)(uint32_t f1)
{
    env->fregs[f1].d = float64_zero;
}

/* load 128-bit FP zero */
void HELPER(lzxr)(uint32_t f1)
{
    CPU_QuadU x;
    x.q = float64_to_float128(float64_zero, &env->fpu_status);
    env->fregs[f1].ll = x.ll.upper;
    env->fregs[f1 + 1].ll = x.ll.lower;
}

/* 128-bit FP subtraction RR */
uint32_t HELPER(sxbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU v1;
    v1.ll.upper = env->fregs[f1].ll;
    v1.ll.lower = env->fregs[f1 + 2].ll;
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    CPU_QuadU res;
    res.q = float128_sub(v1.q, v2.q, &env->fpu_status);
    env->fregs[f1].ll = res.ll.upper;
    env->fregs[f1 + 2].ll = res.ll.lower;
    return set_cc_nz_f128(res.q);
}

/* 128-bit FP addition RR */
uint32_t HELPER(axbr)(uint32_t f1, uint32_t f2)
{
    CPU_QuadU v1;
    v1.ll.upper = env->fregs[f1].ll;
    v1.ll.lower = env->fregs[f1 + 2].ll;
    CPU_QuadU v2;
    v2.ll.upper = env->fregs[f2].ll;
    v2.ll.lower = env->fregs[f2 + 2].ll;
    CPU_QuadU res;
    res.q = float128_add(v1.q, v2.q, &env->fpu_status);
    env->fregs[f1].ll = res.ll.upper;
    env->fregs[f1 + 2].ll = res.ll.lower;
    return set_cc_nz_f128(res.q);
}

/* 32-bit FP multiplication RR */
void HELPER(meebr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].l.upper = float32_mul(env->fregs[f1].l.upper, env->fregs[f2].l.upper, &env->fpu_status);
}

/* 64-bit FP division RR */
void HELPER(ddbr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].d = float64_div(env->fregs[f1].d, env->fregs[f2].d, &env->fpu_status);
}

/* 64-bit FP multiply and add RM */
void HELPER(madb)(uint32_t f1, uint64_t a2, uint32_t f3)
{
    HELPER_LOG("%s: f1 %d a2 0x%lx f3 %d\n", __FUNCTION__, f1, a2, f3);
    CPU_DoubleU v2;
    v2.ll = ldq(a2);
    env->fregs[f1].d = float64_add(env->fregs[f1].d, float64_mul(v2.d, env->fregs[f3].d, &env->fpu_status), &env->fpu_status);
}

/* 64-bit FP multiply and add RR */
void HELPER(madbr)(uint32_t f1, uint32_t f3, uint32_t f2)
{
    HELPER_LOG("%s: f1 %d f2 %d f3 %d\n", __FUNCTION__, f1, f2, f3);
    env->fregs[f1].d = float64_add(float64_mul(env->fregs[f2].d, env->fregs[f3].d, &env->fpu_status), env->fregs[f1].d, &env->fpu_status);
}

/* 64-bit FP multiply and subtract RR */
void HELPER(msdbr)(uint32_t f1, uint32_t f3, uint32_t f2)
{
    HELPER_LOG("%s: f1 %d f2 %d f3 %d\n", __FUNCTION__, f1, f2, f3);
    env->fregs[f1].d = float64_sub(float64_mul(env->fregs[f2].d, env->fregs[f3].d, &env->fpu_status), env->fregs[f1].d, &env->fpu_status);
}

/* 32-bit FP multiply and add RR */
void HELPER(maebr)(uint32_t f1, uint32_t f3, uint32_t f2)
{
    env->fregs[f1].l.upper = float32_add(env->fregs[f1].l.upper, float32_mul(env->fregs[f2].l.upper, env->fregs[f3].l.upper, &env->fpu_status), &env->fpu_status);
}

/* convert 64-bit float to 128-bit float */
void HELPER(lxdb)(uint32_t f1, uint64_t a2)
{
    CPU_DoubleU v2;
    v2.ll = ldq(a2);
    CPU_QuadU v1;
    v1.q = float64_to_float128(v2.d, &env->fpu_status);
    env->fregs[f1].ll = v1.ll.upper;
    env->fregs[f1 + 2].ll = v1.ll.lower;
}

/* test data class 32-bit */
uint32_t HELPER(tceb)(uint32_t f1, uint64_t m2)
{
    float32 v1 = env->fregs[f1].l.upper;
    int neg = float32_is_neg(v1);
    uint32_t cc = 0;
    HELPER_LOG("%s: v1 0x%lx m2 0x%lx neg %d\n", __FUNCTION__, v1, m2, neg);
    if (float32_is_zero(v1) && (m2 & (1 << (11-neg)))) cc = 1;
    else if (float32_is_infinity(v1) && (m2 & (1 << (5-neg)))) cc = 1;
    else if (float32_is_nan(v1) && (m2 & (1 << (3-neg)))) cc = 1;
    else if (float32_is_signaling_nan(v1) && (m2 & (1 << (1-neg)))) cc = 1;
    else /* assume normalized number */ if (m2 & (1 << (9-neg))) cc = 1;
    /* FIXME: denormalized? */
    return cc;
}

/* test data class 64-bit */
uint32_t HELPER(tcdb)(uint32_t f1, uint64_t m2)
{
    float64 v1 = env->fregs[f1].d;
    int neg = float64_is_neg(v1);
    uint32_t cc = 0;
    HELPER_LOG("%s: v1 0x%lx m2 0x%lx neg %d\n", __FUNCTION__, v1, m2, neg);
    if (float64_is_zero(v1) && (m2 & (1 << (11-neg)))) cc = 1;
    else if (float64_is_infinity(v1) && (m2 & (1 << (5-neg)))) cc = 1;
    else if (float64_is_nan(v1) && (m2 & (1 << (3-neg)))) cc = 1;
    else if (float64_is_signaling_nan(v1) && (m2 & (1 << (1-neg)))) cc = 1;
    else /* assume normalized number */ if (m2 & (1 << (9-neg))) cc = 1;
    /* FIXME: denormalized? */
    return cc;
}

/* test data class 128-bit */
uint32_t HELPER(tcxb)(uint32_t f1, uint64_t m2)
{
    CPU_QuadU v1;
    uint32_t cc = 0;
    v1.ll.upper = env->fregs[f1].ll;
    v1.ll.lower = env->fregs[f1 + 2].ll;
    
    int neg = float128_is_neg(v1.q);
    if (float128_is_zero(v1.q) && (m2 & (1 << (11-neg)))) cc = 1;
    else if (float128_is_infinity(v1.q) && (m2 & (1 << (5-neg)))) cc = 1;
    else if (float128_is_nan(v1.q) && (m2 & (1 << (3-neg)))) cc = 1;
    else if (float128_is_signaling_nan(v1.q) && (m2 & (1 << (1-neg)))) cc = 1;
    else /* assume normalized number */ if (m2 & (1 << (9-neg))) cc = 1;
    /* FIXME: denormalized? */
    return cc;
}

/* find leftmost one */
uint32_t HELPER(flogr)(uint32_t r1, uint64_t v2)
{
    uint64_t res = 0;
    uint64_t ov2 = v2;
    while (!(v2 & 0x8000000000000000ULL) && v2) {
        v2 <<= 1;
        res++;
    }
    if (!v2) {
        env->regs[r1] = 64;
        env->regs[r1 + 1] = 0;
        return 0;
    }
    else {
        env->regs[r1] = res;
        env->regs[r1 + 1] = ov2 & ~(0x8000000000000000ULL >> res);
        return 2;
    }
}

/* square root 64-bit RR */
void HELPER(sqdbr)(uint32_t f1, uint32_t f2)
{
    env->fregs[f1].d = float64_sqrt(env->fregs[f2].d, &env->fpu_status);
}
