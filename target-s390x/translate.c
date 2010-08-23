/*
 *  S/390 translation
 *
 *  Copyright (c) 2009 Ulrich Hecht
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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define S390X_DEBUG_DISAS
#ifdef S390X_DEBUG_DISAS
#  define LOG_DISAS(...) qemu_log(__VA_ARGS__)
#else
#  define LOG_DISAS(...) do { } while (0)
#endif

#include "cpu.h"
#include "exec-all.h"
#include "disas.h"
#include "tcg-op.h"
#include "qemu-log.h"

/* global register indexes */
static TCGv_ptr cpu_env;

#include "gen-icount.h"
#include "helpers.h"
#define GEN_HELPER 1
#include "helpers.h"

typedef struct DisasContext DisasContext;
struct DisasContext {
    uint64_t pc;
    int is_jmp;
    CPUS390XState *env;
    struct TranslationBlock *tb;
};

#define DISAS_EXCP 4
#define DISAS_SVC 5

void cpu_dump_state(CPUState *env, FILE *f,
                    int (*cpu_fprintf)(FILE *f, const char *fmt, ...),
                    int flags)
{
    int i;
    for (i = 0; i < 16; i++) {
        cpu_fprintf(f, "R%02d=%016lx", i, env->regs[i]);
        if ((i % 4) == 3) {
            cpu_fprintf(f, "\n");
        } else {
            cpu_fprintf(f, " ");
        }
    }
    for (i = 0; i < 16; i++) {
        cpu_fprintf(f, "F%02d=%016lx", i, env->fregs[i]);
        if ((i % 4) == 3) {
            cpu_fprintf(f, "\n");
        } else {
            cpu_fprintf(f, " ");
        }
    }
    cpu_fprintf(f, "PSW=mask %016lx addr %016lx cc %02x\n", env->psw.mask, env->psw.addr, env->cc);
}

#define TCGREGS

static TCGv global_cc;
#ifdef TCGREGS
/* registers stored in TCG variables enhance performance */
static TCGv_i64 tcgregs[16];
static TCGv_i32 tcgregs32[16];
#endif
static TCGv cc;
static TCGv psw_addr;

void s390x_translate_init(void)
{
    cpu_env = tcg_global_reg_new_ptr(TCG_AREG0, "env");
    global_cc = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUState, cc), "global_cc");
#ifdef TCGREGS
    int i;
    char rn[4];
    for (i = 0; i < 16; i++) {
        sprintf(rn, "R%d", i);
        tcgregs[i] = tcg_global_mem_new_i64(TCG_AREG0, offsetof(CPUState, regs[i]), strdup(rn));
        sprintf(rn, "r%d", i);
        tcgregs32[i] = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUState, regs[i])
#ifdef HOST_WORDS_BIGENDIAN
                                                                                     + 4
#endif
                                                                                        , strdup(rn));
    }
#endif
    psw_addr = tcg_global_mem_new_i64(TCG_AREG0, offsetof(CPUState, psw.addr), "psw_addr");
}

#ifdef TCGREGS
static inline void sync_reg64(int reg)
{
    tcg_gen_sync_i64(tcgregs[reg]);
}
static inline void sync_reg32(int reg)
{
    tcg_gen_sync_i32(tcgregs32[reg]);
}
#endif

static TCGv load_reg(int reg)
{
    TCGv r = tcg_temp_new_i64();
#ifdef TCGREGS
    sync_reg32(reg);
    tcg_gen_mov_i64(r, tcgregs[reg]);
    return r;
#else
    tcg_gen_ld_i64(r, cpu_env, offsetof(CPUState, regs[reg]));
    return r;
#endif
}

static TCGv load_freg(int reg)
{
    TCGv r = tcg_temp_new_i64();
    tcg_gen_ld_i64(r, cpu_env, offsetof(CPUState, fregs[reg].d));
    return r;
}

static TCGv_i32 load_freg32(int reg)
{
    TCGv_i32 r = tcg_temp_new_i32();
    tcg_gen_ld_i32(r, cpu_env, offsetof(CPUState, fregs[reg].l.upper));
    return r;
}

static void load_reg32_var(TCGv_i32 r, int reg)
{
#ifdef TCGREGS
    sync_reg64(reg);
    tcg_gen_mov_i32(r, tcgregs32[reg]);
#else
#ifdef HOST_WORDS_BIGENDIAN
    tcg_gen_ld_i32(r, cpu_env, offsetof(CPUState, regs[reg]) + 4);
#else
    tcg_gen_ld_i32(r, cpu_env, offsetof(CPUState, regs[reg]));
#endif
#endif
}

static TCGv_i32 load_reg32(int reg)
{
    TCGv_i32 r = tcg_temp_new_i32();
    load_reg32_var(r, reg);
    return r;
}

static void store_reg(int reg, TCGv v)
{
#ifdef TCGREGS
    sync_reg32(reg);
    tcg_gen_mov_i64(tcgregs[reg], v);
#else
    tcg_gen_st_i64(v, cpu_env, offsetof(CPUState, regs[reg]));
#endif
}

static void store_freg(int reg, TCGv v)
{
    tcg_gen_st_i64(v, cpu_env, offsetof(CPUState, fregs[reg].d));
}

static void store_reg32(int reg, TCGv_i32 v)
{
#ifdef TCGREGS
    sync_reg64(reg);
    tcg_gen_mov_i32(tcgregs32[reg], v);
#else
#ifdef HOST_WORDS_BIGENDIAN
    tcg_gen_st_i32(v, cpu_env, offsetof(CPUState, regs[reg]) + 4);
#else
    tcg_gen_st_i32(v, cpu_env, offsetof(CPUState, regs[reg]));
#endif
#endif
}

static void store_reg8(int reg, TCGv_i32 v)
{
#ifdef TCGREGS
    TCGv_i32 tmp = tcg_temp_new_i32();
    sync_reg64(reg);
    tcg_gen_andi_i32(tmp, tcgregs32[reg], 0xffffff00UL);
    tcg_gen_or_i32(tcgregs32[reg], tmp, v);
    tcg_temp_free(tmp);
#else
#ifdef HOST_WORDS_BIGENDIAN
    tcg_gen_st8_i32(v, cpu_env, offsetof(CPUState, regs[reg]) + 7);
#else
    tcg_gen_st8_i32(v, cpu_env, offsetof(CPUState, regs[reg]));
#endif
#endif
}

static void store_freg32(int reg, TCGv v)
{
    tcg_gen_st_i32(v, cpu_env, offsetof(CPUState, fregs[reg].l.upper));
}

static void gen_illegal_opcode(DisasContext *s)
{
    TCGv tmp = tcg_const_i64(EXCP_SPEC);
    gen_helper_exception(tmp);
    tcg_temp_free(tmp);
    s->is_jmp = DISAS_EXCP;
}

#define DEBUGINSN LOG_DISAS("insn: 0x%lx\n", insn);

static TCGv get_address(int x2, int b2, int d2)
{
    TCGv tmp = 0, tmp2;
    if (d2) tmp = tcg_const_i64(d2);
    if (x2) {
        if (d2) {
            tmp2 = load_reg(x2);
            tcg_gen_add_i64(tmp, tmp, tmp2);
            tcg_temp_free(tmp2);
        }
        else {
            tmp = load_reg(x2);
        }
    }
    if (b2) {
        if (d2 || x2) {
            tmp2 = load_reg(b2);
            tcg_gen_add_i64(tmp, tmp, tmp2);
            tcg_temp_free(tmp2);
        }
        else {
            tmp = load_reg(b2);
        }
    }
    
    if (!(d2 || x2 || b2)) tmp = tcg_const_i64(0);
    
    return tmp;
}

static inline void set_cc_nz_u32(TCGv val)
{
    gen_helper_set_cc_nz_u32(cc, val);
}

static inline void set_cc_nz_u64(TCGv val)
{
    gen_helper_set_cc_nz_u64(cc, val);
}

static inline void set_cc_s32(TCGv val)
{
    gen_helper_set_cc_s32(cc, val);
}

static inline void set_cc_s64(TCGv val)
{
    gen_helper_set_cc_s64(cc, val);
}

static inline void cmp_s32(TCGv v1, TCGv v2)
{
    gen_helper_cmp_s32(cc, v1, v2);
}

static inline void cmp_u32(TCGv v1, TCGv v2)
{
    gen_helper_cmp_u32(cc, v1, v2);
}

/* this is a hysterical raisin */
static inline void cmp_s32c(TCGv v1, int32_t v2)
{
    TCGv_i32 tmp = tcg_const_i32(v2);
    gen_helper_cmp_s32(cc, v1, tmp);
    tcg_temp_free(tmp);
}
static inline void cmp_u32c(TCGv v1, uint32_t v2)
{
    TCGv_i32 tmp = tcg_const_i32(v2);
    gen_helper_cmp_u32(cc, v1, tmp);
    tcg_temp_free(tmp);
}


static inline void cmp_s64(TCGv v1, TCGv v2)
{
    gen_helper_cmp_s64(cc, v1, v2);
}

static inline void cmp_u64(TCGv v1, TCGv v2)
{
    gen_helper_cmp_u64(cc, v1, v2);
}

/* see cmp_[su]32c() */
static inline void cmp_s64c(TCGv v1, int64_t v2)
{
    TCGv_i32 tmp = tcg_const_i64(v2);
    gen_helper_cmp_s64(cc, v1, tmp);
    tcg_temp_free(tmp);
}
static inline void cmp_u64c(TCGv v1, uint64_t v2)
{
    TCGv_i32 tmp = tcg_const_i64(v2);
    gen_helper_cmp_u64(cc, v1, tmp);
    tcg_temp_free(tmp);
}

static void gen_bcr(uint32_t mask, int tr, uint64_t offset)
{
    TCGv target, o;
    TCGv_i32 m;
    if (mask == 0xf) {	/* unconditional */
      target = load_reg(tr);
      tcg_gen_mov_i64(psw_addr, target);
    }
    else {
      m = tcg_const_i32(mask);
      o = tcg_const_i64(offset);
      gen_helper_bcr(cc, m, (target = load_reg(tr)), o);
      tcg_temp_free(m);
      tcg_temp_free(o);
    }
    tcg_temp_free(target);
}

static inline void gen_goto_tb(DisasContext *s, int tb_num, target_ulong pc)
{
    TranslationBlock *tb;

    tb = s->tb;
    /* NOTE: we handle the case where the TB spans two pages here */
    if ((pc & TARGET_PAGE_MASK) == (tb->pc & TARGET_PAGE_MASK) ||
        (pc & TARGET_PAGE_MASK) == ((s->pc - 1) & TARGET_PAGE_MASK))  {
        /* jump to same page: we can use a direct jump */
        tcg_gen_mov_i32(global_cc, cc);
        tcg_gen_goto_tb(tb_num);
        tcg_gen_movi_i64(psw_addr, pc);
        tcg_gen_exit_tb((long)tb + tb_num);
    } else {
        /* jump to another page: currently not optimized */
        tcg_gen_movi_i64(psw_addr, pc);
        tcg_gen_mov_i32(global_cc, cc);
        tcg_gen_exit_tb(0);
    }
}

static void gen_brc(uint32_t mask, DisasContext *s, int32_t offset)
{
    TCGv_i32 r;
    TCGv_i32 tmp, tmp2;
    int skip;
    
    if (mask == 0xf) {	/* unconditional */
      //tcg_gen_movi_i64(psw_addr, s->pc + offset);
      gen_goto_tb(s, 0, s->pc + offset);
    }
    else {
      tmp = tcg_const_i32(3);
      tcg_gen_sub_i32(tmp, tmp, cc);	/* 3 - cc */
      tmp2 = tcg_const_i32(1);
      tcg_gen_shl_i32(tmp2, tmp2, tmp);	/* 1 << (3 - cc) */
      r = tcg_const_i32(mask);
      tcg_gen_and_i32(r, r, tmp2);	/* mask & (1 << (3 - cc)) */
      tcg_temp_free(tmp);
      tcg_temp_free(tmp2);
      skip = gen_new_label();
      tcg_gen_brcondi_i32(TCG_COND_EQ, r, 0, skip);
      gen_goto_tb(s, 0, s->pc + offset);
      gen_set_label(skip);
      gen_goto_tb(s, 1, s->pc + 4);
      //tcg_gen_mov_i32(global_cc, cc);
      tcg_temp_free(r);
    }
    s->is_jmp = DISAS_TB_JUMP;
}

static void gen_set_cc_add64(TCGv v1, TCGv v2, TCGv vr)
{
    gen_helper_set_cc_add64(cc, v1, v2, vr);
}

static void disas_e3(DisasContext* s, int op, int r1, int x2, int b2, int d2)
{
    TCGv tmp, tmp2, tmp3;
    
    LOG_DISAS("disas_e3: op 0x%x r1 %d x2 %d b2 %d d2 %d\n", op, r1, x2, b2, d2);
    tmp = get_address(x2, b2, d2);
    switch (op) {
    case 0x2: /* LTG R1,D2(X2,B2) [RXY] */
    case 0x4: /* lg r1,d2(x2,b2) */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld64(tmp2, tmp, 1);
        store_reg(r1, tmp2);
        if (op == 0x2) set_cc_s64(tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x12: /* LT R1,D2(X2,B2) [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32s(tmp2, tmp, 1);
        store_reg32(r1, tmp2);
        set_cc_s32(tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0xc: /* MSG      R1,D2(X2,B2)     [RXY] */
    case 0x1c: /* MSGF     R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        if (op == 0xc) {
            tcg_gen_qemu_ld64(tmp2, tmp, 1);
        }
        else {
            tcg_gen_qemu_ld32s(tmp2, tmp, 1);
        }
        tcg_temp_free(tmp);
        tmp = load_reg(r1);
        tcg_gen_mul_i64(tmp, tmp, tmp2);
        store_reg(r1, tmp);
        tcg_temp_free(tmp2);
        break;
    case 0xd: /* DSG      R1,D2(X2,B2)     [RXY] */
    case 0x1d: /* DSGF      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        if (op == 0x1d) {
            tcg_gen_qemu_ld32s(tmp2, tmp, 1);
        }
        else {
            tcg_gen_qemu_ld64(tmp2, tmp, 1);
        }
        tcg_temp_free(tmp);
        tmp = load_reg(r1 + 1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_div_i64(tmp3, tmp, tmp2);
        store_reg(r1 + 1, tmp3);
        tcg_gen_rem_i64(tmp3, tmp, tmp2);
        store_reg(r1, tmp3);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x8: /* AG      R1,D2(X2,B2)     [RXY] */
    case 0xa: /* ALG      R1,D2(X2,B2)     [RXY] */
    case 0x18: /* AGF       R1,D2(X2,B2)     [RXY] */
    case 0x1a: /* ALGF      R1,D2(X2,B2)     [RXY] */
        if (op == 0x1a) {
            tmp2 = tcg_temp_new_i64();
            tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        }
        else if (op == 0x18) {
            tmp2 = tcg_temp_new_i64();
            tcg_gen_qemu_ld32s(tmp2, tmp, 1);
        }
        else {
            tmp2 = tcg_temp_new_i64();
            tcg_gen_qemu_ld64(tmp2, tmp, 1);
        }
        tcg_temp_free(tmp);
        tmp = load_reg(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_add_i64(tmp3, tmp, tmp2);
        store_reg(r1, tmp3);
        switch (op) {
        case 0x8: case 0x18: gen_set_cc_add64(tmp, tmp2, tmp3); break;
        case 0xa: case 0x1a: gen_helper_set_cc_addu64(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x9: /* SG      R1,D2(X2,B2)     [RXY] */
    case 0xb: /* SLG      R1,D2(X2,B2)     [RXY] */
    case 0x19: /* SGF      R1,D2(X2,B2)     [RXY] */
    case 0x1b: /* SLGF     R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        if (op == 0x19) {
            tcg_gen_qemu_ld32s(tmp2, tmp, 1);
        }
        else if (op == 0x1b) {
            tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        }
        else {
            tcg_gen_qemu_ld64(tmp2, tmp, 1);
        }
        tcg_temp_free(tmp);
        tmp = load_reg(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_sub_i64(tmp3, tmp, tmp2);
        store_reg(r1, tmp3);
        switch (op) {
        case 0x9: case 0x19: gen_helper_set_cc_sub64(cc, tmp, tmp2, tmp3); break;
        case 0xb: case 0x1b: gen_helper_set_cc_subu64(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x14: /* LGF      R1,D2(X2,B2)     [RXY] */
    case 0x16: /* LLGF      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        switch (op) {
        case 0x14: tcg_gen_ext32s_i64(tmp2, tmp2); break;
        case 0x16: break;
        default: tcg_abort();
        }
        store_reg(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x15: /* LGH     R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld16s(tmp2, tmp, 1);
        store_reg(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x17: /* LLGT      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        tcg_gen_andi_i64(tmp2, tmp2, 0x7fffffffULL);
        store_reg(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x1e: /* LRV R1,D2(X2,B2) [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        tcg_gen_bswap32_i64(tmp2, tmp2);
        store_reg32(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x20: /* CG      R1,D2(X2,B2)     [RXY] */
    case 0x21: /* CLG      R1,D2(X2,B2) */
    case 0x30: /* CGF       R1,D2(X2,B2)     [RXY] */
    case 0x31: /* CLGF      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        switch (op) {
        case 0x20:
        case 0x21:
            tcg_gen_qemu_ld64(tmp2, tmp, 1);
            break;
        case 0x30:
            tcg_gen_qemu_ld32s(tmp2, tmp, 1);
            break;
        case 0x31:
            tcg_gen_qemu_ld32u(tmp2, tmp, 1);
            break;
        default:
            tcg_abort();
        }
        tcg_temp_free(tmp);
        tmp = load_reg(r1);
        switch (op) {
        case 0x20: case 0x30: cmp_s64(tmp, tmp2); break;
        case 0x21: case 0x31: cmp_u64(tmp, tmp2); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp2);
        break;
    case 0x24: /* stg r1, d2(x2,b2) */
        tmp2 = load_reg(r1);
        tcg_gen_qemu_st64(tmp2, tmp, 1);
        tcg_temp_free(tmp2);
        break;
    case 0x3e: /* STRV R1,D2(X2,B2) [RXY] */
        tmp2 = load_reg32(r1);
        tcg_gen_bswap32_i32(tmp2, tmp2);
        tcg_gen_qemu_st32(tmp2, tmp, 1);
        tcg_temp_free(tmp2);
        break;
    case 0x50: /* STY  R1,D2(X2,B2) [RXY] */
        tmp2 = load_reg32(r1);
        tcg_gen_qemu_st32(tmp2, tmp, 1);
        tcg_temp_free(tmp2);
        break;
    case 0x57: /* XY R1,D2(X2,B2) [RXY] */
        tmp2 = load_reg32(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp3, tmp, 1);
        tcg_gen_xor_i32(tmp, tmp2, tmp3);
        store_reg32(r1, tmp);
        set_cc_nz_u32(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x58: /* LY R1,D2(X2,B2) [RXY] */
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp3, tmp, 1);
        store_reg32(r1, tmp3);
        tcg_temp_free(tmp3);
        break;
    case 0x5a: /* AY R1,D2(X2,B2) [RXY] */
    case 0x5b: /* SY R1,D2(X2,B2) [RXY] */
        tmp2 = load_reg32(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32s(tmp3, tmp, 1);
        switch (op) {
        case 0x5a: tcg_gen_add_i32(tmp, tmp2, tmp3); break;
        case 0x5b: tcg_gen_sub_i32(tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp);
        switch (op) {
        case 0x5a: gen_helper_set_cc_add32(cc, tmp2, tmp3, tmp); break;
        case 0x5b: gen_helper_set_cc_sub32(cc, tmp2, tmp3, tmp); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x71: /* LAY R1,D2(X2,B2) [RXY] */
        store_reg(r1, tmp);
        break;
    case 0x72: /* STCY R1,D2(X2,B2) [RXY] */
        tmp2 = load_reg32(r1);
        tcg_gen_qemu_st8(tmp2, tmp, 1);
        tcg_temp_free(tmp2);
        break;
    case 0x73: /* ICY R1,D2(X2,B2) [RXY] */
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp3, tmp, 1);
        store_reg8(r1, tmp3);
        tcg_temp_free(tmp3);
        break; 
    case 0x76: /* LB R1,D2(X2,B2) [RXY] */
    case 0x77: /* LGB R1,D2(X2,B2) [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8s(tmp2, tmp, 1);
        switch (op) {
        case 0x76:
            tcg_gen_ext8s_i64(tmp2, tmp2);
            store_reg32(r1, tmp2);
            break;
        case 0x77:
            tcg_gen_ext8s_i64(tmp2, tmp2);
            store_reg(r1, tmp2);
            break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp2);
        break;
    case 0x78: /* LHY R1,D2(X2,B2) [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld16s(tmp2, tmp, 1);
        store_reg32(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x80: /* NG      R1,D2(X2,B2)     [RXY] */
    case 0x81: /* OG      R1,D2(X2,B2)     [RXY] */
    case 0x82: /* XG      R1,D2(X2,B2)     [RXY] */
        tmp2 = load_reg(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld64(tmp3, tmp, 1);
        switch (op) {
        case 0x80: tcg_gen_and_i64(tmp, tmp2, tmp3); break;
        case 0x81: tcg_gen_or_i64(tmp, tmp2, tmp3); break;
        case 0x82: tcg_gen_xor_i64(tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        store_reg(r1, tmp);
        set_cc_nz_u64(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x86: /* MLG      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld64(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tmp = tcg_const_i32(r1);
        gen_helper_mlg(tmp, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x87: /* DLG      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld64(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tmp = tcg_const_i32(r1);
        gen_helper_dlg(tmp, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x88: /* ALCG      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld64(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tmp = load_reg(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_shri_i64(tmp3, cc, 1);
        tcg_gen_andi_i64(tmp3, tmp3, 1);
        tcg_gen_add_i64(tmp3, tmp2, tmp3);;
        tcg_gen_add_i64(tmp3, tmp, tmp3);
        store_reg(r1, tmp3);
        gen_helper_set_cc_addc_u64(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x89: /* SLBG      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld64(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tmp = load_reg(r1);
        tmp3 = tcg_const_i32(r1);
        gen_helper_slbg(cc, cc, tmp3, tmp, tmp2);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x90: /* LLGC      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp2, tmp, 1);
        store_reg(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x91: /* LLGH      R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld16u(tmp2, tmp, 1);
        store_reg(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x94: /* LLC     R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp2, tmp, 1);
        store_reg32(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x95: /* LLH     R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld16u(tmp2, tmp, 1);
        store_reg32(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x98: /* ALC     R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tmp = tcg_const_i32(r1);
        gen_helper_addc_u32(cc, cc, tmp, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x99: /* SLB     R1,D2(X2,B2)     [RXY] */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tmp = load_reg32(r1);
        tmp3 = tcg_const_i32(r1);
        gen_helper_slb(cc, cc, tmp3, tmp, tmp2);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    default:
        LOG_DISAS("illegal e3 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        break;
    }
    tcg_temp_free(tmp);
}

static void disas_eb(DisasContext *s, int op, int r1, int r3, int b2, int d2)
{
    TCGv tmp, tmp2, tmp3, tmp4;
    int i;
    
    LOG_DISAS("disas_eb: op 0x%x r1 %d r3 %d b2 %d d2 0x%x\n", op, r1, r3, b2, d2);
    switch (op) {
    case 0xc: /* SRLG     R1,R3,D2(B2)     [RSY] */
    case 0xd: /* SLLG     R1,R3,D2(B2)     [RSY] */
    case 0xa: /* SRAG     R1,R3,D2(B2)     [RSY] */
    case 0x1c: /* RLLG     R1,R3,D2(B2)     [RSY] */
        if (b2) {
            tmp = get_address(0, b2, d2);
            tcg_gen_andi_i64(tmp, tmp, 0x3f);
        } else {
            tmp = tcg_const_i64(d2 & 0x3f);
        }
        tmp2 = load_reg(r3);
        tmp3 = tcg_temp_new_i64();
        switch (op) {
        case 0xc: tcg_gen_shr_i64(tmp3, tmp2, tmp); break;
        case 0xd: tcg_gen_shl_i64(tmp3, tmp2, tmp); break;
        case 0xa: tcg_gen_sar_i64(tmp3, tmp2, tmp); break;
        case 0x1c: tcg_gen_rotl_i64(tmp3, tmp2, tmp); break;
        default: tcg_abort(); break;
        }
        store_reg(r1, tmp3);
        if (op == 0xa) set_cc_s64(tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x1d: /* RLL    R1,R3,D2(B2)        [RSY] */
        if (b2) {
            tmp = get_address(0, b2, d2);
            tcg_gen_andi_i64(tmp, tmp, 0x3f);
        } else {
            tmp = tcg_const_i64(d2 & 0x3f);
        }
        tmp2 = load_reg32(r3);
        tmp3 = tcg_temp_new_i32();
        switch (op) {
        case 0x1d: tcg_gen_rotl_i32(tmp3, tmp2, tmp); break;
        default: tcg_abort(); break;
        }
        store_reg32(r1, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x4: /* LMG     R1,R3,D2(B2)     [RSY] */
    case 0x24: /* stmg */
        /* Apparently, unrolling lmg/stmg of any size gains performance -
           even for very long ones... */
        if (r3 > r1) {
            tmp = get_address(0, b2, d2);
            for (i = r1; i <= r3; i++) {
                if (op == 0x4) {
                    tmp2 = tcg_temp_new_i64();
                    tcg_gen_qemu_ld64(tmp2, tmp, 1);
                    store_reg(i, tmp2);
                    /* At least one register is usually read after an lmg
                       (br %rsomething), which is why freeing them is
                       detrimental to performance */
                }
                else {
                    tmp2 = load_reg(i);
                    tcg_gen_qemu_st64(tmp2, tmp, 1);
                    /* R15 is usually read after an stmg; other registers
                       generally aren't and can be free'd */
                    if (i != 15) tcg_temp_free(tmp2);
                }
                tcg_gen_addi_i64(tmp, tmp, 8);
            }
        }
        else {
            tmp = tcg_const_i32(r1);
            tmp2 = tcg_const_i32(r3);
            tmp3 = tcg_const_i32(b2);
            tmp4 = tcg_const_i32(d2);
            if (op == 0x4) gen_helper_lmg(tmp, tmp2, tmp3, tmp4);
            else gen_helper_stmg(tmp, tmp2, tmp3, tmp4);
            tcg_temp_free(tmp2);
            tcg_temp_free(tmp3);
            tcg_temp_free(tmp4);
        }
        tcg_temp_free(tmp);
        break;
    case 0x2c: /* STCMH R1,M3,D2(B2) [RSY] */
        tmp2 = get_address(0, b2, d2);
        tmp = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r3);
        gen_helper_stcmh(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x30: /* CSG     R1,R3,D2(B2)     [RSY] */
        tmp2 = get_address(0, b2, d2);
        tmp = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r3);
        gen_helper_csg(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x3e: /* CDSG R1,R3,D2(B2) [RSY] */
        tmp2 = get_address(0, b2, d2);
        tmp = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r3);
        gen_helper_cdsg(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x51: /* TMY D1(B1),I2 [SIY] */
        tmp = get_address(0, b2, d2); /* SIY -> this is the destination */
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tmp = tcg_const_i32((r1 << 4) | r3);
        gen_helper_tm(cc, tmp2, tmp);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x52: /* MVIY D1(B1),I2 [SIY] */
        tmp2 = tcg_const_i32((r1 << 4) | r3);
        tmp = get_address(0, b2, d2); /* SIY -> this is the destination */
        tcg_gen_qemu_st8(tmp2, tmp, 1);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x55: /* CLIY D1(B1),I2 [SIY] */
        tmp3 = get_address(0, b2, d2); /* SIY -> this is the 1st operand */
        tmp = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp, tmp3, 1);
        cmp_u32c(tmp, (r1 << 4) | r3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp3);
        break;
    case 0x80: /* ICMH      R1,M3,D2(B2)     [RSY] */
        tmp2 = get_address(0, b2, d2);
        tmp = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r3);
        gen_helper_icmh(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    default:
        LOG_DISAS("illegal eb operation 0x%x\n", op);
        gen_illegal_opcode(s);
        break;
    }
}

static void disas_ed(DisasContext *s, int op, int r1, int x2, int b2, int d2, int r1b)
{
    TCGv_i32 tmp;
    TCGv tmp2, tmp3;
    tmp2 = get_address(x2, b2, d2);
    tmp = tcg_const_i32(r1);
    switch (op) {
    case 0x5: /* LXDB R1,D2(X2,B2) [RXE] */
        gen_helper_lxdb(tmp, tmp2);
        break;
    case 0x9: /* CEB    R1,D2(X2,B2)       [RXE] */
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp3, tmp2, 1);
        gen_helper_ceb(cc, tmp, tmp3);
        tcg_temp_free(tmp3);
        break;
    case 0xa: /* AEB    R1,D2(X2,B2)       [RXE] */
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp3, tmp2, 1);
        gen_helper_aeb(cc, tmp, tmp3);
        tcg_temp_free(tmp3);
        break;
    case 0xb: /* SEB    R1,D2(X2,B2)       [RXE] */
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp3, tmp2, 1);
        gen_helper_seb(cc, tmp, tmp3);
        tcg_temp_free(tmp3);
        break;
    case 0xd: /* DEB    R1,D2(X2,B2)       [RXE] */
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp3, tmp2, 1);
        gen_helper_deb(tmp, tmp3);
        tcg_temp_free(tmp3);
        break;
    case 0x10: /* TCEB   R1,D2(X2,B2)       [RXE] */
        gen_helper_tceb(cc, tmp, tmp2);
        break;
    case 0x11: /* TCDB   R1,D2(X2,B2)       [RXE] */
        gen_helper_tcdb(cc, tmp, tmp2);
        break;
    case 0x12: /* TCXB   R1,D2(X2,B2)       [RXE] */
        gen_helper_tcxb(cc, tmp, tmp2);
        break;
    case 0x17: /* MEEB   R1,D2(X2,B2)       [RXE] */
        tmp3 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp3, tmp2, 1);
        gen_helper_meeb(tmp, tmp3);
        tcg_temp_free(tmp3);
        break;
    case 0x19: /* CDB    R1,D2(X2,B2)       [RXE] */
        gen_helper_cdb(cc, tmp, tmp2);
        break;
    case 0x1a: /* ADB    R1,D2(X2,B2)       [RXE] */
        gen_helper_adb(cc, tmp, tmp2);
        break;
    case 0x1b: /* SDB    R1,D2(X2,B2)       [RXE] */
        gen_helper_sdb(cc, tmp, tmp2);
        break;
    case 0x1c: /* MDB    R1,D2(X2,B2)       [RXE] */
        gen_helper_mdb(tmp, tmp2);
        break;
    case 0x1d: /* DDB    R1,D2(X2,B2)       [RXE] */
        gen_helper_ddb(tmp, tmp2);
        break;
    case 0x1e: /* MADB  R1,R3,D2(X2,B2) [RXF] */
        /* for RXF insns, r1 is R3 and r1b is R1 */
        tmp3 = tcg_const_i32(r1b);
        gen_helper_madb(tmp3, tmp2, tmp);
        tcg_temp_free(tmp3);
        break;
    default:
        LOG_DISAS("illegal ed operation 0x%x\n", op);
        gen_illegal_opcode(s);
        return;
    }
    tcg_temp_free(tmp);
    tcg_temp_free(tmp2);
}

static void disas_a5(DisasContext *s, int op, int r1, int i2)
{
    TCGv tmp, tmp2;
    uint64_t vtmp;
    LOG_DISAS("disas_a5: op 0x%x r1 %d i2 0x%x\n", op, r1, i2);
    switch (op) {
    case 0x0: /* IIHH     R1,I2     [RI] */
    case 0x1: /* IIHL     R1,I2     [RI] */
        tmp = load_reg(r1);
        vtmp = i2;
        switch (op) {
        case 0x0: tcg_gen_andi_i64(tmp, tmp, 0x0000ffffffffffffULL); vtmp <<= 48; break;
        case 0x1: tcg_gen_andi_i64(tmp, tmp, 0xffff0000ffffffffULL); vtmp <<= 32; break;
        default: tcg_abort();
        }
        tcg_gen_ori_i64(tmp, tmp, vtmp);
        store_reg(r1, tmp);
        break;
    case 0x4: /* NIHH     R1,I2     [RI] */
    case 0x8: /* OIHH     R1,I2     [RI] */
        tmp = load_reg(r1);
        switch (op) {
        case 0x4:
            tmp2 = tcg_const_i64( (((uint64_t)i2) << 48) | 0x0000ffffffffffffULL);
            tcg_gen_and_i64(tmp, tmp, tmp2);
            break;
        case 0x8:
            tmp2 = tcg_const_i64(((uint64_t)i2) << 48);
            tcg_gen_or_i64(tmp, tmp, tmp2);
            break;
        default: tcg_abort();
        }
        store_reg(r1, tmp);
        tcg_gen_shri_i64(tmp2, tmp, 48);
        tcg_gen_trunc_i64_i32(tmp2, tmp2);
        set_cc_nz_u32(tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x5: /* NIHL     R1,I2     [RI] */
    case 0x9: /* OIHL     R1,I2     [RI] */
        tmp = load_reg(r1);
        switch (op) {
        case 0x5:
            tmp2 = tcg_const_i64( (((uint64_t)i2) << 32) | 0xffff0000ffffffffULL);
            tcg_gen_and_i64(tmp, tmp, tmp2);
            break;
        case 0x9:
            tmp2 = tcg_const_i64(((uint64_t)i2) << 32);
            tcg_gen_or_i64(tmp, tmp, tmp2);
            break;
        default: tcg_abort();
        }
        store_reg(r1, tmp);
        tcg_gen_shri_i64(tmp2, tmp, 32);
        tcg_gen_trunc_i64_i32(tmp2, tmp2);
        tcg_gen_andi_i32(tmp2, tmp2, 0xffff);
        set_cc_nz_u32(tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x6: /* NILH     R1,I2     [RI] */
    case 0xa: /* OILH     R1,I2     [RI] */
        tmp = load_reg(r1);
        switch (op) {
        case 0x6:
            tmp2 = tcg_const_i64( (((uint64_t)i2) << 16) | 0xffffffff0000ffffULL);
            tcg_gen_and_i64(tmp, tmp, tmp2);
            break;
        case 0xa:
            tmp2 = tcg_const_i64(((uint64_t)i2) << 16);
            tcg_gen_or_i64(tmp, tmp, tmp2);
            break;
        default: tcg_abort();
        }
        store_reg(r1, tmp);
        tcg_gen_shri_i64(tmp2, tmp, 16);
        tcg_gen_trunc_i64_i32(tmp2, tmp2);
        tcg_gen_andi_i32(tmp2, tmp2, 0xffff);
        set_cc_nz_u32(tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x7: /* NILL     R1,I2     [RI] */
    case 0xb: /* OILL     R1,I2     [RI] */
        tmp = load_reg(r1);
        switch (op) {
        case 0x7:
            tmp2 = tcg_const_i64(i2 | 0xffffffffffff0000ULL);
            tcg_gen_and_i64(tmp, tmp, tmp2);
            break;
        case 0xb: 
            tmp2 = tcg_const_i64(i2);
            tcg_gen_or_i64(tmp, tmp, tmp2);
            break;
        default: tcg_abort(); break;
        }
        store_reg(r1, tmp);
        tcg_gen_trunc_i64_i32(tmp, tmp);
        tcg_gen_andi_i32(tmp, tmp, 0xffff);
        set_cc_nz_u32(tmp);	/* signedness should not matter here */
        tcg_temp_free(tmp2);
        break;
    case 0xc: /* LLIHH     R1,I2     [RI] */
        tmp = tcg_const_i64( ((uint64_t)i2) << 48 );
        store_reg(r1, tmp);
        break;
    case 0xd: /* LLIHL     R1,I2     [RI] */
        tmp = tcg_const_i64( ((uint64_t)i2) << 32 );
        store_reg(r1, tmp);
        break;
    case 0xe: /* LLILH     R1,I2     [RI] */
        tmp = tcg_const_i64( ((uint64_t)i2) << 16 );
        store_reg(r1, tmp);
        break;
    case 0xf: /* LLILL     R1,I2     [RI] */
        tmp = tcg_const_i64(i2);
        store_reg(r1, tmp);
        break;
    default:
        LOG_DISAS("illegal a5 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        return;
    }
    tcg_temp_free(tmp);
}

static void disas_a7(DisasContext *s, int op, int r1, int i2)
{
    TCGv tmp, tmp2, tmp3;
    LOG_DISAS("disas_a7: op 0x%x r1 %d i2 0x%x\n", op, r1, i2);
    switch (op) {
    case 0x0: /* TMLH or TMH     R1,I2     [RI] */
        tmp = load_reg(r1);
        tcg_gen_shri_i64(tmp, tmp, 16);
        tmp2 = tcg_const_i32((uint16_t)i2);
        gen_helper_tmxx(cc, tmp, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x1: /* TMLL or TML     R1,I2     [RI] */
        tmp = load_reg(r1);
        tmp2 = tcg_const_i32((uint16_t)i2);
        gen_helper_tmxx(cc, tmp, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x2: /* TMHH     R1,I2     [RI] */
        tmp = load_reg(r1);
        tcg_gen_shri_i64(tmp, tmp, 48);
        tmp2 = tcg_const_i32((uint16_t)i2);
        gen_helper_tmxx(cc, tmp, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x3: /* TMHL     R1,I2     [RI] */
        tmp = load_reg(r1);
        tcg_gen_shri_i64(tmp, tmp, 32);
        tmp2 = tcg_const_i32((uint16_t)i2);
        gen_helper_tmxx(cc, tmp, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x4: /* brc m1, i2 */
        gen_brc(r1, s, i2 * 2);
        return;
    case 0x5: /* BRAS     R1,I2     [RI] */
        tmp = tcg_const_i64(s->pc + 4);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        tmp = tcg_const_i64(s->pc + i2 * 2);
        tcg_gen_st_i64(tmp, cpu_env, offsetof(CPUState, psw.addr));
        s->is_jmp = DISAS_JUMP;
        break;
    case 0x6: /* BRCT     R1,I2     [RI] */
        tmp = load_reg32(r1);
        tcg_gen_subi_i32(tmp, tmp, 1);
        store_reg32(r1, tmp);
        tmp2 = tcg_const_i64(s->pc);
        tmp3 = tcg_const_i32(i2 * 2);
        gen_helper_brct(tmp, tmp2, tmp3);
        s->is_jmp = DISAS_JUMP;
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x7: /* BRCTG     R1,I2     [RI] */
        tmp = load_reg(r1);
        tcg_gen_subi_i64(tmp, tmp, 1);
        store_reg(r1, tmp);
        tmp2 = tcg_const_i64(s->pc);
        tmp3 = tcg_const_i32(i2 * 2);
        gen_helper_brctg(tmp, tmp2, tmp3);
        s->is_jmp = DISAS_JUMP;
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x8: /* lhi r1, i2 */
        tmp = tcg_const_i32(i2);
        store_reg32(r1, tmp);
        break;
    case 0x9: /* lghi r1, i2 */
        tmp = tcg_const_i64(i2);
        store_reg(r1, tmp);
        break;
    case 0xa: /* AHI     R1,I2     [RI] */
        tmp = load_reg32(r1);
        tmp3 = tcg_temp_new_i32();
        tcg_gen_addi_i32(tmp3, tmp, i2);
        store_reg32(r1, tmp3);
        tmp2 = tcg_const_i32(i2);
        gen_helper_set_cc_add32(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0xb: /* aghi r1, i2 */
        tmp = load_reg(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_addi_i64(tmp3, tmp, i2);
        store_reg(r1, tmp3);
        tmp2 = tcg_const_i64(i2);
        gen_set_cc_add64(tmp, tmp2, tmp3);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0xc: /* MHI     R1,I2     [RI] */
        tmp = load_reg32(r1);
        tcg_gen_muli_i32(tmp, tmp, i2);
        store_reg32(r1, tmp);
        break;
    case 0xd: /* MGHI     R1,I2     [RI] */
        tmp = load_reg(r1);
        tcg_gen_muli_i64(tmp, tmp, i2);
        store_reg(r1, tmp);
        break;
    case 0xe: /* CHI     R1,I2     [RI] */
        tmp = load_reg32(r1);
        cmp_s32c(tmp, i2);
        break;
    case 0xf: /* CGHI     R1,I2     [RI] */
        tmp = load_reg(r1);
        cmp_s64c(tmp, i2);
        break;
    default:
        LOG_DISAS("illegal a7 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        return;
    }
    tcg_temp_free(tmp);
}

static void disas_b2(DisasContext *s, int op, int r1, int r2)
{
    TCGv_i32 tmp, tmp2, tmp3;
    LOG_DISAS("disas_b2: op 0x%x r1 %d r2 %d\n", op, r1, r2);
    switch (op) {
    case 0x22: /* IPM    R1               [RRE] */
        tmp = tcg_const_i32(r1);
        gen_helper_ipm(cc, tmp);
        break;
    case 0x4e: /* SAR     R1,R2     [RRE] */
        tmp = load_reg32(r2);
        tcg_gen_st_i32(tmp, cpu_env, offsetof(CPUState, aregs[r1]));
        break;
    case 0x4f: /* EAR     R1,R2     [RRE] */
        tmp = tcg_temp_new_i32();
        tcg_gen_ld_i32(tmp, cpu_env, offsetof(CPUState, aregs[r2]));
        store_reg32(r1, tmp);
        break;
    case 0x52: /* MSR     R1,R2     [RRE] */
        tmp = load_reg32(r1);
        tmp2 = load_reg32(r2);
        tcg_gen_mul_i32(tmp, tmp, tmp2);
        store_reg32(r1, tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x55: /* MVST     R1,R2     [RRE] */
        tmp = load_reg32(0);
        tmp2 = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r2);
        gen_helper_mvst(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x5d: /* CLST     R1,R2     [RRE] */
        tmp = load_reg32(0);
        tmp2 = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r2);
        gen_helper_clst(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x5e: /* SRST     R1,R2     [RRE] */
        tmp = load_reg32(0);
        tmp2 = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r2);
        gen_helper_srst(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    default:
        LOG_DISAS("illegal b2 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        return;
    }
    tcg_temp_free(tmp);
}

static void disas_b3(DisasContext *s, int op, int m3, int r1, int r2)
{
    TCGv_i32 tmp, tmp2, tmp3;
    LOG_DISAS("disas_b3: op 0x%x m3 0x%x r1 %d r2 %d\n", op, m3, r1, r2);
#define FP_HELPER(i) \
    tmp = tcg_const_i32(r1); \
    tmp2 = tcg_const_i32(r2); \
    gen_helper_ ## i (tmp, tmp2); \
    tcg_temp_free(tmp); \
    tcg_temp_free(tmp2);

#define FP_HELPER_CC(i) \
    tmp = tcg_const_i32(r1); \
    tmp2 = tcg_const_i32(r2); \
    gen_helper_ ## i (cc, tmp, tmp2); \
    tcg_temp_free(tmp); \
    tcg_temp_free(tmp2);

    switch (op) {
    case 0x0: /* LPEBR       R1,R2             [RRE] */
        FP_HELPER_CC(lpebr); break;
    case 0x2: /* LTEBR       R1,R2             [RRE] */
        FP_HELPER_CC(ltebr); break;
    case 0x3: /* LCEBR       R1,R2             [RRE] */
        FP_HELPER_CC(lcebr); break;
    case 0x4: /* LDEBR       R1,R2             [RRE] */
        FP_HELPER(ldebr); break;
    case 0x5: /* LXDBR       R1,R2             [RRE] */
        FP_HELPER(lxdbr); break;
    case 0x9: /* CEBR        R1,R2             [RRE] */
        FP_HELPER_CC(cebr); break;
    case 0xa: /* AEBR        R1,R2             [RRE] */
        FP_HELPER_CC(aebr); break;
    case 0xb: /* SEBR        R1,R2             [RRE] */
        FP_HELPER_CC(sebr); break;
    case 0xd: /* DEBR        R1,R2             [RRE] */
        FP_HELPER(debr); break;
    case 0x10: /* LPDBR       R1,R2             [RRE] */
        FP_HELPER_CC(lpdbr); break;
    case 0x12: /* LTDBR       R1,R2             [RRE] */
        FP_HELPER_CC(ltdbr); break;
    case 0x13: /* LCDBR       R1,R2             [RRE] */
        FP_HELPER_CC(lcdbr); break;
    case 0x15: /* SQBDR       R1,R2             [RRE] */
        FP_HELPER(sqdbr); break;
    case 0x17: /* MEEBR       R1,R2             [RRE] */
        FP_HELPER(meebr); break;
    case 0x19: /* CDBR        R1,R2             [RRE] */
        FP_HELPER_CC(cdbr); break;
    case 0x1a: /* ADBR        R1,R2             [RRE] */
        FP_HELPER_CC(adbr); break;
    case 0x1b: /* SDBR        R1,R2             [RRE] */
        FP_HELPER_CC(sdbr); break;
    case 0x1c: /* MDBR        R1,R2             [RRE] */
        FP_HELPER(mdbr); break;
    case 0x1d: /* DDBR        R1,R2             [RRE] */
        FP_HELPER(ddbr); break;
    case 0xe: /* MAEBR  R1,R3,R2 [RRF] */
    case 0x1e: /* MADBR R1,R3,R2 [RRF] */
    case 0x1f: /* MSDBR R1,R3,R2 [RRF] */
        /* for RRF insns, m3 is R1, r1 is R3, and r2 is R2 */
        tmp = tcg_const_i32(m3);
        tmp2 = tcg_const_i32(r2);
        tmp3 = tcg_const_i32(r1);
        switch (op) {
        case 0xe: gen_helper_maebr(tmp, tmp3, tmp2); break;
        case 0x1e: gen_helper_madbr(tmp, tmp3, tmp2); break;
        case 0x1f: gen_helper_msdbr(tmp, tmp3, tmp2); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x40: /* LPXBR       R1,R2             [RRE] */
        FP_HELPER_CC(lpxbr); break;
    case 0x42: /* LTXBR       R1,R2             [RRE] */
        FP_HELPER_CC(ltxbr); break;
    case 0x43: /* LCXBR       R1,R2             [RRE] */
        FP_HELPER_CC(lcxbr); break;
    case 0x44: /* LEDBR       R1,R2             [RRE] */
        FP_HELPER(ledbr); break;
    case 0x45: /* LDXBR       R1,R2             [RRE] */
        FP_HELPER(ldxbr); break;
    case 0x46: /* LEXBR       R1,R2             [RRE] */
        FP_HELPER(lexbr); break;
    case 0x49: /* CXBR        R1,R2             [RRE] */
        FP_HELPER_CC(cxbr); break;
    case 0x4a: /* AXBR        R1,R2             [RRE] */
        FP_HELPER_CC(axbr); break;
    case 0x4b: /* SXBR        R1,R2             [RRE] */
        FP_HELPER_CC(sxbr); break;
    case 0x4c: /* MXBR        R1,R2             [RRE] */
        FP_HELPER(mxbr); break;
    case 0x4d: /* DXBR        R1,R2             [RRE] */
        FP_HELPER(dxbr); break;
    case 0x65: /* LXR         R1,R2             [RRE] */
        tmp = load_freg(r2);
        store_freg(r1, tmp);
        tcg_temp_free(tmp);
        tmp = load_freg(r2 + 2);
        store_freg(r1 + 2, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x74: /* LZER        R1                [RRE] */
        tmp = tcg_const_i32(r1);
        gen_helper_lzer(tmp);
        tcg_temp_free(tmp);
        break;
    case 0x75: /* LZDR        R1                [RRE] */
        tmp = tcg_const_i32(r1);
        gen_helper_lzdr(tmp);
        tcg_temp_free(tmp);
        break;
    case 0x76: /* LZXR        R1                [RRE] */
        tmp = tcg_const_i32(r1);
        gen_helper_lzxr(tmp);
        tcg_temp_free(tmp);
        break;
    case 0x84: /* SFPC        R1                [RRE] */
        tmp = load_reg32(r1);
        tcg_gen_st_i32(tmp, cpu_env, offsetof(CPUState, fpc));
        tcg_temp_free(tmp);
        break;
    case 0x8c: /* EFPC        R1                [RRE] */
        tmp = tcg_temp_new_i32();
        tcg_gen_ld_i32(tmp, cpu_env, offsetof(CPUState, fpc));
        store_reg32(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x94: /* CEFBR       R1,R2             [RRE] */
    case 0x95: /* CDFBR       R1,R2             [RRE] */
    case 0x96: /* CXFBR       R1,R2             [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = load_reg32(r2);
        switch (op) {
        case 0x94: gen_helper_cefbr(tmp, tmp2); break;
        case 0x95: gen_helper_cdfbr(tmp, tmp2); break;
        case 0x96: gen_helper_cxfbr(tmp, tmp2); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x98: /* CFEBR       R1,R2             [RRE] */
    case 0x99: /* CFDBR	      R1,R2             [RRE] */
    case 0x9a: /* CFXBR       R1,R2             [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = tcg_const_i32(r2);
        tmp3 = tcg_const_i32(m3);
        switch (op) {
        case 0x98: gen_helper_cfebr(cc, tmp, tmp2, tmp3); break;
        case 0x99: gen_helper_cfdbr(cc, tmp, tmp2, tmp3); break;
        case 0x9a: gen_helper_cfxbr(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0xa4: /* CEGBR       R1,R2             [RRE] */
    case 0xa5: /* CDGBR       R1,R2             [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = load_reg(r2);
        switch (op) {
        case 0xa4: gen_helper_cegbr(tmp, tmp2); break;
        case 0xa5: gen_helper_cdgbr(tmp, tmp2); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0xa6: /* CXGBR       R1,R2             [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = load_reg(r2);
        gen_helper_cxgbr(tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0xa8: /* CGEBR       R1,R2             [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = tcg_const_i32(r2);
        tmp3 = tcg_const_i32(m3);
        gen_helper_cgebr(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0xa9: /* CGDBR       R1,R2             [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = tcg_const_i32(r2);
        tmp3 = tcg_const_i32(m3);
        gen_helper_cgdbr(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0xaa: /* CGXBR       R1,R2             [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = tcg_const_i32(r2);
        tmp3 = tcg_const_i32(m3);
        gen_helper_cgxbr(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    default:
        LOG_DISAS("illegal b3 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        break;
    }
}

static void disas_b9(DisasContext *s, int op, int r1, int r2)
{
    TCGv tmp, tmp2, tmp3;
    LOG_DISAS("disas_b9: op 0x%x r1 %d r2 %d\n", op, r1, r2);
    switch (op) {
    case 0: /* LPGR     R1,R2     [RRE] */
    case 0x10: /* LPGFR R1,R2 [RRE] */
        if (op == 0) {
            tmp2 = load_reg(r2);
        }
        else {
            tmp2 = load_reg32(r2);
            tcg_gen_ext32s_i64(tmp2, tmp2);
        }
        tmp = tcg_const_i32(r1);
        gen_helper_abs_i64(cc, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 1: /* LNGR     R1,R2     [RRE] */
        tmp2 = load_reg(r2);
        tmp = tcg_const_i32(r1);
        gen_helper_nabs_i64(cc, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 2: /* LTGR R1,R2 [RRE] */
        tmp = load_reg(r2);
        if (r1 != r2) store_reg(r1, tmp);
        set_cc_s64(tmp);
        tcg_temp_free(tmp);
        break;
    case 3: /* LCGR     R1,R2     [RRE] */
    case 0x13: /* LCGFR    R1,R2     [RRE] */
        if (op == 0x13) {
            tmp = load_reg32(r2);
            tcg_gen_ext32s_i64(tmp, tmp);
        }
        else {
            tmp = load_reg(r2);
        }
        tcg_gen_neg_i64(tmp, tmp);
        store_reg(r1, tmp);
        gen_helper_set_cc_comp_s64(cc, tmp);
        tcg_temp_free(tmp);
        break;
    case 4: /* LGR R1,R2 [RRE] */
        tmp = load_reg(r2);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x6: /* LGBR R1,R2 [RRE] */
        tmp2 = load_reg(r2);
        tcg_gen_ext8s_i64(tmp2, tmp2);
        store_reg(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 8: /* AGR     R1,R2     [RRE] */
    case 0xa: /* ALGR     R1,R2     [RRE] */
        tmp = load_reg(r1);
        tmp2 = load_reg(r2);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_add_i64(tmp3, tmp, tmp2);
        store_reg(r1, tmp3);
        switch (op) {
        case 0x8: gen_set_cc_add64(tmp, tmp2, tmp3); break;
        case 0xa: gen_helper_set_cc_addu64(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 9: /* SGR     R1,R2     [RRE] */
    case 0xb: /* SLGR     R1,R2     [RRE] */
    case 0x1b: /* SLGFR     R1,R2     [RRE] */
    case 0x19: /* SGFR     R1,R2     [RRE] */
        tmp = load_reg(r1);
        switch (op) {
        case 0x1b: case 0x19:
            tmp2 = load_reg32(r2);
            if (op == 0x19) tcg_gen_ext32s_i64(tmp2, tmp2);
            else tcg_gen_ext32u_i64(tmp2, tmp2);
            break;
        default:
            tmp2 = load_reg(r2);
            break;
        }
        tmp3 = tcg_temp_new_i64();
        tcg_gen_sub_i64(tmp3, tmp, tmp2);
        store_reg(r1, tmp3);
        switch (op) {
        case 9: case 0x19: gen_helper_set_cc_sub64(cc, tmp,tmp2,tmp3); break;
        case 0xb: case 0x1b: gen_helper_set_cc_subu64(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0xc: /* MSGR      R1,R2     [RRE] */
    case 0x1c: /* MSGFR      R1,R2     [RRE] */
        tmp = load_reg(r1);
        tmp2 = load_reg(r2);
        if (op == 0x1c) tcg_gen_ext32s_i64(tmp2, tmp2);
        tcg_gen_mul_i64(tmp, tmp, tmp2);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0xd: /* DSGR      R1,R2     [RRE] */
    case 0x1d: /* DSGFR      R1,R2     [RRE] */
        tmp = load_reg(r1 + 1);
        if (op == 0xd) {
            tmp2 = load_reg(r2);
        }
        else {
            tmp2 = load_reg32(r2);
            tcg_gen_ext32s_i64(tmp2, tmp2);
        }
        tmp3 = tcg_temp_new_i64();
        tcg_gen_div_i64(tmp3, tmp, tmp2);
        store_reg(r1 + 1, tmp3);
        tcg_gen_rem_i64(tmp3, tmp, tmp2);
        store_reg(r1, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x14: /* LGFR     R1,R2     [RRE] */
        tmp = load_reg32(r2);
        tmp2 = tcg_temp_new_i64();
        tcg_gen_ext32s_i64(tmp2, tmp);
        store_reg(r1, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x16: /* LLGFR      R1,R2     [RRE] */
        tmp = load_reg32(r2);
        tcg_gen_ext32u_i64(tmp, tmp);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x17: /* LLGTR      R1,R2     [RRE] */
        tmp = load_reg32(r2);
        tcg_gen_andi_i64(tmp, tmp, 0x7fffffffUL);
        tcg_gen_ext32u_i64(tmp, tmp);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x18: /* AGFR     R1,R2     [RRE] */
    case 0x1a: /* ALGFR     R1,R2     [RRE] */
        tmp2 = load_reg32(r2);
        switch (op) {
        case 0x18: tcg_gen_ext32s_i64(tmp2, tmp2); break;
        case 0x1a: tcg_gen_ext32u_i64(tmp2, tmp2); break;
        default: tcg_abort();
        }
        tmp = load_reg(r1);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_add_i64(tmp3, tmp, tmp2);
        store_reg(r1, tmp3);
        switch (op) {
        case 0x18: gen_set_cc_add64(tmp, tmp2, tmp3); break;
        case 0x1a: gen_helper_set_cc_addu64(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x20: /* CGR     R1,R2     [RRE] */
    case 0x30: /* CGFR     R1,R2     [RRE] */
        tmp2 = load_reg(r2);
        if (op == 0x30) tcg_gen_ext32s_i64(tmp2, tmp2);
        tmp = load_reg(r1);
        cmp_s64(tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x21: /* CLGR     R1,R2     [RRE] */
    case 0x31: /* CLGFR    R1,R2     [RRE] */
        tmp2 = load_reg(r2);
        if (op == 0x31) tcg_gen_ext32u_i64(tmp2, tmp2);
        tmp = load_reg(r1);
        cmp_u64(tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x26: /* LBR R1,R2 [RRE] */
        tmp2 = load_reg32(r2);
        tcg_gen_ext8s_i32(tmp2, tmp2);
        store_reg32(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x27: /* LHR R1,R2 [RRE] */
        tmp2 = load_reg32(r2);
        tcg_gen_ext16s_i32(tmp2, tmp2);
        store_reg32(r1, tmp2);
        tcg_temp_free(tmp2);
        break;
    case 0x80: /* NGR R1,R2 [RRE] */
    case 0x81: /* OGR R1,R2 [RRE] */
    case 0x82: /* XGR R1,R2 [RRE] */
        tmp = load_reg(r1);
        tmp2 = load_reg(r2);
        switch (op) {
        case 0x80: tcg_gen_and_i64(tmp, tmp, tmp2); break;
        case 0x81: tcg_gen_or_i64(tmp, tmp, tmp2); break;
        case 0x82: tcg_gen_xor_i64(tmp, tmp, tmp2); break;
        default: tcg_abort();
        }
        store_reg(r1, tmp);
        set_cc_nz_u64(tmp);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x83: /* FLOGR R1,R2 [RRE] */
        tmp2 = load_reg(r2);
        tmp = tcg_const_i32(r1);
        gen_helper_flogr(cc, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x84: /* LLGCR R1,R2 [RRE] */
        tmp = load_reg(r2);
        tcg_gen_andi_i64(tmp, tmp, 0xff);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x85: /* LLGHR R1,R2 [RRE] */
        tmp = load_reg(r2);
        tcg_gen_andi_i64(tmp, tmp, 0xffff);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x87: /* DLGR      R1,R2     [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = load_reg(r2);
        gen_helper_dlg(tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x88: /* ALCGR     R1,R2     [RRE] */
        tmp = load_reg(r1);
        tmp2 = load_reg(r2);
        tmp3 = tcg_temp_new_i64();
        tcg_gen_shri_i64(tmp3, cc, 1);
        tcg_gen_andi_i64(tmp3, tmp3, 1);
        tcg_gen_add_i64(tmp3, tmp2, tmp3);
        tcg_gen_add_i64(tmp3, tmp, tmp3);
        store_reg(r1, tmp3);
        gen_helper_set_cc_addc_u64(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x89: /* SLBGR   R1,R2     [RRE] */
        tmp = load_reg(r1);
        tmp2 = load_reg(r2);
        tmp3 = tcg_const_i32(r1);
        gen_helper_slbg(cc, cc, tmp3, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x94: /* LLCR R1,R2 [RRE] */
        tmp = load_reg32(r2);
        tcg_gen_andi_i32(tmp, tmp, 0xff);
        store_reg32(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x95: /* LLHR R1,R2 [RRE] */
        tmp = load_reg32(r2);
        tcg_gen_andi_i32(tmp, tmp, 0xffff);
        store_reg32(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x98: /* ALCR    R1,R2     [RRE] */
        tmp = tcg_const_i32(r1);
        tmp2 = load_reg32(r2);
        gen_helper_addc_u32(cc, cc, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x99: /* SLBR    R1,R2     [RRE] */
        tmp = load_reg32(r1);
        tmp2 = load_reg32(r2);
        tmp3 = tcg_const_i32(r1);
        gen_helper_slb(cc, cc, tmp3, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    default:
        LOG_DISAS("illegal b9 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        break;
    }
}

static void disas_c0(DisasContext *s, int op, int r1, int i2)
{
    TCGv tmp, tmp2, tmp3;
    LOG_DISAS("disas_c0: op 0x%x r1 %d i2 %d\n", op, r1, i2);
    uint64_t target = s->pc + i2 * 2;
    /* FIXME: huh? */ target &= 0xffffffff;
    switch (op) {
    case 0: /* larl r1, i2 */
        tmp = tcg_const_i64(target);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x1: /* LGFI R1,I2 [RIL] */
        tmp = tcg_const_i64((int64_t)i2);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0x4: /* BRCL     M1,I2     [RIL] */
        tmp = tcg_const_i32(r1); /* aka m1 */
        tmp2 = tcg_const_i64(s->pc);
        tmp3 = tcg_const_i64(i2 * 2);
        gen_helper_brcl(cc, tmp, tmp2, tmp3);
        s->is_jmp = DISAS_JUMP;
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x5: /* brasl r1, i2 */
        tmp = tcg_const_i64(s->pc + 6);
        store_reg(r1, tmp);
        tmp = tcg_const_i64(target);
        tcg_gen_st_i64(tmp, cpu_env, offsetof(CPUState, psw.addr));
        s->is_jmp = DISAS_JUMP;
        tcg_temp_free(tmp);
        break;
    case 0x7: /* XILF R1,I2 [RIL] */
    case 0xb: /* NILF R1,I2 [RIL] */
    case 0xd: /* OILF R1,I2 [RIL] */
        tmp = load_reg32(r1);
        switch (op) {
        case 0x7: tcg_gen_xori_i32(tmp, tmp, (uint32_t)i2); break;
        case 0xb: tcg_gen_andi_i32(tmp, tmp, (uint32_t)i2); break;
        case 0xd: tcg_gen_ori_i32(tmp, tmp, (uint32_t)i2); break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp);
        tcg_gen_trunc_i64_i32(tmp, tmp);
        set_cc_nz_u32(tmp);
        tcg_temp_free(tmp);
        break;
    case 0x9: /* IILF R1,I2 [RIL] */
        tmp = tcg_const_i32((uint32_t)i2);
        store_reg32(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0xa: /* NIHF R1,I2 [RIL] */
        tmp = load_reg(r1);
        switch (op) {
        case 0xa: tcg_gen_andi_i64(tmp, tmp, (((uint64_t)((uint32_t)i2)) << 32) | 0xffffffffULL); break;
        default: tcg_abort();
        }
        store_reg(r1, tmp);
        tcg_gen_shr_i64(tmp, tmp, 32);
        tcg_gen_trunc_i64_i32(tmp, tmp);
        set_cc_nz_u32(tmp);
        tcg_temp_free(tmp);
        break;
    case 0xe: /* LLIHF R1,I2 [RIL] */
        tmp = tcg_const_i64(((uint64_t)(uint32_t)i2) << 32);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    case 0xf: /* LLILF R1,I2 [RIL] */
        tmp = tcg_const_i64((uint32_t)i2);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        break;
    default:
        LOG_DISAS("illegal c0 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        break;
    }
}

static void disas_c2(DisasContext *s, int op, int r1, int i2)
{
    TCGv tmp, tmp2, tmp3;
    switch (op) {
    case 0x4: /* SLGFI R1,I2 [RIL] */
    case 0xa: /* ALGFI R1,I2 [RIL] */
        tmp = load_reg(r1);
        tmp2 = tcg_const_i64((uint64_t)(uint32_t)i2);
        tmp3 = tcg_temp_new_i64();
        switch (op) {
        case 0x4:
            tcg_gen_sub_i64(tmp3, tmp, tmp2);
            gen_helper_set_cc_subu64(cc, tmp, tmp2, tmp3);
            break;
        case 0xa:
            tcg_gen_add_i64(tmp3, tmp, tmp2);
            gen_helper_set_cc_addu64(cc, tmp, tmp2, tmp3);
            break;
        default: tcg_abort();
        }
        store_reg(r1, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0x5: /* SLFI R1,I2 [RIL] */
    case 0xb: /* ALFI R1,I2 [RIL] */
        tmp = load_reg32(r1);
        tmp2 = tcg_const_i32(i2);
        tmp3 = tcg_temp_new_i32();
        switch (op) {
        case 0x5:
            tcg_gen_sub_i32(tmp3, tmp, tmp2);
            gen_helper_set_cc_subu32(cc, tmp, tmp2, tmp3);
            break;
        case 0xb:
            tcg_gen_add_i32(tmp3, tmp, tmp2);
            gen_helper_set_cc_addu32(cc, tmp, tmp2, tmp3);
            break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        break;
    case 0xc: /* CGFI R1,I2 [RIL] */
        tmp = load_reg(r1);
        cmp_s64c(tmp, (int64_t)i2);
        tcg_temp_free(tmp);
        break;
    case 0xe: /* CLGFI R1,I2 [RIL] */
        tmp = load_reg(r1);
        cmp_u64c(tmp, (uint64_t)(uint32_t)i2);
        tcg_temp_free(tmp);
        break;
    case 0xd: /* CFI R1,I2 [RIL] */
    case 0xf: /* CLFI R1,I2 [RIL] */
        tmp = load_reg32(r1);
        switch (op) {
        case 0xd: cmp_s32c(tmp, i2); break;
        case 0xf: cmp_u32c(tmp, i2); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        break;
    default:
        LOG_DISAS("illegal c2 operation 0x%x\n", op);
        gen_illegal_opcode(s);
        break;
    }
}

static inline uint64_t ld_code2(uint64_t pc)
{
    return (uint64_t)lduw_code(pc);
}

static inline uint64_t ld_code4(uint64_t pc)
{
    return (uint64_t)ldl_code(pc);
}

static inline uint64_t ld_code6(uint64_t pc)
{
    uint64_t opc;
    opc = (uint64_t)lduw_code(pc) << 32;
    opc |= (uint64_t)(unsigned int)ldl_code(pc+2);
    return opc;
}

static void disas_s390_insn(CPUState *env, DisasContext *s)
{
    TCGv tmp, tmp2, tmp3;
    unsigned char opc;
    uint64_t insn;
    int op, r1, r2, r3, d1, d2, x2, b1, b2, i, i2, r1b;
    TCGv vl, vd1, vd2, vb;
    
    opc = ldub_code(s->pc);
    LOG_DISAS("opc 0x%x\n", opc);

#define FETCH_DECODE_RR \
    insn = ld_code2(s->pc); \
    DEBUGINSN \
    r1 = (insn >> 4) & 0xf; \
    r2 = insn & 0xf;

#define FETCH_DECODE_RX \
    insn = ld_code4(s->pc); \
    DEBUGINSN \
    r1 = (insn >> 20) & 0xf; \
    x2 = (insn >> 16) & 0xf; \
    b2 = (insn >> 12) & 0xf; \
    d2 = insn & 0xfff; \
    tmp = get_address(x2, b2, d2);

#define FREE_RX \
    tcg_temp_free(tmp);

#define FETCH_DECODE_RS \
    insn = ld_code4(s->pc); \
    DEBUGINSN \
    r1 = (insn >> 20) & 0xf; \
    r3 = (insn >> 16) & 0xf; /* aka m3 */ \
    b2 = (insn >> 12) & 0xf; \
    d2 = insn & 0xfff;
        
#define FETCH_DECODE_SI \
    insn = ld_code4(s->pc); \
    i2 = (insn >> 16) & 0xff; \
    b1 = (insn >> 12) & 0xf; \
    d1 = insn & 0xfff; \
    tmp = get_address(0, b1, d1);

#define FREE_SI \
    tcg_temp_free(tmp);

    switch (opc) {
    case 0x7: /* BCR    M1,R2     [RR] */
        FETCH_DECODE_RR
        if (r2) {
            gen_bcr(r1, r2, s->pc);
            s->is_jmp = DISAS_JUMP;
        }
        else {
            /* FIXME: "serialization and checkpoint-synchronization function"? */
        }
        s->pc += 2;
        break;
    case 0xa: /* SVC    I         [RR] */
        insn = ld_code2(s->pc);
        DEBUGINSN
        i = insn & 0xff;
        tmp = tcg_const_i64(s->pc);
        tcg_gen_st_i64(tmp, cpu_env, offsetof(CPUState, psw.addr));
        tcg_temp_free(tmp);
        s->is_jmp = DISAS_SVC;
        s->pc += 2;
        break;
    case 0xd: /* BASR   R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp = tcg_const_i64(s->pc + 2);
        store_reg(r1, tmp);
        if (r2) {
            tmp2 = load_reg(r2);
            tcg_gen_st_i64(tmp2, cpu_env, offsetof(CPUState, psw.addr));
            tcg_temp_free(tmp2);
            s->is_jmp = DISAS_JUMP;
        }
        tcg_temp_free(tmp);
        s->pc += 2;
        break;
    case 0x10: /* LPR    R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp2 = load_reg32(r2);
        tmp = tcg_const_i32(r1);
        gen_helper_abs_i32(cc, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 2;
        break;
    case 0x11: /* LNR    R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp2 = load_reg32(r2);
        tmp = tcg_const_i32(r1);
        gen_helper_nabs_i32(cc, tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 2;
        break;
    case 0x12: /* LTR    R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp = load_reg32(r2);
        if (r1 != r2) store_reg32(r1, tmp);
        set_cc_s32(tmp);
        tcg_temp_free(tmp);
        s->pc += 2;
        break;
    case 0x13: /* LCR    R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp = load_reg32(r2);
        tcg_gen_neg_i32(tmp, tmp);
        store_reg32(r1, tmp);
        gen_helper_set_cc_comp_s32(cc, tmp);
        tcg_temp_free(tmp);
        s->pc += 2;
        break;
    case 0x14: /* NR     R1,R2     [RR] */
    case 0x16: /* OR     R1,R2     [RR] */
    case 0x17: /* XR     R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp2 = load_reg32(r2);
        tmp = load_reg32(r1);
        switch (opc) {
        case 0x14: tcg_gen_and_i32(tmp, tmp, tmp2); break;
        case 0x16: tcg_gen_or_i32(tmp, tmp, tmp2); break;
        case 0x17: tcg_gen_xor_i32(tmp, tmp, tmp2); break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp);
        set_cc_nz_u32(tmp);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 2;
        break;
    case 0x18: /* LR     R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp = load_reg32(r2);
        store_reg32(r1, tmp);
        tcg_temp_free(tmp);
        s->pc += 2;
        break;
    case 0x15: /* CLR    R1,R2     [RR] */
    case 0x19: /* CR     R1,R2     [RR] */ 
        FETCH_DECODE_RR
        tmp = load_reg32(r1);
        tmp2 = load_reg32(r2);
        switch (opc) {
        case 0x15: cmp_u32(tmp, tmp2); break;
        case 0x19: cmp_s32(tmp, tmp2); break;
        default: tcg_abort();
        }
        s->pc += 2;
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x1a: /* AR     R1,R2     [RR] */
    case 0x1e: /* ALR    R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp = load_reg32(r1);
        tmp2 = load_reg32(r2);
        tmp3 = tcg_temp_new_i32();
        tcg_gen_add_i32(tmp3, tmp, tmp2);
        store_reg32(r1, tmp3);
        switch (opc) {
        case 0x1a: gen_helper_set_cc_add32(cc, tmp, tmp2, tmp3); break;
        case 0x1e: gen_helper_set_cc_addu32(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 2;
        break;
    case 0x1b: /* SR     R1,R2     [RR] */
    case 0x1f: /* SLR    R1,R2     [RR] */
        FETCH_DECODE_RR
        tmp = load_reg32(r1);
        tmp2 = load_reg32(r2);
        tmp3 = tcg_temp_new_i32();
        tcg_gen_sub_i32(tmp3, tmp, tmp2);
        store_reg32(r1, tmp3);
        switch (opc) {
        case 0x1b: gen_helper_set_cc_sub32(cc, tmp, tmp2, tmp3); break;
        case 0x1f: gen_helper_set_cc_subu32(cc, tmp, tmp2, tmp3); break;
        default: tcg_abort();
        }
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 2;
        break;
    case 0x28: /* LDR    R1,R2               [RR] */
        FETCH_DECODE_RR
        tmp = load_freg(r2);
        store_freg(r1, tmp);
        tcg_temp_free(tmp);
        s->pc += 2;
        break;
    case 0x38: /* LER    R1,R2               [RR] */
        FETCH_DECODE_RR
        tmp = load_freg32(r2);
        store_freg32(r1, tmp);
        tcg_temp_free(tmp);
        s->pc += 2;
        break;
    case 0x40: /* STH    R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = load_reg32(r1);
        tcg_gen_qemu_st16(tmp2, tmp, 1);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x41:	/* la */
        FETCH_DECODE_RX
        store_reg(r1, tmp); /* FIXME: 31/24-bit addressing */
        FREE_RX
        s->pc += 4;
        break;
    case 0x42: /* STC    R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = load_reg32(r1);
        tcg_gen_qemu_st8(tmp2, tmp, 1);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x43: /* IC     R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp2, tmp, 1);
        store_reg8(r1, tmp2);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x44: /* EX     R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = load_reg(r1);
        tmp3 = tcg_const_i64(s->pc + 4);
        gen_helper_ex(cc, cc, tmp2, tmp, tmp3);
        FREE_RX
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0x47: /* BC     M1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        /* FIXME: optimize m1 == 0xf (unconditional) case */
        tmp2 = tcg_const_i32(r1); /* aka m1 */
        tmp3 = tcg_const_i64(s->pc);
        gen_helper_bc(cc, tmp2, tmp, tmp3);
        FREE_RX
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->is_jmp = DISAS_JUMP;
        s->pc += 4;
        break;
    case 0x48: /* LH     R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld16s(tmp2, tmp, 1);
        store_reg32(r1, tmp2);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x49: /* CH     R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld16s(tmp2, tmp, 1);
        FREE_RX
        tmp = load_reg32(r1);
        cmp_s32(tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x4a: /* AH     R1,D2(X2,B2)     [RX] */
    case 0x4b: /* SH     R1,D2(X2,B2)     [RX] */
    case 0x4c: /* MH     R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld16s(tmp2, tmp, 1);
        FREE_RX
        tmp = load_reg32(r1);
        tmp3 = tcg_temp_new_i32();
        switch (opc) {
        case 0x4a:
            tcg_gen_add_i32(tmp3, tmp, tmp2);
            gen_helper_set_cc_add32(cc, tmp, tmp2, tmp3);
            break;
        case 0x4b:
            tcg_gen_sub_i32(tmp3, tmp, tmp2);
            gen_helper_set_cc_sub32(cc, tmp, tmp2, tmp3);
            break;
        case 0x4c:
            tcg_gen_mul_i32(tmp3, tmp, tmp2);
            break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0x50: /* st r1, d2(x2, b2) */
        FETCH_DECODE_RX
        tmp2 = load_reg32(r1);
        tcg_gen_qemu_st32(tmp2, tmp, 1);
        s->pc += 4;
        FREE_RX
        tcg_temp_free(tmp2);
        break;
    case 0x55: /* CL     R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        FREE_RX
        tmp = load_reg32(r1);
        cmp_u32(tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x54: /* N      R1,D2(X2,B2)     [RX] */
    case 0x56: /* O      R1,D2(X2,B2)     [RX] */
    case 0x57: /* X      R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        FREE_RX
        tmp = load_reg32(r1);
        switch (opc) {
        case 0x54: tcg_gen_and_i32(tmp, tmp, tmp2); break;
        case 0x56: tcg_gen_or_i32(tmp, tmp, tmp2); break;
        case 0x57: tcg_gen_xor_i32(tmp, tmp, tmp2); break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp);
        set_cc_nz_u32(tmp);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x58: /* l r1, d2(x2, b2) */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        store_reg32(r1, tmp2);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x59: /* C      R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32s(tmp2, tmp, 1);
        FREE_RX
        tmp = load_reg32(r1);
        cmp_s32(tmp, tmp2);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x5a: /* A      R1,D2(X2,B2)     [RX] */
    case 0x5b: /* S      R1,D2(X2,B2)     [RX] */
    case 0x5e: /* AL     R1,D2(X2,B2)     [RX] */
    case 0x5f: /* SL     R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = load_reg32(r1);
        tcg_gen_qemu_ld32s(tmp, tmp, 1);
        tmp3 = tcg_temp_new_i32();
        switch (opc) {
        case 0x5a: case 0x5e: tcg_gen_add_i32(tmp3, tmp2, tmp); break;
        case 0x5b: case 0x5f: tcg_gen_sub_i32(tmp3, tmp2, tmp); break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp3);
        switch (opc) {
        case 0x5a: gen_helper_set_cc_add32(cc, tmp2, tmp, tmp3); break;
        case 0x5e: gen_helper_set_cc_addu32(cc, tmp2, tmp, tmp3); break;
        case 0x5b: gen_helper_set_cc_sub32(cc, tmp2, tmp, tmp3); break;
        case 0x5f: gen_helper_set_cc_subu32(cc, tmp2, tmp, tmp3); break;
        default: tcg_abort();
        }
        FREE_RX
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0x60: /* STD    R1,D2(X2,B2)        [RX] */
        FETCH_DECODE_RX
        tmp2 = load_freg(r1);
        tcg_gen_qemu_st64(tmp2, tmp, 1);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x68: /* LD    R1,D2(X2,B2)        [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld64(tmp2, tmp, 1);
        store_freg(r1, tmp2);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x70: /* STE R1,D2(X2,B2) [RX] */
        FETCH_DECODE_RX
        tmp2 = load_freg32(r1);
        tcg_gen_qemu_st32(tmp2, tmp, 1);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x71: /* MS      R1,D2(X2,B2)     [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32s(tmp2, tmp, 1);
        FREE_RX
        tmp = load_reg(r1);
        tcg_gen_mul_i32(tmp, tmp, tmp2);
        store_reg(r1, tmp);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x78: /* LE     R1,D2(X2,B2)        [RX] */
        FETCH_DECODE_RX
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld32u(tmp2, tmp, 1);
        store_freg32(r1, tmp2);
        FREE_RX
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x88: /* SRL    R1,D2(B2)        [RS] */
    case 0x89: /* SLL    R1,D2(B2)        [RS] */
    case 0x8a: /* SRA    R1,D2(B2)        [RS] */
        FETCH_DECODE_RS
        tmp = get_address(0, b2, d2);
        tcg_gen_andi_i64(tmp, tmp, 0x3f);
        tmp2 = load_reg32(r1);
        switch (opc) {
        case 0x88: tcg_gen_shr_i32(tmp2, tmp2, tmp); break;
        case 0x89: tcg_gen_shl_i32(tmp2, tmp2, tmp); break;
        case 0x8a: tcg_gen_sar_i32(tmp2, tmp2, tmp); break;
        default: tcg_abort();
        }
        store_reg32(r1, tmp2);
        if (opc == 0x8a) set_cc_s32(tmp2);
        s->pc += 4;
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        break;
    case 0x91: /* TM     D1(B1),I2        [SI] */
        FETCH_DECODE_SI
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp2, tmp, 1);
        FREE_SI
        tmp = tcg_const_i32(i2);
        gen_helper_tm(cc, tmp2, tmp);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x92: /* MVI    D1(B1),I2        [SI] */
        FETCH_DECODE_SI
        tmp2 = tcg_const_i32(i2);
        tcg_gen_qemu_st8(tmp2, tmp, 1);
        FREE_SI
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x94: /* NI     D1(B1),I2        [SI] */
    case 0x96: /* OI     D1(B1),I2        [SI] */
    case 0x97: /* XI     D1(B1),I2        [SI] */
        FETCH_DECODE_SI
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp2, tmp, 1);
        switch (opc) {
        case 0x94: tcg_gen_andi_i32(tmp2, tmp2, i2); break;
        case 0x96: tcg_gen_ori_i32(tmp2, tmp2, i2); break;
        case 0x97: tcg_gen_xori_i32(tmp2, tmp2, i2); break;
        default: tcg_abort();
        }
        tcg_gen_qemu_st8(tmp2, tmp, 1);
        set_cc_nz_u32(tmp2);
        FREE_SI
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x95: /* CLI    D1(B1),I2        [SI] */
        FETCH_DECODE_SI
        tmp2 = tcg_temp_new_i64();
        tcg_gen_qemu_ld8u(tmp2, tmp, 1);
        cmp_u32c(tmp2, i2);
        FREE_SI
        tcg_temp_free(tmp2);
        s->pc += 4;
        break;
    case 0x9b: /* STAM     R1,R3,D2(B2)     [RS] */
        FETCH_DECODE_RS
        tmp = tcg_const_i32(r1);
        tmp2 = get_address(0, b2, d2);
        tmp3 = tcg_const_i32(r3);
        gen_helper_stam(tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0xa5:
        insn = ld_code4(s->pc);
        r1 = (insn >> 20) & 0xf;
        op = (insn >> 16) & 0xf;
        i2 = insn & 0xffff;
        disas_a5(s, op, r1, i2);
        s->pc += 4;
        break;
    case 0xa7:
        insn = ld_code4(s->pc);
        r1 = (insn >> 20) & 0xf;
        op = (insn >> 16) & 0xf;
        i2 = (short)insn;
        disas_a7(s, op, r1, i2);
        s->pc += 4;
        break;
    case 0xa8: /* MVCLE   R1,R3,D2(B2)     [RS] */
        FETCH_DECODE_RS
        tmp = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r3);
        tmp2 = get_address(0, b2, d2);
        gen_helper_mvcle(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0xa9: /* CLCLE   R1,R3,D2(B2)     [RS] */
        FETCH_DECODE_RS
        tmp = tcg_const_i32(r1);
        tmp3 = tcg_const_i32(r3);
        tmp2 = get_address(0, b2, d2);
        gen_helper_clcle(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0xb2:
        insn = ld_code4(s->pc);
        op = (insn >> 16) & 0xff;
        switch (op) {
        case 0x9c: /* STFPC    D2(B2) [S] */
            d2 = insn & 0xfff;
            b2 = (insn >> 12) & 0xf;
            tmp = tcg_temp_new_i32();
            tcg_gen_ld_i32(tmp, cpu_env, offsetof(CPUState, fpc));
            tmp2 = get_address(0, b2, d2);
            tcg_gen_qemu_st32(tmp, tmp2, 1);
            tcg_temp_free(tmp);
            tcg_temp_free(tmp2);
            break;
        default:
            r1 = (insn >> 4) & 0xf;
            r2 = insn & 0xf;
            disas_b2(s, op, r1, r2);
            break;
        }
        s->pc += 4;
        break;
    case 0xb3:
        insn = ld_code4(s->pc);
        op = (insn >> 16) & 0xff;
        r3 = (insn >> 12) & 0xf; /* aka m3 */
        r1 = (insn >> 4) & 0xf;
        r2 = insn & 0xf;
        disas_b3(s, op, r3, r1, r2);
        s->pc += 4;
        break;
    case 0xb9:
        insn = ld_code4(s->pc);
        r1 = (insn >> 4) & 0xf;
        r2 = insn & 0xf;
        op = (insn >> 16) & 0xff;
        disas_b9(s, op, r1, r2);
        s->pc += 4;
        break;
    case 0xba: /* CS     R1,R3,D2(B2)     [RS] */
        FETCH_DECODE_RS
        tmp = tcg_const_i32(r1);
        tmp2 = get_address(0, b2, d2);
        tmp3 = tcg_const_i32(r3);
        gen_helper_cs(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0xbd: /* CLM    R1,M3,D2(B2)     [RS] */
        FETCH_DECODE_RS
        tmp3 = get_address(0, b2, d2);
        tmp2 = tcg_const_i32(r3); /* aka m3 */
        tmp = load_reg32(r1);
        gen_helper_clm(cc, tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0xbe: /* STCM R1,M3,D2(B2) [RS] */
        FETCH_DECODE_RS
        tmp3 = get_address(0, b2, d2);
        tmp2 = tcg_const_i32(r3); /* aka m3 */
        tmp = load_reg32(r1);
        gen_helper_stcm(tmp, tmp2, tmp3);
        tcg_temp_free(tmp);
        tcg_temp_free(tmp2);
        tcg_temp_free(tmp3);
        s->pc += 4;
        break;
    case 0xbf: /* ICM    R1,M3,D2(B2)     [RS] */
        FETCH_DECODE_RS
        if (r3 == 15) {	/* effectively a 32-bit load */
            tmp = get_address(0, b2, d2);
            tmp2 = tcg_temp_new_i64();
            tcg_gen_qemu_ld32u(tmp2, tmp, 1);
            store_reg32(r1, tmp2);
            tcg_temp_free(tmp);
            tmp = tcg_const_i32(r3);
            gen_helper_set_cc_icm(cc, tmp, tmp2);
            tcg_temp_free(tmp);
            tcg_temp_free(tmp2);
        }
        else if (r3) {
            uint32_t mask = 0x00ffffffUL;
            uint32_t shift = 24;
            int m3 = r3;
            tmp3 = load_reg32(r1);
            tmp = get_address(0, b2, d2);
            tmp2 = tcg_temp_new_i64();
            while (m3) {
                if (m3 & 8) {
                    tcg_gen_qemu_ld8u(tmp2, tmp, 1);
                    if (shift) tcg_gen_shli_i32(tmp2, tmp2, shift);
                    tcg_gen_andi_i32(tmp3, tmp3, mask);
                    tcg_gen_or_i32(tmp3, tmp3, tmp2);
                    tcg_gen_addi_i64(tmp, tmp, 1);
                }
                m3 = (m3 << 1) & 0xf;
                mask = (mask >> 8) | 0xff000000UL;
                shift -= 8;
            }
            store_reg32(r1, tmp3);
            tcg_temp_free(tmp);
            tmp = tcg_const_i32(r3);
            gen_helper_set_cc_icm(cc, tmp, tmp2);
            tcg_temp_free(tmp);
            tcg_temp_free(tmp2);
            tcg_temp_free(tmp3);
        }
        else {
            tmp = tcg_const_i32(0);
            gen_helper_set_cc_icm(cc, tmp, tmp);	/* i.e. env->cc = 0 */
            tcg_temp_free(tmp);
        }
        s->pc += 4;
        break;
    case 0xc0:
    case 0xc2:
        insn = ld_code6(s->pc);
        r1 = (insn >> 36) & 0xf;
        op = (insn >> 32) & 0xf;
        i2 = (int)insn;
        switch (opc) {
        case 0xc0: disas_c0(s, op, r1, i2); break;
        case 0xc2: disas_c2(s, op, r1, i2); break;
        default: tcg_abort();
        }
        s->pc += 6;
        break;
    case 0xd2: /* mvc d1(l, b1), d2(b2) */
    case 0xd4: /* NC     D1(L,B1),D2(B2)         [SS] */
    case 0xd5: /* CLC    D1(L,B1),D2(B2)         [SS] */
    case 0xd6: /* OC     D1(L,B1),D2(B2)         [SS] */
    case 0xd7: /* xc d1(l, b1), d2(b2) */
        insn = ld_code6(s->pc);
        vl = tcg_const_i32((insn >> 32) & 0xff);
        b1 = (insn >> 28) & 0xf;
        vd1 = tcg_const_i32((insn >> 16) & 0xfff);
        b2 = (insn >> 12) & 0xf;
        vd2 = tcg_const_i32(insn & 0xfff);
        vb = tcg_const_i32((b1 << 4) | b2);
        switch (opc) {
        case 0xd2: gen_helper_mvc(vl, vb, vd1, vd2); break;
        case 0xd4: gen_helper_nc(cc, vl, vb, vd1, vd2); break;
        case 0xd5: gen_helper_clc(cc, vl, vb, vd1, vd2); break;
        case 0xd6: gen_helper_oc(cc, vl, vb, vd1, vd2); break;
        case 0xd7: gen_helper_xc(cc, vl, vb, vd1, vd2); break;
        default: tcg_abort(); break;
        }
        s->pc += 6;
        break;
    case 0xe3:
        insn = ld_code6(s->pc);
        DEBUGINSN
        d2 = (  (int) ( (((insn >> 16) & 0xfff) | ((insn << 4) & 0xff000)) << 12 )  ) >> 12;
        disas_e3(s, /* op */ insn & 0xff, /* r1 */ (insn >> 36) & 0xf, /* x2 */ (insn >> 32) & 0xf, /* b2 */ (insn >> 28) & 0xf, d2 );
        s->pc += 6;
        break;
    case 0xeb:
        insn = ld_code6(s->pc);
        DEBUGINSN
        op = insn & 0xff;
        r1 = (insn >> 36) & 0xf;
        r3 = (insn >> 32) & 0xf;
        b2 = (insn >> 28) & 0xf;
        d2 = (  (int) ( (((insn >> 16) & 0xfff) | ((insn << 4) & 0xff000)) << 12 )  ) >> 12;
        disas_eb(s, op, r1, r3, b2, d2);
        s->pc += 6;
        break;
    case 0xed:
        insn = ld_code6(s->pc);
        DEBUGINSN
        op = insn & 0xff;
        r1 = (insn >> 36) & 0xf;
        x2 = (insn >> 32) & 0xf;
        b2 = (insn >> 28) & 0xf;
        d2 = (short)((insn >> 16) & 0xfff);
        r1b = (insn >> 12) & 0xf;
        disas_ed(s, op, r1, x2, b2, d2, r1b);
        s->pc += 6;
        break;
    default:
        LOG_DISAS("unimplemented opcode 0x%x\n", opc);
        gen_illegal_opcode(s);
        s->pc += 6;
        break;
    }
}

static inline void gen_intermediate_code_internal (CPUState *env,
                                                          TranslationBlock *tb,
                                                          int search_pc)
{
    DisasContext dc;
    target_ulong pc_start;
    uint64_t next_page_start;
    uint16_t *gen_opc_end;
    int j, lj = -1;
    int num_insns, max_insns;
    
    pc_start = tb->pc;
    
    dc.pc = tb->pc;
    dc.env = env;
    dc.pc = pc_start;
    dc.is_jmp = DISAS_NEXT;
    dc.tb = tb;
    
    gen_opc_end = gen_opc_buf + OPC_MAX_SIZE;
    
    next_page_start = (pc_start & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
    
    num_insns = 0;
    max_insns = tb->cflags & CF_COUNT_MASK;
    if (max_insns == 0)
        max_insns = CF_COUNT_MASK;

    gen_icount_start();

    /* using a temp for the condition code allows TCG to optimize away
       any condition code calculations that are not actually used */
    cc = tcg_temp_local_new_i32();
    tcg_gen_mov_i32(cc, global_cc);
    do {
        if (search_pc) {
            j = gen_opc_ptr - gen_opc_buf;
            if (lj < j) {
                lj++;
                while (lj < j)
                    gen_opc_instr_start[lj++] = 0;
            }
            gen_opc_pc[lj] = dc.pc;
            gen_opc_instr_start[lj] = 1;
            gen_opc_icount[lj] = num_insns;
        }
        if (num_insns + 1 == max_insns && (tb->cflags & CF_LAST_IO))
            gen_io_start();
#if defined S390X_DEBUG_DISAS
        LOG_DISAS("pc " TARGET_FMT_lx "\n",
                  dc.pc);
#endif
        disas_s390_insn(env, &dc);
        
        num_insns++;
    } while (!dc.is_jmp && gen_opc_ptr < gen_opc_end && dc.pc < next_page_start
             && num_insns < max_insns && !env->singlestep_enabled);

    if (dc.is_jmp != DISAS_TB_JUMP) {
        tcg_gen_mov_i32(global_cc, cc);
        tcg_temp_free(cc);
    }
    
    if (!dc.is_jmp) {
        tcg_gen_st_i64(tcg_const_i64(dc.pc), cpu_env, offsetof(CPUState, psw.addr));
    }
    
    if (dc.is_jmp == DISAS_SVC) {
        tcg_gen_st_i64(tcg_const_i64(dc.pc), cpu_env, offsetof(CPUState, psw.addr));
        TCGv tmp = tcg_const_i32(EXCP_SVC);
        gen_helper_exception(tmp);
    }

    if (tb->cflags & CF_LAST_IO)
        gen_io_end();
    /* Generate the return instruction */
    if (dc.is_jmp != DISAS_TB_JUMP) {
        tcg_gen_exit_tb(0);
    }
    gen_icount_end(tb, num_insns);
    *gen_opc_ptr = INDEX_op_end;
    if (search_pc) {
        j = gen_opc_ptr - gen_opc_buf;
        lj++;
        while (lj <= j)
            gen_opc_instr_start[lj++] = 0;
    } else {
        tb->size = dc.pc - pc_start;
        tb->icount = num_insns;
    }
#if defined S390X_DEBUG_DISAS
    log_cpu_state_mask(CPU_LOG_TB_CPU, env, 0);
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("IN: %s\n", lookup_symbol(pc_start));
        log_target_disas(pc_start, dc.pc - pc_start, 1);
        qemu_log("\n");
    }
#endif
}

void gen_intermediate_code (CPUState *env, struct TranslationBlock *tb)
{
    gen_intermediate_code_internal(env, tb, 0);
}

void gen_intermediate_code_pc (CPUState *env, struct TranslationBlock *tb)
{
    gen_intermediate_code_internal(env, tb, 1);
}

void gen_pc_load(CPUState *env, TranslationBlock *tb,
                unsigned long searched_pc, int pc_pos, void *puc)
{
    env->psw.addr = gen_opc_pc[pc_pos];
}
