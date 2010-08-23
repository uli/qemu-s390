#include "def-helper.h"

DEF_HELPER_1(exception, void, i32)
DEF_HELPER_4(nc, i32, i32, i32, i32, i32)
DEF_HELPER_4(oc, i32, i32, i32, i32, i32)
DEF_HELPER_4(xc, i32, i32, i32, i32, i32)
DEF_HELPER_4(mvc, void, i32, i32, i32, i32)
DEF_HELPER_4(clc, i32, i32, i32, i32, i32)
DEF_HELPER_4(lmg, void, i32, i32, i32, s32)
DEF_HELPER_4(stmg, void, i32, i32, i32, s32)
DEF_HELPER_FLAGS_1(set_cc_s32, TCG_CALL_PURE|TCG_CALL_CONST, i32, s32)
DEF_HELPER_FLAGS_1(set_cc_s64, TCG_CALL_PURE|TCG_CALL_CONST, i32, s64)
DEF_HELPER_FLAGS_1(set_cc_comp_s32, TCG_CALL_PURE|TCG_CALL_CONST, i32, s32)
DEF_HELPER_FLAGS_1(set_cc_comp_s64, TCG_CALL_PURE|TCG_CALL_CONST, i32, s64)
DEF_HELPER_FLAGS_1(set_cc_nz_u32, TCG_CALL_PURE|TCG_CALL_CONST, i32, i32)
DEF_HELPER_FLAGS_1(set_cc_nz_u64, TCG_CALL_PURE|TCG_CALL_CONST, i32, i64)
DEF_HELPER_FLAGS_2(set_cc_icm, TCG_CALL_PURE|TCG_CALL_CONST, i32, i32, i32)
DEF_HELPER_3(brctg, void, i64, i64, s32)
DEF_HELPER_3(brct, void, i32, i64, s32)
DEF_HELPER_4(brcl, void, i32, i32, i64, s64)
DEF_HELPER_4(bcr, void, i32, i32, i64, i64)
DEF_HELPER_4(bc, void, i32, i32, i64, i64)
DEF_HELPER_FLAGS_2(cmp_u64, TCG_CALL_PURE|TCG_CALL_CONST, i32, i64, i64)
DEF_HELPER_FLAGS_2(cmp_u32, TCG_CALL_PURE|TCG_CALL_CONST, i32, i32, i32)
DEF_HELPER_FLAGS_2(cmp_s32, TCG_CALL_PURE|TCG_CALL_CONST, i32, s32, s32)
DEF_HELPER_FLAGS_2(cmp_s64, TCG_CALL_PURE|TCG_CALL_CONST, i32, s64, s64)
DEF_HELPER_3(clm, i32, i32, i32, i64)
DEF_HELPER_3(stcm, void, i32, i32, i64)
DEF_HELPER_2(mlg, void, i32, i64)
DEF_HELPER_2(dlg, void, i32, i64)
DEF_HELPER_FLAGS_3(set_cc_add64, TCG_CALL_PURE|TCG_CALL_CONST, i32, s64, s64, s64)
DEF_HELPER_FLAGS_3(set_cc_addu64, TCG_CALL_PURE|TCG_CALL_CONST, i32, i64, i64, i64)
DEF_HELPER_FLAGS_3(set_cc_add32, TCG_CALL_PURE|TCG_CALL_CONST, i32, s32, s32, s32)
DEF_HELPER_FLAGS_3(set_cc_addu32, TCG_CALL_PURE|TCG_CALL_CONST, i32, i32, i32, i32)
DEF_HELPER_FLAGS_3(set_cc_sub64, TCG_CALL_PURE|TCG_CALL_CONST, i32, s64, s64, s64)
DEF_HELPER_FLAGS_3(set_cc_subu64, TCG_CALL_PURE|TCG_CALL_CONST, i32, i64, i64, i64)
DEF_HELPER_FLAGS_3(set_cc_sub32, TCG_CALL_PURE|TCG_CALL_CONST, i32, s32, s32, s32)
DEF_HELPER_FLAGS_3(set_cc_subu32, TCG_CALL_PURE|TCG_CALL_CONST, i32, i32, i32, i32)
DEF_HELPER_3(srst, i32, i32, i32, i32)
DEF_HELPER_3(clst, i32, i32, i32, i32)
DEF_HELPER_3(mvst, i32, i32, i32, i32)
DEF_HELPER_3(csg, i32, i32, i64, i32)
DEF_HELPER_3(cdsg, i32, i32, i64, i32)
DEF_HELPER_3(cs, i32, i32, i64, i32)
DEF_HELPER_4(ex, i32, i32, i64, i64, i64)
DEF_HELPER_FLAGS_2(tm, TCG_CALL_PURE|TCG_CALL_CONST, i32, i32, i32)
DEF_HELPER_FLAGS_2(tmxx, TCG_CALL_PURE|TCG_CALL_CONST, i32, i64, i32)
DEF_HELPER_2(abs_i32, i32, i32, s32)
DEF_HELPER_2(nabs_i32, i32, i32, s32)
DEF_HELPER_2(abs_i64, i32, i32, s64)
DEF_HELPER_2(nabs_i64, i32, i32, s64)
DEF_HELPER_3(stcmh, i32, i32, i64, i32)
DEF_HELPER_3(icmh, i32, i32, i64, i32)
DEF_HELPER_2(ipm, void, i32, i32)
DEF_HELPER_3(addc_u32, i32, i32, i32, i32)
DEF_HELPER_FLAGS_3(set_cc_addc_u64, TCG_CALL_PURE|TCG_CALL_CONST, i32, i64, i64, i64)
DEF_HELPER_3(stam, void, i32, i64, i32)
DEF_HELPER_3(mvcle, i32, i32, i64, i32)
DEF_HELPER_3(clcle, i32, i32, i64, i32)
DEF_HELPER_4(slb, i32, i32, i32, i32, i32)
DEF_HELPER_4(slbg, i32, i32, i32, i64, i64)
DEF_HELPER_2(cefbr, void, i32, s32)
DEF_HELPER_2(cdfbr, void, i32, s32)
DEF_HELPER_2(cxfbr, void, i32, s32)
DEF_HELPER_2(cegbr, void, i32, s64)
DEF_HELPER_2(cdgbr, void, i32, s64)
DEF_HELPER_2(cxgbr, void, i32, s64)
DEF_HELPER_2(adbr, i32, i32, i32)
DEF_HELPER_2(aebr, i32, i32, i32)
DEF_HELPER_2(sebr, i32, i32, i32)
DEF_HELPER_2(sdbr, i32, i32, i32)
DEF_HELPER_2(debr, void, i32, i32)
DEF_HELPER_2(dxbr, void, i32, i32)
DEF_HELPER_2(mdbr, void, i32, i32)
DEF_HELPER_2(mxbr, void, i32, i32)
DEF_HELPER_2(ldebr, void, i32, i32)
DEF_HELPER_2(ldxbr, void, i32, i32)
DEF_HELPER_2(lxdbr, void, i32, i32)
DEF_HELPER_2(ledbr, void, i32, i32)
DEF_HELPER_2(lexbr, void, i32, i32)
DEF_HELPER_2(lpebr, i32, i32, i32)
DEF_HELPER_2(lpdbr, i32, i32, i32)
DEF_HELPER_2(lpxbr, i32, i32, i32)
DEF_HELPER_2(ltebr, i32, i32, i32)
DEF_HELPER_2(ltdbr, i32, i32, i32)
DEF_HELPER_2(ltxbr, i32, i32, i32)
DEF_HELPER_2(lcebr, i32, i32, i32)
DEF_HELPER_2(lcdbr, i32, i32, i32)
DEF_HELPER_2(lcxbr, i32, i32, i32)
DEF_HELPER_2(ceb, i32, i32, i32)
DEF_HELPER_2(aeb, i32, i32, i32)
DEF_HELPER_2(deb, void, i32, i32)
DEF_HELPER_2(meeb, void, i32, i32)
DEF_HELPER_2(cdb, i32, i32, i64)
DEF_HELPER_2(adb, i32, i32, i64)
DEF_HELPER_2(seb, i32, i32, i32)
DEF_HELPER_2(sdb, i32, i32, i64)
DEF_HELPER_2(mdb, void, i32, i64)
DEF_HELPER_2(ddb, void, i32, i64)
DEF_HELPER_FLAGS_2(cebr, TCG_CALL_PURE, i32, i32, i32)
DEF_HELPER_FLAGS_2(cdbr, TCG_CALL_PURE, i32, i32, i32)
DEF_HELPER_FLAGS_2(cxbr, TCG_CALL_PURE, i32, i32, i32)
DEF_HELPER_3(cgebr, i32, i32, i32, i32)
DEF_HELPER_3(cgdbr, i32, i32, i32, i32)
DEF_HELPER_3(cgxbr, i32, i32, i32, i32)
DEF_HELPER_1(lzer, void, i32)
DEF_HELPER_1(lzdr, void, i32)
DEF_HELPER_1(lzxr, void, i32)
DEF_HELPER_3(cfebr, i32, i32, i32, i32)
DEF_HELPER_3(cfdbr, i32, i32, i32, i32)
DEF_HELPER_3(cfxbr, i32, i32, i32, i32)
DEF_HELPER_2(axbr, i32, i32, i32)
DEF_HELPER_2(sxbr, i32, i32, i32)
DEF_HELPER_2(meebr, void, i32, i32)
DEF_HELPER_2(ddbr, void, i32, i32)
DEF_HELPER_3(madb, void, i32, i64, i32)
DEF_HELPER_3(maebr, void, i32, i32, i32)
DEF_HELPER_3(madbr, void, i32, i32, i32)
DEF_HELPER_3(msdbr, void, i32, i32, i32)
DEF_HELPER_2(lxdb, void, i32, i64)
DEF_HELPER_FLAGS_2(tceb, TCG_CALL_PURE, i32, i32, i64)
DEF_HELPER_FLAGS_2(tcdb, TCG_CALL_PURE, i32, i32, i64)
DEF_HELPER_FLAGS_2(tcxb, TCG_CALL_PURE, i32, i32, i64)
DEF_HELPER_2(flogr, i32, i32, i64)
DEF_HELPER_2(sqdbr, void, i32, i32)

#include "def-helper.h"
