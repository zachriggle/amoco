# -*- coding: utf-8 -*-

# This code is part of Amoco
# Copyright (C) 2012-2013 Axel Tillequin (bdcht3@gmail.com)
# published under GPLv2 license

# spec_xxx files are providers for instruction objects.
# These objects are wrapped and created by disasm.py.

# ref: MIPS32™ Architecture For Programmers, Volume II: The MIPS32™ Instruction Set
# 72 basic instructions, all encoded in 32 bits.

from amoco.arch.mips import env

from amoco.arch.core import *

#-------------------------------------------------------
# instruction mips decoders
#-------------------------------------------------------

ISPECS = []


@ispec("32[ 10 rd(5) 0 a 0000 rs1(5) i -------- rs2(5) =simm13(13) ]", mnemonic="add")


#==============================================================================
#                                 ABS.S FD, FS
#==============================================================================
@ispec("32[010001 fmt(5) 00000 fs(5) fd(6) 000101]", mnemonic="abs")
@def mips_abs_f(obj,fmt,fs,fd):
    return StoreFPR(obj, fd, fmt, AbsoluteValue(ValueFPR(fs, fmt)))

#==============================================================================
#                                ADD RD, RS, RT
#==============================================================================
@ispec("32[000000 rs(5) rt(5) rd(5) 00000 100000]", mnemonic="add")
@ispec("32[000000 rs(5) rt(5) rd(5) 00000 100001]", mnemonic="addu")
@ispec("32[000000 rs(5) rt(5) rd(5) 00000 100100]", mnemonic="and")
def mips_register_arith(obj,rs,rt,rd):
    obj.type = type_data_processing
    obj.operands = [env.r[rs],
                    env.r[rt],
                    env.r[td]]

"""
def sparc_arith_(obj,rd,a,rs1,i,rs2,simm13):
    obj.misc['icc'] = (a==1)
    src1 = env.r[rs1]
    src2 = env.r[rs2] if i==0 else env.cst(simm13,13).signextend(32)
    dst  = env.r[rd]
    obj.operands = [src1,src2,dst]
    obj.type = type_data_processing
"""

#==============================================================================
#       R-TYPE INSTRUCTIONS (ADD, SUB, AND, OR, SLT): RD <-- RS FUNCT RT
#==============================================================================
# @ispec("32[ 000000 rs(5) rt(5) rd(5) shamt(5) funct(6)")


#==============================================================================
#              RI-TYPE INSTRUCTIONS (ADDIU): RT <-- RS FUNCT I16
#==============================================================================
# @ispec("32[ 000000 rs(5) rt(5) i16(16)")
@ispec("32[001000 rs(5) rt(5) i16(16)]", mnemonic="addi")
@ispec("32[001001 rs(5) rt(5) i16(16)]", mnemonic="addiu")
@ispec("32[001100 rs(5) rt(5) i16(16)]", mnemonic="andi")
@ispec("32[000100 rs(5) rt(5) i16(16)]", mnemonic="beq")
@ispec("32[000101 rs(5) rt(5) i16(16)]", mnemonic="bne")
@ispec("32[010101 rs(5) rt(5) i16(16)]", mnemonic="bnel")
    obj.type = type_data_processing
    obj.operands = [env.r[rs],
                    env.r[rt],
                    env.cst(i16, 16)]

#==============================================================================
#            LOAD: RT <-- MEM[RS + I16] STORE: MEM[RS + I16] <-- RT
#==============================================================================
# @ispec("32[ 000000 rs(5) rt(5) i16(16)")


#==============================================================================
#         BRANCH EQUAL: PC <-- (RS == RT) ? PC + 4 + I16 <<2 : PC + 4
#==============================================================================
@ispec("32[000001 rs(5) 10001 i16(16)]", mnemonic="bgezal")
@ispec("32[000001 rs(5) 10011 i16(16)]", mnemonic="bgezall")
def mips_branch_with_link(obj, rs, i16):
    pass
@ispec("32[0 likely(1) 0101 rs(5) 00000 i16(16)]", mnemonic="bne")

@ispec("32[000001 rs(5) 000 likely(1) 0 i16(16)]", mnemonic="bltz")
@ispec("32[000001 rs(5) 000 likely(1) 1 i16(16)]", mnemonic="bgez")
@ispec("32[0 likely(1) 0111 rs(5) 00000 i16(16)]", mnemonic="bgtz")
def mips_branch(obj, rs, i16):
    obj.type = type_control_flow
    obj.operands = [env.r[rs], env.cst(i16, 16)]


@ispec("32[000001 00000 10001 i16(16)]", mnemonic="bal")
def mips_bal(obj,rs,rt,rd):



##==============================================================================
#                            J AND JAL: PC <-- I26
#==============================================================================
===================================================================

//******************************************************************************
//                                  J AND JAL
//******************************************************************************


"""
#-------------------------------------------------------
# instruction sparcs decoders
#-------------------------------------------------------

ISPECS = []

# format 3
#---------

# ld instructions:
@ispec("32[ 11 rd(5) 0 a 1001 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="ldsb")
@ispec("32[ 11 rd(5) 0 a 1010 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="ldsh")
@ispec("32[ 11 rd(5) 0 a 0001 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="ldub")
@ispec("32[ 11 rd(5) 0 a 0010 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="lduh")
@ispec("32[ 11 rd(5) 0 a 0000 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="ld")
@ispec("32[ 11 rd(5) 0 a 0011 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="ldd")
@ispec("32[ 11 rd(5) 0 a 1101 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="ldstub")
@ispec("32[ 11 rd(5) 0 a 1111 =op3(6) rs1(5) i asi(8) rs2(5) =simm13(13) ]", mnemonic="swap")
def sparc_ld_(obj,rd,a,op3,rs1,i,asi,rs2,simm13):
    adr = env.r[rs1]
    if i==0:
        adr += env.r[rs2]
        if a==1: obj.mnemonic += 'a'
        src = env.ptr(adr,seg=asi)
    else:
        adr += env.cst(simm13,13).signextend(32)
        if a==1: raise InstructionError(obj)
        src = env.ptr(adr)
    dst = env.r[rd]
    if op3&0xf==0b0011 and rd%1==1: raise InstructionError(obj)
    obj.operands = [src,dst]
    obj.type = type_data_processing
"""