# ----------------------------------------------------------------------
# AMD 29K Processor Module
# Processor Module Template: 
#     Copyright (c) Hex-Rays
# Processor Module
#     Copyright 2016 Arne Wichmann

import sys
import idaapi
import copy
from idaapi import *

debug = False

# general purpose helpers
def sign_extend(value, sign_bit):
    sign_bit_mask = 1 << (sign_bit- 1)
    return (value & (sign_bit_mask - 1)) - (value & sign_bit_mask)

def create_xref(fr, to, t, note=""):
    decode_insn(fr)
    ua_add_cref(0, to, t)
    if debug: 
        print("{2}:\t\t\t {0:#0x}\t -> {1:#0x}".format(fr, to, note))

# compare operands using type, register, value and addr
def get_op_sig(op):
    return (op.type, op.reg, op.value, op.addr)

def compare_op(a,b):
    return get_op_sig(a) == b

def decode_opcode(b):
    b = b >> 24
    return (b&0xFE, b&0x01 == 0x00)

def decode_rc(w):
    return ("reg", (w&0x00FF0000)>>16)
def decode_rb(w):
    return ("reg", w&0x00FF)
def decode_ra(w):
    return ("reg", (w&0x0000FF00)>>8)
def decode_sa(w):
    return ("sreg", (w&0x0000FF00)>>8)
def decode_i(w):
    return ("imm", w&0x00FF)
def decode_vn(w):
    return ("imm", (w&0x00FF0000)>>16)
def decode_i15(w):
    return (w&0x00FF0000)>>8
def decode_i7(w):
    return w&0x00FF
def decode_i17(w):
    return (w&0x00FF0000)>>6
def decode_i9(w):
    return (w&0x00FF)<<2

def decode_3op_2opi(w):
    opcode, mode = decode_opcode(w)
    if mode: # RC, RA, RB
        return (opcode, [decode_rc(w), decode_ra(w), decode_rb(w)])
    else: # RC, RA, I
        return (opcode, [decode_rc(w), decode_ra(w), decode_i(w)])

def decode_3op(w,ea):
    # RC, RA, RB
    return (w>>24, [decode_rc(w), decode_ra(w), decode_rb(w)])

def decode_1op16i(w,ea):
    # I15..8, RA, I7..I0
    return (w>>24, [decode_ra(w),("imm",decode_i15(w) + decode_i7(w))])

def decode_1op16a(w,ea):
    # I17..I10, RA, I9..I2
    opcode, mode = decode_opcode
    if mode:
        return (w>>24, [decode_ra(w),("addr", ea + sign_extend(decode_i17(w) + decode_i9(w),17))])
    else:
        return (w>>24, [decode_ra(w),("addr", decode_i17(w) + decode_i9(w))])
        


def decode_2optv(w,ea):
    opcode, mode = decode_opcode(w>>24)
    if mode: # VN, RA, RB
        return (opcode, [decode_vn(w), decode_ra(w), decode_rb(w)])
    else: # VN, RA, I
        return (opcode, [decode_vn(w), decode_ra(w), decode_i(w)])

def decode_ldst(w,ea):
    opcode, mode = decode_opcode(w>>24)
    ce = w&0x800000 >> 23
    cntl = w & 0x7F0000 >> 16
    if mode: # CE:CNTL, RA, RB
        return (opcode, [("imm",ce), ("imm", cntl), decode_ra(w), decode_rb(w)])
    else: # CE:CNTL, RA, I
        return (opcode, [("imm",ce), ("imm", cntl), decode_ra(w), decode_i(w)])

# ----------------------------------------------------------------------
class amd29k_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 29000

    # Processor features
    flag = PR_USE32 | PRN_HEX | PR_ALIGN | PR_DELAYED | PR_CNDINSNS | PR_TYPEINFO

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['a29k']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['AMD 29k']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    codestart = ['\x25\x01\x01', '\x03\x00', '\x03', '\x24\x79\x7e']

    # Array of 'return' instruction opcodes (optional)
    retcodes = ['\x15\x7F\x81\x00','\x56\x41\x81\x7F']

    # Array of instructions
    instruc = [
{'name': '',  'feature': 0},                                # placeholder for "not an instruction"

{ 'name': "nop",    'op': [0x70400101], 'proc':[29000, 29050] , 'decode': lambda w: (w>>24, None)   , 'feature' : 0  }

{ 'name': "add",    'op': [0x14,0x15 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {} + {}'},
{ 'name': "addc",   'op': [0x1C,0x1D ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {} + {} + C'},
{ 'name': "addcs",  'op': [0x18,0x19 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {} + {}\nIF signed overflow THEN Trap (Out Of Range)'},
{ 'name': "addcu",  'op': [0x1A,0x1B ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {} + {} + C\nIF unsigned overflow THEN Trap (Out Of Range)'},
{ 'name': "adds",   'op': [0x10,0x11 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {} + {}\nIF signed overflow THEN Trap (Out Of Range)'},
{ 'name': "addu",   'op': [0x12,0x13 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {} + {}\nIF unsigned overflow THEN Trap (Out Of Range)'},
{ 'name': "and",    'op': [0x90,0x91 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {} & {}'},
{ 'name': "andn",   'op': [0x9C,0x9D ], 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': '{} <- {} & ~ {}'},
{ 'name': "aseq",   'op': [0x70,0x70 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} = {2} THEN Continue ELSE Trap ({0})'},
{ 'name': "asge",   'op': [0x5C ,0x5D] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} >= {2} THEN Continue ELSE Trap ({0})'},
{ 'name': "asgeu",  'op': [0x5E ,0x5F] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} >= {2} (unsigned) THEN Continue ELSE Trap ({0})'},
{ 'name': "asgt",   'op': [0x58 ,0x59] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} > {2} THEN Continue ELSE Trap ({0})'},
{ 'name': "asgtu",  'op': [0x5A ,0x5B] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} > {2} (unsigned) THEN Continue ELSE Trap ({0})'},
{ 'name': "asle",   'op': [0x54 ,0x55] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} <= {2} THEN Continue ELSE Trap ({0})'},
{ 'name': "asleu",  'op': [0x56 ,0x57] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} <= {2} (unsigned) THEN Continue ELSE Trap ({0})'},
{ 'name': "aslt",   'op': [0x50 ,0x51] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} < {2} THEN Continue ELSE Trap ({0})'},
{ 'name': "asltu",  'op': [0x52 ,0x53] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} < {2} (unsigned) THEN Continue ELSE Trap ({0})'},
{ 'name': "asneq",  'op': [0x72 ,0x73] , 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF {1} <> {2} THEN Continue ELSE Trap ({0})'},
{ 'name': "call",   'op': [0xA8 ,0xA9] , 'proc':[29000, 29050], 'decode': decode_1op16a   , 'feature' : CF_CALL  , 'cmt':'{0} <- PC//00 + 8\n{0} <- {1}'},
{ 'name': "calli",  'op': [0xC8] ,  'proc':[29000, 29050], 'decode': lambda w: (w >> 24,[decode_ra(w), decode_rb(w)])   , 'feature' : CF_CALL , 'cmt':'{0} <- PC//00 + 8\n{0} <- {1}' },
{ 'name': "class",  'op': [0xE6] ,  'proc':[29050, 29050], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w), ('imm', w&3)])  , 'feature' : 0  , 'cmt': '{0} <- CLASS({1}) mode: {2}'},
{ 'name': "clz",    'op': [0x08 ,0x09] , 'proc':[29000, 29050], 'decode': lambda w: ((w>>24)&0xFE, [decode_rc(w), decode_rb(w) if w&0x01000000 == 0 else decode_i(w))    , 'feature' : 0  , 'cmt': 'Determine number of leading zeros in a word'},
{ 'name': "const",  'op': [0x03] ,  'proc':[29000, 29050], 'decode': decode_1op16i   , 'feature' : 0  , 'cmt': '{} <- {}'},
{ 'name': "consth", 'op': [0x02] ,  'proc':[29000, 29050], 'decode': decode_1op16i   , 'feature' : 0  , 'cmt': '{0} <- ({0} & 0xFFFF) | {1}0000'},
{ 'name': "consthz",'op': [0x05] ,  'proc':[ 29050], 'decode': decode_1op16i   , 'feature' : 0  , 'cmt': '{} <- {}0000'},
{ 'name': "constn", 'op': [0x01] ,  'proc':[ 29050], 'decode': decode_1op16i   , 'feature' : 0  , 'cmt': '{} <- 0xFFFF{}'},
{ 'name': "convert",'op': [0xE4] ,  'proc':[ 29050], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w), ('imm',(w&0x80)>>7), ('imm',(w&0x70)>>4), ('imm',(w&0xC)>>2), ('imm', w&3)])    , 'feature' : 0 , 'cmt': '{0} <- {1}, with format per UI: {2}, RND: {3}, FD: {4}, FS:{5})'},
{ 'name': "cpbyte", 'op': [0x2E , 0x2F ], 'proc':[29000, 29050], 'decode': decode_3op_2opi    , 'feature' : 0  , 'cmt': 'IF ({1}.BYTE0 = {2}.BYTE0) OR ({1}.BYTE1 = {2}.BYTE1) OR ({1}.BYTE2 = {2}.BYTE2) OR ({1}.BYTE3 = {2}.BYTE3) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpeq",   'op': [0x60 , 0x61 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} = {2} THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpge",   'op': [0x4C , 0x4D ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} >= {2} THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpgeu",  'op': [0x4E , 0x4F ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} >= {2} (unsigned) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpgt",   'op': [0x48 , 0x49 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} > {2} THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpgtu",  'op': [0x4A , 0x4B ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} > {2} (unsigned) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cple",   'op': [0x44 , 0x45 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} <= {2} THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpleu",  'op': [0x46 , 0x47 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} <= {2} (unsigned) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cplt",   'op': [0x40 , 0x41 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} < {2} THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpltu",  'op': [0x42 , 0x43 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} < {2} (unsigned) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "cpneq",  'op': [0x62 , 0x63 ], 'proc':[29000, 29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'IF {1} <> {2} THEN {0} <- TRUE ELSE {0} <- FALSE'},
# 29000 opcodes replaced by 29050 convert
{ 'name': "cvdf",   'op': [0xE9] , 'proc':[29000], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)])   , 'feature' : 0  , 'cmt': '{0} (single) <- {1} (double)'},
{ 'name': "cvdint",   'op': [0xE7 ], 'proc':[29000], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)])   , 'feature' : 0  , 'cmt': '{0} (int) <- {1} (double)'},
{ 'name': "cvfd",   'op': [0xE8 ],  'proc':[29000], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)])   , 'feature' : 0  , 'cmt': '{0} (double) <- {1} (single)'},
{ 'name': "cvfint",   'op': [0xE6]  , 'proc':[29000], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)])   , 'feature' : 0  , 'cmt': '{0} (int) <- {1} (single)'},
{ 'name': "cvintd",   'op': [0xE5]  , 'proc':[29000], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)])   , 'feature' : 0  , 'cmt': '{0} (double) <- {1} (int)'},
{ 'name': "cvintf",   'op': [0xE4]  , 'proc':[29000], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)])   , 'feature' : 0  , 'cmt': '{0} (single) <- {1} (int)'},

{ 'name': "dadd",   'op':[ 0xF1 ,  'proc':[29000, 29050], 'decode': decode_3op    , 'feature' : 0  , 'cmt': '{} <- {} + {} (double)'},
{ 'name': "ddiv",   'op':[ 0xF7 ],  'proc':[29000, 29050], 'decode': decode_3op    , 'feature' : 0  , 'cmt': '{} <- {} / {} (double)'},
{ 'name': "deq",    'op':[ 0xEB ],  'proc':[29000, 29050], 'decode': decode_3op    , 'feature' : 0  , 'cmt': 'IF {1} = {2} (double) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "dge",    'op':[ 0xEF ], 'proc':[29050], 'decode': decode_3op    , 'feature' : 0  , 'cmt': 'IF {1} >= {2} (double) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "dgt",    'op':[ 0xED ] , 'proc':[29000,29050], 'decode':  decode_3op  , 'feature' : 0  , 'cmt': 'IF {1} > {2} (double) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "div",    'op': [0x6A,0x6B]  , 'proc':[29000,29050], 'decode':  decode_3op_2opi  , 'feature' : 0  , 'cmt': 'Perform one-bit step of a divide operation (unsigned)'},
{ 'name': "div0",   'op': [0x68,0x69] , 'proc':[29000,29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'Initialize for a sequence of dicide steps (unsigned)'},
{ 'name': "divide", 'op':[ 0xE1 ], 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{0} <- {1} / {2} (signed)\n{1} <- Remainder'},
{ 'name': "dividu", 'op':[ 0xE3 ] , 'proc':[29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{0} <- {1} / {2} (unsigned)\n{1} <- Remainder'},
{ 'name': "divl",   'op': [0x6C, 0x6D] , 'proc':[29000,29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'Complete a sequence of divide steps (unsigned)'},
{ 'name': "divrem", 'op': [0x6E, 0x6F] , 'proc':[29000,29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': 'Generate remainder for divide operation (unsigned)'},
{ 'name': "dlt", 'op':[ 0xEF  ], 'proc':[29000], 'decode': decode_3op   , 'feature' : 0  , 'cmt': 'IF {1} < {2} (double) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "dmac",   'op': [0xD9],  'proc':[29050], 'decode': lambda w: (w >> 24,[('imm', (w&0x3C0000) >> 18), ('imm', (w&0x30000)>>16),decode_rc(w), decode_ra(w)])   , 'feature' : 0 ,
    'cmt': 'ACC({1}) (double) <- func_{0}({2},{3},ACC({1}))' },
{ 'name': "dmsm",   'op': [0xDB],  'proc':[29050], 'decode': decode_3op   , 'feature' : 0 , 'cmt': '{0} <- {1} * ACC(0) + {2} (double)'},
{ 'name': "dmul",   'op': [0xF5] , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{} <- {} * {} (double)'},
{ 'name': "dsub",   'op': [0xF3] , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{} <- {} - {} (double)'},
{ 'name': "emulate",'op': [0xF8] , 'proc':[29000,29050], 'decode': decode_2optv   , 'feature' : 0  , 'cmt': 'Load IPA and IPB with operand register-numbers, and Trap Vector Number in field-C'},
{ 'name': "exbyte", 'op': [0x0A, 0x0B] , 'proc':[29000,29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- {}, with low-order byte replaced by byte in {} selected by BP'},
{ 'name': "exhw",   'op': [0x7C, 0x7D] , 'proc':[29000,29050], 'decode': decode_2op_2opi   , 'feature' : 0  , 'cmt': '{} <- {}, with low-order half-word replaced by byte in {} selected by BP'},
{ 'name': "exhws",  'op': [0x7E] , 'proc':[29000,29050], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)])   , 'feature' : 0  , 'cmt': '{} <- half-word in {} selected by BP, sign-exteded to 32 bits'},
{ 'name': "extract",'op': [0x7A,0x7B] , 'proc':[29000,29050], 'decode': decode_3op_2opi   , 'feature' : 0  , 'cmt': '{} <- high-order word of ({}//{} << FC)'},
{ 'name': "fadd",   'op': [0xF0]  , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{} <- {} + {} (single)'},
{ 'name': "fdiv",   'op': [0xF6]  , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{} <- {} / {} (single)'},
{ 'name': "fdmul",  'op': [0xF9]  , 'proc':[29050], 'decode': decode_3op   , 'feature' : 0 , 'cmt': '{} (double) <- {} (single) * (single)'},
{ 'name': "feq",    'op': [0xEA]  , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': 'IF {1} = {2} (single) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "fge",    'op': [0xEE]  , 'proc':[29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': 'IF {1} >= {2} (single) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "fgt",    'op': [0xEC]  , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': 'IF {1} > {2} (single) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "flt",    'op': [0xEE]  , 'proc':[29000], 'decode': decode_3op   , 'feature' : 0  , 'cmt': 'IF {1} < {2} (single) THEN {0} <- TRUE ELSE {0} <- FALSE'},
{ 'name': "fmac",   'op': [0xD8]  , 'proc':[29050], 'decode':  lambda w: (w >> 24,[('imm', (w&0x3C0000) >> 18), ('imm', (w&0x30000)>>16),decode_rc(w), decode_ra(w)])    , 'feature' : 0 , 'cmt': 'ACC({1}) (variable) <- C({1}))'},
{ 'name': "fmsm",   'op': [0xDA], , 'proc':[29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{0} <- {1} * ACC(0) + {2} (single)'},
{ 'name': "fmul",   'op': [0xF4]  , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{} <- {} * {} (single)'},
{ 'name': "fsub",   'op': [0xF2]  , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0  , 'cmt': '{} <- {} - {} (single)'},
{ 'name': "halt",   'op': [0x89]  , 'proc':[29000,29050], 'decode': lambda w: (w>>24,None)   , 'feature' : CF_STOP , 'cmt':'Enter Halt mode on next cycle' },
{ 'name': "inbyte", 'op': [0x0C,0x0D]  , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0  , 'cmt': '{} <- {}, with byte selected by BP replaced by low-order byte of {}'},
{ 'name': "inhw",   'op': [0x78,0x79]  , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0  , 'cmt': '{} <- {}, with half-word selected by BP replaced by low-order half-word of {}'},
{ 'name': "inv",    'op': [0x9F] , 'proc':[29000,29050], 'decode': lambda w: (w>>24, None)   , 'feature' : 0 , 'cmt':'INV reset all Valid bits in instruction and data caches\nINV 1; reset all Valid bits in instruction cache\nINV 2; reset all Valid bits in data cache' },
{ 'name': "iret",   'op': [0x88] , 'proc':[29000,29050], 'decode': lambda w: (w>>24, None)   , 'feature' : CF_STOP , 'cmt':'perform an interrupt return sequence' },
{ 'name': "iretinv",'op': [0x8C]  , 'proc':[29000,29050], 'decode': lambda w: (w>>24, None)   , 'feature' : CF_STOP , 'cmt':'IRETINV perform an interrupt return and invalidate all caches' },
#{ 'name': "iretinv",'op': 0x8C ,'mask': 0xFF000000 , 'proc':[29000,29050], 'decode': lambda w: (w>>24, None)   , 'feature' : CF_STOP , 'cmt':'IRETINV perform an interrupt return and invalidate all caches\nIRETINV 1; perform an interrupt return and invalidate instruction cache\nIRETINV 2; perform an interrupt return and invalidate date cache' },
{ 'name': "jmp",    'op': [0xA0 ,0xA1]  , 'proc':[29000, 29050], 'decode': decode_1op16a   , 'feature' : CF_JUMP , 'cmt':'PC <- {}' },
{ 'name': "jmpf",   'op': [0xA4 ,0xA5]  , 'proc':[29000, 29050], 'decode': decode_1op16a   , 'feature' : CF_JUMP , 'cmt':'IF {} = FALSE THEN PC <- {}' },
{ 'name': "jmpfdec",'op': [0xB4 ,0xB5]  , 'proc':[29000, 29050], 'decode': decode_1op16a   , 'feature' : CF_JUMP , 'cmt':'IF {0} = FALSE THEN {0} <- {0} - 1; PC <- {1} ELSE {0} <- {0} - 1' },
{ 'name': "jmpfi",  'op': [0xC4]  , 'proc':[29000, 29050], 'decode': lambda w: (w >> 24,[decode_ra(w), decode_rb(w)])   , 'feature' : CF_JUMP  , 'cmt':'IF {} = FALSE THEN PC <- {}'},
{ 'name': "jmpi",   'op': [0xC0]  , 'proc':[29000, 29050], 'decode': lambda w: (w >> 24,[decode_rb(w)]), 'feature' : CF_JUMP , 'cmt':'PC <- {}' },
{ 'name': "jmpt",   'op': [0xAC]  , 'proc':[29000, 29050], 'decode': decode_1op16a   , 'feature' : CF_JUMP , 'cmt':'IF {} = TRUE THEN PC <- {}' },
{ 'name': "jmpti",  'op': [0xCC]  , 'proc':[29000, 29050], 'decode': lambda w: (w >> 24,[decode_ra(w), decode_rb(w)])   , 'feature' : CF_JUMP  , 'cmt':'IF {} = TRUE THEN PC <- {}'},
{ 'name': "load",   'op': [0x16 ,0x17]  , 'proc':[29000, 29050], 'decode': decode_ldst   , 'feature' : 0 , 'cmt':'{0} <- {2}[{3}]' },
{ 'name': "loadl",  'op': [0x06 ,0x07]  , 'proc':[29000, 29050], 'decode': decode_ldst   , 'feature' : 0 , 'cmt':'{0} <- {2}[{3}]\nassert *LOCK output during access' },
{ 'name': "loadm",  'op': [0x36 ,0x37]  , 'proc':[29000, 29050], 'decode': decode_ldst   , 'feature' : 0 , 'cmt':'{0}..{0} + COUNT <- {2}[{3}] .. {2}[{3}+COUNT*4]' },
{ 'name': "loadset",'op': [0x26 ,0x27]  , 'proc':[29000, 29050], 'decode': decode_ldst   , 'feature' : 0 , 'cmt':'{0} <- {2}[{3}]\n{2}[{3}] <- 0xFFFFFFFF\nassert *LOCK output during access' },
{ 'name': "mfacc",  'op': [0xE9],  'proc':[29050], 'decode': lambda w: (w >> 24,[decode_rc(w), ('imm',(w&0xC)>>2), ('imm', w&3)])   , 'feature' : 0 , 'cmt':'{0} <- ACC({2})'},
{ 'name': "mtacc",  'op': [0xE8],  'proc':[29050], 'decode': lambda w: (w >> 24,[decode_ra(w), ('imm',(w&0xC)>>2), ('imm', w&3)]), 'feature' : 0 , 'cmt':'ACC({2}) <- {0}'},
{ 'name': "mfsr",   'op': [0xC6] , 'proc':[29000,29050], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_sa(w)]), 'feature' : 0 , 'cmt':'{} <- {}' },
{ 'name': "mftlb",  'op': [0xB6] , 'proc':[29000,29050], 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w)]), 'feature' : 0 , 'cmt':'{} <- TLB[{}]' },
{ 'name': "mtsr",   'op': [0xCE] , 'proc':[29000,29050], 'decode': lambda w: (w >> 24,[decode_sa(w), decode_rb(w)]), 'feature' : 0 , 'cmt':'{} <- {}' },
{ 'name': "mtsrim", 'op': [0x04] , 'proc':[29000,29050], 'decode': lambda w:  (w>>24, [decode_sa(w),("imm",decode_i15(w) + decode_i7(w))]) , 'feature' : 0 , 'cmt':'{} <- {}' },
{ 'name': "mttlb",  'op': [0xBE] , 'proc':[29000,29050], 'decode': lambda w: (w >> 24,[decode_ra(w), decode_rb(w)]), 'feature' : 0 , 'cmt':'TLB[{}] <- {}' },
{ 'name': "mul",    'op': [0x64 ,0x65] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} * {} (signed)\nPerform one-bit step of a multiply operation (signed)' },
{ 'name': "mull",   'op': [0x66 ,0x67] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'Complete a sequence of multiply steps' },
{ 'name': "multiplu",'op':[ 0xE2] , 'proc':[29050], 'decode': decode_3op   , 'feature' : 0 , 'cmt':'{} <- {} * {} (unsigned)' },
{ 'name': "multiply",'op':[ 0xE0] , 'proc':[29000,29050], 'decode': decode_3op   , 'feature' : 0 , 'cmt':'{} <- {} * {} (signed)' },
{ 'name': "multm",  'op': [0xDE], 'proc':[29050], 'decode': decode_3op   , 'feature' : 0 , 'cmt':'{} <- higher order 32 bit( {} * {} ) (signed)' },
{ 'name': "multmu",  'op':[ 0xDF],  'proc':[29050], 'decode': decode_3op   , 'feature' : 0 , 'cmt':'{} <- higher order 32 bit( {} * {} ) (unsigned)' },
{ 'name': "mulu",   'op': [0x74 ,0x75] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} * {} (unsigned)' },
{ 'name': "nand",   'op': [0x9A ,0x9B] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- ~ ({} & {})' },
{ 'name': "nor",    'op': [0x98 ,0x99] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- ~ ({} | {})' },
{ 'name': "or",	    'op': [0x92 ,0x93] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} | {}' },
{ 'name': "orn",    'op': [0xAA,0xAB] ,'proc':[29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} | ~ {}'},
{ 'name': "setip",  'op': [0x9E] , 'proc':[29000,29050] , 'decode': decode_3op   , 'feature' : 0, 'cmt':'Set IPA, IPB, and IPC with operand register-numbers' },
{ 'name': "sll",    'op': [0x80 ,0x81] , 'proc':[29000,29050] , 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} << {} (zero fill)'},
{ 'name': "sqrt",   'op': [0xE5] , 'proc': [29050] , 'decode': lambda w: (w >> 24,[decode_rc(w), decode_ra(w), ('imm', w&3)])   , 'feature' : 0 , 'cmt':'{0} <- SQRT({1}) FS: {2}'},
{ 'name': "sra",    'op': [0x86 ,0x87] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} >> {} (sign fill)'},
{ 'name': "srl",    'op': [0x82 ,0x83] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} >> {} (zero fill)'},
{ 'name': "store",  'op': [0x1E ,0x1F] , 'proc':[29000,29050], 'decode': decode_ldst   , 'feature' : 0 , 'cmt':'{0}[{3}] <- {2}'},
{ 'name': "storel", 'op': [0x0E ,0x0F] , 'proc':[29000,29050], 'decode': decode_ldst   , 'feature' : 0 , 'cmt':'{0}[{3}] <- {2}\nassert *LOCK output during access'},
{ 'name': "storem", 'op': [0x3E ,0x3F] , 'proc':[29000,29050], 'decode': decode_ldst   , 'feature' : 0 , 'cmt':'{0}[{3}] ..  {0} [{3} + COUNT * 4] <- {2} .. {2} + COUNT'},
{ 'name': "sub",    'op': [0x24 ,0x25] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{} <- {} - {}'},                                                    
{ 'name': "subc",   'op': [0x2C ,0x2D] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{} <- {} - {} - 1 + C'},                                                
{ 'name': "subcs",  'op': [0x28 ,0x29] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{} <- {} - {} - 1 + C\nIF signed overflow THEN Trap (Out Of Range)'},       
{ 'name': "subcu",  'op': [0x2A ,0x2B] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{} <- {} - {} - 1 + C\nIF unsigned underflow THEN Trap (Out Of Range)'},
{ 'name': "subr",   'op': [0x34 ,0x35] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{0} <- {2} - {1}'},                                                    
{ 'name': "subrc",  'op': [0x3C ,0x3D] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{0} <- {2} - {1} - 1 + C'},                                                
{ 'name': "subrcs", 'op': [0x38 ,0x39] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{0} <- {2} - {1} - 1 + C\nIF signed overflow THEN Trap (Out Of Range)'},       
{ 'name': "subrcu", 'op': [0x3A ,0x3B] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{0} <- {2} - {1} - 1 + C\nIF unsigned underflow THEN Trap (Out Of Range)'},
{ 'name': "subrs",  'op': [0x30 ,0x31] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{0} <- {2} - {1}\nIF signed overflow THEN Trap (Out Of Range)'},       
{ 'name': "subru",  'op': [0x32 ,0x33] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{0} <- {2} - {1}\nIF unsigned underflow THEN Trap (Out Of Range)'},
{ 'name': "subs",   'op': [0x20 ,0x21] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{} <- {} - {}\nIF signed overflow THEN Trap (Out Of Range)'},       
{ 'name': "subu",   'op': [0x22 ,0x23] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt': '{} <- {} - {}\nIF unsigned underflow THEN Trap (Out Of Range)'},
{ 'name': "xnor",   'op': [0x96 ,0x97] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- ~ ({} ^ {})'},
{ 'name': "xor",    'op': [0x94 ,0x95] , 'proc':[29000,29050], 'decode': decode_3op2opi   , 'feature' : 0 , 'cmt':'{} <- {} ^ {}'},
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    # tbyte_size = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0 ,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "AMD 29k assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': [".a29k"],

        # array of unsupported instructions (array of cmd.itype) (optional)
        #'badworks': [],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        #'a_qword': "dq",

        # remove if not allowed
        #'a_oword': "xmmword",

        # remove if not allowed
        #'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        #'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        #'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        #
        # translation to use in character and string constants.
        # usually 1:1, i.e. trivial translation
        # If specified, must be 256 chars long
        # (optional)
        #'XlatAsciiOutput': "".join([chr(x) for x in xrange(256)]),

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 3-byte data (optional)
        #'a_3byte': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler
    
    def strop(self,op):
        """
        Get String Representation of Operand
        @return None or the comment string
        """
        optype = op.type

        if optype == o_reg:
            return self.regNames[op.reg]
        elif optype == o_imm:
            return "{:#0x}".format(op.value)
        elif optype == o_far:
            name = get_colored_name(op.addr)
            return name
        
        return None

    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[self.cmd.itype]:
            fmt = self.instruc[self.cmd.itype]['cmt'].format(*map(self.strop, self.cmd.Operands))
            return fmt
            
            
    def notify_is_basic_block_end(self, call_insn_stops_block):
        """
        Is the current instruction end of a basic block?
        This function should be defined for processors
        with delayed jump slots. The current instruction
        is stored in 'cmd'
        args:
          call_insn_stops_block
          returns: 1-unknown, 0-no, 2-yes
        """
        prev = DecodeInstruction(self.cmd.ea -4)
        if prev is None:
            return 1
        elif prev.get_canon_feature() & CF_JUMP:
            return 2
        
        return 0

    # ----------------------------------------------------------------------
    def notify_is_sane_insn(self, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'cmd'
        returns: 1-ok, <=0-no, the instruction isn't
        likely to appear in the program
        """
        w = get_32bit(self.cmd.ea)
        if no_crefs == 0 and( w == 0 or w == -1 or (w&0xff000000) == 0):
          return 0
        return 1

    def check_extract_flow(self,definition, start):
        """
        walks backwards from current instructions and tries to match the definition template.
        returns: (catch, anchor, match, success)
            catch: collected operand values
            anchor: ea of start instruction
            match: ea of end instruction
            success: True on successful match
        """

        instrs = definition.split(";")
        instrs = [i.split(" ") for i in instrs]
        instrs = [(inst, ops.split(",")) for inst, ops in instrs]

        # catch register definition values
        catch = {}

        # anchor instruction
        anchorinst = instrs[len(instrs)-1][0]
        anchor = start
        if anchor == None:
            if debug:
                print("no anchor found")
            return (catch, anchor, None, False)
            
        # walk instructions backwards, tracking operand definition/uses according to template
        ea = anchor

        todo = list(reversed(instrs))

        def recursor(cmd, ea,anchor,o_catch, todo):
            if debug:
                print("{0:#0x}".format(ea))
            catch = copy.copy(o_catch)
            inst,ops = todo[0]
            if cmd is not None and self.instruc[cmd.itype]["name"] == inst:
                if debug:
                    print("instruction match")
                i = -1
                for op in ops:
                    i = i+1
                    if op == '_':
                        continue
                    if debug:
                        print(op, cmd[i].type, cmd[i].reg, cmd[i].value)
                    if op in catch and not compare_op(cmd[i], catch[op]):
                        if debug:
                            print("operand mismatch")
                            print(op,i)
                        return (catch, anchor,ea, False)
                    else:
                        catch[op] = get_op_sig(cmd[i])
            else:
                if debug: 
                    print("instruction mismatch {0} != {1}, {2}".format(inst, self.instruc[cmd.itype]["name"], cmd.itype))
                return (catch, anchor,ea, False)
            l_todo = todo[1:]
            print l_todo
            if len(l_todo) > 0: 
                for c in [DecodePreviousInstruction(ea), DecodePrecedingInstruction(ea)[0], DecodeInstruction(ea - 4)]:
                    if c is not None:
                        t = recursor(c, c.ea, anchor, catch, l_todo)
                        if t[-1] == True:
                            return t

                return (catch, anchor,ea, False)
            else:
                return (catch, anchor,ea, True)

        cmd = DecodeInstruction(ea)
        return recursor(cmd, ea, ea, catch, todo)
        

    def is_switch(self, si):
        """
        Find 'switch' idiom.
        Fills 'si' structure with information

        @return: Boolean (True if switch was found and False otherwise)
        """
        
        if debug:
            print( "is_switch for {0:#0x}".format(self.cmd.ea))

        def fill_switch_full(data, anchor,end ,match,si):
                                si.jumps = data['tl'][2] + data['th'][2]
                                si.flags = SWI_DEFAULT | SWI_V32 | SWI_J32
                                si.ncases = data['num'][2]
                                si.defjump = data['def'][3]
                                si.lowcase = 0
                                si.startea = end

        def fill_switch_part(data, anchor,end ,match,si):
                                si.jumps = data['tl'][2] + data['th'][2]
                                si.flags = SWI_DEFAULT | SWI_V32 | SWI_J32
                                si.ncases = data['num'][2] + 1
                                #si.defjump = data['def'][3]
                                si.lowcase = 0
                                si.startea = end

        idioms = [ ("cpgtu i,j,num;"\
                    "jmpt i,def;"\
                    "nop ;"\
                    "load _,_,g,h;"\
                    "sll f,g,_;"\
                    "sll a,f,_;"\
                    "const b,tl;"\
                    "consth b,th;"\
                    "add c,a,b;"\
                    "load _,_,e,c;"\
                    "jmpi e",
                        fill_switch_full
                    ) ,(
                    "cpgtu _,_,num;"\
                    "jmpf _,_;"\
                    "const b,tl;"\
                    "consth b,th;"\
                    "add c,b,a;"\
                    "load _,_,e,c;"\
                    "jmpi e",
                        fill_switch_part)
                 ]
        
        start = self.cmd.ea

        for i,h in idioms:
            print("checking idiom {0}".format(i))
            (d,a,e,match) = self.check_extract_flow(i,start)
            if match:
                if debug:
                    print("found switch {0:#0x} .. {1:#0x}".format(a,e))
                    print(d)
                h(d,a,e,match,si)
                return True
            if debug:
                print(d)
        return False
        
    def real_next_inst(self,ea):
        """
        helper to find the ea of the next executed instruction.
        takes care of reordering delayed instructions
        """
        if self.reorderdelayed: 
            this = DecodeInstruction(ea)
            if is_delayed_branch(this.auxpref):
                return self.real_next_inst(ea + 4)
            else:
                return ea
        else:   
            return ea

    def find_targets(self,ea):
        """
        helper to determine the targets of jump and call instructions
        """
        decode_insn(ea)
        # add jump or call targets
        t = fl_JN if idaapi.cmd.get_canon_feature() & CF_JUMP else fl_CN
        tgt = idaapi.cmd.Operands[1]
        if idaapi.cmd.Operands[1].type == o_void:
            tgt = idaapi.cmd.Operands[0]
        # tgt containes the branch target
        if tgt.type == o_far: 
            create_xref(ea, self.real_next_inst(tgt.addr), t,"immediate branch")
        elif tgt.type == o_reg:
            # walk backwards and find const/consth pair for address
            lowdone = False
            highdone = False
            error = False
            itea = ea
            target = 0
            reg = tgt.reg
            while not (lowdone and highdone) and not error:
                #print("{0:#0x}".format(ea))
                prec,succ = DecodePrecedingInstruction(itea)
                if prec is None:
                    prec = DecodePreviousInstruction(itea)
                    if prec is None:
                        error = True 
                        break
                
                # for itype
                if not lowdone and self.instruc[prec.itype]["name"] == "const" and prec[0].reg == reg:
                    target = target + prec[1].value
                    lowdone = True
                elif not highdone and self.instruc[prec.itype]["name"] == "consth" and prec[0].reg == reg:
                    target = target + prec[1].value
                    highdone = True
                else:
                    for i in xrange(0,5):
                        if prec[i].type == o_reg and prec[i].reg == reg:
                            error = True
                            break
                
                itea = prec.ea
            if not error:
                create_xref(ea, self.real_next_inst(target), t, "indirect branch")
            else:
                decode_insn(ea)
                if debug:
                    print("unknown branch {0:#0x}".format(ea))
                QueueSet(Q_jumps, ea)
        
    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        if self.cmd.itype == self.itype_null:
            return 0

        aux = self.get_auxpref()
        cmd = self.cmd
        ea = self.cmd.ea


        this = DecodeInstruction(ea)
        Feature = self.cmd.get_canon_feature()
        prev = DecodeInstruction(ea-4)
        is_delayed = is_delayed_branch(prev.auxpref) if prev is not None else False
        is_jmporcall = (Feature & CF_JUMP) or (Feature & CF_CALL)
        is_stop = Feature & CF_STOP
        is_cond = this[1].type != o_void if is_jmporcall else False
        prev_is_cond = prev_is_jmporcall = prev_Feature = None
        if prev is not None:
            prev_Feature = prev.get_canon_feature()
            prev_is_jmporcall = (prev_Feature & CF_JUMP) or (prev_Feature & CF_CALL)
            prev_is_cond = prev[1].type != o_void if prev_is_jmporcall else False

        #if is_delayed_branch(aux):
        #    execute_next = True

        # a jmp b c => a b jmp c
        # a jmpc,d b c d => a b jmpc=cd

        if self.reorderdelayed: 
            if is_delayed:
                create_xref(int(ea), int(ea) -4, fl_JF, "delayed instruction")
                return 1
            elif is_stop:
                if debug:
                    print("stop instruction {0:#0x}".format(ea))
                return 1

            if is_jmporcall:
                if debug: 
                    print("finding targets: {0:#0x}".format(ea))
                self.find_targets(ea)
                if is_cond:
                    create_xref(ea, self.real_next_inst(ea + 8), fl_JF, "conditional continuation")
                return 1

            if ea + 4 == self.real_next_inst(ea+4):
                create_xref(ea, self.real_next_inst(ea + 4), fl_F, "next instruction")
            else:
                create_xref(ea, self.real_next_inst(ea + 4), fl_JF, "next instruction is delayed")
        else:
            if is_delayed:
                create_xref(ea-4, ea, fl_F, "delayed instruction")
                if not prev_is_cond:
                    return 1
            if is_stop:
                if debug:
                    print("stop instruction {0:#0x}".format(ea))
                return 1
            if is_jmporcall:
                if debug: 
                    print("finding targets: {0:#0x}".format(ea))
                self.find_targets(ea)
                if is_cond:
                    create_xref(ea, ea + 4, fl_F, "conditional continuation")
                else:
                    create_xref(ea, ea + 4, fl_F, "delayed continuation")
                    
                return 1
            create_xref(ea, ea + 4, fl_F, "next instruction")
            
        
        return 1
        
    # ----------------------------------------------------------------------
    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by the emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type

        if optype == o_reg:
            out_register(self.regNames[op.reg])
        elif optype == o_imm:
            OutValue(op, OOFW_32)
        elif optype == o_far:
            r = out_name_expr(op, op.addr, BADADDR)
            if not r: 
                out_addr_tag(self.cmd.ea)
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
        else: 
            return False

        return True

    # ----------------------------------------------------------------------
    def out(self):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by emu() function.
        Returns: nothing
        """
        # Init output buffer
        buf = idaapi.init_output_buffer(1024)

        postfix = ""

        # first argument (8) is the width of the mnemonic field
        OutMnem(8, postfix)

        # output first operand
        # kernel will call outop()
        if self.cmd.Op1.type != o_void:
            out_one_operand(0)

        # output the rest of operands separated by commas
        for i in xrange(1, 6):
            if self.cmd[i].type == o_void:
                break
            out_symbol(',')
            OutChar(' ')
            out_one_operand(i)

        term_output_buffer()
        cvar.gl_comm = 1 # generate comment at the next call to MakeLine()
        MakeLine(buf)

    # ----------------------------------------------------------------------
    def ana(self):
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """
        #print ("{0:#0x}".format(self.cmd.ea))
        if (self.cmd.ea & 3) != 0:
            return 4-(self.cmd.ea&3)

        w = get_32bit(self.cmd.ea)
        self.cmd.size=4
        
        opcode = (w&0xff000000) 
        self.cmd.auxpref = opcode>>24


        if w # nop?
            self.cmd.itype = self.Instructions[w]
        else: 
            try: 
                self.cmd.itype = self.Instructions[opcode] if opcode in self.Instructions else self.itype_null

                inst = self.instruc[self.cmd.itype]
                i = 0
                for op in 
                    if op == '':
                        continue
                    self.cmd.Operands[i].type = o_void
                    self.cmd.Operands[i].specval = op
                    if op # register or special register
                        self.cmd.Operands[i].type = o_reg
                        self.cmd.Operands[i].reg = decode[op] +( 256 if op == "s" else 0)
                    if op # address-like thing
                        self.cmd.Operands[i].type = o_far
                        self.cmd.Operands[i].addr = decode[op]
                    if op # immediate
                        self.cmd.Operands[i].type = o_imm
                        self.cmd.Operands[i].value = decode[op]
                    i = i+1
            except:
                print(self.cmd.ea, decode, self.instruc[self.Instructions[opcode]])

        return self.cmd.size

    def set_idp_options(self, keyword, type, value):
        """
        Set IDP-specific option
        args:
          keyword - the option name
                    or empty string (check type when 0 below)
          type    - one of
                      IDPOPT_STR  string constant
                      IDPOPT_NUM  number
                      IDPOPT_BIT  zero/one
                      IDPOPT_FLT  float
                      IDPOPT_I64  64bit number
                      0 -> You should display a dialog to configure the processor module
          value   - the actual value
        Returns:
           IDPOPT_OK        ok
           IDPOPT_BADKEY    illegal keyword
           IDPOPT_BADTYPE   illegal type of value
           IDPOPT_BADVALUE  illegal value (bad range, for example)
        otherwise return a string containing the error messages
        """
        if type == 0: 
            ret = AskYN(0,"reoder delayed instructions")
            if ret != -1:
                self.reorderdelayed = True if ret == 1 else False
            ret = AskYN(0,"is big endian")
            if ret != -1:
                idaapi.cvar.inf.mf = 1 if ret == 1 else 0
        return idaapi.IDPOPT_OK


    # ----------------------------------------------------------------------
    def init_instructions(self):
        self.Instructions = {}
        i = 0
        for x in self.instruc:
            if x['name'] != '':
                # setting itype_... does not work for us (MNEMs not unique)
                #setattr(self, 'itype_' + x['name'], i)
                if 'opcode' in x:
                    self.Instructions[x['opcode']] = i
            else:
                setattr(self, 'itype_null', i)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(self.instruc) + 1

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_null
    

    # ----------------------------------------------------------------------
    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""
        # Registers definition
        self.regNames = ["CS","DS"]

        # Create the ireg_XXXX constants
        for i in xrange(len(self.regNames)):
            setattr(self, 'ireg_' + self.regNames[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.regFirstSreg = self.ireg_CS
        self.regLastSreg  = self.ireg_DS

        # number of CS register
        self.regCodeSreg = self.ireg_CS

        # number of DS register
        self.regDataSreg = self.ireg_DS

    # ----------------------------------------------------------------------
    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()
        self.reorderdelayed = False
        # big endian default
        idaapi.cvar.inf.mf = 1

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return amd29k_processor_t()
