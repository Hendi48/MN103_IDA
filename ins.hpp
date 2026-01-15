/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

// register numbers
#define A0	0
#define A1	1
#define A2	2
#define A3	3

#define D0	4
#define D1	5
#define D2	6
#define D3	7

#define MDR	8
#define PSW	9

#define SP	10

#define LIR	11
#define LAR	12

// macros to extract the register numbers from the various fields in an opcode
// (duplicated so we can match with the naming scheme in the pdf)
#define AM_0(x)	((x)&3)				// a0...a3
#define DM_0(x)	(((x)&3)+4)			// d0...d4
#define AN_0(x)	((x)&3)				// a0...a3
#define DN_0(x)	(((x)&3)+4)			// d0...d4
#define AI_0(x)	((x)&3)				// a0...a3
#define DI_0(x)	(((x)&3)+4)			// d0...d4

#define AN_2(x)	(((x)>>2) & 3)		// a0...a3
#define DN_2(x)	((((x)>>2) & 3)+4)	// d0...d4
#define AM_2(x)	(((x)>>2) & 3)		// a0...a3
#define DM_2(x)	((((x)>>2) & 3)+4)	// d0...d4
#define AI_2(x)	(((x)>>2) & 3)		// a0...a3
#define DI_2(x)	((((x)>>2) & 3)+4)	// d0...d4

#define AI_4(x)	(((x)>>4) & 3)		// a0...a3
#define DI_4(x)	((((x)>>4) & 3)+4)	// d0...d4
#define AM_4(x)	(((x)>>4) & 3)		// a0...a3
#define DM_4(x)	((((x)>>4) & 3)+4)	// d0...d4
#define AN_4(x)	(((x)>>4) & 3)		// a0...a3
#define DN_4(x)	((((x)>>4) & 3)+4)	// d0...d4

extern instruc_t Instructions[];

enum nameNum {

MN103_null = 0,	// Unknown Operation

MN103_jsr,		// Absolute Call
MN103_call,		// Absolute Call
MN103_calls,	// Absolute Call
MN103_add,		// Add Second Operand to Acc
MN103_addc,		// Add Second Operand to Acc with carry
MN103_jmp,		// Absolute Jump
MN103_and,		// Logical AND (op1 &= op2)
MN103_divu,		// Divide Acc by B
MN103_tbnz,		// Jump if Bit is set
MN103_bcs,		// Jump if Carry is set
MN103_tbz,		// Jump if Bit is clear
MN103_bcc,		// Jump if Carry is clear

MN103_mov,		// Move (Op1 -> Op2)
MN103_movb,		// Move (Op1 -> Op2)
MN103_movbu,	// Move (Op1 -> Op2)
MN103_movhu,	// Move (Op1 -> Op2)
MN103_movi,		// Move (Op1 -> Op2)
MN103_movm,		// Move (Op1 -> Op2)
MN103_movc,		// Move code byte relative to second op to Acc
MN103_movx,		// Move from/to external RAM

MN103_mulu,		// Multiply Acc by B
MN103_div,		// Multiply Acc by B
MN103_nop,		// No operation
MN103_or,		// Logical OR (op1 |= op2)
MN103_rts,		// Return from subroutine
MN103_rti,		// Return from Interrupt
MN103_asl,		// Rotate Acc left
MN103_rol,		// Rotate Acc left through Carry
MN103_lsr,		// Rotate Acc right
MN103_ror,		// Rotate Acc right through Carry
MN103_bset,		// Set Direct Bit
MN103_bclr,		// Set Direct Bit
MN103_clr,		// 

MN103_inc,		// 
MN103_inc4,		// 
MN103_asl2,		// 

MN103_bra,		// Short jump
MN103_subc,		// Subtract Second Operand from Acc with Borrow
MN103_xor,		// Exclusive OR (op1 ^= op2)
MN103_ble,		// Jump if less than or equal (signed)
MN103_bgt,		// Jump if greater than (signed)
MN103_bls,		// Jump if less than or equal
MN103_bhi,		// Jump if greater than
MN103_blt,		// Jump if less than (signed)
MN103_bge,		// Jump if greater than or equal (signed)
MN103_beq,		// Jump if equal
MN103_bne,		// Jump if not equal

MN103_movh,		// Move immediate 16-bit data to the high word of a dword (double-word) register
MN103_movz,		// Move 8-bit register to 16-bit register with zero extension
MN103_movs,		// Move 8-bit register to 16-bit register with sign extension
MN103_asr,		// Shift arithmetic right by 1 bit
MN103_sub,		// Subtract
MN103_cmp,		// Compare

MN103_extx,		// 
MN103_extxu,	// 
MN103_extxb,	// 
MN103_extxbu,	// 

MN103_extb,		// 
MN103_extbu,	// 
MN103_exth ,	// 
MN103_exthu,	// 

MN103_blcr,		// 
MN103_mulql,	// 
MN103_mulq,		// 
MN103_mulqh,	// 
MN103_mul,		// 
MN103_ext,		// 
MN103_not,		// 
MN103_pxst,		// 
MN103_bltx,		// 
MN103_bgtx,		// 
MN103_bgex,		// 
MN103_blex,		// 
MN103_bcsx,		// 
MN103_bhix,		// 
MN103_bccx,		// 
MN103_blsx,		// 
MN103_beqx,		// 
MN103_bnex,		// 
MN103_bvcx,		// 
MN103_bvsx,		// 
MN103_bncx,		// 
MN103_bnsx,		// 
MN103_bvc,		// 
MN103_bvs,		// 
MN103_bnc,		// 
MN103_bns,		// 
MN103_btst,		// 
MN103_addnf,	// 

MN103_llt,		// 
MN103_lgt,		// 
MN103_lge,		// 
MN103_lle,		// 
MN103_lcs,		// 
MN103_lhi,		// 
MN103_lcc,		// 
MN103_lls,		// 
MN103_leq,		// 
MN103_lne,		// 
MN103_lra,		// 

MN103_setlb,	// 
MN103_retf,		// 
MN103_ret,		// 
MN103_rets,		// 

MN103_trap,		// 

MN103_udf00,	// 
MN103_udf01,	// 
MN103_udf02,	// 
MN103_udf03,	// 
MN103_udf04,	// 
MN103_udf05,	// 
MN103_udf06,	// 
MN103_udf07,	// 
MN103_udf08,	// 
MN103_udf09,	// 

MN103_udf10,	// 
MN103_udf11,	// 
MN103_udf12,	// 
MN103_udf13,	// 
MN103_udf14,	// 
MN103_udf15,	// 
MN103_udf16,	// 
MN103_udf17,	// 
MN103_udf18,	// 
MN103_udf19,	// 

MN103_udf20,	// 
MN103_udf21,	// 
MN103_udf22,	// 
MN103_udf23,	// 
MN103_udf24,	// 
MN103_udf25,	// 
MN103_udf26,	// 
MN103_udf27,	// 
MN103_udf28,	// 
MN103_udf29,	// 

MN103_udf30,	// 
MN103_udf31,	// 
MN103_udf32,	// 
MN103_udf33,	// 
MN103_udf34,	// 
MN103_udf35,	// 

MN103_udfu00,	// 
MN103_udfu01,	// 
MN103_udfu02,	// 
MN103_udfu03,	// 
MN103_udfu04,	// 
MN103_udfu05,	// 
MN103_udfu06,	// 
MN103_udfu07,	// 
MN103_udfu08,	// 
MN103_udfu09,	// 

MN103_udfu10,	// 
MN103_udfu11,	// 
MN103_udfu12,	// 
MN103_udfu13,	// 
MN103_udfu14,	// 
MN103_udfu15,	// 
MN103_udfu16,	// 
MN103_udfu17,	// 
MN103_udfu18,	// 
MN103_udfu19,	// 

MN103_udfu20,	// 
MN103_udfu21,	// 
MN103_udfu22,	// 
MN103_udfu23,	// 
MN103_udfu24,	// 
MN103_udfu25,	// 
MN103_udfu26,	// 
MN103_udfu27,	// 
MN103_udfu28,	// 
MN103_udfu29,	// 

MN103_udfu30,	// 
MN103_udfu31,	// 
MN103_udfu32,	// 
MN103_udfu33,	// 
MN103_udfu34,	// 
MN103_udfu35,	// 

MN103_last,		// 

};

#endif
