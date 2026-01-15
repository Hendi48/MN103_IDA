/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 *
 *      This file lists the features of each instruction in the mn103
 *      instruction set. It details how each operand is used, and what
 *      effect the instruction has on its operands, amoung other things.
 *
 */

#include "mn103.hpp"

instruc_t Instructions[] =
{
	{ "???",		0								},      // Unknown Operation
	
	{ "jsr",		CF_USE1|CF_CALL                 },      // Absolute Call
	{ "call",		CF_USE1|CF_CALL                 },      // Absolute Call
	{ "calls",		CF_USE1|CF_CALL                 },      // Absolute Call
	{ "add",		CF_USE1|CF_USE2|CF_CHG2         },      // Add Second Operand to Acc
	{ "addc",		CF_USE1|CF_USE2|CF_CHG2         },      // Add Second Operand to Acc with carry
	{ "jmp",		CF_USE1|CF_STOP|CF_JUMP			},      // Absolute Jump
	{ "and",		CF_USE1|CF_USE2|CF_CHG2         },      // Logical AND (op1 &= op2)
	{ "div",		CF_USE1|CF_USE2|CF_CHG2			},      // Divide Acc by B
	{ "tbnz",		CF_USE1|CF_USE2|CF_USE3|CF_JUMP	},      // Jump if Bit is set
	{ "bcs",		CF_USE1|CF_JUMP					},      // Jump if Carry is set
	{ "tbz",		CF_USE1|CF_USE2|CF_USE3|CF_JUMP	},      // Jump if Bit is clear
	{ "bcc",		CF_USE1|CF_JUMP					},      // Jump if Carry is clear
	
	{ "mov",		CF_CHG2|CF_USE1                 },      // Move (Op1 -> Op2)
	{ "movb",		CF_CHG2|CF_USE1                 },      // Move (Op1 -> Op2)
	{ "movbu",		CF_CHG2|CF_USE1                 },      // Move (Op1 -> Op2)
	{ "movhu",		CF_CHG2|CF_USE1                 },      // Move (Op1 -> Op2)
	{ "movi",		CF_CHG2|CF_USE1                 },      // Move (Op1 -> Op2)
	{ "movm",		CF_CHG2|CF_USE1                 },      // Move (Op1 -> Op2)
	{ "movc",		CF_CHG2|CF_USE2                 },      // Move code byte relative to second op to Acc
	{ "movx",		CF_CHG2|CF_USE2                 },      // Move from/to external RAM
	
	{ "mulu",		CF_USE1|CF_CHG2                 },      // Multiply Acc by B
	{ "div",		CF_USE1|CF_CHG2                 },      // Multiply Acc by B
	{ "nop",		0                               },      // No operation
	{ "or",			CF_USE1|CF_USE2|CF_CHG2         },      // Logical OR (op1 |= op2)
	{ "rts",		CF_STOP                         },      // Return from subroutine
	{ "rti",		CF_STOP                         },      // Return from Interrupt
	{ "asl",		CF_USE1|CF_CHG2                 },      // Rotate Acc left
	{ "rol",		CF_USE1|CF_CHG1                 },      // Rotate Acc left through Carry
	{ "lsr",		CF_USE1|CF_CHG2                 },      // Rotate Acc right
	{ "ror",		CF_USE1|CF_CHG2                 },      // Rotate Acc right through Carry
	{ "bset",		CF_USE1|CF_CHG2					},      // Set Direct Bit
	{ "bclr",		CF_USE1|CF_CHG2					},      // Set Direct Bit
	{ "clr",		CF_USE1|CF_CHG1					},      
	
	{ "inc",		CF_USE1|CF_CHG1					},
	{ "inc4",		CF_USE1|CF_CHG1					},
	{ "asl2",		CF_USE1|CF_CHG1					},
	
	{ "bra",		CF_USE1|CF_STOP                 },      // Short jump
	{ "subc",		CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Second Operand from Acc with Borrow
	{ "xor",		CF_USE1|CF_USE2|CF_CHG2         },      // Exclusive OR (op1 ^= op2)

	{ "ble",		CF_USE1|CF_JUMP					},      // Jump if less than or equal (signed)
	{ "bgt",		CF_USE1|CF_JUMP					},      // Jump if greater than (signed)
	{ "bls",		CF_USE1|CF_JUMP					},      // Jump if less than or equal
	{ "bhi",		CF_USE1|CF_JUMP					},      // Jump if greater than
	{ "blt",		CF_USE1|CF_JUMP					},      // Jump if less than (signed)
	{ "bge",		CF_USE1|CF_JUMP					},      // Jump if greater than or equal (signed)
	{ "beq",		CF_USE1|CF_JUMP					},      // Jump if equal
	{ "bne",		CF_USE1|CF_JUMP					},      // Jump if not equal
	
	{ "movh",		CF_CHG2|CF_USE2                 },      // Move immediate 16-bit data to the high word of a dword (double-word) register
	{ "movz",		CF_CHG2|CF_USE2                 },      // Move 8-bit register to 16-bit register with zero extension
	{ "movs",		CF_CHG2|CF_USE2                 },      // Move 8-bit register to 16-bit register with sign extension
	{ "asr",		CF_CHG2|CF_USE1					},      // Shift arithmetic right by 1 bit
	{ "sub",		CF_CHG2|CF_USE2                 },      // Subtract
	{ "cmp",		CF_USE1|CF_USE2                 },      // Compare
	
	{ "extx",		CF_CHG1|CF_USE1					},      
	{ "extxu",		CF_CHG1|CF_USE1					},      
	{ "extxb",		CF_CHG1|CF_USE1					},      
	{ "extxbu",		CF_CHG1|CF_USE1					},      
	
	{ "extb",		CF_CHG1|CF_USE1					},      
	{ "extbu",		CF_CHG1|CF_USE1					},      
	{ "exth",		CF_CHG1|CF_USE1					},      
	{ "exthu",		CF_CHG1|CF_USE1					},      
	
	{ "blcr",		CF_USE1                         },      
	{ "mulql",		CF_USE1                         },      
	{ "mulq",		CF_USE1                         },      
	{ "mulqh",		CF_USE1                         },      
	{ "mul",		CF_USE1                         },      
	{ "ext",		CF_USE1                         },      
	{ "not",		CF_USE1                         },      
	{ "pxst",		CF_USE1                         },      
	{ "bltx",		CF_USE1|CF_JUMP					},      
	{ "bgtx",		CF_USE1|CF_JUMP					},      
	{ "bgex",		CF_USE1|CF_JUMP					},      
	{ "blex",		CF_USE1|CF_JUMP					},      
	{ "bcsx",		CF_USE1|CF_JUMP					},      
	{ "bhix",		CF_USE1|CF_JUMP					},      
	{ "bccx",		CF_USE1|CF_JUMP					},      
	{ "blsx",		CF_USE1|CF_JUMP					},      
	{ "beqx",		CF_USE1|CF_JUMP					},      
	{ "bnex",		CF_USE1|CF_JUMP					},      
	{ "bvcx",		CF_USE1|CF_JUMP					},      
	{ "bvsx",		CF_USE1|CF_JUMP					},      
	{ "bncx",		CF_USE1|CF_JUMP					},      
	{ "bnsx",		CF_USE1|CF_JUMP					},      
	{ "bvc",		CF_USE1|CF_JUMP					},      
	{ "bvs",		CF_USE1|CF_JUMP					},      
	{ "bnc",		CF_USE1|CF_JUMP					},      
	{ "bns",		CF_USE1|CF_JUMP					},      
	{ "btst",		CF_USE1|CF_USE2					},      
	{ "addnf",		CF_USE1                         },      
	
	{ "llt",		0                               },
	{ "lgt",		0                               },
	{ "lge",		0                               },
	{ "lle",		0                               },
	{ "lcs",		0                               },
	{ "lhi",		0                               },
	{ "lcc",		0                               },
	{ "lls",		0                               },
	{ "leq",		0                               },
	{ "lne",		0                               },
	{ "lra",		0                               },
	
	{ "setlb",		0                               },
	{ "retf",		CF_CHG1|CF_USE2|CF_STOP			},
	{ "ret",		CF_CHG1|CF_USE2|CF_STOP			},
	{ "rets",		CF_STOP							},
	
	{ "trap",		CF_JUMP|CF_STOP					},
	
	{ "udf00",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf01",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf02",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf03",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf04",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf05",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf06",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf07",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf08",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf09",		CF_USE1|CF_USE2|CF_CHG2			},
	
	{ "udf10",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf11",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf12",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf13",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf14",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf15",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf16",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf17",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf18",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf19",		CF_USE1|CF_USE2|CF_CHG2			},
	
	{ "udf20",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf21",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf22",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf23",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf24",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf25",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf26",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf27",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf28",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf29",		CF_USE1|CF_USE2|CF_CHG2			},
	
	{ "udf30",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf31",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf32",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf33",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf34",		CF_USE1|CF_USE2|CF_CHG2			},
	{ "udf35",		CF_USE1|CF_USE2|CF_CHG2			},
	
	{ "udfu00",		CF_USE1|CF_USE2					},
	{ "udfu01",		CF_USE1|CF_USE2					},
	{ "udfu02",		CF_USE1|CF_USE2					},
	{ "udfu03",		CF_USE1|CF_USE2					},
	{ "udfu04",		CF_USE1|CF_USE2					},
	{ "udfu05",		CF_USE1|CF_USE2					},
	{ "udfu06",		CF_USE1|CF_USE2					},
	{ "udfu07",		CF_USE1|CF_USE2					},
	{ "udfu08",		CF_USE1|CF_USE2					},
	{ "udfu09",		CF_USE1|CF_USE2					},
	
	{ "udfu10",		CF_USE1|CF_USE2					},
	{ "udfu11",		CF_USE1|CF_USE2					},
	{ "udfu12",		CF_USE1|CF_USE2					},
	{ "udfu13",		CF_USE1|CF_USE2					},
	{ "udfu14",		CF_USE1|CF_USE2					},
	{ "udfu15",		CF_USE1|CF_USE2					},
	{ "udfu16",		CF_USE1|CF_USE2					},
	{ "udfu17",		CF_USE1|CF_USE2					},
	{ "udfu18",		CF_USE1|CF_USE2					},
	{ "udfu19",		CF_USE1|CF_USE2					},
	
	{ "udfu20",		CF_USE1|CF_USE2					},
	{ "udfu21",		CF_USE1|CF_USE2					},
	{ "udfu22",		CF_USE1|CF_USE2					},
	{ "udfu23",		CF_USE1|CF_USE2					},
	{ "udfu24",		CF_USE1|CF_USE2					},
	{ "udfu25",		CF_USE1|CF_USE2					},
	{ "udfu26",		CF_USE1|CF_USE2					},
	{ "udfu27",		CF_USE1|CF_USE2					},
	{ "udfu28",		CF_USE1|CF_USE2					},
	{ "udfu29",		CF_USE1|CF_USE2					},
	
	{ "udfu30",		CF_USE1|CF_USE2					},
	{ "udfu31",		CF_USE1|CF_USE2					},
	{ "udfu32",		CF_USE1|CF_USE2					},
	{ "udfu33",		CF_USE1|CF_USE2					},
	{ "udfu34",		CF_USE1|CF_USE2					},
	{ "udfu35",		CF_USE1|CF_USE2					},
};

#ifdef __BORLANDC__
#if sizeof(Instructions)/sizeof(Instructions[0]) != MN103_last
#error          No match:  sizeof(InstrNames) !!!
#endif
#endif

