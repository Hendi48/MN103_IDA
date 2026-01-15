/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */

#include "mn103.hpp"

static int ana_main(void);

// core extension functions
static int extF0(void);
static int extF1(void);
static int extF2(void);
static int extF3(void);
static int extF4(void);
static int extF5(void);
static int extF6(void);
static int extF7(void);
static int extF8(void);
static int extF9(void);
static int extFA(void);
static int extFB(void);
static int extFC(void);
static int extFD(void);
static int extFE(void);
static int extFF(void);

//----------------------------------------------------------------------

static int extF0(void)
{
	ushort b1 ,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	
	switch(n1)
	{
		case 0x0:	// mov (Am),An
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = 0;
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_2(b1);
			cmd.size=2;
			break;
		case 0x1:	// mov Am,(An)
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = 0;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=2;
			break;
		case 0x2:
		case 0x3:	// invalid!
			break;
		case 0x4:	// movbu (Am),Dn
			cmd.itype = MN103_movbu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = 0;
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=2;
			break;
		case 0x5:	// movbu Dm,(An)
			cmd.itype = MN103_movbu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = 0;
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=2;
			break;
		case 0x6:	// movhu (Am),Dn
			cmd.itype = MN103_movhu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = 0;
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_word;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=2;
			break;
		case 0x7:	// movhu Dm,(An)
			cmd.itype = MN103_movhu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = 0;
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_word;
			cmd.size=2;
			break;
		case 0x8:	// bset Dm,(An)
			cmd.itype = MN103_bset;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = 0;
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=2;
			break;
		case 0x9:	// bclr Dm,(An)
			cmd.itype = MN103_bclr;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = 0;
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=2;
			break;
		case 0xa:
		case 0xb:
		case 0xc:
		case 0xd:
		case 0xe:	// invalid!
			break;
		case 0xf:
			switch(n2)
			{
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:	// calls (An)
					cmd.itype = MN103_calls;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = 0;
					cmd.Op1.reg = AN_0(b1);
					cmd.size=2;
					break;
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:	// jmp (An)
					cmd.itype = MN103_jmp;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = 0;
					cmd.Op1.reg = AN_0(b1);
					cmd.size=2;
					break;
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:	// invalid
					break;
				case 0xc:	// rets
					cmd.itype = MN103_rets;
					cmd.size=2;
					break;
				case 0xd:	// rti
					cmd.itype = MN103_rti;
					cmd.size=2;
					break;
				case 0xe:	// trap
					cmd.itype = MN103_trap;
					cmd.size=2;
					break;
				case 0xf:	// invalid!
					break;
			}
			break;
	}

	return(cmd.size);
}

static int extF1(void)
{
	ushort b1 ,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);

	switch(n1)
	{
		case 0x0:	// sub Dm,Dn
			cmd.itype= MN103_sub;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x1:	// sub Am,Dn
			cmd.itype= MN103_sub;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x2:	// sub Dm,An
			cmd.itype= MN103_sub;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=2;
			break;
		case 0x3:	// sub Am,An
			cmd.itype= MN103_sub;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=2;
			break;
		case 0x4:	// addc Dm,Dn
			cmd.itype= MN103_addc;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x5:	// add Am,Dn
			cmd.itype= MN103_add;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x6:	// add Dm,An
			cmd.itype= MN103_add;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=2;
			break;
		case 0x7:	// add Am,An
			cmd.itype= MN103_add;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=2;
			break;
		case 0x8:	// subc Dm,Dn
			cmd.itype= MN103_subc;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x9:	// cmp Am,Dn
			cmd.itype= MN103_cmp;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0xa:	// cmp Dm,An
			cmd.itype= MN103_cmp;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=2;
			break;
		case 0xb:	
		case 0xc:	// invalid!
			break;
		case 0xd:	// mov Am,Dn
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0xe:	// mov Dm,An
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=2;
			break;
		case 0xf:	// invalid!
			break;
	}

	return(cmd.size);
}

static int extF2(void)
{
	ushort b1 ,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	ushort d3 = (b1 >> 2)&0x03;
	ushort d4 = (b1)&0x03;
	
	switch(n1)
	{
		case 0x0:	// and Dm,Dn
			cmd.itype= MN103_and;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x1:	// or Dm,Dn
			cmd.itype= MN103_or;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x2:	// xor Dm,Dn
			cmd.itype= MN103_xor;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x3:	// not Dn
			cmd.itype= MN103_not;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x4:	// mul Dm,Dn
			cmd.itype= MN103_mul;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x5:	// mulu Dm,Dn
			cmd.itype= MN103_mulu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x6:	// div Dm,Dn
			cmd.itype= MN103_div;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x7:	// divu Dm,Dn
			cmd.itype= MN103_divu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0x8:	
			switch(d3)
			{
				case 0:	// rol Dn 
					cmd.itype= MN103_rol;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_0(b1);
					cmd.size=2;
					break;
				case 1: // ror Dn
					cmd.itype= MN103_ror;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_0(b1);
					cmd.size=2;
					break;
			}
			break;
		case 0x9:	// asl Dm,Dn
			cmd.itype= MN103_asl;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0xa:	// lsr Dm,Dn
			cmd.itype= MN103_lsr;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0xb:	// asr Dm,Dn
			cmd.itype= MN103_asr;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=2;
			break;
		case 0xc:	// invalid!
			cmd.size=0;
			break;
		case 0xd:	// ext Dn
			if(n2<4)
			{
				cmd.itype= MN103_ext;
				cmd.Op1.type = o_reg;
				cmd.Op1.reg = DN_0(b1);
				cmd.size=2;
			}
			else
			{
				// invalid!
				cmd.size=0;
			}
			break;
		case 0xe:	 
			switch(d3)
			{
				case 0:	// mov mdr,Dn
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = MDR;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=2;
					break;
				case 1:	// mov psw,Dn
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = PSW;
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=2;
					break;
			}
			cmd.size=2;
			break;
		case 0xf:
			switch(d4)
			{
				case 0x0:	// mov An,sp
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AN_2(b1);
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = SP;
					cmd.size=2;
					break;
				case 0x1:	// invalid!
					break;
				case 0x2:	// mov Dn,mdr
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = MDR;
					cmd.size=2;
					break;
				case 0x3:	// mov Dn,psw
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = PSW;
					cmd.Op2.dtyp = dt_word;
					cmd.size=2;
					break;
			}

			break;
	}

	return(cmd.size);
}

static int extF3(void)
{
	ushort b1 ,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	
	cmd.itype= MN103_mov;
	switch(n1)
	{
		case 0x0:
		case 0x1:
		case 0x2:
		case 0x3:	// mov (Di,Am),Dn
			cmd.Op1.type = o_phrase;
			cmd.Op1.indreg = DI_2(b1);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_4(b1);
			break;
		case 0x4:
		case 0x5:
		case 0x6:
		case 0x7:	// mov Dm,(Di,An)
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_4(b1);
			cmd.Op2.type = o_phrase;
			cmd.Op2.indreg = DI_2(b1);
			cmd.Op2.reg = AN_0(b1);
			break;
		case 0x8:
		case 0x9:
		case 0xa:
		case 0xb:	// mov (Di,Am),An
			cmd.Op1.type = o_phrase;
			cmd.Op1.indreg = DI_2(b1);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_4(b1);
			break;
		case 0xc:
		case 0xd:
		case 0xe:
		case 0xf:	// mov Am,(Di,An)
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_4(b1);
			cmd.Op2.type = o_phrase;
			cmd.Op2.indreg = DI_2(b1);
			cmd.Op2.reg = AN_0(b1);
			break;
	}
	cmd.size= 2;
	
	return(cmd.size);
}

static int extF4(void)
{
	ushort b1 ,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	
	switch(n1)
	{
		case 0x0:
		case 0x1:
		case 0x2:
		case 0x3:	// movbu (Di,Am),Dn
			cmd.itype= MN103_movbu;
			cmd.Op1.type = o_phrase;
			cmd.Op1.indreg = DI_2(b1);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_4(b1);
			break;
		case 0x4:
		case 0x5:
		case 0x6:
		case 0x7:	// movbu Dm,(Di,An)
			cmd.itype= MN103_movbu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_4(b1);
			cmd.Op2.type = o_phrase;
			cmd.Op2.indreg = DI_2(b1);
			cmd.Op2.reg = AN_0(b1);
			break;
		case 0x8:
		case 0x9:
		case 0xa:
		case 0xb:	// movhu (Di,Am),Dn
			cmd.itype= MN103_movhu;
			cmd.Op1.type = o_phrase;
			cmd.Op1.indreg = DI_2(b1);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_4(b1);
			break;
		case 0xc:
		case 0xd:
		case 0xe:
		case 0xf:	// movhu Dm,(Di,An)
			cmd.itype= MN103_movhu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_4(b1);
			cmd.Op2.type = o_phrase;
			cmd.Op2.indreg = DI_2(b1);
			cmd.Op2.reg = AN_0(b1);
			break;
	}
	cmd.size= 2;

	return(cmd.size);
}

// udf20..35 Dm, Dn
static int extF5(void)
{
	ushort b1 ,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	
	int op1[16] = 
	{
		MN103_udf20,
		MN103_udf21,
		MN103_udf22,
		MN103_udf23,
		MN103_udf24,
		MN103_udf25,
		MN103_udf26,
		MN103_udf27,
		MN103_udf28,
		MN103_udf29,
		MN103_udf30,
		MN103_udf31,
		MN103_udf32,
		MN103_udf33,
		MN103_udf34,
		MN103_udf35,
	};
	
	cmd.itype = op1[n1];
	cmd.Op1.type = o_reg;
	cmd.Op1.reg = DM_2(b1);
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = DN_0(b1);
	cmd.size = 2;
	return(cmd.size);
}
// udf00..15 Dm, Dn
static int extF6(void)
{
	ushort b1,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	
	int op1[16] = 
	{
		MN103_udf00,
		MN103_udf01,
		MN103_udf02,
		MN103_udf03,
		MN103_udf04,
		MN103_udf05,
		MN103_udf06,
		MN103_udf07,
		MN103_udf08,
		MN103_udf09,
		MN103_udf10,
		MN103_udf11,
		MN103_udf12,
		MN103_udf13,
		MN103_udf14,
		MN103_udf15,
	};

	cmd.itype = op1[n1];
	cmd.Op1.type = o_reg;
	cmd.Op1.reg = DM_2(b1);
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = DN_0(b1);
	cmd.size = 2;
	return(cmd.size);
}

// custom extension
static int extF7(void)
{
	cmd.size=4;
	cmd.Op1.type = o_imm;
	cmd.Op1.value = get_byte(cmd.ea+1);
	cmd.Op2.type = o_imm;
	cmd.Op2.value = get_byte(cmd.ea+2);
	cmd.Op3.type = o_imm;
	cmd.Op3.value = get_byte(cmd.ea+3);
	return(cmd.size);
}

static int extF8(void)
{
	ushort b1, n2, n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	
	switch(n1)
	{
		case 0x0:	// mov (d8,Am),Dn
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=3;
			break;
		case 0x1:	// mov Dm,(d8,An)
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=3;
			break;
		case 0x2:	// mov (d8,Am),An
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_2(b1);
			cmd.size=3;
			break;
		case 0x3:	// mov Am,(d8,An)
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=3;
			break;
		case 0x4:	// movbu (d8,Am),Dn
			cmd.itype= MN103_movbu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=3;
			break;
		case 0x5:	// movbu Dm,(d8,An)
			cmd.itype= MN103_movbu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=3;
			break;
		case 0x6:	// movhu (d8,Am),Dn
			cmd.itype= MN103_movhu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=3;
			break;
		case 0x7:	// movhu Dm,(d8,An)
			cmd.itype= MN103_movhu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed char)get_byte(cmd.ea+2);
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=3;
			break;
		case 0x8:	// invalid!
			break;
		case 0x9:
			switch(n2)
			{
				case 0x2:	// movbu Dn,(d8,SP)
				case 0x6:
				case 0xa:
				case 0xe:
					cmd.itype= MN103_movbu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+2);
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_byte;
					cmd.size=3;
					break;
				case 0x3:	// movhu Dn,(d8,SP)
				case 0x7:
				case 0xb:
				case 0xf:
					cmd.itype= MN103_movhu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+2);
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_byte;
					cmd.size=3;
					break;
			}
			break;
		case 0xa:	// invalid
			break;
		case 0xb:
			switch(n2)
			{
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:	// invalid
					break;
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:	// movbu (d8,SP),Dn
					cmd.itype= MN103_movbu;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = get_byte(cmd.ea+2);
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=3;
					break;
				case 0xc:
				case 0xd:
				case 0xe:
				case 0xf:	// movhu (d8,SP),Dn
					cmd.itype= MN103_movhu;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = get_byte(cmd.ea+2);
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=3;
					break;
			}
			break;
		case 0xc:
			switch(n2)
			{
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:	// asl imm8,Dn
					cmd.itype= MN103_asl;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 3;
					break;
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:	// lsr imm8,Dn
					cmd.itype= MN103_lsr;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 3;
					break;
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:	// asr imm8,Dn
					cmd.itype= MN103_asr;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 3;
					break;
				case 0xc:
				case 0xd:
				case 0xe:
				case 0xf:	// invalid
					break;
			}
			break;
		case 0xd:	// invalid
			break;
		case 0xe:
			switch(n2)
			{
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:	// and imm8,Dn
					cmd.itype = MN103_and;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 3;
					break;
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:	// or imm8,Dn
					cmd.itype = MN103_or;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 3;
					break;
				case 0x8:	// bvc (d8,PC)
					cmd.itype = MN103_bvc;
					cmd.Op1.type = o_near;
					cmd.Op1.addr = cmd.ea+(signed char) get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.size = 3;
					break;
				case 0x9:	// bvs (d8,PC)
					cmd.itype = MN103_bvs;
					cmd.Op1.type = o_near;
					cmd.Op1.addr = cmd.ea+(signed char) get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.size = 3;
					break;
				case 0xa:	// bnc (d8,PC)
					cmd.itype = MN103_bnc;
					cmd.Op1.type = o_near;
					cmd.Op1.addr = cmd.ea+(signed char) get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.size = 3;
					break;
				case 0xb:	// bns (d8,PC)
					cmd.itype = MN103_bns;
					cmd.Op1.type = o_near;
					cmd.Op1.addr = cmd.ea+(signed char) get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.size = 3;
					break;
				case 0xc:
				case 0xd:	
				case 0xe:	
				case 0xf:	// btst imm8,Dn	
					cmd.itype = MN103_btst;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 3;
					break;
			}
			break;
		case 0xf:	
			switch(n2)
			{
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:	// mov (d8,An),SP
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = get_byte(cmd.ea+2);
					cmd.Op1.reg = AN_0(b1);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = SP;
					cmd.size=3;
					break;
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:	// mov SP,(d8,An)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = SP;
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+2);
					cmd.Op2.reg = AN_0(b1);
					cmd.Op2.dtyp = dt_byte;
					cmd.size=3;
					break;
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:
				case 0xc:
				case 0xd:	// invalid!
					break;
				case 0xe:	// add imm8,SP
					cmd.itype = MN103_add;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = SP;
					cmd.size = 3;
					break;
				case 0xf:	// invalid!
					break;
			}
			break;
	}

	return(cmd.size);
}

static int extF9(void)	// udf imm8,Dn
{
ushort b1;
	int op1[16*4] = 
	{
		MN103_udf00,MN103_udfu00,MN103_udf20,MN103_udfu20,
		MN103_udf01,MN103_udfu01,MN103_udf21,MN103_udfu21,
		MN103_udf02,MN103_udfu02,MN103_udf22,MN103_udfu22,
		MN103_udf03,MN103_udfu03,MN103_udf23,MN103_udfu23,
		MN103_udf04,MN103_udfu04,MN103_udf24,MN103_udfu24,
		MN103_udf05,MN103_udfu05,MN103_udf25,MN103_udfu25,
		MN103_udf06,MN103_udfu06,MN103_udf26,MN103_udfu26,
		MN103_udf07,MN103_udfu07,MN103_udf27,MN103_udfu27,
		MN103_udf08,MN103_udfu08,MN103_udf28,MN103_udfu28,
		MN103_udf09,MN103_udfu09,MN103_udf29,MN103_udfu29,
		MN103_udf10,MN103_udfu10,MN103_udf30,MN103_udfu30,
		MN103_udf11,MN103_udfu11,MN103_udf31,MN103_udfu31,
		MN103_udf12,MN103_udfu12,MN103_udf32,MN103_udfu32,
		MN103_udf13,MN103_udfu13,MN103_udf33,MN103_udfu33,
		MN103_udf14,MN103_udfu14,MN103_udf34,MN103_udfu34,
		MN103_udf15,MN103_udfu15,MN103_udf35,MN103_udfu35,
	};

	b1 = get_byte(cmd.ea+1);

	cmd.itype = op1[b1>>2];
	cmd.Op1.type = o_imm;
	cmd.Op1.value = (signed char)get_byte(cmd.ea+2);
	cmd.Op1.dtyp = dt_byte;
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = DN_0(b1);
	cmd.size = 3;

	return(cmd.size);
}

static int extFA(void)
{
	ushort b1,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	ushort d3 = (b1 >> 2)&0x03;
	ushort d4 = (b1)&0x03;
	
	switch(n1)
	{
		case 0x0:	// mov (d16,Am),Dn
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_word;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=4;
			break;
		case 0x1:	// mov Dm,(d16,An)
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_word;
			cmd.size=4;
			break;
		case 0x2:	// mov (d16,Am),An
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_word;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_2(b1);
			cmd.size=4;
			break;
		case 0x3:	// mov Am,(d16,An)
			cmd.itype= MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_word;
			cmd.size=4;
			break;
		case 0x4:	// movbu (d16,Am),Dn
			cmd.itype= MN103_movbu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_word;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=4;
			break;
		case 0x5:	// movbu Dm,(d16,An)
			cmd.itype= MN103_movbu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_word;
			cmd.size=4;
			break;
		case 0x6:	// movhu (d16,Am),Dn
			cmd.itype= MN103_movhu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_word;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=4;
			break;
		case 0x7:	// movhu Dm,(d16,An)
			cmd.itype= MN103_movhu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed short)((get_byte(cmd.ea+3)<<8)+(get_byte(cmd.ea+2)));
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_word;
			cmd.size=4;
			break;
		case 0x8:
			switch(d4)
			{
				case 0:	// mov An,(abs16)
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AM_2(b1);
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op2.dtyp = dt_word;
					cmd.size=4;
					break;
				case 1:
				case 2:
				case 3:	// invalid
					break;
			}
			break;
		case 0x9:
			switch(d4)
			{
				case 0:	// mov An,(d16,SP)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AM_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_word;
					cmd.size=4;
					break;
				case 1:	// mov Dn,(d16,SP)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DM_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_word;
					cmd.size=4;
					break;
				case 2:	// movbu Dn,(d16,SP)
					cmd.itype = MN103_movbu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DM_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_word;
					cmd.size=4;
					break;
				case 3:	// movhu Dn,(d16,SP)
					cmd.itype = MN103_movhu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DM_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_word;
					cmd.size=4;
					break;
			}
			break;
		case 0xa:
			switch(d3)
			{
				case 0:	// mov (abs16),An
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size=4;
					break;
				case 1:
				case 2:
				case 3:	// invalid
					break;
			}
			break;
		case 0xb:
			switch(d3)
			{
				case 0:	// mov (d16,SP),An
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AM_0(b1);
					cmd.size=4;
					break;
				case 1:	// mov (d16,SP),Dn
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DM_0(b1);
					cmd.size=4;
					break;
				case 2:	// movbu (d16,SP),Dn
					cmd.itype = MN103_movbu;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DM_0(b1);
					cmd.size=4;
					break;
				case 3:	// movhu (d16,SP),Dn
					cmd.itype = MN103_movhu;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DM_0(b1);
					cmd.size=4;
					break;
			}
			break;
		case 0xc:
			switch(d3)
			{
				case 0:	// add imm16,Dn
					cmd.itype = MN103_add;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (signed short) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 4;
					break;
				case 1:	// invalid
					break;
				case 2:	// cmp imm16,Dn
					cmd.itype = MN103_cmp;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (signed short) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 4;
					break;
				case 3:	// invalid
					break;
			}
			break;
		case 0xd:
			switch(d3)
			{
				case 0:	// add imm16,An
					cmd.itype = MN103_add;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size = 4;
					break;
				case 1:	// invalid
					break;
				case 2:	// cmp imm16,An
					cmd.itype = MN103_cmp;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size = 4;
					break;
				case 3:	// invalid
					break;
			}
			break;
		case 0xe:
			switch(n2)
			{
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:	// and imm16,Dn
					cmd.itype = MN103_and;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 4;
					break;
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:	// or imm16,Dn
					cmd.itype = MN103_or;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 4;
					break;
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:	// xor imm16,Dn
					cmd.itype = MN103_xor;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 4;
					break;
				case 0xc:
				case 0xd:
				case 0xe:
				case 0xf:	// btst imm16,Dn
					cmd.itype = MN103_btst;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size = 4;
					break;
			}
			break;
		case 0xf:
			switch(n2)
			{
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:	// bset imm8,(d8,An)
					cmd.itype = MN103_bset;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+3);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+2);
					cmd.Op2.reg = AN_0(b1);
					cmd.Op2.dtyp = dt_byte;
					cmd.size = 4;
					break;
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:	// bclr imm8,(d8,An)
					cmd.itype = MN103_bclr;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+3);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+2);
					cmd.Op2.reg = AN_0(b1);
					cmd.Op2.dtyp = dt_byte;
					cmd.size = 4;
					break;
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:	// btst imm8,(d8,An)
					cmd.itype = MN103_btst;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+3);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+2);
					cmd.Op2.reg = AN_0(b1);
					cmd.Op1.dtyp = dt_byte;
					cmd.size = 4;
					break;
				case 0xc:	// and imm16,PSW
					cmd.itype= MN103_and;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = PSW;
					cmd.Op2.dtyp = dt_word;
					cmd.size= 4;
					break;
				case 0xd:	// or imm16,PSW
					cmd.itype= MN103_or;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = PSW;
					cmd.Op2.dtyp = dt_word;
					cmd.size= 4;
					break;
				case 0xe:	// add imm16,SP
					cmd.itype= MN103_add;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (signed short)((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = SP;
					cmd.size= 4;
					break;
				case 0xf:	// calls (d16,PC)
					cmd.Op1.type = o_near;
					cmd.Op1.addr = cmd.ea+(signed short) ((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.size=4;
					break;
			}

			break;
	}

	return(cmd.size);
}

static int extFB(void)	// udf imm16,Dn
{
	ushort b1;
	int op1[16*4] = 
	{
		MN103_udf00,MN103_udfu00,MN103_udf20,MN103_udfu20,
		MN103_udf01,MN103_udfu01,MN103_udf21,MN103_udfu21,
		MN103_udf02,MN103_udfu02,MN103_udf22,MN103_udfu22,
		MN103_udf03,MN103_udfu03,MN103_udf23,MN103_udfu23,
		MN103_udf04,MN103_udfu04,MN103_udf24,MN103_udfu24,
		MN103_udf05,MN103_udfu05,MN103_udf25,MN103_udfu25,
		MN103_udf06,MN103_udfu06,MN103_udf26,MN103_udfu26,
		MN103_udf07,MN103_udfu07,MN103_udf27,MN103_udfu27,
		MN103_udf08,MN103_udfu08,MN103_udf28,MN103_udfu28,
		MN103_udf09,MN103_udfu09,MN103_udf29,MN103_udfu29,
		MN103_udf10,MN103_udfu10,MN103_udf30,MN103_udfu30,
		MN103_udf11,MN103_udfu11,MN103_udf31,MN103_udfu31,
		MN103_udf12,MN103_udfu12,MN103_udf32,MN103_udfu32,
		MN103_udf13,MN103_udfu13,MN103_udf33,MN103_udfu33,
		MN103_udf14,MN103_udfu14,MN103_udf34,MN103_udfu34,
		MN103_udf15,MN103_udfu15,MN103_udf35,MN103_udfu35,
	};

	b1 = get_byte(cmd.ea+1);

	cmd.itype = op1[b1>>2];
	cmd.Op1.type = o_imm;
	if((b1>>2)&1)
	{
		cmd.Op1.value = (unsigned short)((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
	}
	else
	{
		cmd.Op1.value = (signed short)((get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
	}
	cmd.Op1.dtyp = dt_word;
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = DN_0(b1);
	cmd.size = 4;

	return(cmd.size);
}

static int extFC(void)
{
	ushort b1 = get_byte(cmd.ea+1);
	
	ushort n1 = (b1 >> 4);
	ushort n2 = (b1 & 0xF);
	
	ushort d3 = (b1 >> 2)&0x03;
	ushort d4 = (b1)&0x03;
	
	switch(n1)
	{
		case 0x0:	// mov (d32,Am),Dn
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=6;
			break;
		case 0x1:	// mov Dm,(d32,An)
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op2.reg = AN_0(b1);
			cmd.size=6;
			break;
		case 0x2:	// mov (d32,Am),An
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_2(b1);
			cmd.size=6;
			break;
		case 0x3:	// mov Am,(d32,An)
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = AM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op2.reg = AN_0(b1);
			cmd.size=6;
			break;
		case 0x4:	// movbu (d32,Am),Dn
			cmd.itype = MN103_movbu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=6;
			break;
		case 0x5:	// movbu Dm,(d32,An)
			cmd.itype = MN103_movbu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=6;
			break;
		case 0x6:	// movhu (d32,Am),Dn
			cmd.itype = MN103_movhu;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op1.reg = AM_0(b1);
			cmd.Op1.dtyp = dt_word;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=6;
			break;
		case 0x7:	// movhu Dm,(d32,An)
			cmd.itype = MN103_movhu;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
			cmd.Op2.reg = AN_0(b1);
			cmd.Op2.dtyp = dt_word;
			cmd.size=6;
			break;
		case 0x8:
			switch(d4)
			{
				case 0:	// mov An,(abs32)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AN_2(b1);
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.size=6;
					break;
				case 1:	// mov Dn,(abs32)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.size=6;
					break;
				case 2:	// movbu Dn,(abs32)
					cmd.itype = MN103_movbu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op2.dtyp = dt_byte;
					cmd.size=6;
					break;
				case 3:	// movhu Dn,(abs32)
					cmd.itype = MN103_movhu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op2.dtyp = dt_word;
					cmd.size=6;
					break;
			}
			break;
		case 0x9:
			switch(d4)
			{
				case 0:	// mov An,(d32,SP)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AN_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.size=6;
					break;
				case 1:	// mov Dn,(d32,SP)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.size=6;
					break;
				case 2:	// movbu Dn,(d32,SP)
					cmd.itype = MN103_movbu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_byte;
					cmd.size=6;
					break;
				case 3:	// movhu Dn,(d32,SP)
					cmd.itype = MN103_movhu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op2.reg = SP;
					cmd.Op2.dtyp = dt_word;
					cmd.size=6;
					break;
			}
			break;
		case 0xa:
			switch(d3)
			{
				case 0:	// mov (abs32),An
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size=6;
					break;
				case 1:	// mov (abs32),Dn
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=6;
					break;
				case 2:	// movbu (abs32),Dn
					cmd.itype = MN103_movbu;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=6;
					break;
				case 3:	// movhu (abs32),Dn
					cmd.itype = MN103_movhu;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=6;
					break;
			}
			break;
		case 0xb:
			switch(d3)
			{
				case 0:	// mov (d32,SP),An
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size=6;
					break;
				case 1:	// mov (d32,SP),Dn
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=6;
					break;
				case 2:	// movbu (d32,SP),Dn
					cmd.itype = MN103_movbu;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=6;
					break;
				case 3:	// movhu (d32,SP),Dn
					cmd.itype = MN103_movhu;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = (signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.Op1.reg = SP;
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=6;
					break;
			}
			break;
		case 0xc:
			switch(d3)
			{
				case 0:	// add imm32,Dn
					cmd.itype = MN103_add;
					break;
				case 1:	// sub imm32,Dn
					cmd.itype = MN103_sub;
					break;
				case 2:	// cmp imm32,Dn
					cmd.itype = MN103_cmp;
					break;
				case 3:	// mov imm32,Dn
					cmd.itype = MN103_mov;
					break;
			}
			cmd.Op1.type = o_imm;
			cmd.Op1.value = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=6;
			break;
		case 0xd:
			switch(d3)
			{
				case 0:	// add imm32,An
					cmd.itype = MN103_add;
					break;
				case 1:	// sub imm32,An
					cmd.itype = MN103_sub;
					break;
				case 2:	// cmp imm32,An
					cmd.itype = MN103_cmp;
					break;
				case 3:	// mov imm32,An
					cmd.itype = MN103_mov;
					break;
			}
			cmd.Op1.type = o_imm;
			cmd.Op1.value = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=6;
			break;
		case 0xe:
			switch(d3)
			{
				case 0:	// and imm32,Dn
					cmd.itype = MN103_and;
					break;
				case 1:	// or imm32,Dn
					cmd.itype = MN103_or;
					break;
				case 2:	// xor imm32,Dn
					cmd.itype = MN103_xor;
					break;
				case 3:	// btst imm32,Dn
					cmd.itype = MN103_btst;
					break;
			}
			cmd.Op1.type = o_imm;
			cmd.Op1.value = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=6;
			break;
		case 0xf:
			switch(n2)
			{
				case 0x0e:	// add imm32,SP
					cmd.itype = MN103_add;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = SP;
					cmd.size=6;
					break;
				case 0x0f:	// calls (d32,PC)
					cmd.itype = MN103_calls;
					cmd.Op1.type = o_near;
					cmd.Op1.addr = cmd.ea+(signed long) ((get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2));
					cmd.size=6;
					break;
			}
			break;
	}

	return(cmd.size);
}

static int extFD(void)	// udf imm32,Dn
{
ushort b1;
	int op1[16*4] = 
	{
		MN103_udf00,MN103_udfu00,MN103_udf20,MN103_udfu20,
		MN103_udf01,MN103_udfu01,MN103_udf21,MN103_udfu21,
		MN103_udf02,MN103_udfu02,MN103_udf22,MN103_udfu22,
		MN103_udf03,MN103_udfu03,MN103_udf23,MN103_udfu23,
		MN103_udf04,MN103_udfu04,MN103_udf24,MN103_udfu24,
		MN103_udf05,MN103_udfu05,MN103_udf25,MN103_udfu25,
		MN103_udf06,MN103_udfu06,MN103_udf26,MN103_udfu26,
		MN103_udf07,MN103_udfu07,MN103_udf27,MN103_udfu27,
		MN103_udf08,MN103_udfu08,MN103_udf28,MN103_udfu28,
		MN103_udf09,MN103_udfu09,MN103_udf29,MN103_udfu29,
		MN103_udf10,MN103_udfu10,MN103_udf30,MN103_udfu30,
		MN103_udf11,MN103_udfu11,MN103_udf31,MN103_udfu31,
		MN103_udf12,MN103_udfu12,MN103_udf32,MN103_udfu32,
		MN103_udf13,MN103_udfu13,MN103_udf33,MN103_udfu33,
		MN103_udf14,MN103_udfu14,MN103_udf34,MN103_udfu34,
		MN103_udf15,MN103_udfu15,MN103_udf35,MN103_udfu35,
	};

	b1 = get_byte(cmd.ea+1);

	cmd.itype = op1[b1>>2];
	cmd.Op1.type = o_imm;
	cmd.Op1.value = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = DN_0(b1);
	cmd.size = 6;

	return(cmd.size);
}

static int extFE(void)
{
	ushort b1,n2,n1;
	b1 = get_byte(cmd.ea+1);
	n2 = (b1 & 0xF);
	n1 = (b1 >> 4);
	
	switch(n1)
	{
		case 0:
			switch(n2)
			{
				case 0:	// bset imm8,(abs32)
					cmd.itype = MN103_bset;
					break;
				case 1:	// bclr imm8,(abs32)
					cmd.itype = MN103_bclr;
					break;
				case 2:	// btst imm8,(abs32)
					cmd.itype = MN103_btst;
					break;
			}
			cmd.Op1.type = o_imm;
			cmd.Op1.value = get_byte(cmd.ea+6);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_mem;
			cmd.Op2.addr = (get_byte(cmd.ea+5)<<24)+(get_byte(cmd.ea+4)<<16)+(get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=7;
			break;
		case 8:
			switch(n2)
			{
				case 0:	// bset imm8,(abs16)
					cmd.itype = MN103_bset;
					break;
				case 1:	// bclr imm8,(abs16)
					cmd.itype = MN103_bclr;
					break;
				case 2:	// btst imm8,(abs16)
					cmd.itype = MN103_btst;
					break;
			}
			cmd.Op1.type = o_imm;
			cmd.Op1.value = get_byte(cmd.ea+4);
			cmd.Op1.dtyp = dt_byte;
			cmd.Op2.type = o_mem;
			cmd.Op2.addr = (get_byte(cmd.ea+3)<<8)+get_byte(cmd.ea+2);
			cmd.Op2.dtyp = dt_byte;
			cmd.size=5;
			break;
	}

	return(cmd.size);
}

// invalid
static int extFF(void)
{
	cmd.size=1;
	return(cmd.size);
}


// main routine for analysing an instructions
static int ana_main(void)
{
	// get next byte to analyse
	ushort b1 = ua_next_byte();
	
	// split the byte high and low 4bits
	ushort n1 = (b1 >> 4);
	ushort n2 = (b1 & 0xF);
	
	// split the low 4bits into high and low 2 bits
	ushort d3 = (b1 >> 2)&0x03;
	ushort d4 = (b1)&0x03;
	
	switch(n1)
	{
		case 0x0:	
			switch(d4)
			{
				case 0:	// clr Dn
					cmd.itype = MN103_clr;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.size=1;
					break;
				case 1: // mov Dm,(abs16)
					cmd.itype = MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DM_2(b1);
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1);
					cmd.size=3;
					break;
				case 2: // movbu Dm, (abs16)
					cmd.itype = MN103_movbu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DM_2(b1);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1);
					cmd.Op2.dtyp = dt_byte;
					cmd.size=3;
					break;
				case 3: // movhu Dm, (abs16)
					cmd.itype = MN103_movhu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DM_2(b1);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_mem;
					cmd.Op2.addr = (get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1);
					cmd.Op2.dtyp = dt_word;
					cmd.size=3;
					break;
			}
			break;
		case 0x1:	
			switch(d3)
			{
				case 0:	// extb Dn
					cmd.itype= MN103_extb;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_0(b1);
					break;
				case 1:	// extbu Dn
					cmd.itype= MN103_extbu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_0(b1);
					break;
				case 2:	// exth Dn
					cmd.itype= MN103_exth;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_0(b1);
					break;
				case 3:	// exthu Dn
					cmd.itype= MN103_exthu;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_0(b1);
					break;
			}
			cmd.size=1;
			break;
		case 0x2:
			switch(d3)
			{
				case 0:	// add imm8,An
					cmd.itype= MN103_add;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+1);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size= 2;
					break;
				case 1:	// mov imm16,An
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size= 3;
					break;
				case 2:	// add imm8,Dn
					cmd.itype= MN103_add;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = get_byte(cmd.ea+1);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size= 2;
					break;	
				case 3:	// mov imm16,Dn
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_imm;
					cmd.Op1.value = (signed short)((get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1));
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size= 3;
					break;
			}	
			//cmd.size=1;
			break;
		case 0x3:	
			switch(d3)
			{
				case 0:	// mov (abs16),Dn
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1);
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=3;
					break;
				case 1:	// movbu (abs16),Dn
					cmd.itype= MN103_movbu;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1);
					cmd.Op1.dtyp = dt_byte;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=3;
					break;
				case 2:	// movhu (abs16),Dn
					cmd.itype= MN103_movhu;
					cmd.Op1.type = o_mem;
					cmd.Op1.addr = (get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1);
					cmd.Op1.dtyp = dt_word;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=3;
					break;
				case 3:	// mov SP,An
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = SP;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size=1;
					break;
			}
			break;
		case 0x4:	
			switch(d4)
			{
				case 0:	// inc Dn
					cmd.itype= MN103_inc;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_2(b1);
					cmd.size=1;
					break;
				case 1:	// inc An
					cmd.itype= MN103_inc;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AN_2(b1);
					cmd.size=1;
					break;
				case 2:	// mov Dm,(d8,SP)
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DM_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+1);
					cmd.Op2.reg = SP;
					cmd.size=2;
					break;
				case 3:	// mov Am,(d8,SP)
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AM_2(b1);
					cmd.Op2.type = o_displ;
					cmd.Op2.addr = get_byte(cmd.ea+1);
					cmd.Op2.reg = SP;
					cmd.size=2;
					break;
			}
			break;
		case 0x5:
			switch(d3)
			{
				case 0:	// inc4 An
					cmd.itype= MN103_inc4;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = AN_0(b1);
					cmd.size=1;
					break;
				case 1:	// asl2 Dn
					cmd.itype= MN103_asl2;
					cmd.Op1.type = o_reg;
					cmd.Op1.reg = DN_0(b1);
					cmd.size=1;
					break;
				case 2:	// mov (d8,SP),Dn
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = get_byte(cmd.ea+1);
					cmd.Op1.reg = SP;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = DN_0(b1);
					cmd.size=2;
					break;
				case 3:	// mov (d8,SP),An
					cmd.itype= MN103_mov;
					cmd.Op1.type = o_displ;
					cmd.Op1.addr = get_byte(cmd.ea+1);
					cmd.Op1.reg = SP;
					cmd.Op2.type = o_reg;
					cmd.Op2.reg = AN_0(b1);
					cmd.size=2;
					break;
			}	
			break;
		case 0x6:	// mov Dm,(An)
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_displ;
			cmd.Op2.addr = 0;
			cmd.Op2.reg = AN_0(b1);
			cmd.size=1;
			break;
		case 0x7:	// mov (Am),Dn
			cmd.itype = MN103_mov;
			cmd.Op1.type = o_displ;
			cmd.Op1.addr = 0;
			cmd.Op1.reg = AM_0(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_2(b1);
			cmd.size=1;
			break;
		case 0x8:
			cmd.itype = MN103_mov;
			if(DM_2(b1)==DN_0(b1))
			{
				// mov imm8,Dn
				cmd.Op1.type = o_imm;
				cmd.Op1.value = get_byte(cmd.ea+1);
				cmd.Op1.dtyp = dt_byte;
				cmd.size=2;
			}
			else
			{
				// mov Dm,Dn
				cmd.Op1.type = o_reg;
				cmd.Op1.reg = DM_2(b1);
				cmd.size=1;
			}
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			break;
		case 0x9:	
			cmd.itype = MN103_mov;
			if(AM_2(b1)==AN_0(b1))
			{
				// mov imm8,An
				cmd.Op1.type = o_imm;
				cmd.Op1.value = get_byte(cmd.ea+1);
				cmd.Op1.dtyp = dt_byte;
				cmd.size=2;
			}
			else
			{
				// mov Am,An
				cmd.Op1.type = o_reg;
				cmd.Op1.reg = AM_2(b1);
				cmd.size=1;
			}
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			break;
		case 0xa:	
			cmd.itype = MN103_cmp;
			if(DM_2(b1)==DN_0(b1))
			{
				// cmp imm8,Dn
				cmd.Op1.type = o_imm;
				cmd.Op1.value = get_byte(cmd.ea+1);
				cmd.Op1.dtyp = dt_byte;
				cmd.size=2;
			}
			else
			{
				// cmp Dm,Dn
				cmd.Op1.type = o_reg;
				cmd.Op1.reg = DM_2(b1);
				cmd.size=1;
			}
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			break;
		case 0xb:	
			cmd.itype = MN103_cmp;
			if(AM_2(b1)==AN_0(b1))
			{
				// cmp imm8,An
				cmd.Op1.type = o_imm;
				cmd.Op1.value = get_byte(cmd.ea+1);
				cmd.Op1.dtyp = dt_byte;
				cmd.size=2;
			}
			else
			{
				// cmp Am,An
				cmd.Op1.type = o_reg;
				cmd.Op1.reg = AM_2(b1);
				cmd.size=1;
			}
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = AN_0(b1);
			break;
		case 0xc:	
			{
				int op1[16] = 
				{
					MN103_blt,MN103_bgt,MN103_bge,MN103_ble,
					MN103_bcs,MN103_bhi,MN103_bcc,MN103_bls,
					MN103_beq,MN103_bne,MN103_bra,MN103_nop,
					MN103_jmp,MN103_call,MN103_movm,MN103_movm,
				};
				cmd.itype = op1[n2];
				switch(n2)
				{
					case 0x0:	// blt (d8,PC)
					case 0x1:	// bgt (d8,PC)
					case 0x2:	// bge (d8,PC)
					case 0x3:	// ble (d8,PC)
					case 0x4:	// bcs (d8,PC)
					case 0x5:	// bhi (d8,PC)
					case 0x6:	// bcc (d8,PC)
					case 0x7:	// bls (d8,PC)
					case 0x8:	// beq (d8,PC)
					case 0x9:	// bne (d8,PC)
					case 0xa:	// bra (d8,PC)
						cmd.Op1.type = o_near;
						cmd.Op1.addr = cmd.ea+(signed char) get_byte(cmd.ea+1);
						cmd.size=2;
						break;
					case 0xb:	// nop
						cmd.size=1;
						break;
					case 0xc:	// jmp (d16,PC)
						cmd.Op1.type = o_near;
						cmd.Op1.addr = cmd.ea+(signed short) ((get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1));
						cmd.size=3;
						break;
					case 0xd:	// call (d16,PC)
						cmd.Op1.type = o_near;
						cmd.Op1.addr = cmd.ea+(signed short) ((get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1));

						cmd.Op2.type = o_regs;
						cmd.Op2.value = get_byte(cmd.ea+3);

						cmd.Op3.type = o_imm;
						cmd.Op3.value = get_byte(cmd.ea+4);

						cmd.size=5;
						break;
					case 0xe:	// movm (SP),regs
						cmd.Op1.type = o_displ;
						cmd.Op1.addr = 0;
						cmd.Op1.reg = SP;
						cmd.Op2.type = o_regs;
						cmd.Op2.value = get_byte(cmd.ea+1);
						cmd.size=2;
						break;
					case 0xf:	// movm regs,(SP)
						cmd.Op1.type = o_regs;
						cmd.Op1.value = get_byte(cmd.ea+1);
						cmd.Op2.type = o_displ;
						cmd.Op2.addr = 0;
						cmd.Op2.reg = SP;
						cmd.size=2;
						break;
				}
			}
			break;
		case 0xd:	
			{
				int op1[16] = 
				{
					MN103_llt,MN103_lgt,MN103_lge,MN103_lle,
					MN103_lcs,MN103_lhi,MN103_lcc,MN103_lls,
					MN103_leq,MN103_lne,MN103_lra,MN103_setlb,
					MN103_jmp,MN103_call,MN103_retf,MN103_ret,
				};
				cmd.itype = op1[n2];
				switch(n2)
				{
					case 0x0:	// llt
					case 0x1:	// lgt
					case 0x2:	// lge
					case 0x3:	// lle
					case 0x4:	// lcs
					case 0x5:	// lhi
					case 0x6:	// lcc
					case 0x7:	// lls
					case 0x8:	// leq
					case 0x9:	// lne
					case 0xa:	// lra
					case 0xb:	// setlb
						cmd.size=1;
						break;
					case 0xc:	// jmp (d32,PC)
						cmd.Op1.type = o_near;
						cmd.Op1.addr = cmd.ea+(signed long) ((get_byte(cmd.ea+4)<<24)+(get_byte(cmd.ea+3)<<16)+(get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1));
						cmd.size=5;
						break;
					case 0xd:	// call (d32,PC)
						cmd.Op1.type = o_near;
						cmd.Op1.addr = cmd.ea+(signed long) ((get_byte(cmd.ea+4)<<24)+(get_byte(cmd.ea+3)<<16)+(get_byte(cmd.ea+2)<<8)+get_byte(cmd.ea+1));

						cmd.Op2.type = o_regs;
						cmd.Op2.value = get_byte(cmd.ea+5);

						cmd.Op3.type = o_imm;
						cmd.Op3.value = get_byte(cmd.ea+6);
						cmd.size=7;
						break;
					case 0xe:	// retf regs,imm8
					case 0xf:	// ret regs,imm8

						cmd.Op1.type = o_regs;
						cmd.Op1.value = get_byte(cmd.ea+1);

						cmd.Op2.type = o_imm;
						cmd.Op2.value = get_byte(cmd.ea+2);
						cmd.Op2.dtyp = dt_byte;

						cmd.size=3;
						break;
				}
			}
			break;
		case 0xe:	// add Dm,Dn	
			cmd.itype = MN103_add;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = DM_2(b1);
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = DN_0(b1);
			cmd.size=1;
			break;
		case 0xf:	
			switch(n2)
			{
				case 0x0:
					cmd.size=extF0();
					break;
				case 0x1:
					cmd.size=extF1();
					break;
				case 0x2:
					cmd.size=extF2();
					break;
				case 0x3:
					cmd.size=extF3();
					break;
				case 0x4:
					cmd.size=extF4();
					break;
				case 0x5:
					cmd.size=extF5();
					break;
				case 0x6:
					cmd.size=extF6();
					break;
				case 0x7:
					cmd.size=extF7();
					break;
				case 0x8:
					cmd.size=extF8();
					break;
				case 0x9:
					cmd.size=extF9();
					break;
				case 0xa:
					cmd.size=extFA();
					break;
				case 0xb:
					cmd.size=extFB();
					break;
				case 0xc:
					cmd.size=extFC();
					break;
				case 0xd:
					cmd.size=extFD();
					break;
				case 0xe:
					cmd.size=extFE();
					break;
				case 0xf:
					cmd.size=extFF();
					break;
			}
			break;
  }
  return cmd.size;
}


//----------------------------------------------------------------------
// this is the externally accessable routine that analyses an instruction
// returns: size of command, or 0

int ana(void)
{
	cmd.itype = 0; // opcode
	// cmd.auxpref |= aux_1ext; ?
	// addr mode (o_imm, o_near, o_reg, o_mem, o_phrase, o_bit, o_bitnot
	// o_displ - register indirect with displacement
	cmd.Op1.type = o_void; 
	cmd.Op2.type = o_void; 
	cmd.Op3.type = o_void; 
	
	cmd.Op1.offb = 0; 
//	cmd.Op1.b251_bitneg = 0;
//	cmd.Op1.indreg = 0; // for o_phrase
	cmd.Op1.addr = 0; // o_displ
	cmd.Op1.reg = 0; // for o_reg
	cmd.Op1.value = 0; // for o_imm
	cmd.Op1.phrase = 0; // for o_phrase, o_displ
	
	// dt_byte  =  8 bit
	// dt_word  = 16 bit
	// dt_dword = 32 bit
	
	// set all to data types to initiall be 'dword' since processor is 32bit
	// these will get updated in ana_main() if they are not 32bit
	cmd.Op1.dtyp = dt_dword;
	cmd.Op2.dtyp = dt_dword;
	cmd.Op3.dtyp = dt_dword;
	
	cmd.size = 0;
	return ana_main();
}
