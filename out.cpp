/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */

#include "mn103.hpp"
#include <fpro.h>
#include <diskio.hpp>

//----------------------------------------------------------------------
class out_mn103_t : public outctx_t
{
  out_mn103_t(void) : outctx_t(BADADDR) {} // not used
public:
  inline void OutReg(int rgnum)
  {
    out_register(ph.reg_names[rgnum]);
  }

  void OutVarName(const op_t &x);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_mn103_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_mn103_t)

//----------------------------------------------------------------------
static void vlog(const char *format, va_list va)
{
  static FILE *fp = NULL;
  if ( fp == NULL ) fp = fopenWT("debug_log");
  qvfprintf(fp, format, va);
  qflush(fp);
}
//----------------------------------------------------------------------
inline void log(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vlog(format, va);
  va_end(va);
}

#if 0
#define AT   COLSTR("@", SCOLOR_SYMBOL)
#define PLUS COLSTR("+", SCOLOR_SYMBOL)
#endif

//----------------------------------------------------------------------
void out_mn103_t::OutVarName(const op_t &x)
{
  ea_t toea = map_code_ea(insn, x);
  if ( !out_name_expr(x, toea, x.addr) )
  {
    out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
// generate the text representation of an operand

bool out_mn103_t::out_operand(const op_t & x)
{
  uval_t v;
  char ptr[MAXSTR];

//  int dir, bit;
  switch ( x.type )
  {

	case o_regs:
		{
		int flg=0;
		out_symbol('[');

		if(x.value&0x80)
		{
			if(flg)out_symbol(',');
			OutReg(rD2);
			flg=1;
		}
		if(x.value&0x40)
		{
			if(flg)out_symbol(',');
			OutReg(rD3);
			flg=1;
		}
		if(x.value&0x20)
		{
			if(flg)out_symbol(',');
			OutReg(rA2);
			flg=1;
		}
		if(x.value&0x10)
		{
			if(flg)out_symbol(',');
			OutReg(rA3);
			flg=1;
		}
		if(x.value&0x08)
		{
			if(flg)out_symbol(',');
			OutReg(rD0);
			flg=1;
			if(flg)out_symbol(',');
			OutReg(rD1);
			flg=1;
			if(flg)out_symbol(',');
			OutReg(rA0);
			flg=1;
			if(flg)out_symbol(',');
			OutReg(rA1);
			flg=1;
			if(flg)out_symbol(',');
			OutReg(rMDR);
			flg=1;
			if(flg)out_symbol(',');
			OutReg(rLIR);
			flg=1;
			if(flg)out_symbol(',');
			OutReg(rLAR);
			flg=1;
		}

		out_symbol(']');
		}
		break;

    case o_reg:
      OutReg(x.reg);
      break;
    
    case o_phrase:
      out_symbol('(');
      OutReg(x.indreg);
      out_symbol(',');
      OutReg(x.reg);
      out_symbol(')');
        break;
    
    case o_displ:
	    out_symbol('(');
	    if(x.addr!=0)
	    {
	    //out_symbol('#');
		    //out_value(x, OOF_ADDR | OOFS_IFSIGN | OOFW_16);
		    out_value(x, OOF_ADDR | OOFS_IFSIGN | OOFW_32);
		    out_symbol(',');
	    }
	    OutReg(x.reg);
	    out_symbol(')');
      break;

    case o_imm:
      //out_symbol('#');
      //if ( insn.auxpref & aux_0ext ) out_symbol('0');
      //if ( insn.auxpref & aux_1ext ) out_symbol('1');
      out_value(x, OOFS_IFSIGN | OOFW_IMM| OOFW_32);
      break;

    case o_mem:
      out_symbol('(');
      OutVarName(x);
      out_symbol(')');
	    break;
    case o_near:
      OutVarName(x);
      break;

    case o_void:
      return false;

//    case o_bit251:
//      if ( x.b251_bitneg ) out_symbol('/');
//      dir = x.addr;
//      bit = x.b251_bit;
//      goto OUTBIT;

//    case o_bitnot:
//      out_symbol('/');
    case o_bit:
	    out_value(x, 0);
#if 0	    
      dir = (x.reg & 0xF8);
      bit = x.reg & 7;
      if ( (dir & 0x80) == 0 ) dir = dir/8 + 0x20;
OUTBIT:
      if(ash.uflag & UAS_PBIT)
      {
        const ioport_bit_t *predef = find_bit(dir, bit);
        if ( predef != NULL )
        {
          out_line(predef->name, COLOR_REG);
          break;
        }
      }
      {
        v = map_addr(dir, x.n, true);
        char *rname = get_name_expr(insn.ea+x.offb, x.n, v, dir);
        if ( rname != NULL && strchr(rname, '+') == NULL )
        {

      // we want to output the bit names always in COLOR_REG,
      // so remove the color tags and output it manually:

          if ( dir < 0x80 )
          {
            OutLine(rname);
          }
          else
          {
            tag_remove(rname, rname, 0);
            out_register(rname);
          }
        }
        else
        {
          out_long(dir, 16);
        }
        out_symbol(ash.uflag & UAS_NOBIT ? '_' : '.');
        out_symbol('0'+bit);
      }
#endif      
      break;

     default:
       warning("out: %a: bad optype",insn.ea,x.type);
       break;
  }
  return true;
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the 'insn' structure

void out_mn103_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);                   // output the first operand

  if ( insn.Op2.type != o_void)
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);                 // output the second operand
  }

  if ( insn.Op3.type != o_void)
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);                 // output the third operand
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
// generate header of the disassembly

void idaapi mn103_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, device.c_str(), deviceparams.c_str());
}

//--------------------------------------------------------------------------
// generate start of a segment

void idaapi mn103_segstart(outctx_t &ctx, segment_t *Sarea)
{
  char buf[MAXSTR];

  qstring name;
  get_visible_segm_name(&name, Sarea);

  if ( ash.uflag & UAS_SECT )
  {
    if ( Sarea->type == SEG_IMEM )
      ctx.flush_buf(".RSECT", inf.indent);
    else
      ctx.gen_printf(0, COLSTR("%s: .section", SCOLOR_ASMDIR), name.c_str());
  }
  else
  {
    if ( ash.uflag & UAS_NOSEG )
      ctx.gen_printf(inf.indent, COLSTR("%s.segment %s", SCOLOR_AUTOCMT), ash.cmnt, name.c_str());
    else
      ctx.gen_printf(inf.indent, COLSTR("segment %s",SCOLOR_ASMDIR), name.c_str());
    if ( ash.uflag & UAS_SELSG )
      ctx.flush_buf(name.c_str(), inf.indent);
    if ( ash.uflag & UAS_CDSEG )
      ctx.flush_buf(Sarea->type == SEG_IMEM
                  ? COLSTR("DSEG", SCOLOR_ASMDIR)
                  : COLSTR("CSEG", SCOLOR_ASMDIR),
                    inf.indent);
    // XSEG - eXternal memory
  }
  if ( (inf.outflags & OFLG_GEN_ORG) != 0 )
  {
    adiff_t org = ctx.insn_ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      btoa(buf, sizeof(buf), org);
      ctx.gen_cmt_line("%s %s", ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly

void idaapi mn103_footer(outctx_t &ctx)
{
  if ( ash.end != NULL )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf.start_ea) > 0 )
    {
      ctx.out_char(' ');
      if ( ash.uflag & UAS_NOENS )
        ctx.out_line(ash.cmnt);
      ctx.out_line(name.begin());
    }
    ctx.flush_outbuf(inf.indent);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi mn103_data(outctx_t &ctx, bool analyze_only)
{
  ctx.out_data(analyze_only);
}
