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
inline void OutReg(int rgnum)
{
  out_register(ph.regNames[rgnum]);
}

//----------------------------------------------------------------------
// generate the text representation of an operand

bool outop(op_t &x)
{
  uval_t v;
#ifdef IDA_49
  char ptr[MAXSTR];
#else
  const char *ptr;
#endif
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
		    //OutValue(x, OOF_ADDR | OOFS_IFSIGN | OOFW_16);
		    OutValue(x, OOF_ADDR | OOFS_IFSIGN | OOFW_32);
		    out_symbol(',');
	    }
	    OutReg(x.reg);
	    out_symbol(')');
      break;

    case o_imm:
      //out_symbol('#');
      //if ( cmd.auxpref & aux_0ext ) out_symbol('0');
      //if ( cmd.auxpref & aux_1ext ) out_symbol('1');
      OutValue(x, OOFS_IFSIGN | OOFW_IMM| OOFW_32);
      break;

    case o_mem:
	    v = map_addr(x.addr, x.n, x.type==o_mem);
#ifdef IDA_49
        if (get_name_expr(cmd.ea+x.offb, x.n, v, x.addr,ptr,sizeof(ptr)))
#else
	    ptr = get_name_expr(cmd.ea+x.offb, x.n, v, x.addr);
	    if( ptr == NULL )
#endif
	    {
		    out_symbol('(');
		    OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
		    out_symbol(')');
		    QueueMark(Q_noName, cmd.ea);
		    break;
	    }

      // we want to output SFR register names always in COLOR_REG,
      // so remove the color tags and output it manually:

/*      
	    if ( x.type == o_mem && x.addr >= 0x80 )
	    {
		    tag_remove(ptr, (char *)ptr, 0);
		    out_symbol('(');
		    out_register(ptr);
		    out_symbol(')');
		    break;
	    }
*/	    
	    out_symbol('(');
	    OutLine(ptr);
	    out_symbol(')');
	    break;
    case o_near:
      v = map_addr(x.addr, x.n, x.type==o_mem);
#ifdef IDA_49
      if (get_name_expr(cmd.ea+x.offb, x.n, v, x.addr,ptr,sizeof(ptr)))
#else
      ptr = get_name_expr(cmd.ea+x.offb, x.n, v, x.addr);
      if( ptr == NULL )
#endif
      {
	      OutValue(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
          QueueMark(Q_noName, cmd.ea);
          break;
      }

      // we want to output SFR register names always in COLOR_REG,
      // so remove the color tags and output it manually:
/*
      if ( x.type == o_mem && x.addr >= 0x80 )
      {
        tag_remove(ptr, (char *)ptr, 0);
	out_register(ptr);
	break;
      }
*/      
      OutLine(ptr);
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
	    OutValue(x, 0);
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
        char *rname = get_name_expr(cmd.ea+x.offb, x.n, v, dir);
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
       warning("out: %a: bad optype",cmd.ea,x.type);
       break;
  }
  return true;
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the 'cmd' structure

void out(void)
{
  char buf[MAXSTR];

  init_output_buffer(buf, sizeof(buf)); // setup the output pointer
  OutMnem();                            // output instruction mnemonics

  out_one_operand(0);                   // output the first operand

  if ( cmd.Op2.type != o_void)
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(1);                 // output the second operand
  }

  if ( cmd.Op3.type != o_void)
  {
    out_symbol(',');
    OutChar(' ');
    out_one_operand(2);                 // output the third operand
  }


  // output a character representation of the immediate values
  // embedded in the instruction as comments

  if ( isVoid(cmd.ea,uFlag,0) ) OutImmChar(cmd.Op1);
  if ( isVoid(cmd.ea,uFlag,1) ) OutImmChar(cmd.Op2);
  if ( isVoid(cmd.ea,uFlag,2) ) OutImmChar(cmd.Op3);

  term_output_buffer();                 // terminate the output string
  gl_comm = 1;                          // ask to attach a possible user-
                                        // defined comment to it
  MakeLine(buf);                        // pass the generated line to the
                                        // kernel
}

//--------------------------------------------------------------------------
// generate header of the disassembly

void header(void)
{
  gen_cmt_line("Processor:        %s [%s]", device[0] ? device : inf.procName, deviceparams);
  gen_cmt_line("Processor:        %s", inf.procName);
  gen_cmt_line("Target assembler: %s", ash.name);
  if ( ash.header != NULL )
    for ( const char **ptr=ash.header; *ptr != NULL; ptr++ ) MakeLine(*ptr,0);
}

//--------------------------------------------------------------------------
// generate start of a segment

void segstart(ea_t ea)
{
	char buf[MAXSTR];
	segment_t *Sarea = getseg(ea);
	char segm_name[MAXNAMELEN];
#ifdef IDA_49
	get_segm_name(Sarea, segm_name, sizeof(segm_name));
#else
	strcpy(segm_name, get_segm_name(Sarea));
#endif
	
	if ( ash.uflag & UAS_SECT )
	{
      if ( Sarea->type == SEG_IMEM )
      {
      	MakeLine(".RSECT");
      }
      else
      {
        qsnprintf(buf, sizeof(buf), COLSTR("%s: .section", SCOLOR_ASMDIR), segm_name);
        MakeLine(buf,0);
      }
    }
    else
	{
      if (ash.uflag & UAS_NOSEG)
	  {
          qsnprintf(buf, sizeof(buf), COLSTR("%s.segment %s", SCOLOR_AUTOCMT), ash.cmnt, segm_name);
	  }
      else
	  {
		  qsnprintf(buf, sizeof(buf), COLSTR("segment %s",SCOLOR_ASMDIR), segm_name);
	  }
      MakeLine(buf);
      
      if(ash.uflag & UAS_SELSG)
	  {
		  MakeLine(segm_name);
	  }
      if(ash.uflag & UAS_CDSEG)
        MakeLine((Sarea->type == SEG_IMEM) ?
              COLSTR("DSEG", SCOLOR_ASMDIR) : COLSTR("CSEG", SCOLOR_ASMDIR));
              // XSEG - eXternal memory
    }
    if ( inf.s_org )
    {
		adiff_t org = ea - get_segm_base(Sarea);
		char org_str[MAXSTR];
#ifdef IDA_49
		btoa32(org_str, sizeof(org_str), org);
#else
		strcpy(org_str, btoa32(org));
#endif
		if( org != 0 ) gen_cmt_line("%s %s", ash.origin, org_str);
    }
}

//--------------------------------------------------------------------------
// generate end of the disassembly

void footer(void)
{
  char buf[MAXSTR];
  if ( ash.end != NULL)
  {
    MakeNull();
    char *const end = buf + sizeof(buf);
    char *ptr = tag_addstr(buf, end, COLOR_ASMDIR, ash.end);
    char name[MAXSTR];
    if ( get_colored_name(BADADDR, inf.beginEA, name, sizeof(name)) != NULL )
    {
      APPCHAR(ptr, end, ' ');
      if( ash.uflag & UAS_NOENS )
        APPEND(ptr, end, ash.cmnt);
      APPEND(ptr, end, name);
    }
    MakeLine(buf);
  }
  else
  {
    gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
// output one "equ" directive
#if 0
static void do_out_equ(const char *name, const char *equ, uchar off)
{
  char buf[MAXSTR];
  char *ptr = buf;
  char *const end = buf + sizeof(buf);
  gl_name = 0;
  if (ash.uflag & UAS_PSAM)
  {
    ptr = tag_addstr(ptr, end, COLOR_KEYWORD, equ);
    APPCHAR(ptr, end, ' ');
    APPEND(ptr, end, name);
    ptr = tag_addchr(ptr, end, COLOR_SYMBOL, ',');
  }
  else
  {
    APPEND(ptr, end, name);
    if(ash.uflag & UAS_EQCLN)
      ptr = tag_addchr(ptr, end, COLOR_SYMBOL, ':');
    APPCHAR(ptr, end, ' ');
    ptr = tag_addstr(ptr, end, COLOR_KEYWORD, equ);
    APPCHAR(ptr, end, ' ');
  }
  tag_addstr(ptr, end, COLOR_NUMBER, btoa32(off));
  MakeLine(buf,0);
}

//--------------------------------------------------------------------------
// output "equ" directive(s) if necessary
static int out_equ(ea_t ea)
{
  segment_t *s = getseg(ea);
  if ( s != NULL && s->type == SEG_IMEM && ash.a_equ != NULL)
  {
    char nbuf[MAXSTR];
    char *name = get_name(BADADDR, ea, nbuf, sizeof(nbuf));
    if ( name != NULL
      && ((ash.uflag & UAS_PBYTNODEF) == 0 || !IsPredefined(name)) )
    {
      char buf[MAXSTR];
      char *const end = buf + sizeof(buf);
      get_colored_name(BADADDR, ea, buf, sizeof(buf));
      uchar off = uchar(ea - get_segm_base(s));
      do_out_equ(buf, ash.a_equ, off);
      if ( (ash.uflag & UAS_AUBIT) == 0 && (off & 0xF8) == off )
      {
        char *ptr = tag_on(tail(buf), end, COLOR_SYMBOL);
        APPCHAR(ptr, end, ash.uflag & UAS_NOBIT ? '_' : '.');
        APPCHAR(ptr, end, '0');
        tag_off(ptr, end, COLOR_SYMBOL);
        for ( int i=0; i < 8; i++ )
        {
          const ioport_bit_t *b = find_bit(off, i);
          char *p2 = ptr;
          if ( b == NULL || b->name == NULL )
            ptr[-1] = '0' + i;
          else
            p2 = tag_addstr(ptr-1, end, COLOR_HIDNAME, b->name);
          tag_off(p2, end, COLOR_SYMBOL);
          do_out_equ(buf, ash.a_equ, off+i);
        }
        MakeNull();
      }
    }
    else
    {
      gl_name = 0;
      MakeLine("");
    }
    return 1;
  }
  if ( ash.uflag & UAS_NODS )
  {
    if ( !hasValue(getFlags(ea)) && s->type == SEG_CODE )
    {
      adiff_t org = ea - get_segm_base(s) + get_item_size(ea);
      printf_line(inf.indent, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, btoa32(org));
      return 1;
    }
  }
  return 0;
} 
#endif

//--------------------------------------------------------------------------
// generate a data representation
// usually all the job is handled by the kernel's standard procedure,
// intel_data()
// But 8051 has its own quirks (namely, "equ" directives) and intel_data()
// can't handle them. So we output "equ" ourselves and pass everything
// else to intel_data()
// Again, let's repeat: usually the data items are output by the kernel
// function intel_data(). You have to override it only if the processor
// has special features and the data items should be displayed in a
// special way.

void mn103_data(ea_t ea)
{
	gl_name = 1;
	intel_data(ea);
}
