/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */

#include "mn103.hpp"
#include <entry.hpp>
#include <srarea.hpp>

//--------------------------------------------------------------------------
processor_subtype_t ptype;
//ea_t intmem = 0;	// doesnt work when removed ?!
//ea_t sfrmem = 0;	// doesnt work when removed ?!
  
static char *RegNames[] =
{
	"A0",
	"A1",
	"A2",
	"A3",

	"D0",
	"D1",
	"D2",
	"D3",

	"MDR","PSW",

	"SP",	

	"LIR","LAR",

	"cs","ds" //?
};

//----------------------------------------------------------------------
netnode helper;
char device[MAXSTR] = "";
static size_t numports;
static ioport_t *ports;
static const char cfgname[] = "mn103.cfg";

#ifndef IDA_48
inline const char *get_cfg_path(void) { return cfgname; }
void get_cfg_filename(char *name,int size) { qstrncpy(name,cfgname,size); }
#else
inline const char *get_cfg_path(void) { return cfgname; }
void get_cfg_filename(char *name,int size) { qstrncpy(name,cfgname,size); }
#endif // IDA_48

#define NO_GET_CFG_PATH
#include "../iocommon.cpp"

//------------------------------------------------------------------
const char *set_idp_options(const char *keyword,int /*value_type*/,const void * /*value*/)
{
  if ( keyword != NULL ) return IDPOPT_BADKEY;

#ifndef IDA_48
    if ( choose_ioport_device(get_cfg_path(), device, parse_area_line0) )
	{
    		set_device_name(device, IORESP_PORT|IORESP_INT);
	}
#else
  	if ( choose_ioport_device(get_cfg_path(), device, sizeof(device), parse_area_line0) )
	{
    		set_device_name(device, IORESP_PORT|IORESP_INT);
	}
#endif

  return IDPOPT_OK;
}

//------------------------------------------------------------------
const ioport_t *find_sym(int address)
{
  return find_ioport(ports, numports, address);
}

const ioport_bit_t *find_bit(int address, int bit)
{
  return find_ioport_bit(ports, numports, address, bit);
}

//----------------------------------------------------------------------
bool IsPredefined(const char *name)
{
  for ( unsigned int i=0; i < numports; i++ )
  {
    ioport_t &p = ports[i];
    if ( strcmp(p.name, name) == 0 )
      return true;
    if ( p.bits != NULL )
    {
      for ( int j=0; j < sizeof(ioport_bits_t)/sizeof(ioport_bit_t); j++ )
      {
        const ioport_bit_t *b = (*p.bits)+j;
        if ( b->name != NULL && strcmp(b->name, name) == 0 )
          return true;
      }
    }
  }
  return false;
}

//----------------------------------------------------------------------
//static void apply_symbols(void)
//{
//  for ( int i=0; i < numports; i++ )
//  {
//    ioport_t &p = ports[i];
//    ea_t ea = sfrmem + p.address;
//    ea_t oldea = get_name_ea(BADADDR, p.name);
//    if ( oldea != ea )
//    {
//      if ( oldea != BADADDR ) del_global_name(oldea);
//      do_unknown(ea, 1);
//      set_name(ea, p.name, SN_NOLIST);
//    }
//    if ( p.cmt != NULL ) set_cmt(ea,p.cmt, 1);
//  }
//}

//----------------------------------------------------------------------
typedef struct
{
  char proc;
  unsigned long off;
  char *name;
  char *cmt;
} entry_t;

static entry_t entries[] =
{
	{ prc_mn103,  0x90000020, "RESET", "RESET Vector" },
};

//----------------------------------------------------------------------
// Get linear address of a special segment
//      sel - selector of the segment
#if 0
static ea_t specialSeg(sel_t sel)
{
  segment_t *s = get_segm_by_sel(sel);
  if ( s != NULL )
  {
    if ( s->type != SEG_IMEM )          // is the segment type correct? - no
    {
      s->type = SEG_IMEM;               // fix it
      s->update();
    }
    return s->startEA;
  }
  return BADADDR;
}

//----------------------------------------------------------------------
static ea_t AdditionalSegment(int size,int offset,char *name)
{
  segment_t s;
  s.startEA = (ptype > prc_mn103)
                   ? (inf.maxEA + 0xF) & ~0xF
                   : freechunk(0, size, 0xF);
  s.endEA   = s.startEA + size;
  s.sel     = allocate_selector((s.startEA-offset) >> 4);
  s.type    = SEG_IMEM;                         // internal memory
  add_segm_ex(&s, name, NULL, ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.startEA - offset;
}
#endif
//----------------------------------------------------------------------
#if 0
static void setup_data_segment_pointers(void)
{
  sel_t sel;
  if ( atos("INTMEM",&sel) || atos("RAM", &sel) ) intmem = specialSeg(sel);
  if ( atos("SFR",&sel)    || atos("FSR", &sel) ) sfrmem = specialSeg(sel) - 0x80;
}
#endif
//----------------------------------------------------------------------
// The kernel event notifications
// Here you may take desired actions upon some kernel events

#ifndef IDA_48
extern processor_t ph;
#else
idaman processor_t ida_export_data ph;   // Current processor
#endif

static int notify(processor_t::idp_notify msgid, ...)
{
  static int first_time = 1;
  va_list va;
  va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:


//msg("%s:%d\n",__FILE__,__LINE__);


  int code = invoke_callbacks(HT_IDP, msgid, va);
  if ( code ) return code;

  if(msgid==ph.init)
  {
//msg("%s:%d\n",__FILE__,__LINE__);
      helper.create("$ mn103");
      //inf.mf = 1;       // Set a big endian mode of the IDA kernel
      //inf.mf = 0;       // Set a little endian mode of the IDA kernel
  }
  else if(msgid==ph.newfile)
  {
//msg("%s:%d\n",__FILE__,__LINE__);
        segment_t *sptr = getnseg(0);
	msg("*** n1\n");
	if ( sptr != NULL )
        {
		msg("*** n2: %08x %08x\n",sptr->startEA,get_segm_base(sptr));
		//if ( sptr->startEA-get_segm_base(sptr) == 0 )
			if ( sptr->startEA == 0x80000 )
		{
            inf.beginEA = sptr->startEA;
            inf.startIP = 0;
	    msg("*** n3\n");
	    for ( int i=0; i < qnumber(entries); i++ )
            {
              if ( entries[i].proc > ptype ) continue;
              ea_t ea = inf.beginEA+entries[i].off;
	      if ( isEnabled(ea) /*&& get_byte(ea) != 0xFF*/ )
              {
		      msg("*** entry %08x\n",ea);
		      add_entry(ea, ea, entries[i].name, 1);
                set_cmt(ea, entries[i].cmt, 1);
              }
            }
          }
        }
        segment_t *scode = getnseg(0);
        set_segm_class(scode, "CODE");

        if ( ptype > prc_mn103 )
        {
#if 0		
          AdditionalSegment(0x10000-256-128, 256+128, "RAM");
          if ( scode != NULL )
          {
            ea_t align = (scode->endEA + 0xFFF) & ~0xFFF;
            if ( getseg(align-7) == scode )     // the code segment size is
            {                                   // multiple of 4K or near it
              uchar b0 = get_byte(align-8);
              // 251:
              //  0  : 1-source, 0-binary mode
              //  6,7: must be 1s
              // 82930:
              //  0  : 1-source, 0-binary mode
              //  7  : must be 1s
//              uchar b1 = get_byte(align-7);
              // 251
              //  0: eprommap 0 - FE2000..FE4000 is mapped into 00E000..100000
              //              1 - .............. is not mapped ...............
              //  1: must be 1
              //  3:
              //  2: must be 1
              //  4: intr 1 - upon interrupt PC,PSW are pushed into stack
              //          0 - upon interrupt only PC is pushed into stack
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
              // 82930:
              //  3: must be 1
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
//                msg("b0=%x b1=%x\n", b0, b1);
//              if ( (b0 & 0x80) == 0x80 && (b1 & 0xEA) == 0xEA )
#if 0	      
              {                         // the init bits are correct
                char pname[sizeof(inf.procName)+1];
                inf.get_proc_name(pname);
                char ntype = (b0 & 1) ? 's' : 'b';
                char *ptr = tail(pname)-1;
                if ( ntype != *ptr
                  && askyn_c(1,
                       "The input file seems to be for the %s mode of the processor. "
                       "Do you want to change the current processor type?",
                       ntype == 's' ? "source" : "binary") > 0 )
                {
                  *ptr = ntype;
                  first_time = 1;
                  set_processor_type(pname, SETPROC_COMPAT);
                }
              }
#endif	      
            }
          }
#endif	  
        }

#if 0
        // the default data segment will be INTMEM
        {
          segment_t *s = getseg(intmem);
          if ( s != NULL )
            set_default_dataseg(s->sel);
        }
#endif

//msg("%s:%d\n",__FILE__,__LINE__);

#ifndef IDA_48
		if ( choose_ioport_device(get_cfg_path(), device, parse_area_line0) )
	{
//msg("%s:%d\n",__FILE__,__LINE__);
          set_device_name(device, IORESP_ALL);
	}
#else
        if ( choose_ioport_device(get_cfg_path(), device, sizeof(device), parse_area_line0) )
	{
          set_device_name(device, IORESP_ALL);
	}
#endif // IDA_48

#if 0
        if ( get_segm_by_name("RAM") == NULL )
          AdditionalSegment(256, 0, "RAM");
        if ( get_segm_by_name("FSR") == NULL )
          AdditionalSegment(128, 128, "FSR");
	setup_data_segment_pointers();
#endif

  }
  else if(msgid==ph.oldfile)
  {
//msg("%s:%d\n",__FILE__,__LINE__);
	//setup_data_segment_pointers();
  }
  else if(msgid==ph.newseg)
  {
#if 0	    
        // make the default DS point to INTMEM
        // (8051 specific issue)
      {
        segment_t *newseg = va_arg(va, segment_t *);
        segment_t *intseg = getseg(intmem);
        if ( intseg != NULL )
          newseg->defsr[rVds-ph.regFirstSreg] = intseg->sel;
      }
#endif      
//msg("%s:%d\n",__FILE__,__LINE__);

	{                  // default DS is equal to CS
//msg("%s:%d\n",__FILE__,__LINE__);

// crashes here?!		
//	segment_t *sptr = va_arg(va, segment_t *);
//msg("%s:%d\n",__FILE__,__LINE__);
//	sptr->defsr[rVds-ph.regFirstSreg] = sptr->sel;
//msg("%s:%d\n",__FILE__,__LINE__);
	}
//msg("%s:%d\n",__FILE__,__LINE__);
  }
  else if(msgid==ph.newprc) // new processor
  {
//msg("%s:%d\n",__FILE__,__LINE__);
        processor_subtype_t prcnum = processor_subtype_t(va_arg(va, int));
#if 0	
        if ( !first_time && prcnum != ptype )
        {
          warning("Sorry, it is not possible to change" // (this is 8051 specific)
                  " the processor mode on the fly."
                  " Please reload the input file"
                  " if you want to change the processor.");
          return 0;
        }
#endif	
        first_time = 0;
        ptype = prcnum;
  }
  else if(msgid==ph.newasm) // new assembler type
  {
//msg("%s:%d\n",__FILE__,__LINE__);
	char val[MAXSTR];
#ifdef IDA_49
	helper.supval(-1, val, sizeof(val));
#else
	strcpy(val, helper.supval(-1));
#endif
	set_device_name(val, IORESP_NONE);
  }
  else if(msgid==ph.move_segm)// A segment is moved
                                // Fix processor dependent address sensitive information
                                // args: ea_t from - old segment address
                                //       segment_t - moved segment
  {
//msg("%s:%d\n",__FILE__,__LINE__);
        // ea_t from    = va_arg(va, ea_t);
        // segment_t *s = va_arg(va, segment_t *);

        // Add commands to adjust your internal variables here
        // Most of the time this callback will be empty
        //
        // If you keep information in a netnode's altval array, you can use
        //      node.altshift(from, s->startEA, s->endEA - s->startEA);
        //
        // If you have a variables pointing to somewhere in the disassembled program memory,
        // you can adjust it like this:
        //
        //      asize_t size = s->endEA - s->startEA;
        //      if ( var >= from && var < from+size )
        //        var += s->startEA - from;
  }
//msg("%s:%d\n",__FILE__,__LINE__);
  va_end(va);
//msg("%s:%d\n",__FILE__,__LINE__);

  return(1);
}


#if 0
  switch(msgid)
  {
    case ph.init:
      helper.create("$ mn103");
      //inf.mf = 1;       // Set a big endian mode of the IDA kernel
      //inf.mf = 0;       // Set a little endian mode of the IDA kernel
      break;
    case ph.newfile:
      {
        segment_t *sptr = getnseg(0);
	msg("*** n1\n");
	if ( sptr != NULL )
        {
		msg("*** n2: %08x %08x\n",sptr->startEA,get_segm_base(sptr));
		//if ( sptr->startEA-get_segm_base(sptr) == 0 )
			if ( sptr->startEA == 0x80000 )
		{
            inf.beginEA = sptr->startEA;
            inf.startIP = 0;
	    msg("*** n3\n");
	    for ( int i=0; i < qnumber(entries); i++ )
            {
              if ( entries[i].proc > ptype ) continue;
              ea_t ea = inf.beginEA+entries[i].off;
	      if ( isEnabled(ea) /*&& get_byte(ea) != 0xFF*/ )
              {
		      msg("*** entry %08x\n",ea);
		      add_entry(ea, ea, entries[i].name, 1);
                set_cmt(ea, entries[i].cmt, 1);
              }
            }
          }
        }
        segment_t *scode = getnseg(0);
        set_segm_class(scode, "CODE");

        if ( ptype > prc_mn103 )
        {
#if 0		
          AdditionalSegment(0x10000-256-128, 256+128, "RAM");
          if ( scode != NULL )
          {
            ea_t align = (scode->endEA + 0xFFF) & ~0xFFF;
            if ( getseg(align-7) == scode )     // the code segment size is
            {                                   // multiple of 4K or near it
              uchar b0 = get_byte(align-8);
              // 251:
              //  0  : 1-source, 0-binary mode
              //  6,7: must be 1s
              // 82930:
              //  0  : 1-source, 0-binary mode
              //  7  : must be 1s
//              uchar b1 = get_byte(align-7);
              // 251
              //  0: eprommap 0 - FE2000..FE4000 is mapped into 00E000..100000
              //              1 - .............. is not mapped ...............
              //  1: must be 1
              //  3:
              //  2: must be 1
              //  4: intr 1 - upon interrupt PC,PSW are pushed into stack
              //          0 - upon interrupt only PC is pushed into stack
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
              // 82930:
              //  3: must be 1
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
//                msg("b0=%x b1=%x\n", b0, b1);
//              if ( (b0 & 0x80) == 0x80 && (b1 & 0xEA) == 0xEA )
#if 0	      
              {                         // the init bits are correct
                char pname[sizeof(inf.procName)+1];
                inf.get_proc_name(pname);
                char ntype = (b0 & 1) ? 's' : 'b';
                char *ptr = tail(pname)-1;
                if ( ntype != *ptr
                  && askyn_c(1,
                       "The input file seems to be for the %s mode of the processor. "
                       "Do you want to change the current processor type?",
                       ntype == 's' ? "source" : "binary") > 0 )
                {
                  *ptr = ntype;
                  first_time = 1;
                  set_processor_type(pname, SETPROC_COMPAT);
                }
              }
#endif	      
            }
          }
#endif	  
        }

#if 0
        // the default data segment will be INTMEM
        {
          segment_t *s = getseg(intmem);
          if ( s != NULL )
            set_default_dataseg(s->sel);
        }
#endif

        if ( choose_ioport_device(get_cfg_path(), device, parse_area_line0) )
          set_device_name(device, IORESP_ALL);
#if 0
        if ( get_segm_by_name("RAM") == NULL )
          AdditionalSegment(256, 0, "RAM");
        if ( get_segm_by_name("FSR") == NULL )
          AdditionalSegment(128, 128, "FSR");
	setup_data_segment_pointers();
#endif
      }
      break;
*/

    case ph.oldfile:
      
      break;

    case ph.newseg:
#if 0	    
        // make the default DS point to INTMEM
        // (8051 specific issue)
      {
        segment_t *newseg = va_arg(va, segment_t *);
        segment_t *intseg = getseg(intmem);
        if ( intseg != NULL )
          newseg->defsr[rVds-ph.regFirstSreg] = intseg->sel;
      }
#endif      

	{                  // default DS is equal to CS
	segment_t *sptr = va_arg(va, segment_t *);
	sptr->defsr[rVds-ph.regFirstSreg] = sptr->sel;
	}

      break;

    case ph.newprc: 
      {
        processor_subtype_t prcnum = processor_subtype_t(va_arg(va, int));
#if 0	
        if ( !first_time && prcnum != ptype )
        {
          warning("Sorry, it is not possible to change" // (this is 8051 specific)
                  " the processor mode on the fly."
                  " Please reload the input file"
                  " if you want to change the processor.");
          return 0;
        }
#endif	
        first_time = 0;
        ptype = prcnum;
      }
      break;

    case ph.newasm:    // new assembler type
      set_device_name(helper.supval(-1), IORESP_NONE);
      break;

    case ph.move_segm:          // A segment is moved
                                // Fix processor dependent address sensitive information
                                // args: ea_t from - old segment address
                                //       segment_t - moved segment
      {
        // ea_t from    = va_arg(va, ea_t);
        // segment_t *s = va_arg(va, segment_t *);

        // Add commands to adjust your internal variables here
        // Most of the time this callback will be empty
        //
        // If you keep information in a netnode's altval array, you can use
        //      node.altshift(from, s->startEA, s->endEA - s->startEA);
        //
        // If you have a variables pointing to somewhere in the disassembled program memory,
        // you can adjust it like this:
        //
        //      asize_t size = s->endEA - s->startEA;
        //      if ( var >= from && var < from+size )
        //        var += s->startEA - from;
      }
      break;

  }
#endif


//-----------------------------------------------------------------------
//      Checkarg data. Common for all assemblers. Not good.
//
//      What is checkarg?
//        It is a possibilty to compare the value of a manually entered
//        operand against its original value.
//        Checkarg is currently implemented for IBM PC, 8051, and PDP-11
//        processors. Other processor are unlikely to be supported.
//      You may just get rid of checkarg and replace the pointers to it
//      in the 'LPH' structure by NULLs.
//
//-----------------------------------------------------------------------
static const char *operdim[15] = {  // ÇëÖÉÑÄ à ëíêéÉé 15
     "(", ")", "!", "-", "+", "%",
     "\\", "/", "*", "&", "|", "^", "<<", ">>", NULL};

inline int pere(int c) { return(c&0xFF); }

static int preline(char *argstr, s_preline *S)
{
    char    *pc;
    int     *ind;
    char    *prefix;
    char    *seg;
    char    *reg;
    char    *offset;

    if(!argstr) return(-1); // request for default selector

    ind     = S->ind;
    prefix  = S->prefix;
    seg     = S->seg;
    reg     = S->reg;
    offset  = S->offset;
    *ind = 0;
    *prefix = '\0';
    *reg = '\0';
    *seg = '\0';
    *offset = '\0';

    pc = argstr;
    if (*pc == '#') ++*ind, pc++;
    qstpncpy(offset, pc,0x100); // FIXME: whats maxlen?

    return(0);

} /* preline */

//
//              Definitions of the target assemblers
//              8051 has unusually many of them.
//

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static asm_t gas =
{
	AS_ASCIIC|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
	0,
	"GNU assembler",
	0,
	NULL,         // header lines
	NULL,         // no bad instructions
	".org",       // org
	NULL,         // end

	"!",          // comment string
	'"',          // string delimiter
	'"',          // char delimiter
	"\"",         // special symbols in char and string constants

	".ascii",     // ascii string directive
	".byte",      // byte directive
	".word",      // word directive
	".long",      // double words
	NULL,         // qwords
	NULL,         // oword  (16 bytes)
	".float",     // float  (4 bytes)
	NULL,         // double (8 bytes)
	NULL,         // tbyte  (10/12 bytes)
	NULL,         // packed decimal real
	NULL,         // arrays (#h,#d,#v,#s(...)
	".space %s",  // uninited arrays
	"=",          // equ
	NULL,         // 'seg' prefix (example: push seg seg001)
	NULL,         // Pointer to checkarg_preline() function.
	NULL,         // char *(*checkarg_atomprefix)(char *operand,void *res); // if !NULL, is called before each atom
	NULL,         // const char **checkarg_operations;
	NULL,         // translation to use in character and string constants.
	NULL,         // current IP (instruction pointer)
	NULL,         // void (*func_header)(func_t *,char *buf);
	NULL,         // void (*func_footer)(func_t *);
	".globl",     // "public" name keyword
	NULL,         // "weak"   name keyword
	".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
	".comm",      // "comm" (communal variable)
	NULL,         // const char *(*get_type_name)(long flag,ulong id);
	".align",     // "align" keyword
	'(', ')',	// lbrace, rbrace
	"%",          // mod
	"&",          // and
	"|",          // or
	"^",          // xor
	"~",          // not
	"<<",         // shl
	">>",         // shr
	NULL,         // sizeof
};

//-----------------------------------------------------------------------
//                   ASMI
//-----------------------------------------------------------------------
static asm_t asmi = {
  AS_COLON | ASH_HEXF3 | AS_1TEXT | AS_NCHRE | ASO_OCTF1 | AS_RELSUP,
  UAS_PSAM | UAS_NOSEG | UAS_AUBIT | UAS_PBIT | UAS_PBYTNODEF | UAS_NOENS,
  "ASMI",
  0,
  NULL,         // no headers
  NULL,         // no bad instructions
  ".equ $, ",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".byte 0xFF;(array %s)", // uninited arrays
  ".equ",       // equ
  NULL,         // seg prefix
  preline, NULL, operdim,
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  "%",    // mod
  "&",    // and
  "|",    // or
  "^",    // xor
  "!",    // not
  "<<",   // shl
  ">>",   // shr
  NULL,   // sizeof
};

//-----------------------------------------------------------------------
//                   8051 Macro Assembler   -   Version 4.02a
//                Copyright (C) 1985 by 2500 A.D. Software, Inc.
//-----------------------------------------------------------------------
static asm_t adasm = {
  AS_COLON | ASH_HEXF0 ,
  UAS_PBIT | UAS_SECT,
  "8051 Macro Assembler by 2500 A.D. Software",
  0,
  NULL,         // no headers
  NULL,         // no bad instructions
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  "long",       // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "reg",        // equ
  NULL,         // seg prefix
  preline, NULL, operdim,
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,         // mod
  NULL,         // and
  NULL,         // or
  NULL,         // xor
  NULL,         // not
  NULL,         // shl
  NULL,         // shr
  NULL,         // sizeof
  0,            // flag2
  NULL,         // close comment
  COLSTR("<", SCOLOR_SYMBOL) "%s", // low8
  COLSTR(">", SCOLOR_SYMBOL) "%s", // high8
  NULL,         // low16
  NULL,         // high16
};

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const char *ps_headers[] = {
".code",
NULL };

static asm_t pseudosam = {
  AS_COLON | ASH_HEXF1 | AS_N2CHR,
  UAS_PBIT | UAS_PSAM | UAS_SELSG,
  "PseudoSam by PseudoCode",
  0,
  ps_headers,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  ".equ",       // equ
  NULL,         // seg prefix
  preline, NULL, operdim,
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
//      Cross-16 assembler definiton
//-----------------------------------------------------------------------
static const char *cross16_headers[] = {
"cpu \"8051.tbl\"",
NULL };

static asm_t cross16 = {
  AS_COLON | ASH_HEXF0 | AS_NHIAS,
  UAS_PBIT | UAS_NOSEG | UAS_NOBIT | UAS_EQCLN,
  "Cross-16 by Universal Cross-Assemblers",
  0,
  cross16_headers,
  NULL,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "dfb",        // ascii string directive
  "dfb",        // byte directive
  "dwm",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  NULL,         // seg prefix
  preline, NULL, operdim,
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
//      8051 Cross-Assembler by MetaLink Corporation
//-----------------------------------------------------------------------
static asm_t mcross = {
  AS_COLON | ASH_HEXF0 | AS_NHIAS,
  UAS_NOSEG | UAS_CDSEG | UAS_AUBIT | UAS_NODS | UAS_NOENS,
  "8051 Cross-Assembler by MetaLink Corporation",
  0,
  NULL,
  NULL,
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // Equ
  NULL,         // seg prefix
  preline, NULL, operdim,
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

//-----------------------------------------------------------------------
//      TASM assembler definiton
//-----------------------------------------------------------------------
static const char *tasm_headers[] = {
".msfirst",
NULL };

static asm_t tasm = {
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_PBIT | UAS_NOENS | UAS_EQCLN | UAS_NOSEG,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  tasm_headers,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",
  NULL,         // seg prefix
  preline, NULL, operdim,
  NULL,
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  "and",   // and
  "or",    // or
  NULL,    // xor
  "not",   // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

static asm_t *asms[] = { &gas,&asmi, &adasm, &pseudosam, &cross16, &mcross, &tasm, NULL };
//-----------------------------------------------------------------------
// The short and long names of the supported processors
// The short names must match
// the names in the module DESCRIPTION in the makefile (the
// description is copied in the offset 0x80 in the result DLL)

static char *shnames[] =
{
  "mn103",
  NULL
};

static char *lnames[] =
{
	"Panasonic/Matshita mn103",
  NULL
};

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static uchar retcode_1[] = { 0xde }; // retf
static uchar retcode_2[] = { 0xdf }; // ret
static uchar retcode_3[] = { 0xf0,0xfc }; // rets
static uchar retcode_4[] = { 0xf0,0xfd }; // rti

static bytes_t retcodes[] = {
 { sizeof(retcode_1), retcode_1 },
 { sizeof(retcode_2), retcode_2 },
 { sizeof(retcode_3), retcode_3 },
 { sizeof(retcode_4), retcode_4 },
 { 0, NULL }                            // NULL terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
#define PLFM_MN103 0x8103

processor_t LPH =
{
  IDP_INTERFACE_VERSION,// version
  PLFM_MN103,            // id
  PR_USE32|PR_DEFSEG32| //
  PR_SEGS|
  PR_RNAMESOK|          // can use register names for byte names
  PR_SEGTRANS          // segment translation is supported (codeSeg)
//  |PR_BINMEM,           // The module creates RAM/ROM segments for binary files
                        // (the kernel shouldn't ask the user about their sizes and addresses)
  ,8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  header,               // generate the disassembly header
  footer,               // generate the disassembly footer

  segstart,             // generate a segment declaration (start of segment)
  std_gen_segm_footer,  // generate a segment footer (end of segment)

  NULL,                 // generate 'assume' directives

  ana,                  // analyse an instruction and fill the 'cmd' structure
  emu,                  // emulate an instruction

  out,                  // generate a text representation of an instruction
  outop,                // generate a text representation of an operand
  mn103_data,             // generate a text representation of a data item
  NULL,                 // compare operands
  NULL,                 // can an operand have a type?

  qnumber(RegNames),    // Number of registers
  RegNames,             // Regsiter names
  NULL,                 // get abstract register

  0,                    // Number of register files
  NULL,                 // Register file names
  NULL,                 // Register descriptions
  NULL,                 // Pointer to CPU registers

  rVcs,
  rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0,MN103_last,
  Instructions,

  NULL,                 // int  (*is_far_jump)(int icode);
  NULL,                 // Translation function for offsets
  0,                    // int tbyte_size;  -- doesn't exist
  NULL,                 // int (*realcvt)(void *m, ushort *e, ushort swt);
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  NULL,                 // int (*is_switch)(switch_info_t *si);
  NULL,                 // long (*gen_map_file)(FILE *fp);
  NULL,                 // ea_t (*extract_address)(ea_t ea,const char *string,int x);
  NULL,                 // int (*is_sp_based)(op_t &x);
  NULL,                 // int (*create_func_frame)(func_t *pfn);
  NULL,                 // int (*get_frame_retsize(func_t *pfn)
  NULL,                 // void (*gen_stkvar_def)(char *buf,const member_t *mptr,sval_t v);
  gen_spcdef,           // Generate text representation of an item in a special segment
  MN103_rts,              // Icode of return instruction. It is ok to give any of possible return instructions
  set_idp_options,      // const char *(*set_idp_options)(const char *keyword,int value_type,const void *value);
  NULL,                 // int (*is_align_insn)(ea_t ea);
  NULL,                 // mvm_t *mvm;

};
