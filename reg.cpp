/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */

#include "mn103.hpp"
#include <segregs.hpp>

//--------------------------------------------------------------------------
processor_subtype_t ptype = prc_mn103;

static const char *const RegNames[] =
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
static netnode helper;
qstring device;
static ioports_t ports;

#include "../iocommon.cpp"

//------------------------------------------------------------------
const ioport_bit_t *find_bit(ea_t address, int bit)
{
  return find_ioport_bit(ports, address, bit);
}

//----------------------------------------------------------------------
typedef struct
{
  char proc;
  unsigned long off;
  const char *name;
  const char *cmt;
} entry_t;

static const entry_t entries[] =
{
	{ prc_mn103,  0x90000020, "RESET", "RESET Vector" },
};

//----------------------------------------------------------------------
// The kernel event notifications
// Here you may take desired actions upon some kernel events

static ssize_t idaapi notify(void*, int msgid, va_list va)
{
  int code = 0;

  switch (msgid) {
    case processor_t::ev_init:
      // msg("%s:%d\n",__FILE__,__LINE__);
      inf.set_be(false);
      helper.create("$ mn103");
      break;

    case processor_t::ev_term:
      ports.clear();
      break;

    case processor_t::ev_newfile:
      {
        // msg("%s:%d\n",__FILE__,__LINE__);
        segment_t* sptr = getnseg(0);
        msg("*** n1\n");
        if (sptr != NULL)
        {
            msg("*** n2: %08x %08x\n", sptr->start_ea, get_segm_base(sptr));
            // if ( sptr->start_ea-get_segm_base(sptr) == 0 )
            if (sptr->start_ea == 0x80000)
            {
                inf.start_ea = sptr->start_ea;
                inf.start_ip = 0;
                msg("*** n3\n");
                for (int i = 0; i < qnumber(entries); i++)
                {
                    if (entries[i].proc > ptype)
                        continue;
                    ea_t ea = inf.start_ea + entries[i].off;
                    if (is_mapped(ea) /*&& get_byte(ea) != 0xFF*/)
                    {
                        msg("*** entry %08x\n", ea);
                        add_entry(ea, ea, entries[i].name, 1);
                        set_cmt(ea, entries[i].cmt, 1);
                    }
                }
            }
        }
        segment_t* scode = getnseg(0);
        set_segm_class(scode, "CODE");

        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if (choose_ioport_device(&device, cfgfile, parse_area_line0))
            set_device_name(device.c_str(), IORESP_ALL);

        break;
      }

    case processor_t::ev_newprc:
      if ( helper.supstr(&device, -1) > 0 )
        set_device_name(device.c_str(), IORESP_PORT);
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        mn103_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        mn103_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        mn103_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    case processor_t::ev_out_data:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        bool analyze_only = va_argi(va, bool);
        mn103_data(*ctx, analyze_only);
        return 1;
      }
  }

  return code;
}


//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const char *ps_headers[] = {".code", NULL };

static const asm_t pseudosam = {
  AS_COLON | ASH_HEXF3 | AS_N2CHR,
  UAS_PBIT | UAS_PSAM | UAS_SELSG,
  "Generic assembler",
  0,
  ps_headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  ".dd",        // dword  (4 bytes)
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

static const asm_t *const asms[] = { &pseudosam, NULL };
//-----------------------------------------------------------------------
// The short and long names of the supported processors
// The short names must match
// the names in the module DESCRIPTION in the makefile (the
// description is copied in the offset 0x80 in the result DLL)

static const char *const shnames[] =
{
  "mn103",
  NULL
};

static const char *const lnames[] =
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
  ,0,                   // flag2
  8,                    // 8 bits in a byte for code segments
  8,                    // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  RegNames,             // Regsiter names
  qnumber(RegNames),    // Number of registers

  rVcs,
  rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0,MN103_last,
  Instructions,

  3,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  MN103_rts,              // Icode of return instruction. It is ok to give any of possible return instructions
};
