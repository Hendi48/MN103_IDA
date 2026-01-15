/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */

#ifndef _MN103_HPP
#define _MN103_HPP

// uncomment this for ida v4.8 support
//#define IDA_48
// uncomment this for ida v4.9 support
#define IDA_49
// comment out both lines above for v4.7 support

// ensure that for IDA_49 all changes for IDA_48 are taken also into consideration
#ifdef IDA_49
 #ifndef IDA_48
   #define IDA_48
 #endif
#endif

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>

//------------------------------------------------------------------------
// customization of the 'cmd' structure:

#define o_bit           o_idpspec0
//#define o_bitnot        o_idpspec1
#define o_regs           o_idpspec1

// fRi indirect register number (for o_phrase):
#define indreg          specflag1
//#define o_bit251        o_idpspec2
//#define b251_bit        specflag1               // bit number
//#define b251_bitneg     specflag2               // negate?

// cmd.auxpref bits:
//#define aux_0ext      0x0001  // high bit 0-extension immediate value
//#define aux_1ext      0x0002  // high bit 1-extension immediate value

// ash.uflag bit meanings:

#define UAS_PSAM        0x0001          // PseudoSam: use funny form of equ for intmem
#define UAS_SECT        0x0002          // Segments are named .SECTION
#define UAS_NOSEG       0x0004          // No 'segment' directives
#define UAS_NOBIT       0x0008          // No bit.# names, use bit_#
#define UAS_SELSG       0x0010          // Segment should be selected by its name
#define UAS_EQCLN       0x0020          // ':' in EQU directives
#define UAS_AUBIT       0x0040          // Don't use BIT directives - assembler generates bit names itself
#define UAS_CDSEG       0x0080          // Only DSEG,CSEG,XSEG
#define UAS_NODS        0x0100          // No .DS directives in Code segment
#define UAS_NOENS       0x0200          // don't specify start addr in the .end directive
#define UAS_PBIT        0x0400          // assembler knows about predefined bits
#define UAS_PBYTNODEF   0x0800          // do not define predefined byte names

enum processor_subtype_t
{
                // odd types are binary mode
                // even types are source modes
  prc_mn103 = 0,                      // plain mn103
};

extern processor_subtype_t ptype;
extern char device[];
extern char deviceparams[];
 
//extern ea_t intmem;               // address of the internal memory
//extern ea_t sfrmem;               // address of SFR memory

ea_t map_addr(ulong off, int opnum, bool isdata);

//------------------------------------------------------------------------
// Registers

enum mn103_registers
{
  rA0,rA1,rA2,rA3,
  rD0,rD1,rD2,rD3,
  rMDR,rPSW,
  rSP,
  rLIR,rLAR,
  rVcs, rVds            // these 2 registers are required by the IDA kernel
};

const ioport_t *find_sym(int address);
const ioport_bit_t *find_bit(int address, int bit);
bool IsPredefined(const char *name);

//------------------------------------------------------------------------
void    header(void);
void    footer(void);

void    segstart(ea_t ea);

int     ana(void);
int     emu(void);
void    out(void);
bool    outop(op_t &op);

void    mn103_data(ea_t ea);
 
#endif

