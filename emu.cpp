/*
 *      MN103 module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */
 
#include "mn103.hpp"

static bool flow;               // does the current instruction pass
                                // execution to the next instruction?

//
// Reference type.  Used between emu() and handle_operand() to
// flag whether an operand is written to or read from.
//
enum opRefType {
	hop_READ,
	hop_WRITE,
};


//------------------------------------------------------------------------
// Handle an operand with an immediate value:
//      - mark it with FF_IMMD flag
//      - for bit logical instructions specify the operand type as a number
//        because such an operand is likely a plain number rather than
//        an offset or of another type.

static void set_immd_bit(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  switch ( insn.itype )
  {
    case MN103_and:
    case MN103_or:
    case MN103_xor:
      op_num(insn.ea,1);
//    op_num(insn.ea,n);
      break;
//  case MN103_mov:
//      op_dec(insn.ea, n);
//      break;
  }
}

//----------------------------------------------------------------------
static void attach_bit_comment(const insn_t &insn, ea_t addr, int bit)
{
  const ioport_bit_t *predef = find_bit(addr, bit);
  if ( predef != NULL && get_cmt(NULL, insn.ea, false) <= 0 )
    set_cmt(insn.ea, predef->cmt.c_str(), false);
}

//----------------------------------------------------------------------
// Handle an operand. What this function usually does:
//      - creates cross-references from the operand
//        (the kernel deletes all xrefs before calling emu())
//      - creates permanent comments
//      - if possible, specifies the operand type (for example, it may
//        create stack variables)
//      - anything else you might need to emulate or trace

static void handle_operand(const insn_t &insn, const op_t &x, int loading /* 1: use 0: change */)
{
	ea_t ea = map_code_ea(insn, x);
	flags_t F = get_flags(insn.ea);
	switch ( x.type )
	{
		// no special handling for these types
		case o_phrase:
		case o_reg:
		case o_regs:
			break;
		
		// immediate operand
		case o_imm:
			// can't write to an immediate value
			if ( loading == hop_WRITE ) goto BAD_LOGIC;
			set_immd_bit(insn, x.n);
			
			// if the value was converted to an offset, then create a data xref:
			if ( op_adds_xrefs(F, x.n) )
			{
				insn.add_off_drefs(x, dr_O, OOFS_IFSIGN);
			}
			// if the value is in range of the program, create a data xref:
//			else if( is_mapped(x.value) )
//			{
//				ua_add_dref(/*x.offb*/0, x.value, (loading==hop_READ)?dr_R:dr_W);
//			}
			break;
		
		case o_displ:
			set_immd_bit(insn, x.n);                    // handle immediate number
			
			// if the value was converted to an offset, then create a data xref:
			if ( op_adds_xrefs(F, x.n) )
			  insn.add_off_drefs(x, loading ? dr_R : dr_W, OOFS_IFSIGN|OOF_ADDR); // FIXME loading == hop_READ?
			break;

		case o_mem:                         // an ordinary memory data reference
			insn.create_op_data(ea, x);
			insn.add_dref(ea, x.offb, loading == hop_READ ? dr_R : dr_W);
			break;

		case o_far:                         // a code reference
		case o_near:                        // a code reference
		{
			int iscall = has_insn_feature(insn.itype, CF_CALL);
			insn.add_cref(ea, x.offb, iscall ? fl_CN : fl_JN);
			if ( flow && iscall )
			{
				func_t *pfn = get_func(ea);
				if ( pfn != NULL && (pfn->flags & FUNC_NORET) ) flow = false;
			}
		}
			break;
		
		default:
BAD_LOGIC:
			warning("%a (%s): bad logic (emu.cpp)", insn.ea, Instructions[insn.itype].name);
			break;
	}
}

//----------------------------------------------------------------------
// Emulate an instruction
// This function should:
//      - create all xrefs from the instruction
//      - perform any additional analysis of the instruction/program
//        and convert the instruction operands, create comments, etc.
//      - create stack variables
//      - analyse the delayed branches and similar constructs
// The kernel calls ana() before calling emu(), so you may be sure that
// the 'cmd' structure contains a valid and up-to-date information.
// You are not allowed to modify the 'cmd' structure.
// Upon entering this function, the 'uFlag' variable contains the flags of
// cmd.ea. If you change the characteristics of the current instruction, you
// are required to refresh 'uFlag'.
// Usually the kernel calls emu() with consecutive addresses in cmd.ea but
// you can't rely on this - for example, if the user asks to analyse an
// instruction at arbirary address, his request will be handled immediately,
// thus breaking the normal sequence of emulation.
// If you need to analyse the surroundings of the current instruction, you
// are allowed to save the contents of the 'cmd' structure and call ana().
// For example, this is a very common pattern:
//  {
//    insn_t saved = cmd;
//    if ( decode_prev_insn(cmd.ea) != BADADDR )
//    {
//      ....
//    }
//    cmd = saved;
//  }
//
// This sample emu() function is a very simple emulation engine.

int emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  // operands that are read
  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, hop_READ);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, hop_READ);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, hop_READ);

  // operands that are written
  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, hop_WRITE);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, hop_WRITE);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, hop_WRITE);

  // let IDA know that instruction makes a branch
  if ( Feature & CF_JUMP ) remember_problem(PR_JUMP, insn.ea);
 
  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyse the next instruction.

  if ( flow )
  {
	  add_cref(insn.ea, insn.ea+insn.size, fl_F);
  }

  return 1;    // actually the return value is unimportant, but let's it be so
}
