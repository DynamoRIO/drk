#include <linux/module.h>
#include "dr_api.h"
MODULE_LICENSE("Dual BSD/GPL");

/* check if instr update the whol register */
static bool
instr_writes_to_whole_reg(instr_t *instr, reg_id_t reg)
{
    if (instr_writes_to_exact_reg(instr, reg))
        return true;
#ifdef X64
    reg = reg_64_to_32(reg);
    if (instr_writes_to_exact_reg(instr, reg))
        return true;
#endif
    return false;
}

/* check if this instr set an register to immed value */
static bool
reg_set_immed(instr_t *instr, reg_id_t reg)
{
    int opcode = instr_get_opcode(instr);

    // for case of r1 = r1 - r1, or r1 = r1 xor r1
    if((opcode == OP_sub || opcode == OP_xor) &&
       (opnd_same(instr_get_src(instr, 0), 
                  instr_get_src(instr, 1))))
	return true;

    if(opcode == OP_mov_ld          && 
       opnd_is_immed(instr_get_src(instr, 0)))
        return true;
    if (opcode == OP_mov_imm)
        return true;

    return false;
}

/* check if register is dead before this intre */
bool 
register_is_dead(instr_t *instr, reg_id_t reg)
{
    int  opcode;

    // when at interupt, register never die
    if(instr_is_syscall(instr) || instr_is_interrupt(instr))
        return false;
    
    opcode = instr_get_opcode(instr);
    // dead reg must be exact dst being written
    if (!instr_writes_to_whole_reg(instr, reg))
        return false;

    // reg is set to be immed
    // r1 = r1 - r1 || r1 = r1 xor r1 || r1 = immed
    if(reg_set_immed(instr, reg))
        return true;

    // dead reg cannot be used 
    if(instr_reg_in_src(instr, reg))
	return false;
    
    // must be a dead reg now
    return true;
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
         bool translating) {
    reg_t reg;
    instr_t *instr;
    for (reg = DR_REG_START_64; reg <= DR_REG_STOP_64; reg++) {
        for (instr = instrlist_last(bb);
             instr != NULL; instr = instr_get_prev(instr)) {
            if (register_is_dead(instr, reg)) {
                for (;;) {
                    instr_t *prev = instr_get_prev(instr);
                    if (prev == NULL || instr_reads_from_reg(prev, reg)) {
                        instr_t *mov =
                            INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(reg),
                                                 OPND_CREATE_INT64(0xdeadf00dbeef1337));
                        instrlist_meta_preinsert(bb, instr, mov);
                        break;
                    }
                    instr = prev;
                }
                break;
            }
        }
    }
    return DR_EMIT_DEFAULT;
}

void
drinit(client_id_t id)
{
    printk("drinit %d\n", id);
    dr_register_bb_event(bb_event);
}
