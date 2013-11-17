#ifndef __SEGMENT_DESCRIPTOR_H_
#define __SEGMENT_DESCRIPTOR_H_

#include "basic_types.h"
#include "static_assert.h"

typedef enum {
    SEGMENT_GRANULARITY_NOT_SCALED = 0,
    SEGMENT_GRANULARITY_SCALED     = 1,
} segment_granularity_t;

typedef enum {
    SEGMENT_DEFAULT_OPERAND_SIZE_16 = 0,
    SEGMENT_DEFAULT_OPERAND_SIZE_32 = 1,
} segment_default_operand_size_t;

typedef enum {
    SEGMENT_SYSTEM = 0,
    SEGMENT_USER = 1,  
} descriptor_sbit_t;

typedef enum {
    SEGMENT_NOT_PRESENT = 0,
    SEGMNET_PRESENT = 1,
} descriptor_present_t;
 
typedef enum {
    SYSTEM_TYPE_ILLEGAL_0      = 0x0,
    SYSTEM_TYPE_ILLEGAL_1      = 0x1,
    SYSTEM_TYPE_LDT            = 0x2,
    SYSTEM_TYPE_ILLEGAL_2      = 0x3,
    SYSTEM_TYPE_ILLEGAL_3      = 0x4,
    SYSTEM_TYPE_ILLEGAL_4      = 0x5,
    SYSTEM_TYPE_ILLEGAL_5      = 0x6,
    SYSTEM_TYPE_ILLEGAL_6      = 0x7,
    SYSTEM_TYPE_ILLEGAL_7      = 0x8,
    SYSTEM_TYPE_AVAIL_TSS      = 0x9,
    SYSTEM_TYPE_ILLEGAL_8      = 0xA,
    SYSTEM_TYPE_BUSY_TSS       = 0xB,
    SYSTEM_TYPE_CALL_GATE      = 0xC,
    SYSTEM_TYPE_ILLEGAL_9      = 0xD,
    SYSTEM_TYPE_INTERRUPT_GATE = 0xE,
    SYSTEM_TYPE_TRAP_GATE      = 0xF,
} system_descriptor_type_t;

typedef enum {
    SEGMENT_COMPATIBILITY_MODE = 0,
    SEGMENT_64_BIT_MODE = 1,
} code_segment_mode_t;

typedef enum {
    TABLE_INDICATOR_GDT = 0,
    TABLE_INDICATOR_LDT = 1,
} table_indicator_t;

typedef struct {
    union {
        struct {
          uint32 requestor_privilige_level : 2;
          table_indicator_t table_indicator : 1;
          uint32 index : 13;
        } __attribute__((__packed__));
        struct {
            unsigned short selector;
        } __attribute__((__packed__));
    };
} __attribute__((__packed__)) segment_selector_t;
ASSERT_TYPE_SIZE(2, segment_selector_t);

static inline void
segment_selector_decode(int selector, segment_selector_t* output)
{
    output->requestor_privilige_level = selector & 0x3;
    output->table_indicator = (selector & 0x4) >> 2;
    output->index = (selector & 0xfff8) >> 3;
}

#define SEGMENT_SELECTOR_ACCESSOR(selector_reg) \
static inline unsigned short \
get_##selector_reg(void) \
{\
    unsigned short result; \
    asm volatile("movw %%" #selector_reg ", %0" : "=m" (result)); \
    return result; \
}

SEGMENT_SELECTOR_ACCESSOR(cs)
SEGMENT_SELECTOR_ACCESSOR(ds)
SEGMENT_SELECTOR_ACCESSOR(es)
SEGMENT_SELECTOR_ACCESSOR(fs)
SEGMENT_SELECTOR_ACCESSOR(gs)
SEGMENT_SELECTOR_ACCESSOR(ss)

#undef SEGMENT_SELECTOR_ACCESSOR

typedef struct {
    ushort limit_low : 16;
    ushort base_low : 16;
    byte base_middle : 8;
    union {
        struct {
            system_descriptor_type_t system_type : 4;
            byte system_access : 4;
        } __attribute__((__packed__));
        byte nonsystem_access : 8;
    };
    byte limit_high : 4;
    byte available: 1;
    /* Only valid for CODE_SEGMENT */
    code_segment_mode_t code_mode : 1;
    /* Only valid for CODE_SEGMENT & DATA_SEGMENT */
    segment_default_operand_size_t default_operand_size : 1;
    segment_granularity_t granularity : 1;
    byte base_high : 8;
} __attribute__((__packed__)) segment_descriptor_t;
ASSERT_TYPE_SIZE(8, segment_descriptor_t);

typedef struct {
    ushort target_offset_low : 16;
    segment_selector_t target_selector; /* :16 */
    /* Only valid for interrupt gates. */
    byte interrupt_stack_table_index : 3;
    byte reserved : 5;
    system_descriptor_type_t system_type : 4;
    byte access : 4;
    ushort target_offset_middle : 16;
} __attribute__ ((packed)) gate_descriptor_t;
ASSERT_TYPE_SIZE(8, gate_descriptor_t);

typedef struct {
    uint32 higher_addr;
    uint32 reserved;
} __attribute__ ((packed)) system_descriptor_extra_t;
ASSERT_TYPE_SIZE(8, system_descriptor_extra_t);

typedef struct {
    uint64 unused : 44;
    descriptor_sbit_t sbit : 1;
    byte dpl : 2;
    descriptor_present_t present : 1;
    ushort unused3 : 16;
} __attribute__ ((packed)) generic_descriptor_t;
ASSERT_TYPE_SIZE(8, generic_descriptor_t);

typedef union {
    generic_descriptor_t generic;
    segment_descriptor_t segment;
    gate_descriptor_t gate;
    system_descriptor_extra_t extra;
} descriptor_t;
ASSERT_TYPE_SIZE(8, descriptor_t);

typedef enum {
    DATA_SEGMENT_DESCRIPTOR,
    CODE_SEGMENT_DESCRIPTOR,
    SYSTEM_SEGMENT_DESCRIPTOR,
    GATE_DESCRIPTOR,
    NOT_PRESENT_DESCRIPTOR,
} descriptor_class_t;

static inline descriptor_class_t 
get_descriptor_kind(descriptor_t *desc)
{
    if (!desc->generic.present) {
        return NOT_PRESENT_DESCRIPTOR;
    } else if (desc->generic.sbit == SEGMENT_SYSTEM) {
        switch (desc->segment.system_type) {
        case SYSTEM_TYPE_CALL_GATE:
        case SYSTEM_TYPE_INTERRUPT_GATE:
        case SYSTEM_TYPE_TRAP_GATE:
            return GATE_DESCRIPTOR;
        default:
            return SYSTEM_SEGMENT_DESCRIPTOR;
        }
    } else {
        const uint64 uninterpreted = *((uint64*) desc);
        const uint64 CODE_BIT = 1L << (31 + 12);
        if ((CODE_BIT & uninterpreted) != 0) {
            return CODE_SEGMENT_DESCRIPTOR;
        } else {
            return DATA_SEGMENT_DESCRIPTOR;
        }
    }
}

static inline bool 
is_system_desciptor(descriptor_t *desc)
{
    switch (get_descriptor_kind(desc)) {
    case SYSTEM_SEGMENT_DESCRIPTOR:
    case GATE_DESCRIPTOR:
        return true;
    default:
        return false;
    }
}

typedef struct {
    uint64 limit;
    byte *base;
} segment_t;

typedef struct {
    ushort limit;
    descriptor_t* base;
} __attribute__((__packed__)) system_table_register_t;
ASSERT_TYPE_SIZE(10, system_table_register_t);

static inline void
get_idtr(system_table_register_t* output)
{
    asm volatile ("sidt %0" : "=m" (*output));
}

static inline void
set_idtr(system_table_register_t* input)
{
    asm volatile ("lidt %0" : : "m" (*input));
}

static inline void
get_gdtr(system_table_register_t* output)
{
    asm volatile ("sgdt %0" : "=m" (*output));
}

static inline void
get_ldt_selector(segment_selector_t* output)
{
    asm volatile ("sldt %0" : "=m" (*output));
}

static inline void
get_segment(descriptor_t *desc, segment_t *seg)
{
    seg->limit = ((uint64) desc->segment.limit_low) |
                   (((uint64) desc->segment.limit_high) << 16);
    if (desc->segment.granularity == SEGMENT_GRANULARITY_SCALED) {
        /* Scale by 4kb */
        seg->limit *= 4096;
    }

    seg->base = (byte*) (((uint64) desc->segment.base_low) |
                         (((uint64) desc->segment.base_middle) << 16) |
                         (((uint64) desc->segment.base_high) << 24));
    if (get_descriptor_kind(desc) == SYSTEM_SEGMENT_DESCRIPTOR) {
        seg->base = (byte*) ((uint64) seg->base |
                             ((uint64) (desc + 1)->extra.higher_addr) << 32);
    }
}

static inline byte* 
get_gate_target_offset(gate_descriptor_t *gate)
{
    system_descriptor_extra_t *extra =
        (system_descriptor_extra_t*) (gate + 1);
    uint64 low = (uint64) gate->target_offset_low;
    uint64 middle = (uint64) gate->target_offset_middle;
    uint64 high = (uint64) extra->higher_addr;
    return (byte*) (low | (middle << 16) | (high << 32));
}

static inline void
set_gate_target_offset(gate_descriptor_t *gate, byte *offset)
{
    system_descriptor_extra_t *extra =
        (system_descriptor_extra_t*) (gate + 1);
    gate->target_offset_low = (ushort) (uint64) offset;
    gate->target_offset_middle = (ushort) (((uint64) offset) >> 16);
    extra->higher_addr = (uint32) (((uint64) offset) >> 32);

}


#endif
