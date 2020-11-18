#include "breakpoint.h"
#include "private.h"
#include "sink.h"

/*
 * 1. start by disassembling code from the start address
 * 2. find next control-flow instruction and start monitoring it
 * 3. at control flow instruction remove monitor and create singlestep
 * 4. after a singlestep set start address to current RIP
 * 5. goto step 1
 */

static const char *traptype[] = {
    [VMI_EVENT_SINGLESTEP] = "singlestep",
    [VMI_EVENT_CPUID] = "cpuid",
    [VMI_EVENT_INTERRUPT] = "int3",
};

unsigned long tracer_counter;

extern int interrupted;
extern csh cs_handle;

static addr_t next_cf_vaddr;
static addr_t next_cf_paddr;

static uint8_t cc = 0xCC;
static uint8_t cf_backup;
static addr_t reset_breakpoint;

static vmi_event_t singlestep_event, cc_event;

static struct table *breakpoints;
static struct node *current_bp;

event_response_t (*handle_event)(vmi_instance_t vmi, vmi_event_t *event);

static void breakpoint_next_cf(vmi_instance_t vmi) {
    if (VMI_SUCCESS == vmi_read_pa(vmi, next_cf_paddr, 1, &cf_backup, NULL) &&
        VMI_SUCCESS == vmi_write_pa(vmi, next_cf_paddr, 1, &cc, NULL)) {
        if (debug)
            printf("[TRACER] Next CF: 0x%lx -> 0x%lx\n", next_cf_vaddr, next_cf_paddr);
    }
}

static inline bool is_cf(unsigned int id) {
    switch (id) {
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JBE:
    case X86_INS_JB:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JE:
    case X86_INS_JGE:
    case X86_INS_JG:
    case X86_INS_JLE:
    case X86_INS_JL:
    case X86_INS_JMP:
    case X86_INS_LJMP:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JRCXZ:
    case X86_INS_JS:
    case X86_INS_CALL:
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return true;
    default:
        break;
    }

    return false;
}

#define TRACER_CF_SEARCH_LIMIT 100u

static bool next_cf_insn(vmi_instance_t vmi, addr_t dtb, addr_t start) {
    cs_insn *insn;
    size_t count;

    size_t read, search = 0;
    unsigned char buff[15];
    bool found = false;
    access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = dtb, .addr = start};

    while (!found && search < TRACER_CF_SEARCH_LIMIT) {
        memset(buff, 0, 15);

        if (VMI_FAILURE == vmi_read(vmi, &ctx, 15, buff, &read) && !read) {
            if (debug)
                printf("Failed to grab memory from 0x%lx with PT 0x%lx\n", start, dtb);
            goto done;
        }

        count = cs_disasm(cs_handle, buff, read, ctx.addr, 0, &insn);
        if (!count) {
            if (debug)
                printf("No instruction was found at 0x%lx with PT 0x%lx\n", ctx.addr, dtb);
            goto done;
        }

        size_t j;
        for (j = 0; j < count; j++) {

            ctx.addr = insn[j].address + insn[j].size;

            if (debug)
                printf("Next instruction @ 0x%lx: %s, size %i!\n", insn[j].address,
                       insn[j].mnemonic, insn[j].size);

            if (is_cf(insn[j].id)) {
                next_cf_vaddr = insn[j].address;
                if (VMI_FAILURE == vmi_pagetable_lookup(vmi, dtb, next_cf_vaddr, &next_cf_paddr)) {
                    if (debug)
                        printf("Failed to lookup next instruction PA for 0x%lx with PT 0x%lx\n",
                               next_cf_vaddr, dtb);
                    break;
                }

                found = true;

                if (debug)
                    printf("Found next control flow instruction @ 0x%lx: %s!\n", next_cf_vaddr,
                           insn[j].mnemonic);
                break;
            }
        }
        cs_free(insn, count);
    }

    if (!found && debug)
        printf("Didn't find a control flow instruction starting from 0x%lx with a search limit %u! "
               "Counter: %lu\n",
               start, TRACER_CF_SEARCH_LIMIT, tracer_counter);

done:
    return found;
}

static event_response_t tracer_cb(vmi_instance_t vmi, vmi_event_t *event) {
    if (debug)
        printf("[TRACER %s] 0x%lx. Limit: %lu/%lu\n", traptype[event->type], event->x86_regs->rip,
               tracer_counter, limit);

    if (reset_breakpoint && VMI_EVENT_SINGLESTEP == event->type) {
        access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB,
                                .dtb = event->x86_regs->cr3,
                                .addr = reset_breakpoint};

        vmi_write_8(vmi, &ctx, &cc);

        reset_breakpoint = 0;

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    // reached start address for fuzzing
    if (event->x86_regs->rip == start) {
        printf("VM reached the start address\n");

        access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB,
                                .dtb = event->x86_regs->cr3,
                                .addr = event->x86_regs->rip};

        // Restore instruction byte at start address
        vmi_write_8(vmi, &ctx, &start_byte);

        vmi_pause_vm(vmi);
        interrupted = 1;

        // Set BP for target address
        assert(VMI_SUCCESS == vmi_write_va(vmi, target, 0, 1, &cc, NULL));

        return 0;
    }

    // reached target address for fuzzing
    if (event->x86_regs->rip == target) {
        printf("VM reached the target address.\n");

        access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB,
                                .dtb = event->x86_regs->cr3,
                                .addr = event->x86_regs->rip};

        vmi_write_8(vmi, &ctx, &target_byte);

        vmi_pause_vm(vmi);
        interrupted = 1;

        return 0;
    }

    // check for error sink
    int c;
    for (c = 0; c < __SINK_MAX; c++) {
        if (sink_vaddr[c] == event->x86_regs->rip) {
            crash = 1;

            if (debug)
                printf("\t Sink %s! Tracer counter: %lu. Crash: %i.\n", sinks[c], tracer_counter,
                       crash);

            // Restore instruction byte at sink address
            vmi_write_pa(vmi, sink_paddr[c], 1, &sink_backup[c], NULL);

            // Restore BP for sink afterwards
            reset_breakpoint = sink_vaddr[c];

            if (VMI_EVENT_INTERRUPT == event->type)
                return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

            return 0;
        }
    }

    afl_instrument_location(event->x86_regs->rip);

    return handle_event(vmi, event);
}

event_response_t handle_event_dynamic(vmi_instance_t vmi, vmi_event_t *event) {
    if (VMI_EVENT_SINGLESTEP == event->type) {
        if (next_cf_insn(vmi, event->x86_regs->cr3, event->x86_regs->rip))
            breakpoint_next_cf(vmi);

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    /*
     * Let's allow the control-flow instruction to execute
     * and catch where it continues using MTF singlestep.
     */
    if (VMI_EVENT_INTERRUPT == event->type) {
        event->interrupt_event.reinject = 0;

        /* We are at the expected breakpointed CF instruction */
        vmi_write_pa(vmi, next_cf_paddr, 1, &cf_backup, NULL);

        tracer_counter++;

        if (limit == ~0ul || tracer_counter < limit)
            return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

        if (debug)
            printf("Hit the tracer limit: %lu\n", tracer_counter);
    }

    return 0;
}

event_response_t handle_event_breakpoints(vmi_instance_t vmi, vmi_event_t *event) {
    if (VMI_EVENT_SINGLESTEP == event->type) {
        // FIXME
        if (current_bp != NULL)
            assert(VMI_SUCCESS == vmi_write_va(vmi, current_bp->address, 0, 1, &cc, NULL));

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    /*
     * Let's allow the control-flow instruction to execute
     * and catch where it continues using MTF singlestep.
     */
    if (VMI_EVENT_INTERRUPT == event->type) {
        event->interrupt_event.reinject = 0;

        current_bp = get(breakpoints, event->x86_regs->rip);
        assert(current_bp != NULL);
        assert(VMI_SUCCESS ==
               vmi_write_va(vmi, current_bp->address, 0, 1, &current_bp->cf_backup, NULL));

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    return 0;
}

bool setup_sinks(vmi_instance_t vmi) {
    int c;
    for (c = 0; c < __SINK_MAX; c++) {
        if (!sink_vaddr[c] && VMI_FAILURE == vmi_translate_ksym2v(vmi, sinks[c], &sink_vaddr[c])) {
            if (debug)
                printf("Failed to find %s\n", sinks[c]);
            return false;
        }

        registers_t regs = {0};
        vmi_get_vcpuregs(vmi, &regs, 0);

        if (!sink_paddr[c] &&
            VMI_FAILURE == vmi_pagetable_lookup(vmi, regs.x86.cr3, sink_vaddr[c], &sink_paddr[c]))
            return false;
        if (VMI_FAILURE == vmi_read_pa(vmi, sink_paddr[c], 1, &sink_backup[c], NULL))
            return false;
        if (VMI_FAILURE == vmi_write_pa(vmi, sink_paddr[c], 1, &cc, NULL))
            return false;

        if (debug)
            printf("[TRACER] Setting breakpoint on sink %s 0x%lx -> 0x%lx, backup 0x%x\n", sinks[c],
                   sink_vaddr[c], sink_paddr[c], sink_backup[c]);
    }

    return true;
}

void clear_sinks(vmi_instance_t vmi) {
    int c;
    for (c = 0; c < __SINK_MAX; c++)
        vmi_write_pa(vmi, sink_paddr[c], 1, &sink_backup[c], NULL);
}

bool setup_trace(vmi_instance_t vmi) {
    if (debug)
        printf("Setup trace\n");

    SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, tracer_cb, 0);
    SETUP_INTERRUPT_EVENT(&cc_event, tracer_cb);

    if (VMI_FAILURE == vmi_register_event(vmi, &singlestep_event))
        return false;
    if (VMI_FAILURE == vmi_register_event(vmi, &cc_event))
        return false;

    if (mode == BREAKPOINT) {
        handle_event = &handle_event_breakpoints;

        FILE *fp = fopen(bp_file, "r");
        assert(fp);

        breakpoints = createTable(0x1000);

        char buf[1024];
        while (fgets(buf, 1024, fp)) {
            unsigned long address = module_start + strtoul(strtok(buf, "\n"), NULL, 16);

            unsigned char backup;
            assert(VMI_SUCCESS == vmi_read_va(vmi, address, 0, 1, &backup, NULL));

            insert(breakpoints, address, backup);
        }

        setup_breakpoints(vmi);
    } else {
        handle_event = &handle_event_dynamic;
    }

    if (debug)
        printf("Setup trace finished\n");
    return true;
}

bool start_trace(vmi_instance_t vmi, addr_t address) {
    if (debug)
        printf("Starting trace from 0x%lx.\n", address);

    if (mode == BREAKPOINT)
        return true;

    next_cf_vaddr = 0;
    next_cf_paddr = 0;
    tracer_counter = 0;

    registers_t regs = {0};
    vmi_get_vcpuregs(vmi, &regs, 0);

    if (!next_cf_insn(vmi, regs.x86.cr3, address)) {
        if (debug)
            printf("Failed starting trace from 0x%lx\n", address);
        return false;
    }

    breakpoint_next_cf(vmi);
    return true;
}

void close_trace(vmi_instance_t vmi) {
    vmi_clear_event(vmi, &singlestep_event, NULL);
    vmi_clear_event(vmi, &cc_event, NULL);

    if (debug)
        printf("Closing tracer\n");
}

bool set_breakpoint(vmi_instance_t vmi) {
    if (VMI_FAILURE == vmi_write_va(vmi, start, 0, 1, &cc, NULL))
        return false;

    loop(vmi);

    return true;
}

bool setup_interrupts(vmi_instance_t vmi) {
    if (VMI_FAILURE == vmi_read_va(vmi, start, 0, 1, &start_byte, NULL))
        return false;

    if (VMI_FAILURE == vmi_read_va(vmi, target, 0, 1, &target_byte, NULL))
        return false;

    return true;
}

bool clear_interrupts(vmi_instance_t vmi) {
    if (VMI_FAILURE == vmi_write_va(vmi, start, 0, 1, &start_byte, NULL))
        return false;

    if (VMI_FAILURE == vmi_write_va(vmi, target, 0, 1, &target_byte, NULL))
        return false;

    return true;
}

void setup_breakpoints(vmi_instance_t vmi) {
    int pos;
    for (pos = 0; pos < breakpoints->size; pos++) {

        struct node *list = breakpoints->list[pos];

        while (list) {
            assert(VMI_SUCCESS == vmi_write_va(vmi, list->address, 0, 1, &cc, NULL));
            list = list->next;
        }
    }
}
