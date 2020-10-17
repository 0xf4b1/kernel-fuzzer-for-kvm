#include "private.h"

static void get_input(void) {
    if (!input_limit)
        return;

    if (debug)
        printf("Get %lu bytes of input from %s\n", input_limit, input_path);

    input_file = fopen(input_path, "r");
    if (!input_file) {
        return;
    }

    input = malloc(input_limit);
    if (!input) {
        fclose(input_file);
        input_file = NULL;
        return;
    }

    if (!(input_size = fread(input, 1, input_limit, input_file))) {
        free(input);
        input = NULL;
    }
    fclose(input_file);
    input_file = NULL;

    if (debug)
        printf("Got input size %lu\n", input_size);
}

static bool inject_input(vmi_instance_t vmi) {
    if (!input || !input_size)
        return false;

    registers_t regs = {0};
    vmi_get_vcpuregs(vmi, &regs, 0);

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = regs.x86.cr3, .addr = address};

    if (debug)
        printf("Writing %lu bytes of input to 0x%lx\n", input_size, address);

    return VMI_SUCCESS == vmi_write(vmi, &ctx, input_size, input, NULL);
}

static bool fuzz(void) {
    crash = 0;

    if (afl) {
        afl_rewind(start);
        afl_wait();
    }

    get_input();

    if (!loopmode && !start_trace(vmi, start))
        return false;
    if (!inject_input(vmi)) {
        fprintf(stderr, "Injecting input failed\n");
        printf("Injecting input failed\n");
        return false;
    }

    if (debug)
        printf("Starting fuzz loop\n");
    loop(vmi);
    if (debug)
        printf("Stopping fuzz loop.\n");

    if (afl)
        afl_report(crash);
    else
        printf("Result: %s\n", crash ? "crash" : "no crash");

    free(input);
    input = NULL;

    return true;
}

static void usage(void) {
    printf("Inputs required for FUZZING step:\n");
    printf("\t  --input <path to input file> or @@ with AFL\n");
    printf("\t  --input-limit <limit input size>\n");
    printf("\t  --address <kernel virtual address to inject input to>\n");
    printf("\t  --domain <domain name>\n");
    printf("\t  --json <path to kernel debug json>\n");
    printf("\t  --module <kernel virtual address of kernel module>\n");
    printf("\t  --start <module offset to start fuzzing>\n");
    printf("\t  --target <module offset to end fuzzing>\n");
    printf("\tOptional inputs:\n");
    printf("\t  --limit <limit FUZZING execution to # of CF instructions>\n");
    printf("\t  --loopmode (Run in a loop without coverage trace, for example using /dev/urandom "
           "as input)\n");
    printf("\t  --breakpoints <file that contains addresses of CF instructions>\n");
    printf("\t  --coverage <full|block|edge coverage in breakpoint mode>\n");

    printf("\n\n");
    printf("Optional global inputs:\n");
    printf("\t--debug\n");
    printf("\t--logfile <path to logfile>\n");
}

int main(int argc, char **argv) {
    char *logfile = NULL;
    int c, out = 0, long_index = 0;
    const struct option long_opts[] = {{"help", no_argument, NULL, 'h'},
                                       {"domain", required_argument, NULL, 'd'},
                                       {"json", required_argument, NULL, 'j'},
                                       {"input", required_argument, NULL, 'f'},
                                       {"input-limit", required_argument, NULL, 'L'},
                                       {"address", required_argument, NULL, 'a'},
                                       {"module", required_argument, NULL, 'm'},
                                       {"start", required_argument, NULL, 's'},
                                       {"target", required_argument, NULL, 't'},
                                       {"limit", required_argument, NULL, 'l'},
                                       {"debug", no_argument, NULL, 'v'},
                                       {"logfile", required_argument, NULL, 'F'},
                                       {"loopmode", no_argument, NULL, 'O'},
                                       {"breakpoints", required_argument, NULL, 'b'},
                                       {"coverage", required_argument, NULL, 'c'},
                                       {NULL, 0, NULL, 0}};
    const char *opts = "d:j:f:a:m:s:t:l:F:b:c:vhO";
    limit = ~0;

    input_path = NULL;
    input_size = 0;
    input_limit = 0;
    mode = DYNAMIC;

    module_start = 0;
    start = 0;
    target = 0;

    while ((c = getopt_long(argc, argv, opts, long_opts, &long_index)) != -1) {
        switch (c) {
        case 'd':
            domain = optarg;
            break;
        case 'j':
            json = optarg;
            break;
        case 'f':
            input_path = optarg;
            break;
        case 'a':
            address = strtoull(optarg, NULL, 0);
            break;
        case 'm':
            module_start = strtoull(optarg, NULL, 0);
            break;
        case 's':
            start = strtoull(optarg, NULL, 0);
            break;
        case 't':
            target = strtoull(optarg, NULL, 0);
            break;
        case 'l':
            limit = strtoull(optarg, NULL, 0);
            break;
        case 'L':
            input_limit = strtoull(optarg, NULL, 0);
            break;
        case 'v':
            debug = true;
            break;
        case 'F':
            logfile = optarg;
            break;
        case 'O':
            loopmode = true;
            break;
        case 'b':
            bp_file = optarg;
            break;
        case 'c':
            if (!strcmp(optarg, "block"))
                mode = BLOCK;
            else if (!strcmp(optarg, "edge"))
                mode = EDGE;
            else
                mode = FULL;
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if (!domain || !json || !address || !input_path || !input_limit) {
        usage();
        return -1;
    }

    if (start)
        start = module_start + start;

    if (target)
        target = module_start + target;

    if (logfile) {
        out = open(logfile, O_RDWR | O_CREAT | O_APPEND, 0600);
        if (-1 == dup2(out, fileno(stdout)))
            return -1;
        if (-1 == dup2(out, fileno(stderr)))
            return -1;
    }

    if (debug)
        printf("############ START ################\n");

    setup_handlers();

    if (!setup_vmi(&vmi, domain, json)) {
        fprintf(stderr, "Unable to start VMI on domain\n");
        return -1;
    }

    setup_interrupts(vmi);
    setup_trace(vmi);
    set_breakpoint(vmi);
    setup_sinks(vmi);

    if (cs_open(CS_ARCH_X86, pm == VMI_PM_IA32E ? CS_MODE_64 : CS_MODE_32, &cs_handle)) {
        fprintf(stderr, "Capstone init failed\n");
        goto done;
    }

    afl_setup();

    if (debug)
        printf("Starting fuzzer\n");

    if (loopmode)
        printf("Running in loopmode\n");
    else if (afl)
        printf("Running in AFL mode\n");
    else
        printf("Running in standalone mode\n");

    unsigned long iter = 0, t = time(0), cycle = 0;

    while (fuzz()) {
        iter++;

        if (loopmode) {
            unsigned long now = time(0);
            if (t != now) {
                printf("Completed %lu iterations\n", iter - cycle);
                t = now;
                cycle = iter;
            }
        }

        if (!target)
            set_breakpoint(vmi);
    }

    close_trace(vmi);
    clear_interrupts(vmi);

done:
    clear_sinks(vmi);
    vmi_destroy(vmi);
    cs_close(&cs_handle);
    if (input_file)
        fclose(input_file);

    if (debug)
        printf(" ############ DONE ##############\n");
    if (logfile)
        close(out);

    return 0;
}
