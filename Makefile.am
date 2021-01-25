bin_PROGRAMS = kvmfuzz

kvmfuzz_SOURCES = src/main.c src/private.h \
                  src/signal.c src/signal.h \
                  src/vmi.c src/vmi.h \
                  src/afl.c src/afl.h \
                  src/tracer.c src/tracer.h \
                  src/tracer_dynamic.c src/tracer_dynamic.h \
                  src/fuzz.c src/fuzz.h \
                  src/sink.h \
                  src/breakpoint.c src/breakpoint.h

kvmfuzz_LDADD   = $(LIBS) \
                  $(VMI_LIBS) \
                  $(CAPSTONE_LIBS)
kvmfuzz_CFLAGS  = -Wall -Wextra -fstack-protector \
                  -Wno-override-init \
                  $(CFLAGS) \
                  $(VMI_CFLAGS) \
                  $(CAPSTONE_CFLAGS)

EXTRA_DIST = configure.ac README.md \
             tools/README tools/Makefile tools/vmfork.go \
             patches/0001-AFL-Xen-mode.patch \
             testmodule/Makefile testmodule/testmodule.c
