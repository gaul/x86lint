# XED_PATH locates the Intel XED headers and library and is required to compile
# and link, but not to clean -- so `make clean` works without it (and a
# `make clean && make ...` chain does not short-circuit when it is unset).
ifndef XED_PATH
ifneq ($(MAKECMDGOALS),clean)
$(error must provide XED_PATH)
endif
endif

CFLAGS = -g -Wall -fPIC

%.o: %.c
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ -c $< -o $@

lib: x86lint.o
	ar -crs libx86lint.a $<

# TODO: create utility which reads arbitrary ELF programs

x86lint: x86lint.o main.o
	$(CC) $(CFLAGS) x86lint.o main.o ${XED_PATH}/obj/libxed.a -o x86lint

test: x86lint.o x86lint_test.o
	$(CC) $(CFLAGS) x86lint.o x86lint_test.o ${XED_PATH}/obj/libxed.a -o x86lint_test

all: lib x86lint test

# Corpus-mining research utilities (see "Mining tools" in README.md); not part
# of the default build or of check.
tools: tools/pairscan tools/defuse tools/cohere tools/shapescan tools/framescan \
	tools/rwfuzz

# The tools link liblzma (xz-devel) to read the MiniDebugInfo a stripped
# distro binary keeps in .gnu_debugdata; the linter itself does not.
TOOL_LIBS = ${XED_PATH}/obj/libxed.a -llzma

tools/pairscan: tools/pairscan.c tools/corpus.c tools/corpus.h
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ \
		tools/pairscan.c tools/corpus.c $(TOOL_LIBS) -o $@

tools/framescan: tools/framescan.c tools/corpus.c tools/corpus.h
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ \
		tools/framescan.c tools/corpus.c $(TOOL_LIBS) -o $@

tools/cohere: tools/cohere.c tools/corpus.c tools/corpus.h
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ \
		tools/cohere.c tools/corpus.c $(TOOL_LIBS) -o $@

# shapescan includes x86lint.c for the window checks and the gates they call,
# all of which are static, so it compiles the linter rather than linking it.
tools/shapescan: tools/shapescan.c tools/corpus.c tools/corpus.h x86lint.c x86lint.h
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ \
		tools/shapescan.c tools/corpus.c $(TOOL_LIBS) -o $@

# rwfuzz runs x86lint's advice: it links the linter and assembles with the
# host's compiler driver (RWFUZZ_CC, default cc). See rwfuzz-test. It must be
# a PIE: the programs it runs form addresses from register values that
# cluster below 4 GB, where a non-PIE link puts rwfuzz's own data and heap.
tools/rwfuzz: tools/rwfuzz.c x86lint.o x86lint.h
	$(CC) $(CFLAGS) -pie -I ${XED_PATH}/kits/xed-install/include/ \
		tools/rwfuzz.c x86lint.o ${XED_PATH}/obj/libxed.a -o $@

tools/defuse: tools/defuse.c tools/corpus.c tools/corpus.h
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ \
		tools/defuse.c tools/corpus.c $(TOOL_LIBS) -o $@

# Run the unit suite, the ELF-driver smoke test and the JIT-converter tests.
check: all
	./x86lint_test
	./driver_test.sh
	./jit_test.sh

# Run x86lint's advice: tools/rwfuzz applies each finding's rewrite to random
# programs and runs original and rewrite natively (rwfuzz_test.sh). Not part of
# check: it needs an x86-64 host and an assembler, and takes about a minute.
rwfuzz-test: tools/rwfuzz
	./rwfuzz_test.sh

# Rewrite driver_test.sh's report snapshots from this build's output. Read the
# resulting diff before committing it: an explained change is a new check or a
# deliberate wording edit, and an unexplained one is the regression the layer
# exists to catch.
snapshots: x86lint
	REGEN=1 ./driver_test.sh

clean:
	rm -f \
		x86lint \
		x86lint_test \
		libx86lint.a \
		tools/pairscan \
		tools/defuse \
		tools/cohere \
		tools/shapescan \
		tools/framescan \
		tools/rwfuzz \
		*.o

# None of these name a file that is built; `tools` and `snapshots` are also
# directories that exist, so without this make would call them up to date.
.PHONY: lib all tools check rwfuzz-test snapshots clean
