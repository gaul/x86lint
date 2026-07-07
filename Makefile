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

# Run the unit suite and the ELF-driver smoke test.
check: all
	./x86lint_test
	./driver_test.sh

clean:
	rm -f \
		x86lint \
		x86lint_test \
		libx86lint.a \
		*.o
