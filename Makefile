ifndef XED_PATH
$(error "must provide XED_PATH")
endif

CFLAGS = -g -Wall

%.o: %.c
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install-base-2018-10-30-lin-x86-64/include/ -c $< -o $@

# TODO: create .a for outside projects
# TODO: create utility which reads arbitrary ELF programs
all: asmlint.o asmlint_test.o
	$(CC) $(CFLAGS) asmlint.o asmlint_test.o ${XED_PATH}/obj/libxed.a -o asmlint_test

clean:
	rm -f asmlint_test *.o
