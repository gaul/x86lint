ifndef XED_PATH
$(error "must provide XED_PATH")
endif

CFLAGS = -g -Wall -fPIC

%.o: %.c
	$(CC) $(CFLAGS) -I ${XED_PATH}/kits/xed-install/include/ -c $< -o $@

lib: asmlint.o
	ar -crs libasmlint.a $<

# TODO: create utility which reads arbitrary ELF programs

test: asmlint.o asmlint_test.o
	$(CC) $(CFLAGS) asmlint.o asmlint_test.o ${XED_PATH}/obj/libxed.a -o asmlint_test

all: lib test

clean:
	rm -f asmlint_test libasmlint.a *.o
