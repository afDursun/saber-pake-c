CC 		  = /usr/bin/gcc
CFLAGS  = -Wall -Wextra -Wmissing-prototypes -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native 
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99 
CLANG   = clang -march=native -O3 -fomit-frame-pointer -fwrapv -Qunused-arguments
RM 		  = /bin/rm

saber_pake_test: saber_pake_test \


saber_pake_speed: saber_pake_speed \

SOURCES = pack_unpack.c poly.c fips202.c verify.c cbd.c SABER_indcpa.c SABER_PAKE.c
HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h 

saber_pake_speed: $(SOURCES) $(HEADERS) rng.o speed_print.h speed_print.c saber_pake_speed.c
	$(CC) $(CFLAGS) -o $@ $(SOURCES) rng.o saber_pake_speed.c -lcrypto
	
saber_pake_test: $(SOURCES) $(HEADERS) rng.o saber_pake_test.c
	$(CC) $(CFLAGS) -o $@ $(SOURCES) rng.o saber_pake_test.c -lcrypto

rng.o: rng.c
	$(CC) $(NISTFLAGS) -c rng.c -lcrypto -o $@ 


.PHONY: clean test


clean:
	-$(RM) -f *.o
	-$(RM) -rf saber_pake_speed
	-$(RM) -rf saber_pake_test
