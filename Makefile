CC = clang
CFLAGS = -Wall -pedantic -g -O0

all: crumbd crumb_dump

crumbd: crumbd.c
	$(CC) $(CFLAGS) $^ -o $@

crumb_dump: crumb_dump.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm crumbd
