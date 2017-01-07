crumbd: crumbd.c
	clang -g -O0 crumbd.c -o crumbd -lgdbm -lgdbm_compat -lsqlite3

clean:
	rm crumbd
