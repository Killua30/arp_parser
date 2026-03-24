all: test main

main:
	gcc -Wall -Werror -Wextra -std=c11 main.c arp.c -o main

test: 
	gcc -Wall -Werror -Wextra -std=c11 test.c arp.c -o test -lcheck -lm -lrt -lsubunit -lpthread

clean:
	rm -f test main
run: test
	./test

run-verbose: test
	./test -v

rebuild: clean all

.PHONY: clean run run-verbose rebuild