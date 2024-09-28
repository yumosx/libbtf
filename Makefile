all : main.exe

main.exe : main.c btf.c
	gcc -Wall -g -o $@ $^

clean :
	rm -f main.exe