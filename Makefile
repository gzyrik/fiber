all:coctx_test.exe test.exe
	./coctx_test.exe
	./test.exe

CFLAGS +=-std=c++11 -pthread
ifeq ($(shell uname),Darwin)
CFLAGS +=-DCDECL_ASM
endif

coctx_test.exe:
	g++ $(CFLAGS) -o $@ coctx.cpp coctx_swap.S coctx_test.cpp

test.exe:
	g++ $(CFLAGS) -o $@ coctx.cpp coctx_swap.S test.cpp coroutine.cpp
