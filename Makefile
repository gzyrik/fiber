all:coctx_test.exe test.exe
	./coctx_test.exe
	./test.exe

CFLAGS += -g -std=c++11 -pthread
ifeq ($(shell uname),Darwin)
CFLAGS += -DCDECL_ASM
endif

coctx_test.exe: coctx.cpp coctx_swap.S coctx_test.cpp
	g++ $(CFLAGS) -o $@ $^

test.exe: coctx.cpp coctx_swap.S test.cpp coroutine.cpp
	g++ $(CFLAGS) -o $@ $^
