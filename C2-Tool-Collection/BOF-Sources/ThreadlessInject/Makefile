# ThreadlessInject BOF
SRC = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRC))
CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS := -masm=intel

all: $(OBJS)

%.o: %.c
	$(CC_x64) $(CFLAGS) -o ../$*.x64.o -c $<
clean:
	rm -f ../*.o
