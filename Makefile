TARGET = vm_riskxvii

CC = gcc

CFLAGS     = -c -Wall -Wvla -Werror -O0 -g -std=c11 -lm
SRC        = vm_riskxvii.c
OBJ        = $(SRC:.c=.o)

all:$(TARGET)

$(TARGET):$(OBJ)
	$(CC) -o $@ $(OBJ) -lm

.SUFFIXES: .c .o

.c.o:
	 $(CC) $(CFLAGS) $(ASAN_FLAGS) $<

run:
	./$(TARGET)

tests:
	chmod a+x compile_file.sh
	bash compile_file.sh

run_tests:
	chmod a+x test_script.sh
	bash test_script.sh

clean:
	rm -f *.o *.obj $(TARGET)