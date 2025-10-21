
INCLUDE := -I./include

SRC := $(shell find ./src/core -type f -name '*.c')
OBJ := $(patsubst ./src/core/%.c, ./build/%.o, $(SRC))

LIB := ./build/libcryptolib.a
TARGET:= ./build_testing/main

run: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^

#evil build step
#Compile Crypto Lib into static library 
./build/%.o: ./src/core/%.c
	@mkdir -p $(dir $@)
	gcc -c $< $(INCLUDE) -o $@

#exec build_testing with static library which this works!
exec: 
	gcc ./build_testing/main.c $(LIB) $(INCLUDE) -o $(TARGET) 

#clean build
clean:
	rm -rf ./build

