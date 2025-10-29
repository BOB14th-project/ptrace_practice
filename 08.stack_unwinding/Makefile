CXX := g++
CC  := gcc

LIBELFIN_DIR := ../third_party/libelfin

CXXFLAGS := -std=c++17 -g -gdwarf-4 -Wall -Wextra \
    -I$(LIBELFIN_DIR)/include/dwarf \
    -I$(LIBELFIN_DIR)/include/elf
LDFLAGS := -L$(LIBELFIN_DIR)/lib -ldwarf++ -lelf++

CFLAGS := -g -gdwarf-4 -Wall -Wextra

MINIDBG_SRCS := minidbg.cpp debugger.cpp breakpoint.cpp register.cpp pch.cpp
MINIDBG_OBJS := $(MINIDBG_SRCS:.cpp=.o)

TARGET_SRCS := target.c
TARGET2_SRCS := target2.c

.PHONY: all clean

all: minidbg target target2

minidbg: $(MINIDBG_OBJS)
	$(CXX) $(MINIDBG_OBJS) $(LDFLAGS) -o $@

target: $(TARGET_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

target2: $(TARGET2_SRCS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	$(RM) minidbg target target2 $(MINIDBG_OBJS)
