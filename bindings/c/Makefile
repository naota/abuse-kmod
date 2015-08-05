CC := gcc
CFLAGS := -Wall -O2 -std=gnu11 -pipe
LDFLAGS := -Wl,--as-needed

ABUSE_LIB := libabuse.a
LIBOBJS := libabuse.o

all: abmem
abmem: abmem.o $(ABUSE_LIB)
$(ABUSE_LIB): $(LIBOBJS)
	ar rcu $(ABUSE_LIB) $(LIBOBJS)
