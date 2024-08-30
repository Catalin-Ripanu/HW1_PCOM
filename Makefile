PROJECT=router
SOURCES=skel.c
LIBRARY=nope
INCPATHS=include
LIBPATHS=.
LDFLAGS=-lm -lstdc++ -static-libasan -fsanitize=address
CFLAGS=-c -Wall -g -fsanitize=address
CC=gcc

# Automatic generation of some important lists
OBJECTS=$(SOURCES:.c=.o)
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(PROJECT)

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(OBJECTS) router.o $(LDFLAGS) -o $@

.c.o:
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC router.cpp -o router.o

distclean: clean
	rm -f $(BINARY)

clean:
	rm -f $(OBJECTS) router.o router