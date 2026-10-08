CC = gcc
CFLAGS = -Wall -Wextra $(shell pkg-config --cflags libpcsclite)
LDLIBS = $(shell pkg-config --libs libpcsclite)
TARGET = skyld_test
SRC = skyld_test.c gift128.c sha256.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)

# make -f Makefile.mk 
