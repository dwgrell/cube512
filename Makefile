CC = gcc
CFLAGS = -O3 -march=native -flto -pthread
LIBS = -lssl -lcrypto -larchive -llz4

TARGET = cube512
SOURCES = src/cube512_core.c src/cube512_tool.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
