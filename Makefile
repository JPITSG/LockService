CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall
LDFLAGS = -mwindows -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lshell32 -luser32
OUTDIR  = release
TARGET  = $(OUTDIR)/LockService.exe
SRC     = LockService.c

all: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -s

clean:
	rm -rf $(OUTDIR)

.PHONY: all clean
