CC      = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres
CFLAGS  = -O2 -Wall
LDFLAGS = -mwindows -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -lshell32 -luser32 -lole32
OUTDIR  = release
TARGET  = $(OUTDIR)/LockService.exe
SRC     = LockService.c
RES     = LockService.res.o

all: $(TARGET)

# Build frontend assets
assets/dist/index.html:
	cd assets && npm install && npm run build

$(RES): LockService.rc LockService.manifest assets/dist/index.html
	$(WINDRES) LockService.rc -o $(RES)

$(TARGET): $(SRC) $(RES)
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $< $(RES) $(LDFLAGS) -s

clean:
	rm -rf $(OUTDIR) $(RES) assets/dist assets/node_modules

.PHONY: all clean
