# CS112 Final Project Part1 - HTTPS Proxy Makefile
# Based on a2 Makefile with modifications for proxy

src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc

CFLAGS = -Dfread=BANNED_fread \
         -Dfwrite=BANNED_fwrite \
         -Dfscanf=BANNED_fscanf \
         -Dscanf=BANNED_scanf \
         -Dgets=BANNED_gets \
         -Dputs=BANNED_puts \
         -Dputchar=BANNED_putchar \
         -Dgetchar=BANNED_getchar \
         -Dfgetc=BANNED_fgetc \
         -Dfputc=BANNED_fputc \
         -Dfgets=BANNED_fgets \
         -Dfputs=BANNED_fputs

# OpenSSL related and pthread for multi-threading
LDFLAGS = -lssl -lcrypto -lpthread -lnsl

proxy: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) proxy

