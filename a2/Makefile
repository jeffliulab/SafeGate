src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
CFLAGS = -Dfread=BANNED_fread \
         -Dfwrite=BANNED_fwrite \
         -Dfscanf=BANNED_fscanf \
         -Dfprintf=BANNED_fprintf \
         -Dfopen=BANNED_fopen \
         -Dfclose=BANNED_fclose \
         -Dsscanf=BANNED_sscanf \
         -Dsnprintf=BANNED_snprintf \
         -Dscanf=BANNED_scanf \
         -Dgets=BANNED_gets \
         -Dputs=BANNED_puts \
         -Dputchar=BANNED_putchar \
         -Dgetchar=BANNED_getchar \
         -Dfgetc=BANNED_fgetc \
         -Dfputc=BANNED_fputc \
         -Dfgets=BANNED_fgets \
         -Dfputs=BANNED_fputs
LDFLAGS = -lnsl

a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
