CFLAGS  = -O2 -Wall $(shell pkg-config --cflags gtk+-3.0 openssl libcurl)
LDFLAGS = $(shell pkg-config --libs gtk+-3.0 openssl libcurl) -lm

shroud: main.c
	gcc $(CFLAGS) -o shroud main.c $(LDFLAGS)

clean:
	rm -f shroud

install: shroud
	cp shroud /usr/local/bin/shroud
	chmod 755 /usr/local/bin/shroud
