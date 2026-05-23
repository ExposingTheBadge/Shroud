CFLAGS  = -O2 -Wall $(shell pkg-config --cflags gtk+-3.0 openssl libcurl)
LDFLAGS = $(shell pkg-config --libs gtk+-3.0 openssl libcurl) -lm

ghostlink: main.c
	gcc $(CFLAGS) -o ghostlink main.c $(LDFLAGS)

clean:
	rm -f ghostlink

install: ghostlink
	cp ghostlink /usr/local/bin/ghostlink
	chmod 755 /usr/local/bin/ghostlink
