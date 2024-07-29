MAKEFLAGS += --no-builtin-rules
CFLAGS := -std=c11 -O2 -fpie -pipe -Wall -Wextra -Wshadow -Wdeclaration-after-statement -Werror

.PHONY: all install test clean

all: resizefat32

install: resizefat32
	install -d $(DESTDIR)/usr/bin
	install -m 755 -t $(DESTDIR)/usr/bin $^

test: all
	./test

clean:
	rm -rf resizefat32 test.img

resizefat32: resizefat32.c
	$(CC) $(CFLAGS) -o $@ $^
