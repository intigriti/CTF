CC := gcc
CFLAGS := -no-pie -fstack-protector-all

chal: chal.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f chal