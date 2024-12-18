CC := gcc
CFLAGS := -fstack-protector-all -Wl,-z,relro,-z,now -w

chal: chal.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f chal