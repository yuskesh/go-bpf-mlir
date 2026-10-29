// The C fixture of the uprobe user-buffer tests — a user binary to probe. For each line of stdin it calls a function and prints
// "ok <ctx> <buf>" (the two pointer arguments as hex):
//   "w <len>" — buf_write(&ctx, buffer, len) with a 9000-byte buffer whose byte i is (i * 7 + 3) % 251 (written at startup, so its pages are resident),
//   "f <len>" — buf_write(&ctx, (const void *)8, len) (an unmapped address), "v" — buf_argv(argv, 1) (a char ** argument), "q" — quit.
// The functions are not inlined (a uprobe attaches at the file offset of the function entry).
// Built once with clang -g -O1 -fno-inline-functions and committed (the hash is in SHA256SUMS).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 9000

struct buf_ctx {
	uint64_t calls;
};

__attribute__((noinline, used)) int buf_write(void *ctx, const void *buf, int len)
{
	__asm__ volatile("" ::"r"(ctx), "r"(buf), "r"(len) : "memory");
	return len;
}

__attribute__((noinline, used)) int buf_argv(char **v, int n)
{
	__asm__ volatile("" ::"r"(v), "r"(n) : "memory");
	return n;
}

static unsigned char buffer[BUF_SIZE];
static struct buf_ctx ctx;

int main(int argc, char **argv)
{
	char line[128];
	for (int i = 0; i < BUF_SIZE; i++)
		buffer[i] = (unsigned char)((i * 7 + 3) % 251);
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		if (line[0] == 'q')
			return 0;
		if ((line[0] == 'w' || line[0] == 'f') && line[1] == ' ') {
			int len = (int)strtol(line + 2, NULL, 10);
			const void *p = line[0] == 'w' ? (const void *)buffer : (const void *)8;
			ctx.calls++;
			buf_write(&ctx, p, len);
			printf("ok %lx %lx\n", (unsigned long)(uintptr_t)&ctx, (unsigned long)(uintptr_t)p);
		} else if (line[0] == 'v') {
			printf("ok %d\n", buf_argv(argv, argc));
		} else {
			continue;
		}
		fflush(stdout);
	}
	return 0;
}
