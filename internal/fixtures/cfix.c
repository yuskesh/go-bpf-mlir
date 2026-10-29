// The C fixture of the uprobe tests — a user binary to probe. For each line of stdin it calls a function and prints "ok <value>":
//   "sum <a> <b> <c>" — sum_args(a (int64), b (uint32), c (int32)), "s <string>" — greet(string), "e" — greet(""), "n" — greet(NULL),
//   "q" — quit. The functions are not inlined (a uprobe attaches at the file offset of the function entry).
// Built once with clang -g -O1 -fno-inline-functions and committed (the hash is in SHA256SUMS).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline, used)) int64_t sum_args(int64_t a, uint32_t b, int32_t c)
{
	__asm__ volatile("" ::"r"(a), "r"(b), "r"(c) : "memory");
	return a + (int64_t)b + (int64_t)c;
}

static uint32_t tag;

__attribute__((noinline, used)) uint32_t greet(const char *s, uint32_t t)
{
	__asm__ volatile("" ::"r"(s) : "memory");
	return t;
}

int main(void)
{
	char line[512];
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		if (line[0] == 'q')
			return 0;
		if (strncmp(line, "sum ", 4) == 0) {
			long long a;
			unsigned long b;
			long c;
			if (sscanf(line + 4, "%lld %lu %ld", &a, &b, &c) != 3)
				continue;
			printf("ok %lld\n", (long long)sum_args(a, (uint32_t)b, (int32_t)c));
		} else if (line[0] == 's' && line[1] == ' ') {
			printf("ok %u\n", greet(line + 2, ++tag));
		} else if (line[0] == 'e') {
			printf("ok %u\n", greet("", ++tag));
		} else if (line[0] == 'n') {
			printf("ok %u\n", greet(NULL, ++tag));
		} else {
			continue;
		}
		fflush(stdout);
	}
	return 0;
}
