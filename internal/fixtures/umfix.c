// The C fixture of the uprobe_multi tests — a user binary to probe. For each line of stdin it calls a function and prints "ok <result>":
//   "a <x> <k>" — um_add(x, k), "m <x> <k>" — um_mul(x, k), "s <x> <k>" — um_sub(x, k) (the three share one signature — the attached list),
//   "w <x> <k>" — um_wide((int32_t)x, k) (its first argument has another type — the control kept out of the list and the negative case), "q" — quit. No inlining.
// Built once with clang -g -O1 -fno-inline-functions and committed (the hash is in SHA256SUMS).
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline, used)) int64_t um_add(int64_t x, uint32_t k)
{
	__asm__ volatile("" ::"r"(x), "r"(k) : "memory");
	return x + (int64_t)k;
}

__attribute__((noinline, used)) int64_t um_mul(int64_t x, uint32_t k)
{
	__asm__ volatile("" ::"r"(x), "r"(k) : "memory");
	return x * (int64_t)k;
}

__attribute__((noinline, used)) int64_t um_sub(int64_t x, uint32_t k)
{
	__asm__ volatile("" ::"r"(x), "r"(k) : "memory");
	return x - (int64_t)k;
}

__attribute__((noinline, used)) int64_t um_wide(int32_t x, uint32_t k)
{
	__asm__ volatile("" ::"r"(x), "r"(k) : "memory");
	return (int64_t)x + (int64_t)k;
}

int main(void)
{
	char line[256];
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		if (line[0] == 'q')
			return 0;
		long long x;
		unsigned long k;
		if (line[1] != ' ' || sscanf(line + 2, "%lld %lu", &x, &k) != 2)
			continue;
		int64_t r;
		switch (line[0]) {
		case 'a':
			r = um_add(x, (uint32_t)k);
			break;
		case 'm':
			r = um_mul(x, (uint32_t)k);
			break;
		case 's':
			r = um_sub(x, (uint32_t)k);
			break;
		case 'w':
			r = um_wide((int32_t)x, (uint32_t)k);
			break;
		default:
			continue;
		}
		printf("ok %lld\n", (long long)r);
		fflush(stdout);
	}
	return 0;
}
