// The C fixture of the USDT tests — a user binary with USDT points. The host has no sys/sdt.h, so a small macro emits the same
// `.note.stapsdt` as systemtap's sdt.h (x86_64): owner "stapsdt", type 3, desc = pc, _.stapsdt.base, semaphore, provider, name, argument locations
// (the same form as bpf-mlir's own USDT fixture). The compiler picks each point's argument locations through the inline asm "nor" operands,
// and the size / sign is `<±size>@` (negative = signed).
//
// Points: us:hit (int64 a, uint64 b) — (a, b) in us_site1, (a + 1, 3b) in us_site2, constants (7, 9) in main. us:guarded (int16 x, uint64 y) — guarded
// by a semaphore (the unsigned short `us_guarded_semaphore` in section `.probes` — the kernel raises it while a uprobe attached with its ref_ctr_offset exists),
// x = (int16)(−a), y = b ^ 0x5a. For each stdin line "<a> <b>" it passes the 4 points (guarded only while the semaphore is not 0) and writes
//   `site1 <a> <b>`, `site2 <a+1> <3b>`, `const 7 9`, `guarded <semaphore> <x> <y>`, `ok` to stdout (the test oracle). "q" quits.
// Built once with clang -g -O1 -fno-inline-functions and committed (the hash is in SHA256SUMS).
#include <stdint.h>
#include <stdio.h>

#define US_SZ(x) (((__typeof__(x))-1 < (__typeof__(x))1) ? -(int)sizeof(x) : (int)sizeof(x))
#define US_PROBE2_SEM(prov, name, sem, a1, a2)                                          \
	__asm__ __volatile__("990: nop\n"                                                   \
			     ".pushsection .note.stapsdt,\"?\",\"note\"\n"                  \
			     ".balign 4\n"                                                  \
			     ".4byte 992f-991f, 994f-993f, 3\n"                             \
			     "991: .asciz \"stapsdt\"\n"                                    \
			     "992: .balign 4\n"                                             \
			     "993: .8byte 990b\n"                                           \
			     ".8byte _.stapsdt.base\n"                                      \
			     ".8byte " sem "\n"                                             \
			     ".asciz \"" #prov "\"\n"                                       \
			     ".asciz \"" #name "\"\n"                                       \
			     ".asciz \"%c0@%2 %c1@%3\"\n"                                   \
			     "994: .balign 4\n"                                             \
			     ".popsection\n"                                                \
			     ".ifndef _.stapsdt.base\n"                                     \
			     ".pushsection .stapsdt.base,\"aG\",@progbits,.stapsdt.base,comdat\n" \
			     ".weak _.stapsdt.base\n"                                       \
			     ".hidden _.stapsdt.base\n"                                     \
			     "_.stapsdt.base: .space 1\n"                                   \
			     ".size _.stapsdt.base, 1\n"                                    \
			     ".popsection\n"                                                \
			     ".endif\n"                                                     \
			     :                                                              \
			     : "i"(US_SZ(a1)), "i"(US_SZ(a2)), "nor"(a1), "nor"(a2))
#define US_PROBE2(prov, name, a1, a2) US_PROBE2_SEM(prov, name, "0", a1, a2)

// The same form as sdt.h's _SDT_SEMAPHORE (section `.probes` — writable data with file bytes; the kernel raises and lowers the ref_ctr_offset location).
__attribute__((used, section(".probes"))) volatile unsigned short us_guarded_semaphore;

__attribute__((noinline, used)) void us_site1(int64_t a, uint64_t b)
{
	US_PROBE2(us, hit, a, b);
	printf("site1 %lld %llu\n", (long long)a, (unsigned long long)b);
}

__attribute__((noinline, used)) void us_site2(int64_t a, uint64_t b)
{
	int64_t c = a + 1;
	uint64_t d = b * 3;
	US_PROBE2(us, hit, c, d);
	printf("site2 %lld %llu\n", (long long)c, (unsigned long long)d);
}

__attribute__((noinline, used)) void us_guarded(int64_t a, uint64_t b)
{
	int16_t x = (int16_t)(-a);
	uint64_t y = b ^ 0x5a;
	unsigned short sem = us_guarded_semaphore;
	if (sem)
		US_PROBE2_SEM(us, guarded, "us_guarded_semaphore", x, y);
	printf("guarded %u %d %llu\n", (unsigned)sem, (int)x, (unsigned long long)y);
}

int main(void)
{
	char line[128];
	long long a;
	unsigned long long b;
	while (fgets(line, sizeof line, stdin)) {
		if (line[0] == 'q')
			break;
		if (sscanf(line, "%lld %llu", &a, &b) != 2)
			continue;
		us_site1(a, b);
		us_site2(a, b);
		US_PROBE2(us, hit, (int64_t)7, (uint64_t)9);
		printf("const 7 9\n");
		us_guarded(a, b);
		printf("ok\n");
		fflush(stdout);
	}
	return 0;
}
