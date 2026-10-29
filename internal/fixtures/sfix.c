// The C fixture of the split-DWARF uprobe tests — a user binary whose DWARF lives in a separate debug file. For each line of stdin it calls
// a function and prints "ok <value>":
//   "sum <a> <b> <c>" — split_sum(a (long), b (unsigned), c (int)), "q" — quit. The function is not inlined (a uprobe attaches at the file
//   offset of the function entry).
// Built by scripts/build-uprobe-fixtures.sh: linked with -g, then the DWARF is moved to sfix.debug (--only-keep-debug) and sfix keeps its symbol
// table with no .debug_* sections and a .gnu_debuglink to sfix.debug. sfix-badcrc.debug has the same build ID and a different CRC32, and
// sfix-otherid.debug is the debug file of a different build (a different build ID).
#include <stdio.h>
#include <string.h>

__attribute__((noinline, used)) long split_sum(long a, unsigned b, int c)
{
	__asm__ volatile("" ::"r"(a), "r"(b), "r"(c) : "memory");
	return a + (long)b + (long)c;
}

int main(void)
{
	char line[512];
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		if (line[0] == 'q')
			return 0;
		if (strncmp(line, "sum ", 4) == 0) {
			long a;
			unsigned long b;
			long c;
			if (sscanf(line + 4, "%ld %lu %ld", &a, &b, &c) != 3)
				continue;
			printf("ok %ld\n", split_sum(a, (unsigned)b, (int)c));
		} else {
			continue;
		}
		fflush(stdout);
	}
	return 0;
}
