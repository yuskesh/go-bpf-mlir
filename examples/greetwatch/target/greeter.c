// greeter is the uprobe target of examples/greetwatch — a C program that calls greet(line, number) for each line of stdin and prints "hello, <line>".
// greet is not inlined (the uprobe attaches at the function entry). The binary is built once and committed, so its hash is fixed.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline, used)) uint32_t greet(const char *name, uint32_t n)
{
	__asm__ volatile("" ::"r"(name) : "memory");
	printf("hello, %s\n", name);
	fflush(stdout);
	return n;
}

int main(void)
{
	char line[256];
	uint32_t n = 0;
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		if (strcmp(line, "q") == 0)
			return 0;
		greet(line, ++n);
	}
	return 0;
}
