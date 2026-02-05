// hypercall100.c - userland helper for kvmctf hypercall 100
//
// This is intended to run INSIDE the L1 guest (Debian).
// It issues a raw vmcall with rax=100 and prints the return value.
// Adjust calling convention if the CTF docs use a different ABI.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>

static inline uint64_t do_hypercall_100(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
	uint64_t ret;
	register uint64_t rax asm("rax") = 100;   // hypercall number
	register uint64_t rbx asm("rbx") = arg1;
	register uint64_t rcx asm("rcx") = arg2;
	register uint64_t rdx asm("rdx") = arg3;

	asm volatile(
		"vmcall"
		: "=a"(ret)
		: "a"(rax), "b"(rbx), "c"(rcx), "d"(rdx)
		: "memory"
	);

	return ret;
}

int main(void)
{
	uint64_t ret;

	printf("kvmctf hypercall 100 tester\n");

	// For primitive B, you only call this AFTER your kernel module has
	// successfully done the arbitrary write to write_flag_va.
	// For primitive C, you might use return value as the 64-bit flag.
	ret = do_hypercall_100(0, 0, 0);

	printf("hypercall 100 returned: 0x%016lx (%lu)\n",
	       (unsigned long)ret, (unsigned long)ret);

	return 0;
}
