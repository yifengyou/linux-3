/*
 *  Copyright (C) 1994  Linus Torvalds
 *
 *  Cyrix stuff, June 1998 by:
 *	- Rafael R. Reilova (moved everything from head.S),
 *        <rreilova@ececs.uc.edu>
 *	- Channing Corn (tests & fixes),
 *	- Andrew D. Balsa (code cleanup).
 */
#include <linux/init.h>
#include <linux/utsname.h>
#include <linux/cpu.h>
#include <linux/smp.h>

#include <asm/nospec-branch.h>
#include <asm/cmdline.h>
#include <asm/bugs.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <asm/i387.h>
#include <asm/msr.h>
#include <asm/paravirt.h>
#include <asm/alternative.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>

static double __initdata x = 4195835.0;
static double __initdata y = 3145727.0;

/*
 * This used to check for exceptions..
 * However, it turns out that to support that,
 * the XMM trap handlers basically had to
 * be buggy. So let's have a correct XMM trap
 * handler, and forget about printing out
 * some status at boot.
 *
 * We should really only care about bugs here
 * anyway. Not features.
 */
static void __init check_fpu(void)
{
	s32 fdiv_bug;

	kernel_fpu_begin();

	/*
	 * trap_init() enabled FXSR and company _before_ testing for FP
	 * problems here.
	 *
	 * Test for the divl bug: http://en.wikipedia.org/wiki/Fdiv_bug
	 */
	__asm__("fninit\n\t"
		"fldl %1\n\t"
		"fdivl %2\n\t"
		"fmull %2\n\t"
		"fldl %1\n\t"
		"fsubp %%st,%%st(1)\n\t"
		"fistpl %0\n\t"
		"fwait\n\t"
		"fninit"
		: "=m" (*&fdiv_bug)
		: "m" (*&x), "m" (*&y));

	kernel_fpu_end();

	if (fdiv_bug) {
		set_cpu_bug(&boot_cpu_data, X86_BUG_FDIV);
		pr_warn("Hmm, FPU with FDIV bug\n");
	}
}

static void __init spectre_v2_select_mitigation(void);
static void __init ssb_select_mitigation(void);

/*
 * Our boot-time value of the SPEC_CTRL MSR. We read it once so that any
 * writes to SPEC_CTRL contain whatever reserved bits have been set.
 */
static u64 __ro_after_init x86_spec_ctrl_base;

void __init check_bugs(void)
{
	identify_boot_cpu();

	if (!IS_ENABLED(CONFIG_SMP)) {
		pr_info("CPU: ");
		print_cpu_info(&boot_cpu_data);
	}

	/*
	 * Read the SPEC_CTRL MSR to account for reserved bits which may
	 * have unknown values.
	 */
	if (ibrs_inuse)
		rdmsrl(MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base);

	/* Select the proper spectre mitigation before patching alternatives */
	spectre_v2_select_mitigation();

	/*
	 * Select proper mitigation for any exposure to the Speculative Store
	 * Bypass vulnerability.
	 */
	ssb_select_mitigation();

#ifdef CONFIG_X86_32
	/*
	 * Check whether we are able to run this kernel safely on SMP.
	 *
	 * - i386 is no longer supported.
	 * - In order to run on anything without a TSC, we need to be
	 *   compiled for a i486.
	 */
	if (boot_cpu_data.x86 < 4)
		panic("Kernel requires i486+ for 'invlpg' and other features");

	init_utsname()->machine[1] =
		'0' + (boot_cpu_data.x86 > 6 ? 6 : boot_cpu_data.x86);
	alternative_instructions();

	/*
	 * kernel_fpu_begin/end() in check_fpu() relies on the patched
	 * alternative instructions.
	 */
	if (cpu_has_fpu)
		check_fpu();
#else /* CONFIG_X86_64 */
	alternative_instructions();

	/*
	 * Make sure the first 2MB area is not mapped by huge pages
	 * There are typically fixed size MTRRs in there and overlapping
	 * MTRRs into large pages causes slow downs.
	 *
	 * Right now we don't do that with gbpages because there seems
	 * very little benefit for that case.
	 */
	if (!direct_gbpages)
		set_memory_4k((unsigned long)__va(0), 1);
#endif
}

/* The kernel command line selection */
enum spectre_v2_mitigation_cmd {
	SPECTRE_V2_CMD_NONE,
	SPECTRE_V2_CMD_AUTO,
	SPECTRE_V2_CMD_FORCE,
	SPECTRE_V2_CMD_RETPOLINE,
	SPECTRE_V2_CMD_RETPOLINE_GENERIC,
	SPECTRE_V2_CMD_RETPOLINE_AMD,
};

static const char *spectre_v2_strings[] = {
	[SPECTRE_V2_NONE]			= "Vulnerable",
	[SPECTRE_V2_RETPOLINE_MINIMAL]		= "Vulnerable: Minimal generic ASM retpoline",
	[SPECTRE_V2_RETPOLINE_MINIMAL_AMD]	= "Vulnerable: Minimal AMD ASM retpoline",
	[SPECTRE_V2_RETPOLINE_GENERIC]		= "Mitigation: Full generic retpoline",
	[SPECTRE_V2_RETPOLINE_AMD]		= "Mitigation: Full AMD retpoline",
};

#undef pr_fmt
#define pr_fmt(fmt)     "Spectre V2 mitigation: " fmt

static enum spectre_v2_mitigation spectre_v2_enabled = SPECTRE_V2_NONE;

void x86_spec_ctrl_set(u64 val)
{
	if (val & ~(SPEC_CTRL_IBRS | SPEC_CTRL_RDS))
		WARN_ONCE(1, "SPEC_CTRL MSR value 0x%16llx is unknown.\n", val);
	else
		wrmsrl(MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base | val);
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_set);

u64 x86_spec_ctrl_get_default(void)
{
	return x86_spec_ctrl_base;
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_get_default);

void x86_spec_ctrl_set_guest(u64 guest_spec_ctrl)
{
	if (!ibrs_inuse)
		return;
	if (x86_spec_ctrl_base != guest_spec_ctrl)
		wrmsrl(MSR_IA32_SPEC_CTRL, guest_spec_ctrl);
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_set_guest);

void x86_spec_ctrl_restore_host(u64 guest_spec_ctrl)
{
	if (!ibrs_inuse)
		return;
	if (x86_spec_ctrl_base != guest_spec_ctrl)
		wrmsrl(MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base);
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_restore_host);

static void __init spec2_print_if_insecure(const char *reason)
{
	if (boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s\n", reason);
}

static void __init spec2_print_if_secure(const char *reason)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s\n", reason);
}

static inline bool retp_compiler(void)
{
	return __is_defined(RETPOLINE);
}

static inline bool match_option(const char *arg, int arglen, const char *opt)
{
	int len = strlen(opt);

	return len == arglen && !strncmp(arg, opt, len);
}

static enum spectre_v2_mitigation_cmd __init spectre_v2_parse_cmdline(void)
{
	char arg[20];
	int ret;

	ret = cmdline_find_option(boot_command_line, "spectre_v2", arg,
				  sizeof(arg));
	if (ret > 0)  {
		if (match_option(arg, ret, "off")) {
			goto disable;
		} else if (match_option(arg, ret, "on")) {
			spec2_print_if_secure("force enabled on command line.");
			return SPECTRE_V2_CMD_FORCE;
		} else if (match_option(arg, ret, "retpoline")) {
			spec2_print_if_insecure("retpoline selected on command line.");
			return SPECTRE_V2_CMD_RETPOLINE;
		} else if (match_option(arg, ret, "retpoline,amd")) {
			if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD) {
				pr_err("retpoline,amd selected but CPU is not AMD. Switching to AUTO select\n");
				return SPECTRE_V2_CMD_AUTO;
			}
			spec2_print_if_insecure("AMD retpoline selected on command line.");
			return SPECTRE_V2_CMD_RETPOLINE_AMD;
		} else if (match_option(arg, ret, "retpoline,generic")) {
			spec2_print_if_insecure("generic retpoline selected on command line.");
			return SPECTRE_V2_CMD_RETPOLINE_GENERIC;
		} else if (match_option(arg, ret, "auto")) {
			return SPECTRE_V2_CMD_AUTO;
		}
	}

	if (!cmdline_find_option_bool(boot_command_line, "nospectre_v2"))
		return SPECTRE_V2_CMD_AUTO;
disable:
	spec2_print_if_insecure("disabled on command line.");
	return SPECTRE_V2_CMD_NONE;
}

static void __init spectre_v2_select_mitigation(void)
{
	enum spectre_v2_mitigation_cmd cmd = spectre_v2_parse_cmdline();
	enum spectre_v2_mitigation mode = SPECTRE_V2_NONE;

	/*
	 * If the CPU is not affected and the command line mode is NONE or AUTO
	 * then nothing to do.
	 */
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2) &&
	    (cmd == SPECTRE_V2_CMD_NONE || cmd == SPECTRE_V2_CMD_AUTO))
		return;

	switch (cmd) {
	case SPECTRE_V2_CMD_NONE:
		return;

	case SPECTRE_V2_CMD_FORCE:
		/* FALLTRHU */
	case SPECTRE_V2_CMD_AUTO:
		goto retpoline_auto;

	case SPECTRE_V2_CMD_RETPOLINE_AMD:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_amd;
		break;
	case SPECTRE_V2_CMD_RETPOLINE_GENERIC:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_generic;
		break;
	case SPECTRE_V2_CMD_RETPOLINE:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_auto;
		break;
	}
	pr_err("kernel not compiled with retpoline; no mitigation available!");
	return;

retpoline_auto:
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
	retpoline_amd:
		if (!boot_cpu_has(X86_FEATURE_LFENCE_RDTSC)) {
			pr_err("LFENCE not serializing. Switching to generic retpoline\n");
			goto retpoline_generic;
		}
		mode = retp_compiler() ? SPECTRE_V2_RETPOLINE_AMD :
					 SPECTRE_V2_RETPOLINE_MINIMAL_AMD;
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE_AMD);
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE);
	} else {
	retpoline_generic:
		mode = retp_compiler() ? SPECTRE_V2_RETPOLINE_GENERIC :
					 SPECTRE_V2_RETPOLINE_MINIMAL;
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE);
	}

	spectre_v2_enabled = mode;
	pr_info("%s\n", spectre_v2_strings[mode]);

	pr_info("Speculation control IBPB %s IBRS %s",
	        ibpb_supported ? "supported" : "not-supported",
	        ibrs_supported ? "supported" : "not-supported");

	/*
	 * If we have a full retpoline mode and then disable IBPB in kernel mode
	 * we do not require both.
	 */
	if (mode == SPECTRE_V2_RETPOLINE_AMD ||
	    mode == SPECTRE_V2_RETPOLINE_GENERIC)
	{
		if (ibrs_supported) {
			pr_info("Retpoline compiled kernel.  Defaulting IBRS to disabled");
			set_ibrs_disabled();
			if (!ibrs_inuse)
				sysctl_ibrs_enabled = 0;
		}
	}
}

#undef pr_fmt
#define pr_fmt(fmt)	"Speculative Store Bypass: " fmt

static enum ssb_mitigation ssb_mode = SPEC_STORE_BYPASS_NONE;

/* The kernel command line selection */
enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE,
	SPEC_STORE_BYPASS_CMD_AUTO,
	SPEC_STORE_BYPASS_CMD_ON,
};

static const char *ssb_strings[] = {
	[SPEC_STORE_BYPASS_NONE]	= "Vulnerable",
	[SPEC_STORE_BYPASS_DISABLE]	= "Mitigation: Speculative Store Bypass disabled"
};

static const struct {
	const char *option;
	enum ssb_mitigation_cmd cmd;
} ssb_mitigation_options[] = {
	{ "auto",	SPEC_STORE_BYPASS_CMD_AUTO }, /* Platform decides */
	{ "on",		SPEC_STORE_BYPASS_CMD_ON },   /* Disable Speculative Store Bypass */
	{ "off",	SPEC_STORE_BYPASS_CMD_NONE }, /* Don't touch Speculative Store Bypass */
};

static enum ssb_mitigation_cmd __init ssb_parse_cmdline(void)
{
	enum ssb_mitigation_cmd cmd = SPEC_STORE_BYPASS_CMD_AUTO;
	char arg[20];
	int ret, i;

	if (cmdline_find_option_bool(boot_command_line, "nospec_store_bypass_disable")) {
		return SPEC_STORE_BYPASS_CMD_NONE;
	} else {
		ret = cmdline_find_option(boot_command_line, "spec_store_bypass_disable",
					  arg, sizeof(arg));
		if (ret < 0)
			return SPEC_STORE_BYPASS_CMD_AUTO;

		for (i = 0; i < ARRAY_SIZE(ssb_mitigation_options); i++) {
			if (!match_option(arg, ret, ssb_mitigation_options[i].option))
				continue;

			cmd = ssb_mitigation_options[i].cmd;
			break;
		}

		if (i >= ARRAY_SIZE(ssb_mitigation_options)) {
			pr_err("unknown option (%s). Switching to AUTO select\n", arg);
			return SPEC_STORE_BYPASS_CMD_AUTO;
		}
	}

	return cmd;
}

static enum ssb_mitigation_cmd __init __ssb_select_mitigation(void)
{
	enum ssb_mitigation mode = SPEC_STORE_BYPASS_NONE;
	enum ssb_mitigation_cmd cmd;

	if (!boot_cpu_has(X86_FEATURE_RDS))
		return mode;

	cmd = ssb_parse_cmdline();
	if (!boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS) &&
	    (cmd == SPEC_STORE_BYPASS_CMD_NONE ||
	     cmd == SPEC_STORE_BYPASS_CMD_AUTO))
		return mode;

	switch (cmd) {
	case SPEC_STORE_BYPASS_CMD_AUTO:
	case SPEC_STORE_BYPASS_CMD_ON:
		mode = SPEC_STORE_BYPASS_DISABLE;
		break;
	case SPEC_STORE_BYPASS_CMD_NONE:
		break;
	}

	/*
	 * We have three CPU feature flags that are in play here:
	 *  - X86_BUG_SPEC_STORE_BYPASS - CPU is susceptible.
	 *  - X86_FEATURE_RDS - CPU is able to turn off speculative store bypass
	 *  - X86_FEATURE_SPEC_STORE_BYPASS_DISABLE - engage the mitigation
	 */
	if (mode != SPEC_STORE_BYPASS_NONE) {
		setup_force_cpu_cap(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE);
		/*
		 * Intel uses the SPEC CTRL MSR Bit(2) for this, while AMD uses
		 * a completely different MSR and bit dependent on family.
		 */
		switch (boot_cpu_data.x86_vendor) {
		case X86_VENDOR_INTEL:
			x86_spec_ctrl_base |= SPEC_CTRL_RDS;
			x86_spec_ctrl_set(SPEC_CTRL_RDS);
			break;
		case X86_VENDOR_AMD:
			break;
		}
	}

	return mode;
}

static void ssb_select_mitigation()
{
	ssb_mode = __ssb_select_mitigation();

	if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
		pr_info("%s\n", ssb_strings[ssb_mode]);
}

#undef pr_fmt

void x86_spec_ctrl_setup_ap(void)
{
	if (ibrs_inuse)
		x86_spec_ctrl_set(x86_spec_ctrl_base & (SPEC_CTRL_IBRS | SPEC_CTRL_RDS));
}

#ifdef CONFIG_SYSFS
#ifndef osb
#define osb_is_enabled	(0)
#endif
#ifndef osb_is_enabled
#define osb_is_enabled	(1)
#endif
ssize_t cpu_show_common(struct device *dev, struct device_attribute *attr,
			char *buf, unsigned int bug)
{
	if (!boot_cpu_has_bug(bug))
		return sprintf(buf, "Not affected\n");

	switch (bug) {
	case X86_BUG_CPU_MELTDOWN:
		if (boot_cpu_has(X86_FEATURE_KAISER))
			return sprintf(buf, "Mitigation: PTI\n");
		break;

	case X86_BUG_SPECTRE_V1:
		if (osb_is_enabled)
			return sprintf(buf, "Mitigation: OSB (observable speculation barrier, Intel v6)\n");

	case X86_BUG_SPECTRE_V2:
		return sprintf(buf, "%s%s\n", spectre_v2_strings[spectre_v2_enabled], ibpb_inuse ? ", IBPB (Intel v4)" : "");

	case X86_BUG_SPEC_STORE_BYPASS:
		return sprintf(buf, "%s\n", ssb_strings[ssb_mode]);

	default:
		break;
	}

	return sprintf(buf, "Vulnerable\n");
}

ssize_t cpu_show_meltdown(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_CPU_MELTDOWN);
}

ssize_t cpu_show_spectre_v1(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V1);
}

ssize_t cpu_show_spectre_v2(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V2);
}

ssize_t cpu_show_spec_store_bypass(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPEC_STORE_BYPASS);
}
#endif
