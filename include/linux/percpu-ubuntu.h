#ifndef _LINUX_PERCPU_UBUNTU_H
#define _LINUX_PERCPU_UBUNTU_H

#include <asm/percpu.h>

/*
 * Branching function to split up a function into a set of functions that
 * are called for different scalar sizes of the objects handled.
 */

extern void __bad_size_call_parameter(void);

#define __pcpu_size_call_return(stem, variable)				\
({	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable);break;			\
	case 2: pscr_ret__ = stem##2(variable);break;			\
	case 4: pscr_ret__ = stem##4(variable);break;			\
	case 8: pscr_ret__ = stem##8(variable);break;			\
	default:							\
		__bad_size_call_parameter();break;			\
	}								\
	pscr_ret__;							\
})

/*
 * Special handling for cmpxchg_double.  cmpxchg_double is passed two
 * percpu variables.  The first has to be aligned to a double word
 * boundary and the second has to follow directly thereafter.
 * We enforce this on all architectures even if they don't support
 * a double cmpxchg instruction, since it's a cheap requirement, and it
 * avoids breaking the requirement for architectures with the instruction.
 */

#define __pcpu_size_call(stem, variable, ...)				\
do {									\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
		case 1: stem##1(variable, __VA_ARGS__);break;		\
		case 2: stem##2(variable, __VA_ARGS__);break;		\
		case 4: stem##4(variable, __VA_ARGS__);break;		\
		case 8: stem##8(variable, __VA_ARGS__);break;		\
		default: 						\
			__bad_size_call_parameter();break;		\
	}								\
} while (0)

/*
 * Generic percpu operations for context that are safe from preemption/interrupts.
 * Either we do not care about races or the caller has the
 * responsibility of handling preemption/interrupt issues. Arch code can still
 * override these instructions since the arch per cpu code may be more
 * efficient and may actually get race freeness for free (that is the
 * case for x86 for example).
 *
 * If there is no other protection through preempt disable and/or
 * disabling interupts then one of these RMW operations can show unexpected
 * behavior because the execution thread was rescheduled on another processor
 * or an interrupt occurred and the same percpu variable was modified from
 * the interrupt context.
 */

#ifndef __this_cpu_read
# ifndef __this_cpu_read_1
#  define __this_cpu_read_1(pcp)	(*__this_cpu_ptr(&(pcp)))
# endif
# ifndef __this_cpu_read_2
#  define __this_cpu_read_2(pcp)	(*__this_cpu_ptr(&(pcp)))
# endif
# ifndef __this_cpu_read_4
#  define __this_cpu_read_4(pcp)	(*__this_cpu_ptr(&(pcp)))
# endif
# ifndef __this_cpu_read_8
#  define __this_cpu_read_8(pcp)	(*__this_cpu_ptr(&(pcp)))
# endif
# define __this_cpu_read(pcp)	__pcpu_size_call_return(__this_cpu_read_, (pcp))
#endif

#define __this_cpu_generic_to_op(pcp, val, op)				\
do {									\
	*__this_cpu_ptr(&(pcp)) op val;					\
} while (0)

#ifndef __this_cpu_write
# ifndef __this_cpu_write_1
#  define __this_cpu_write_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
# endif
# ifndef __this_cpu_write_2
#  define __this_cpu_write_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
# endif
# ifndef __this_cpu_write_4
#  define __this_cpu_write_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
# endif
# ifndef __this_cpu_write_8
#  define __this_cpu_write_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
# endif
# define __this_cpu_write(pcp, val)	__pcpu_size_call(__this_cpu_write_, (pcp), (val))
#endif

#endif /* _LINUX_PERCPU_UBUNTU_H */
