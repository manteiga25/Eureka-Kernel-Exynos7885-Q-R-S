/*
 * arch/arm64/include/asm/arch_timer.h
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_ARCH_TIMER_H
#define __ASM_ARCH_TIMER_H

#include <asm/barrier.h>

#include <linux/bug.h>
#include <linux/init.h>
#include <linux/types.h>

#include <clocksource/arm_arch_timer.h>

#if IS_ENABLED(CONFIG_ARM_ARCH_TIMER_OOL_WORKAROUND)
extern struct static_key_false arch_timer_read_ool_enabled;
#define needs_unstable_timer_counter_workaround() \
	static_branch_unlikely(&arch_timer_read_ool_enabled)
#else
#define needs_unstable_timer_counter_workaround()  false
#endif

enum arch_timer_erratum_match_type {
	ate_match_dt,
	ate_match_local_cap_id,
};

struct clock_event_device;

struct arch_timer_erratum_workaround {
	enum arch_timer_erratum_match_type match_type;
	const void *id;
	const char *desc;
	u32 (*read_cntp_tval_el0)(void);
	u32 (*read_cntv_tval_el0)(void);
	u64 (*read_cntvct_el0)(void);
	int (*set_next_event_phys)(unsigned long, struct clock_event_device *);
	int (*set_next_event_virt)(unsigned long, struct clock_event_device *);
};

extern const struct arch_timer_erratum_workaround *timer_unstable_counter_workaround;

/*
 * These register accessors are marked inline so the compiler can
 * nicely work out which register we want, and chuck away the rest of
 * the code.
 */
static __always_inline
void arch_timer_reg_write_cp15(int access, enum arch_timer_reg reg, u32 val)
{
	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("msr cntp_ctl_el0,  %0" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("msr cntp_tval_el0, %0" : : "r" (val));
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("msr cntv_ctl_el0,  %0" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("msr cntv_tval_el0, %0" : : "r" (val));
			break;
		}
	}

	isb();
}

static __always_inline
u32 arch_timer_reg_read_cp15(int access, enum arch_timer_reg reg)
{
	u32 val;

	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrs %0,  cntp_ctl_el0" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mrs %0, cntp_tval_el0" : "=r" (val));
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrs %0,  cntv_ctl_el0" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mrs %0, cntv_tval_el0" : "=r" (val));
			break;
		}
	}

	return val;
}

static inline u32 arch_timer_get_cntfrq(void)
{
	u32 val;
	asm volatile("mrs %0,   cntfrq_el0" : "=r" (val));
	return val;
}

static inline u32 arch_timer_get_cntkctl(void)
{
	u32 cntkctl;
	asm volatile("mrs	%0, cntkctl_el1" : "=r" (cntkctl));
	return cntkctl;
}

static inline void arch_timer_set_cntkctl(u32 cntkctl)
{
	asm volatile("msr	cntkctl_el1, %0" : : "r" (cntkctl));
}

static inline u64 arch_counter_get_cntpct(void)
{
	/*
	 * AArch64 kernel and user space mandate the use of CNTVCT.
	 */
	BUG();
	return 0;
}

static inline u64 arch_counter_get_cntvct(void)
{
	/* ARM64_ERRATUM_858921 */
	u64 cval1;
	u64 cval2;

	isb();
	asm volatile("mrs %0, cntvct_el0" : "=r" (cval1));
	isb();
	asm volatile("mrs %0, cntvct_el0" : "=r" (cval2));

	/*
	 * if bit[32] is different, keep the first value
	 * if bit[32] is the same, keep the second value.
	 */
	if ((cval1 & BIT(32)) != (cval2 & BIT(32)))
		return cval1;
	else
		return cval2;
}

static inline int arch_timer_arch_init(void)
{
	return 0;
}

#endif
