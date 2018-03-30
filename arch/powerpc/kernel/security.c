// SPDX-License-Identifier: GPL-2.0+
//
// Security related flags and so on.
//
// Copyright 2018, Michael Ellerman, IBM Corporation.

#include <linux/kernel.h>
#include <asm/security_features.h>


unsigned long powerpc_security_features = SEC_FTR_DEFAULT;
