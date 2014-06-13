/*
 * Copyright (C) 2014 Intel Corporation; author Matt Fleming
 * Copyright (c) 2014 Red Hat, Inc., Mark Salter <msalter@redhat.com>
 */
#include <linux/efi.h>
#include <linux/reboot.h>

int efi_reboot_quirk_mode = -1;

void efi_reboot(enum reboot_mode reboot_mode, const char *__unused)
{
	int efi_mode;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return;

	switch (reboot_mode) {
	case REBOOT_WARM:
	case REBOOT_SOFT:
		efi_mode = EFI_RESET_WARM;
		break;
	default:
		efi_mode = EFI_RESET_COLD;
		break;
	}

	/*
	 * If a quirk forced an EFI reset mode, always use that.
	 */
	if (efi_reboot_quirk_mode != -1)
		efi_mode = efi_reboot_quirk_mode;

	efi.reset_system(efi_mode, EFI_SUCCESS, 0, NULL);
}
