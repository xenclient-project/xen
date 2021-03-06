/*
 * xen/arch/arm/arm64/debug.S
 *
 * Wrapper for early printk
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2013 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/config.h>

#ifdef EARLY_PRINTK_INC
#include EARLY_PRINTK_INC
#endif

.globl early_putch
/* Print a character on the UART - this function is called by C
 * x0: character to print */
early_putch:
        ldr   x15, =FIXMAP_ADDR(FIXMAP_CONSOLE)
        early_uart_ready x15, 1
        early_uart_transmit x15, w0
        ret

.globl early_flush
/* Flush the UART - this function is called by C */
early_flush:
        ldr   x15, =FIXMAP_ADDR(FIXMAP_CONSOLE)  /* x15 := VA UART base address */
        early_uart_ready x15, 1
        ret

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
