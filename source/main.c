/*
 *  minute - a port of the "mini" IOS replacement for the Wii U.
 *
 *  Copyright (C) 2016          SALT
 *  Copyright (C) 2016          Daz Jones <daz@dazzozo.com>
 *
 *  Copyright (C) 2008, 2009    Haxx Enterprises <bushing@gmail.com>
 *  Copyright (C) 2008, 2009    Sven Peter <svenpeter@gmail.com>
 *  Copyright (C) 2008, 2009    Hector Martin "marcan" <marcan@marcansoft.com>
 *  Copyright (C) 2009          Andre Heider "dhewg" <dhewg@wiibrew.org>
 *  Copyright (C) 2009          John Kelley <wiidev@kelley.ca>
 *
 *  This code is licensed to you under the terms of the GNU GPL, version 2;
 *  see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 */

#include "main.h"

#include "types.h"
#include "utils.h"
#include "latte.h"
#include "sdcard.h"
#include "string.h"
#include "memory.h"
#include "gfx.h"
#include "elm.h"
#include "irq.h"
#include "smc.h"
#include "exception.h"
#include "sdhc.h"
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>

static struct {
    int mode;
    u32 vector;
} boot = {0};

int main_autoboot(void);
void powerpc_dump();

u32 _main(void *base) {
    (void)base;
    int res = 0; (void)res;

    gfx_clear(GFX_ALL, BLACK);

    printf("Initializing exceptions...\n");
    exception_initialize();
    printf("Configuring caches and MMU...\n");
    mem_initialize();

    irq_initialize();
    printf("Interrupts initialized\n");

    printf("Initializing SD card...\n");
    sdcard_init();

    printf("Mounting SD card...\n");
    res = ELM_Mount();
    if(res) {
        printf("Error while mounting SD card (%d).\n", res);
        panic(0);
    }
    
    powerpc_dump(NULL);
    
    printf("Press POWER or EJECT to shutdown the console...\n");
    smc_wait_events(SMC_POWER_BUTTON | SMC_EJECT_BUTTON);	
	    
    smc_power_off();
    
    return boot.vector;
}

// https://github.com/ajd4096/gbadev/blob/romdumper/armboot/powerpc_elf.c#L257
void ppc_write_dumper_stub(u32 location)
{
    size_t i = 0;

    write32(location + i, /*0x4000*/ 0x7c79faa6 /* mfl2cr r3*/); i += sizeof(u32);
    write32(location + i, /*0x4004*/ 0x3c807fff /* lis r4, 0x7FFF*/); i += sizeof(u32);
    write32(location + i, /*0x4008*/ 0x6084ffff /* ori r4, r4, 0xFFFF*/); i += sizeof(u32);
    write32(location + i, /*0x400c*/ 0x7c632038 /* and r3, r3, r4*/); i += sizeof(u32);
    write32(location + i, /*0x4010*/ 0x7c79fba6 /* mtl2cr r3*/); i += sizeof(u32);
    write32(location + i, /*0x4014*/ 0x7c0004ac /* sync*/); i += sizeof(u32);
    write32(location + i, /*0x4018*/ 0x7c70faa6 /* mfdbsr r3*/); i += sizeof(u32);
    write32(location + i, /*0x401c*/ 0x3c80ffff /* lis r4, 0xFFFF*/); i += sizeof(u32);
    write32(location + i, /*0x4020*/ 0x60843fff /* ori r4, r4, 0x3FFF*/); i += sizeof(u32);
    write32(location + i, /*0x4024*/ 0x7c632038 /* and r3, r3, r4*/); i += sizeof(u32);
    write32(location + i, /*0x4028*/ 0x7c70fba6 /* mtdbsr r3*/); i += sizeof(u32);
    write32(location + i, /*0x402c*/ 0x7c0004ac /* sync*/); i += sizeof(u32);
    write32(location + i, /*0x4030*/ 0x3c600132 /* lis r3, 0x0132*/); i += sizeof(u32);
    write32(location + i, /*0x4034*/ 0x3c800c32 /* lis r4, 0x0c32*/); i += sizeof(u32);
    write32(location + i, /*0x4038*/ 0x3ca00000 /* lis r5, 0*/); i += sizeof(u32);
    write32(location + i, /*0x403c*/ 0x3cc00000 /* lis r6, 0*/); i += sizeof(u32);
    
    write32(location + i, /*0x4040*/ 0x2c060040 /* cmpwi r6, 0x40*/); i += sizeof(u32);
    write32(location + i, /*0x4044*/ 0x4080001c /* bge- 0x4060*/); i += sizeof(u32);
    write32(location + i, /*0x4048*/ 0x80a40000 /* lwz r5, 0(r4)*/); i += sizeof(u32);
    write32(location + i, /*0x404c*/ 0x90a30000 /* stw r5, 0(r3)*/); i += sizeof(u32);
    write32(location + i, /*0x4050*/ 0x38630004 /* addi r3, r3, 4*/); i += sizeof(u32);
    write32(location + i, /*0x4054*/ 0x38840004 /* addi r4, r4, 4*/); i += sizeof(u32);
    write32(location + i, /*0x4058*/ 0x38c60004 /* addi r6, r6, 4*/); i += sizeof(u32);
    write32(location + i, /*0x405c*/ 0x4bffffe4 /* b 0x4040*/); i += sizeof(u32);
    
    write32(location + i, /*0x4060*/ 0x3c600133 /* lis r3, 0x0133*/); i += sizeof(u32);
    write32(location + i, /*0x4064*/ 0x3c800000 /* lis r4, 0*/); i += sizeof(u32);
    write32(location + i, /*0x4068*/ 0x3ca00000 /* lis r5, 0*/); i += sizeof(u32);
    write32(location + i, /*0x406c*/ 0x3cc00000 /* lis r6, 0*/); i += sizeof(u32);
    
    write32(location + i, /*0x4070*/ 0x2c064000 /* cmpwi r6, 0x4000*/); i += sizeof(u32);
    write32(location + i, /*0x4074*/ 0x4080001c /* bge- 0x4060*/); i += sizeof(u32);
    write32(location + i, /*0x4075*/ 0x80a40000 /* lwz r5, 0(r4)*/); i += sizeof(u32);
    write32(location + i, /*0x407c*/ 0x90a30000 /* stw r5, 0(r3)*/); i += sizeof(u32);
    write32(location + i, /*0x4080*/ 0x38630004 /* addi r3, r3, 4*/); i += sizeof(u32);
    write32(location + i, /*0x4084*/ 0x38840004 /* addi r4, r4, 4*/); i += sizeof(u32);
    write32(location + i, /*0x4088*/ 0x38c60004 /* addi r6, r6, 4*/); i += sizeof(u32);
    write32(location + i, /*0x408c*/ 0x4bffffe4 /* b 0x4070*/); i += sizeof(u32);
    write32(location + i, /*0x4090*/ 0x48000000  /* b 0x4090*/); i += sizeof(u32);
    dc_flushrange((void*)location, i);
}

const u32 dumper_stub_location = 0x4000;

void ppc_hang(void)
{
    clear32(LT_RESETS_COMPAT, 0x230);
    udelay(100);
}

// Copy pasted from https://github.com/ajd4096/gbadev/blob/romdumper/armboot/powerpc_elf.c#L309
#define WAIT_TIME	2362
void powerpc_dump(const char *path)
{	
    gfx_clear(GFX_ALL, BLACK);
    printf("Hello from powerpc_dump.\r\n");
    
    // I don't think we need that...
    // ppc_prepare();
    // printf("Prepared PPC.\r\n");
    FIL fd;
	u32 boot0 = read32(LT_BOOT0), bw;
		
	// boot0 dump
	write32(LT_BOOT0, boot0&~0x1000);
	f_open(&fd, "sdmc:/boot0.bin", FA_CREATE_ALWAYS|FA_WRITE);
	f_write(&fd, (void*)0xFFF00000, 0x4000, (UINT*) &bw);
	f_close(&fd);
	write32(LT_BOOT0, boot0);	
	printf("Boot0 dump done. \r\n");	
    printf("Now for the bootROM and OTP.\r\n");
	set32(LT_DIFLAGS,DIFLAGS_BOOT_CODE);
	set32(LT_AHBPROT, 0xFFFFFFFF);
	printf("Resetting PPC. \r\n\r\n");    
    int wait_time=WAIT_TIME;    
    while(1){
        ppc_hang();
        
        clear32(LT_RESETS_COMPAT, 0x30);

        // Write code to the reset vector
        write32(0x100, 0x48003f00); // b 0x4000

        //write_stub(dumper_stub_location, dumper_stub, dumper_stub_size);
        ppc_write_dumper_stub(dumper_stub_location);

        dc_flushrange((void*)0x100,32);
        dc_flushrange((void*)0x4000,128);
        
        //reboot ppc side
        clear32(LT_RESETS_COMPAT, 0x30); // HRST+SRST
        udelay(100);
        set32(LT_RESETS_COMPAT, 0x20); // remove SRST
        udelay(100);
        set32(LT_RESETS_COMPAT, 0x10); // remove HRST

        udelay(wait_time++);

        // SRESET
        clear32(LT_RESETS_COMPAT, 0x20);
        udelay(100);
        set32(LT_RESETS_COMPAT, 0x20);
        udelay(2000); // give PPC a moment to dump to RAM
        
        dc_invalidaterange((void*)0x1320000, 0x40);
       
        if(read32(0x1320000) != 0 || wait_time > 3000){
            break;
        }
    }
    
    if(read32(0x1320000) == 0x0){
        printf("Dumping failed.\r\n");
        return;
    }
 
	if (f_open(&fd, "sdmc:/otp_ppc.bin", FA_WRITE|FA_CREATE_ALWAYS) == FR_OK) {
		dc_invalidaterange((void*)0, 0x40);
		f_write(&fd, (void*)0x1320000, 0x40, (UINT*) &bw);
		f_close(&fd);
        printf("Espresso OTP dumped to file.\r\n");
	}
    dc_invalidaterange((void*)0x1330000, 0x4000);


	if (f_open(&fd, "sdmc:/bootrom.bin", FA_WRITE|FA_CREATE_ALWAYS) == FR_OK) {
		dc_invalidaterange((void*)0x1330000, 0x4000);
		f_write(&fd, (void*)0x1330000, 0x4000, (UINT*) &bw);
		f_close(&fd);
        printf("Boot ROM dumped to file.\r\n");
	}    
}
