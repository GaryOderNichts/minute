/*
 *  minute - a port of the "mini" IOS replacement for the Wii U.
 *
 *  Copyright (C) 2016          SALT
 *  Copyright (C) 2016          Daz Jones <daz@dazzozo.com>
 *
 *  Copyright (C) 2008, 2009    Hector Martin "marcan" <marcan@marcansoft.com>
 *  Copyright (C) 2009          Andre Heider "dhewg" <dhewg@wiibrew.org>
 *
 *  This code is licensed to you under the terms of the GNU GPL, version 2;
 *  see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 */


#include "smc.h"
#include "types.h"
#include "latte.h"
#include "ppc.h"
#include "fatfs/ff.h"
#include "utils.h"
#include "gfx.h"
#include <stdio.h>
#include <sys/errno.h>
#include "elf.h"
#include "memory.h"
#include <string.h>

#define PHDR_MAX 10

static int _check_physaddr(u32 addr) {
    if((addr >= 0xFFE00000) && (addr <= 0xFFF1FFFF))
        return 0;

    if((addr <= 0x01FFFFFF))
        return 1;

    if((addr >= 0x14000000) && (addr <= 0x1CFFFFFF))
        return 2;

    if((addr >= 0x28000000) && (addr <= 0xCFFFFFFF))
        return 3;

    return -1;
}

static u32 _translate_physaddr(u32 addr) {
    if((addr >= 0xFFE00000) && (addr <= 0xFFF1FFFF))
        return (addr - 0xFFE00000) + 0x08000000;

    return addr;
}

static int _check_physrange(u32 addr, u32 len) {
    switch (_check_physaddr(addr)) {
        case 0:
            if ((addr + len) <= 0xFFF1FFFF)
                return 0;
            break;
        case 1:
            if ((addr + len) <= 0x01FFFFFF)
                return 1;
            break;
        case 2:
            if ((addr + len) <= 0x1CFFFFFF)
                return 2;
            break;
        case 3:
            if ((addr + len) <= 0xCFFFFFFF)
                return 3;
            break;
    }

    return -1;
}

static Elf32_Ehdr elfhdr;
static Elf32_Phdr phdrs[PHDR_MAX];

int ppc_load_file(const char *path, u32* entry)
{
    int res = 0, read = 0;

    FILE* file = fopen(path, "rb");
    if(!file) return -errno;

    read = fread(&elfhdr, sizeof(elfhdr), 1, file);
    if(read != 1)
        return -100;

    if (memcmp("\x7F" "ELF\x01\x02\x01\x00\x00", elfhdr.e_ident, 9)) {
        printf("ELF: invalid ELF header! 0x%02x 0x%02x 0x%02x 0x%02x\n",
                elfhdr.e_ident[0], elfhdr.e_ident[1],
                        elfhdr.e_ident[2], elfhdr.e_ident[3]);
        return -101;
    }

    if (_check_physaddr(elfhdr.e_entry) < 0) {
        printf("ELF: invalid entry point! 0x%08lX\n", elfhdr.e_entry);
        return -102;
    }

    if (elfhdr.e_phoff == 0 || elfhdr.e_phnum == 0) {
        printf("ELF: no program headers!\n");
        return -103;
    }

    if (elfhdr.e_phnum > PHDR_MAX) {
        printf("ELF: too many (%d) program headers!\n", elfhdr.e_phnum);
        return -104;
    }

    res = fseek(file, elfhdr.e_phoff, SEEK_SET);
    if (res) return -res;

    read = fread(phdrs, sizeof(phdrs[0]), elfhdr.e_phnum, file);
    if(read != elfhdr.e_phnum)
        return -errno;

    Elf32_Phdr *phdr = phdrs;
    u16 count = read;

    ppc_prepare();

    while (count--) {
        if (phdr->p_type != PT_LOAD) {
            printf("ELF: skipping PHDR of type %ld\n", phdr->p_type);
        } else {
            if (_check_physrange(phdr->p_paddr, phdr->p_memsz) < 0) {
                printf("ELF: PHDR out of bounds [0x%08lX...0x%08lX]\n",
                                phdr->p_paddr, phdr->p_paddr + phdr->p_memsz);
                return -106;
            }

            void *dst = (void *) _translate_physaddr(phdr->p_paddr);

            printf("ELF: LOAD 0x%lX @0x%08lX [0x%lX]\n", phdr->p_offset, phdr->p_paddr, phdr->p_filesz);
            if(phdr->p_filesz != 0) {
                res = fseek(file, phdr->p_offset, SEEK_SET);
                if (res) return -res;
                count = fread(dst, phdr->p_filesz, 1, file);
                if(count != 1) return -errno;
            }
        }
        phdr++;
    }

    dc_flushall();

    printf("ELF: load done.\n");
    *entry = elfhdr.e_entry;

    return 0;
}

int ppc_load_mem(const u8 *addr, u32 len, u32* entry)
{
    if (len < sizeof(Elf32_Ehdr))
        return -100;

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) addr;

    if (memcmp("\x7F" "ELF\x01\x02\x01\x00\x00", ehdr->e_ident, 9)) {
        printf("ELF: invalid ELF header! 0x%02x 0x%02x 0x%02x 0x%02x\n",
                        ehdr->e_ident[0], ehdr->e_ident[1],
                        ehdr->e_ident[2], ehdr->e_ident[3]);
        return -101;
    }

    if (_check_physaddr(ehdr->e_entry) < 0) {
        printf("ELF: invalid entry point! 0x%08lX\n", ehdr->e_entry);
        return -102;
    }

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
        printf("ELF: no program headers!\n");
        return -103;
    }

    if (ehdr->e_phnum > PHDR_MAX) {
        printf("ELF: too many (%d) program headers!\n",
                        ehdr->e_phnum);
        return -104;
    }

    u16 count = ehdr->e_phnum;
    if (len < ehdr->e_phoff + count * sizeof(Elf32_Phdr))
        return -105;

    Elf32_Phdr *phdr = (Elf32_Phdr *) &addr[ehdr->e_phoff];

    // TODO: add more checks here
    // - loaded ELF overwrites itself?

    ppc_prepare();

    while (count--) {
        if (phdr->p_type != PT_LOAD) {
            printf("ELF: skipping PHDR of type %ld\n", phdr->p_type);
        } else {
            if (_check_physrange(phdr->p_paddr, phdr->p_memsz) < 0) {
                printf("ELF: PHDR out of bounds [0x%08lX...0x%08lX]\n",
                                phdr->p_paddr, phdr->p_paddr + phdr->p_memsz);
                return -106;
            }

            printf("ELF: LOAD 0x%lX @0x%08lX [0x%lX]\n", phdr->p_offset, phdr->p_paddr, phdr->p_filesz);

            void *dst = (void *) _translate_physaddr(phdr->p_paddr);
            memcpy(dst, &addr[phdr->p_offset], phdr->p_filesz);
        }
        phdr++;
    }

    dc_flushall();

    printf("ELF: load done.\n");
    *entry = ehdr->e_entry;

    return 0;
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


// Copy pasted from https://github.com/ajd4096/gbadev/blob/romdumper/armboot/powerpc_elf.c#L309
#define WAIT_TIME	2380
int powerpc_dump(const char *path)
{	
    gfx_clear(GFX_ALL, BLACK);
    printf("Hello from powerpc_dump.\r\n");
    
    // I don't think we need that...
    // ppc_prepare();
    // printf("Prepared PPC.\r\n");
    FIL fd;
	u32 boot0 = read32(LT_BOOT0), bw, size;
	bool isWiiU = ((read32(0xd8005A0) & 0xFFFF0000) == 0xCAFE0000);
	
	printf("0xd8005A0 register value is %08x.\r\n", read32(0xd8005A0));
	if(isWiiU)
	{	printf("It's a WiiU. Will dump 16k bootROM and 16k boot0.\r\n");
		size = 0x4000;
	}else
	{	printf("It's a Wii. Only dumping 4k boot0.\r\n");
		size = 0x1000;
	}
	
	// boot0 dump
	write32(LT_BOOT0, boot0&~0x1000);
	f_open(&fd, "sdmc:/boot0.bin", FA_CREATE_ALWAYS|FA_WRITE);
	f_write(&fd, (void*)0xFFF00000, size, &bw);
	f_close(&fd);
	write32(LT_BOOT0, boot0);
	
	printf("Boot0 dump done. ");
	if(!isWiiU)
	{	printf("Exiting.\r\n");
		return -1;
	}printf("Now for the bootROM.\r\n");
	set32(LT_DIFLAGS,DIFLAGS_BOOT_CODE);
	set32(LT_AHBPROT, 0xFFFFFFFF);
	printf("Resetting PPC. End on-screen debug output.\r\n\r\n");
    
    ppc_hang();

    set32(LT_COMPAT_MEMCTRL_STATE, 0x20);
    set32(LT_SYSPROT, 0x99);

	
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

    udelay(WAIT_TIME);

    // SRESET
    clear32(LT_RESETS_COMPAT, 0x20);
    udelay(100);
    set32(LT_RESETS_COMPAT, 0x20);
    udelay(2000); // give PPC a moment to dump to RAM
    
    dc_invalidaterange((void*)0x1320000, 0x40);
 
    printf("First bytes of dumped ppc otp: %08X\n.\r\n", read32(0x1320000));   
 
	if (f_open(&fd, "sdmc:/otp_ppc.bin", FA_WRITE|FA_CREATE_ALWAYS) == FR_OK) {
		dc_invalidaterange((void*)0, 0x40);
		f_write(&fd, (void*)0x1320000, 0x40, &bw);
		f_close(&fd);
        printf("Espresso OTP dumped to file.\r\n");
	}
    dc_invalidaterange((void*)0x1330000, 0x4000);


	if (f_open(&fd, "sdmc:/bootrom.bin", FA_WRITE|FA_CREATE_ALWAYS) == FR_OK) {
		dc_invalidaterange((void*)0x1330000, 0x4000);
		f_write(&fd, (void*)0x1330000, 0x4000, &bw);
		f_close(&fd);
        printf("Boot ROM dumped to file.\r\n");
	}
    
    printf("Press POWER or EJECT to shutdown the console...\n");
    smc_wait_events(SMC_POWER_BUTTON | SMC_EJECT_BUTTON);	
	return -1;
}

