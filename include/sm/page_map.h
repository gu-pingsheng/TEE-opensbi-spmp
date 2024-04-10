#ifndef _PAGE_MAP_H
#define _PAGE_MAP_H

#include<sm/vm.h>
#include<sbi/sbi_types.h>
#include<sm/enclave.h>
#include<sm/print.h>
#include<sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>

#define RISCV_PT_LEVEL 3
// const u32 RISCV_PT_LEVEL = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS;

int map_pa2va(struct enclave_t* enclave, virtual_addr_t vaddr, physical_addr_t paddr, unsigned long size, unsigned long perm);

#endif