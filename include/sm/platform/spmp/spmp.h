#ifndef _SPMP_H
#define _SPMP_H
#define SPMP_ENABLED

#include <stdint.h>
#include <sbi/riscv_encoding.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_hartmask.h>

//number of PMP registers
#define NSPMP 16

//R/W/X/A/L field in PMP configuration registers
#define SPMP_R     0x01
#define SPMP_W     0x02
#define SPMP_X     0x04
#define SPMP_A     0x18
#define SPMP_S     0x80

//encoding of A field in PMP configuration registers
#define SPMP_TOR   0x08
#define SPMP_NA4   0x10
#define SPMP_NAPOT 0x18
#define SPMP_OFF   0x00
#define SPMP_NO_PERM  0

//encoding of csr code
#define spmpaddr0        0x1b0
#define spmpaddr1        0x1b1
#define spmpaddr2        0x1b2
#define spmpaddr3        0x1b3
#define spmpaddr4        0x1b4
#define spmpaddr5        0x1b5
#define spmpaddr6        0x1b6
#define spmpaddr7        0x1b7
#define spmpaddr8        0x1b8
#define spmpaddr9        0x1b9
#define spmpaddr10       0x1ba
#define spmpaddr11       0x1bb
#define spmpaddr12       0x1bc
#define spmpaddr13       0x1bd
#define spmpaddr14       0x1be
#define spmpaddr15       0x1bf
#define spmpcfg0         0x1a0
#define spmpcfg2         0x1a2

//set to 1 when spmp trap happened, remember to clear it after handle the trap
#define spmpexpt         0x145

#define read_csr(reg) ({ unsigned long __tmp; \
  asm volatile ("csrr %0, " #reg : "=r"(__tmp)); \
  __tmp; })

#define write_csr(reg, val) ({ \
  asm volatile ("csrw " #reg ", %0" :: "rK"(val)); })

#define swap_csr(reg, val) ({ unsigned long __tmp; \
  asm volatile ("csrrw %0, " #reg ", %1" : "=r"(__tmp) : "rK"(val)); \
  __tmp; })

#define set_csr(reg, bit) ({ unsigned long __tmp; \
  asm volatile ("csrrs %0, " #reg ", %1" : "=r"(__tmp) : "rK"(bit)); \
  __tmp; })

#define clear_csr(reg, bit) ({ unsigned long __tmp; \
  asm volatile ("csrrc %0, " #reg ", %1" : "=r"(__tmp) : "rK"(bit)); \
  __tmp; })

//read spmpcfg & spmpaddr
#define read_spmpcfg(pmpc)   read_csr(pmpc)
#define read_spmpaddr(addr)  read_csr(addr)
#define read_spmpexpt(r)     read_csr(r)
#define set_spmpexpt(r, v)   write_csr(r, v)

//spmpfcg register's structure
//|63    56|55    48|47    40|39    32|31    24|23    16|15     8|7      0|
//|spmp7cfg|spmp6cfg|spmp5cfg|spmp4cfg|spmp3cfg|spmp2cfg|spmp1cfg|spmp1cfg|
#define SPMP_PER_CFG_REG           8
#define SPMPCFG_BIT_NUM            8
#define SPMPCFG_BITS               0xFF

#if __riscv_xlen == 64
# define LIST_OF_SPMP_REGS  X(0,0)  X(1,0)  X(2,0)  X(3,0) \
                           X(4,0)  X(5,0)  X(6,0)  X(7,0) \
                           X(8,2)  X(9,2)  X(10,2) X(11,2) \
                          X(12,2) X(13,2) X(14,2) X(15,2)
# define SPMP_PER_GROUP  8
#else
# define LIST_OF_SPMP_REGS  X(0,0)  X(1,0)  X(2,0)  X(3,0) \
                           X(4,1)  X(5,1)  X(6,1)  X(7,1) \
                           X(8,2)  X(9,2)  X(10,2) X(11,2) \
                           X(12,3) X(13,3) X(14,3) X(15,3)
# define SPMP_PER_GROUP  4
#endif

#define _SPMP_SET(n, g, addr, pmpc) do { \
  asm volatile ("la t0, 1f\n\t" \
                "csrrw t0, mtvec, t0\n\t" \
                "csrw "#n", %0\n\t" \
                "csrw "#g", %1\n\t" \
                "sfence.vma\n\t"\
                ".align 2\n\t" \
                "1: csrw mtvec, t0 \n\t" \
                : : "r" (addr), "r" (pmpc) : "t0"); \
} while(0)

#define _SPMP_READ(n, g, addr, pmpc) do { \
  asm volatile("csrr %0, "#n : "=r"(addr) :); \
  asm volatile("csrr %0, "#g : "=r"(pmpc) :); \
} while(0)

#define SPMP_SET(n, g, addr, pmpc)  _SPMP_SET(n, g, addr, pmpc)
#define SPMP_READ(n, g, addr, pmpc) _SPMP_READ(n, g, addr, pmpc)

struct spmp_config_t
{
  uintptr_t paddr;
  unsigned long size;
  uintptr_t perm;
  uintptr_t mode;
  uintptr_t sbit;

};

struct spmp_data_t
{
  struct spmp_config_t spmp_config_arg;
  int spmp_idx_arg;
  struct sbi_hartmask smask;
};

#define SBI_SPMP_DATA_INIT(__ptr, __spmp_config_arg, __spmp_idx_arg, __src) \
do { \
	(__ptr)->spmp_config_arg = (__spmp_config_arg); \
	(__ptr)->spmp_idx_arg = (__spmp_idx_arg); \
	SBI_HARTMASK_INIT_EXCEPT(&(__ptr)->smask, (__src)); \
} while (0)


void set_spmp_and_sync(int spmp_idx, struct spmp_config_t);
void clear_spmp_and_sync(int spmp_idx);

void set_spmp(int spmp_idx, struct spmp_config_t);

void clear_spmp(int spmp_idx);

struct spmp_config_t get_spmp(int spmp_idx);

#endif /* _SPMP_H */
