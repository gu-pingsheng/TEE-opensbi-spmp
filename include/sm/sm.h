#ifndef _SM_H
#define _SM_H

//#ifndef TARGET_PLATFORM_HEADER
//#error "SM requires to specify a certain platform"
//#endif

//#include TARGET_PLATFORM_HEADER
#include <sm/print.h>
#include <sm/platform/pmp/platform.h>
#include <stdint.h>
#include <sm/enclave_args.h>
#include <sm/page_map.h>

extern uintptr_t _fw_start[], _fw_end[];

#define SM_BASE ((uintptr_t) _fw_start)
#define SM_SIZE (((uintptr_t) _fw_end) - ((uintptr_t) _fw_start))

#define MAX_HARTS 8

//Host SBI numbers
#define SBI_MM_INIT            100
#define SBI_CREATE_ENCLAVE      99
#define SBI_ATTEST_ENCLAVE      98
#define SBI_RUN_ENCLAVE         97
#define SBI_STOP_ENCLAVE        96
#define SBI_RESUME_ENCLAVE      95
#define SBI_DESTROY_ENCLAVE     94
#define SBI_ALLOC_ENCLAVE_MM    93
#define SBI_MEMORY_EXTEND       92
#define SBI_MEMORY_RECLAIM      91
#define SBI_DEBUG_PRINT         88

//Enclave SBI numbers
#define SBI_EXIT_ENCLAVE        99
#define SBI_ENCLAVE_OCALL        98
#define SBI_GET_KEY             88

#define SBI_CREATE_SHM          79  //创建共享内存，既要绑定sPMP并开启sPMP权限，又要attach到共享内存
#define SBI_MAP_SHM             78  //建立共享内存的虚拟地址和物理地址映射
#define SBI_GET_SHM             77  //
#define SBI_GET_SHMID           76
#define SBI_TRANSFER_SHM        75
#define SBI_GETSHM_EID          74
#define SBI_ATTACH_SHM          73

#define SBI_GET_KEY_SIZE        71

#define SBI_GET_TIME_VALUE      70

#define SBI_GET_CLOCK_START     69
#define SBI_GET_CLOCK_END       68


//Error code of SBI_ALLOC_ENCLAVE_MEM
#define ENCLAVE_NO_MEMORY       -2
#define ENCLAVE_ERROR           -1
#define ENCLAVE_SUCCESS          0
#define ENCLAVE_TIMER_IRQ        1
#define ENCLAVE_OCALL            2

//ENCLAVE OCALL NUMBERS
#define OCALL_SYS_WRITE              3
#define OCALL_USER_DEFINED           9

//error code of SBI_RESUME_RNCLAVE
#define RESUME_FROM_TIMER_IRQ    2000
#define RESUME_FROM_STOP         2003
#define RESUME_FROM_OCALL        2

// SM需要管理所有的共享内存段，
#define NUM_SHM 128   // 定义共享内存的数量
#define NUM_EACH_SHM 128 //定义每个共享区可被多少的enclave共享
// #define DEFAULT_SHM_PTR  0x1000080000

// #define ENCLAVE_TYPE_SHIFT 54
// #define SHM_KEY_MASK (~(0x3ffUL << ENCLAVE_TYPE_SHIFT))
// #define ENCLAVE_TYPE_MASK (0x3ffUL << ENCLAVE_TYPE_SHIFT)
#define SHM_KEY_SHIFT 10
#define SHM_KEY_MASK (~(0x3ff))
#define ENCLAVE_TYPE_MASK (0x3ff)

typedef struct shm_enclave
{
  bool used;
  unsigned int eid;
  uint32_t enclave_type;
}shm_enclave;

struct enclave_shm_t
{
  bool used;
  uint64_t key;

  shm_enclave eids[NUM_EACH_SHM];
  // unsigned int eids[NUM_EACH_SHM];
  // bool eids_used[NUM_EACH_SHM]; 
  unsigned long paddr;
  unsigned long size;
  u8 perm; // 被共享者默认具有的静态最大权限
};


void sm_init();

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size);

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size);

uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg);

uintptr_t sm_create_enclave(uintptr_t enclave_create_args);

uintptr_t sm_attest_enclave(uintptr_t enclave_id, uintptr_t report, uintptr_t nonce);

uintptr_t sm_run_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_debug_print(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_stop_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_resume_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_enclave_ocall(uintptr_t *regs, uintptr_t ocall_func_id, uintptr_t arg0, uintptr_t arg1);

uintptr_t sm_enclave_get_key(uintptr_t* regs, uintptr_t salt_va, uintptr_t salt_len,
                        uintptr_t key_buf_va, uintptr_t key_buf_len);

uintptr_t sm_exit_enclave(uintptr_t *regs, unsigned long retval);

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc);

int check_in_enclave_world();



int32_t sm_create_shm(uint64_t key, uint64_t req_size);

int32_t sm_map_shm(virtual_addr_t vaddr, uint32_t shmid);

int32_t sm_get_shmid(uint64_t key);

int32_t sm_attach_shm(uint32_t shmid, uint32_t enclave_type);

uint32_t sm_get_shm(uint32_t shmid);

int32_t sm_getshm_eid(uint32_t shmid, uint32_t enclave_type);

int32_t sm_transfer_shm(uint32_t shmid, uint32_t eid_next, u8 perm);

int32_t sm_get_key_size(virtual_addr_t key, virtual_addr_t size);

uint64_t sm_clock_start();
uint64_t sm_clock_end();

#endif /* _SM_H */
