//#include <sm/atomic.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_locks.h>
#include <sm/sm.h>
#include <sm/pmp.h>
#include <sm/enclave.h>
#include <sm/attest.h>
#include <sm/math.h>
#include <sbi/sbi_console.h>
#include <sm/page_map.h>
#include <sm/platform/pmp/enclave_mm.h>
#include <sbi/sbi_string.h>
#include <sm/platform/spmp/spmp.h>


//static int sm_initialized = 0;
//static spinlock_t sm_init_lock = SPINLOCK_INIT;
static spinlock_t shm_idx_lock = SPIN_LOCK_INITIALIZER;
static spinlock_t shm_eid_idx_lock = SPIN_LOCK_INITIALIZER;
static spinlock_t spmp_idx_lock = SPIN_LOCK_INITIALIZER;
static spinlock_t shm_ownership_lock = SPIN_LOCK_INITIALIZER;
static unsigned long shm_idx = 0;
static unsigned long shm_eid_idx = 0;
static unsigned long spmp_idx = 0;
struct enclave_shm_t enclave_shm[NUM_SHM];

void sm_init()
{
  sbi_memset(enclave_shm, 0, NUM_SHM * sizeof(struct enclave_shm_t));
  // 初始化PMP0，PMP N-1寄存器，sPMP N-1寄存器
  platform_init();
  printm("[sm.c@%s] cur_satp = 0x%lx.\n", __func__, csr_read(CSR_SATP));
  
  // 初始化SM的私钥和公钥
  attest_init();
}

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  printm("[Penglai Monitor] %s paddr:0x%lx, size:0x%lx\r\n",__func__, paddr, size);
  /*DEBUG: Dump PMP registers here */
  dump_pmps();
  // 将内核分配的连续物理内存，通过配置PMP寄存器将其隔离保护
  retval = mm_init(paddr, size);

  // unsigned long PMP_size = size >> 3;
  // uintptr_t PMP_paddr = paddr; 
  // for (int i = 0; i < 8; i++)
  // {
  //   retval = mm_init(PMP_paddr, PMP_size);
  //   PMP_paddr += PMP_size;
  // }

  /*DEBUG: Dump PMP registers here */
  dump_pmps();

  printm("[Penglai Monitor] %s ret:%ld \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);
  // 内存扩展依然通过驱动分配连续的地址空间，并通过配置PMP寄存器保护这片内存
  retval = mm_init(paddr, size);

  printm("[Penglai Monitor] %s return:%ld\r\n",__func__, retval);
  return retval;
}

uintptr_t sm_debug_print(uintptr_t* regs, uintptr_t arg0)
{
  print_buddy_system();
  return 0;
}

uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg)
{
  //mm_alloc_arg_t 中的字段：req_size; resp_addr; resp_size;
  struct mm_alloc_arg_t mm_alloc_arg_local;
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = copy_from_host(&mm_alloc_arg_local,
      (struct mm_alloc_arg_t*)mm_alloc_arg,
      sizeof(struct mm_alloc_arg_t));
  if(retval != 0)
  {
    printm_err("M mode: sm_alloc_enclave_mem: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  // dump_pmps();
  unsigned long resp_size = 0;
  
  // 通过查找已经配置完PMP寄存器的mm_region分配enclave内存
  void* paddr = mm_alloc(mm_alloc_arg_local.req_size, &resp_size);
  if(paddr == NULL)
  {
    printm("M mode: sm_alloc_enclave_mem: no enough memory\r\n");
    return ENCLAVE_NO_MEMORY;
  }
  // dump_pmps();

  // 请求SM分配完内存之后，需要授予内核访问这块内存的权限，内核将会加载Enclave可执行文件，配置Enclave 页表，管理free_mem
  //grant kernel access to this memory
  if(grant_kernel_access(paddr, resp_size) != 0)
  {
    printm_err("M mode: ERROR: faile to grant kernel access to pa 0x%lx, size 0x%lx\r\n", (unsigned long) paddr, resp_size);
    mm_free(paddr, resp_size);
    return ENCLAVE_ERROR;
  }

  mm_alloc_arg_local.resp_addr = (uintptr_t)paddr;
  mm_alloc_arg_local.resp_size = resp_size;

  retval = copy_to_host((struct mm_alloc_arg_t*)mm_alloc_arg,
      &mm_alloc_arg_local,
      sizeof(struct mm_alloc_arg_t));
  if(retval != 0)
  {
    printm_err("M mode: sm_alloc_enclave_mem: unknown error happended when copy to host\r\n");
    return ENCLAVE_ERROR;
  }

  printm("[Penglai Monitor] %s return:%ld\r\n",__func__, retval);

  return ENCLAVE_SUCCESS;
}

uintptr_t sm_create_enclave(uintptr_t enclave_sbi_param)
{
  // printm("[sm.c@%s] cur_satp = 0x%lx.\n", __func__, csr_read(CSR_SATP));

  struct enclave_sbi_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;
  struct enclave_t* enclave;
  unsigned int eid;

  // printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = copy_from_host(&enclave_sbi_param_local,
      (struct enclave_sbi_param_t*)enclave_sbi_param,
      sizeof(struct enclave_sbi_param_t));
  if(retval != 0)
  {
    printm_err("M mode: sm_create_enclave: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  void* paddr = (void*)enclave_sbi_param_local.paddr;
  unsigned long size = (unsigned long)enclave_sbi_param_local.size;

  // 在创建enclave之前，需要撤销内核对Enclave内存访问的权限
  if(retrieve_kernel_access(paddr, size) != 0)
  {
    mm_free(paddr, size);
    return -1UL;
  }

  retval = create_enclave_m(enclave_sbi_param_local);
  eid = *(enclave_sbi_param_local.eid_ptr);
  enclave = get_enclave(eid);
  sbi_memset(enclave->used_shm, 0, NSPMP);

  sbi_memset(enclave->enclave_spmp_context, 0, sizeof(struct spmp_config_t) * NSPMP);
  
  // 创建enclave之后，运行enclave之前，需要配置sPMP0和sPMP1寄存器，
  //config the enclave sPMP structure to allow enclave to access memory
  enclave->enclave_spmp_context[0].paddr = enclave->paddr;
  enclave->enclave_spmp_context[0].size = enclave->size;
  enclave->enclave_spmp_context[0].mode = SPMP_NAPOT;
  enclave->enclave_spmp_context[0].perm = SPMP_R | SPMP_W | SPMP_X;

//set the spmp_1 to let enclave access kbuffer shared memory
  enclave->enclave_spmp_context[1].paddr = enclave_sbi_param_local.kbuffer_paddr;
  enclave->enclave_spmp_context[1].size = enclave_sbi_param_local.kbuffer_size;
  enclave->enclave_spmp_context[1].mode = SPMP_NAPOT;
  enclave->enclave_spmp_context[1].perm = SPMP_R | SPMP_W;
  printm("[Penglai Monitor] %s, kbuffer_paddr: 0x%lx\n", __func__, enclave_sbi_param_local.kbuffer_paddr);
  sbi_memset(enclave->thread_context.host_spmp_context, 0, sizeof(struct spmp_config_t) * (NSPMP-1));

  // enclave->enclave_spmp_context[NSPMP - 1].paddr = 0;
  // enclave->enclave_spmp_context[NSPMP - 1].size = -1UL;
  // enclave->enclave_spmp_context[NSPMP - 1].mode = SPMP_NAPOT;
  // enclave->enclave_spmp_context[NSPMP - 1].perm = SPMP_R | SPMP_W;

  for(int i = 0; i < (NSPMP-1); i++)
  {
  	clear_spmp(i);  
  }

  //config the last sPMP to allow user to access memory
  enclave->thread_context.host_spmp_context[NSPMP-1].paddr = 0;
  enclave->thread_context.host_spmp_context[NSPMP-1].size = -1UL;
  enclave->thread_context.host_spmp_context[NSPMP-1].mode = SPMP_NAPOT;
  enclave->thread_context.host_spmp_context[NSPMP-1].perm = SPMP_NO_PERM;
  enclave->thread_context.host_spmp_context[NSPMP-1].sbit = SPMP_S;
  set_spmp(NSPMP-1, enclave->thread_context.host_spmp_context[NSPMP-1]); 
  
  printm("[Penglai Monitor] %s created return value:%ld \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_attest_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);

  retval = attest_enclave(eid, report, nonce);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);

  return retval;
}

uintptr_t sm_run_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);
#if 0
  dump_pmps();
  printm_err("\n");
#endif
  retval = run_enclave(regs, (unsigned int)eid);
  // sm_create_shm(123, 1<<12, SPMP_R | SPMP_W);
  // print_buddy_system();
#if 0
  dump_pmps();
  printm_err("\n");
  dump_spmps();
#endif
  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);

  return retval;
}

uintptr_t sm_stop_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);

  retval = stop_enclave(regs, (unsigned int)eid);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);
  return retval;
}

uintptr_t sm_resume_enclave(uintptr_t* regs, unsigned long eid)
{
  // printm("[sm.c] %s invoked!\n", __func__);

  uintptr_t retval = 0;
  uintptr_t resume_func_id = regs[11];

  switch(resume_func_id)
  {
    case RESUME_FROM_TIMER_IRQ:
      // printm("[sm.c] RESUME_FROM_TIMER_IRQ invoked!\n");
      retval = resume_enclave(regs, eid);
      break;
    case RESUME_FROM_STOP:
      retval = resume_from_stop(regs, eid);
      break;
    case RESUME_FROM_OCALL:
      retval = resume_from_ocall(regs, eid);
      break;
    default:
      break;
  }

  return retval;
}

uintptr_t sm_exit_enclave(uintptr_t* regs, unsigned long retval)
{
  uintptr_t ret;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  ret = exit_enclave(regs, retval);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, ret);

  return ret;
}

uintptr_t sm_enclave_ocall(uintptr_t* regs, uintptr_t ocall_id, uintptr_t arg0, uintptr_t arg1)
{
  // printm("[Penglai Monitor] %s invoked\r\n",__func__);
  uintptr_t ret = 0;
  switch(ocall_id)
  {
    case OCALL_SYS_WRITE:
      ret = enclave_sys_write(regs);
      // printm("[Penglai Monitor] enclave_sys_write invoked\r\n");
      break;
    case OCALL_USER_DEFINED:
      ret = enclave_user_defined_ocall(regs, arg0);
      printm("[Penglai Monitor] enclave_user_defined_ocall invoked\r\n");
      break;
    default:
      printm_err("[Penglai Monitor@%s] wrong ocall_id(%ld)\r\n", __func__, ocall_id);
      ret = -1UL;
      break;
  }
  return ret;
}

/**
 * \brief Retrun key to enclave.
 * 
 * \param regs          The enclave regs.
 * \param salt_va       Salt pointer in enclave address space.
 * \param salt_len      Salt length in bytes.
 * \param key_buf_va    Key buffer pointer in enclave address space.
 * \param key_buf_len   Key buffer length in bytes.
 */
uintptr_t sm_enclave_get_key(uintptr_t* regs, uintptr_t salt_va, uintptr_t salt_len,
    uintptr_t key_buf_va, uintptr_t key_buf_len)
{
  uintptr_t ret = 0;

  ret = enclave_derive_seal_key(regs, salt_va, salt_len, key_buf_va, key_buf_len);

  return ret;
}

/**
 * \brief This transitional function is used to destroy the enclave.
 *
 * \param regs The host reg.
 * \param enclave_eid The enclave id.
 */
uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id)
{
  uintptr_t ret = 0;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  ret = destroy_enclave(regs, enclave_id);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, ret);

  return ret;
}

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t ret;

  ret = do_timer_irq(regs, mcause, mepc);

  regs[10] = 0; //no errors in all cases for timer handler
  regs[11] = ret; //value
  return ret;
}

int32_t sm_create_shm(uint64_t key, uint64_t req_size){
  printm("[sm.c@%s] ----------sm create shm start---------\n", __func__);
  unsigned long resp_size = 0;
  printm("[sm.c@%s] req mem size is %ld.\n", __func__, (long int)req_size);
  void* paddr = mm_alloc(req_size, &resp_size);
  if(paddr == NULL)
  {
    printm("[sm.c@%s] no enough memory to create share memory.\r\n", __func__);
    return -1;  // 返回值为-1，表示未成功分配share memory
  }
  printm("[sm.c@%s] shm paddr = 0x%lx, alloc mem size is %ld. \n", __func__, (unsigned long)paddr, (long int)resp_size);

  u8 spmp_perm = 0;
  spmp_perm |= SPMP_R;
  spmp_perm |= SPMP_W;

  int eid = -1;
  eid = get_enclave_id();
  if (eid == -1){
    printm("[sm.c@%s] get_enclave_id failed! \n", __func__);
    return -1;
  }
  // else {
  //   printm("[sm.c@%s] get_enclave_id succeed! eid is %d .\n", __func__, eid);
  // }

  struct enclave_t* enclave;
  enclave =  get_enclave(eid);
  
  unsigned long shmid = -1;

  uint32_t enclave_type = key & ENCLAVE_TYPE_MASK;
  uint64_t shm_key = (key & SHM_KEY_MASK) >> SHM_KEY_SHIFT;

  spin_lock(&shm_idx_lock);
  for (shm_idx = 0; shm_idx < NUM_SHM; shm_idx++){
    if (!enclave_shm[shm_idx].used){
      shmid = shm_idx;
      enclave_shm[shm_idx].used = 1;
      enclave_shm[shm_idx].key = shm_key;
      enclave_shm[shm_idx].paddr = (unsigned long)paddr;
      enclave_shm[shm_idx].size = (unsigned long)resp_size;
      enclave_shm[shm_idx].perm = spmp_perm;

      //shm的创建者attach到共享内存
      spin_lock(&shm_eid_idx_lock);
      for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++){
        if (!enclave_shm[shm_idx].eids[shm_eid_idx].used){
          enclave_shm[shm_idx].eids[shm_eid_idx].used = 1;
          enclave_shm[shm_idx].eids[shm_eid_idx].eid = eid;
          enclave_shm[shm_idx].eids[shm_eid_idx].enclave_type = enclave_type;
          break;
        }
      }
      spin_unlock(&shm_eid_idx_lock);
      break;
    } 
  }
  spin_unlock(&shm_idx_lock);

  spin_lock(&spmp_idx_lock);
  //使用当前enclave的一个sPMP寄存器用来保护当前物理地址
  //从第二个sPMP开始遍历，创建共享区sPMP保护
  for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
    if(enclave->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
      enclave->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)paddr;
      enclave->enclave_spmp_context[spmp_idx].size = resp_size;
      enclave->enclave_spmp_context[spmp_idx].perm = spmp_perm;
      enclave->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;
      //sbit默认就是0，其实可以不用再次置为0
      enclave->enclave_spmp_context->sbit = 0;
      enclave->used_shm[spmp_idx] = 1;

      spin_lock(&shm_ownership_lock);
      enclave->shm_ownership = 1;
      spin_unlock(&shm_ownership_lock);

      set_spmp(spmp_idx, enclave->enclave_spmp_context[spmp_idx]);
      break;
    }
  }
  spin_unlock(&spmp_idx_lock);
  dump_spmps();
  return shmid;
}


// 
int32_t sm_map_shm(virtual_addr_t vaddr, uint32_t shmid){
  unsigned long paddr, shm_size;
  u8 spmp_perm = 0, pt_perm = 0;

  spin_lock(&shm_idx_lock);
  shm_idx = shmid;
  if (enclave_shm[shm_idx].used){
    paddr = enclave_shm[shm_idx].paddr;
    shm_size = enclave_shm[shm_idx].size;
    spmp_perm = enclave_shm[shm_idx].perm;
  }else {
    return -1; // -1 share memory不存在
  }
  spin_unlock(&shm_idx_lock);

  pt_perm = spmp_perm << 1;
  pt_perm |=  PTE_U;

  int eid = -1;
  eid = get_enclave_id();
  if (eid == -1){
    printm("[sm.c@%s] get_enclave_id failed! \n", __func__);
    return -2; //-2 is get_enclave_id failed
  } 
  // else {
  //   printm("[sm.c@%s] get_enclave_id succeed! eid is %d.\n", __func__, eid);
  // }

  struct enclave_t* enclave;
  enclave =  get_enclave(eid);

  virtual_addr_t shm_va = enclave->shm_ptr;
  //将物理地址映射至创建者的虚拟地址空间中
  int ret = 0; 
  ret = map_pa2va(enclave, shm_va, (physical_addr_t) paddr, shm_size, pt_perm);

  uintptr_t shm_pa = get_enclave_paddr_from_va(enclave->root_page_table, shm_va);
 
  // printm("[sm.c@%s] get_enclave_paddr_from_va return shm_pa 0x%lx \n", __func__, (long int)shm_pa);
  if (shm_pa == paddr && ret == 0){
	  // printm("[sm.c@%s] ret shm_va 0x%lx \n", __func__, (long int)shm_va);
    enclave->shm_ptr = (unsigned long)shm_va + shm_size;
    // pa是vaddr指针指向的位置
    unsigned long* pa = (unsigned long*)get_enclave_paddr_from_va(enclave->root_page_table, vaddr);
    *pa = shm_va;
    return 0; // 0 映射成功
  }
  return -3;  // -3 映射失败
}

// 根据key
int32_t sm_get_shmid(uint64_t key){
  // uint32_t enclave_type = key & ENCLAVE_TYPE_MASK;
  uint64_t shm_key = (key & SHM_KEY_MASK) >> SHM_KEY_SHIFT;

  int32_t local_shmid = -1;
  spin_lock(&shm_idx_lock);
  for (shm_idx = 0; shm_idx < NUM_SHM; shm_idx++){
    if (enclave_shm[shm_idx].used && enclave_shm[shm_idx].key == shm_key){
      local_shmid = (int32_t) shm_idx;
      spin_unlock(&shm_idx_lock);
      return local_shmid;
    } 
  }
  spin_unlock(&shm_idx_lock);
  return local_shmid;
}


int32_t sm_attach_shm(uint32_t shmid, uint32_t enclave_type){
  unsigned long paddr = 0, shm_size = 0;

  int eid = -1;
  eid = get_enclave_id();
  if (eid == -1){
    printm("[sm.c@%s] get_enclave_id failed! \n", __func__);
    return -1;
  }
  // else {
  //   printm("[sm.c@%s] get_enclave_id succeed! eid is %d .\n", __func__, eid);
  // }

  struct enclave_t* enclave;
  enclave =  get_enclave(eid);


  spin_lock(&shm_idx_lock);
  shm_idx = shmid;
  if (enclave_shm[shm_idx].used){
    paddr = enclave_shm[shm_idx].paddr;
    shm_size = enclave_shm[shm_idx].size;
    spin_lock(&shm_eid_idx_lock);
    for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++){
      if (!enclave_shm[shm_idx].eids[shm_eid_idx].used){
        enclave_shm[shm_idx].eids[shm_eid_idx].used = 1;
        enclave_shm[shm_idx].eids[shm_eid_idx].enclave_type = enclave_type;
        enclave_shm[shm_idx].eids[shm_eid_idx].eid = eid;
        spin_unlock(&shm_eid_idx_lock);
        spin_unlock(&shm_idx_lock);

        spin_lock(&spmp_idx_lock);
        //使用当前enclave的一个sPMP寄存器用来保护当前物理地址
        //从第二个sPMP开始遍历，创建共享区sPMP保护
        for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
          if(!enclave->used_shm[spmp_idx] && enclave->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
            enclave->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)paddr;
            enclave->enclave_spmp_context[spmp_idx].size = shm_size;
            enclave->enclave_spmp_context[spmp_idx].perm = SPMP_NO_PERM;
            enclave->enclave_spmp_context[spmp_idx].mode = SPMP_OFF;
            //sbit默认就是0，其实可以不用再次置为0
            enclave->enclave_spmp_context->sbit = 0;
            enclave->used_shm[spmp_idx] = 1;

            spin_lock(&shm_ownership_lock);
            enclave->shm_ownership = 0;
            spin_unlock(&shm_ownership_lock);
            break;
          }
        }
        spin_unlock(&spmp_idx_lock);
        return 0;
      }
    }
    printm("[SM@%s]error: shm eid has been fully used!\n", __func__);
    spin_unlock(&shm_idx_lock);
    return -1; // 共享内存关联的Enclave已满
  }
  printm("[SM@%s]shmid=%d is not exist.\n", __func__, shmid);
  spin_unlock(&shm_idx_lock);
  return -2; // 共享内存不存在
}

// 根据key中shmid和Enclave类型, 找到指定的Enclave ID
int32_t sm_getshm_eid(uint32_t shmid, uint32_t enclave_type){
  // uint32_t shm_key = key & SHM_KEY_MASK;
  // uint32_t enclave_type = key & ENCLAVE_TYPE_MASK;
  // printm("[SM@%s] enclave_type = %d.\n", __func__, enclave_type);

  // int32_t shmid = sm_get_shmid(key);

  unsigned int eid_next = -1;
  spin_lock(&shm_idx_lock);
  shm_idx = shmid;
  if (enclave_shm[shm_idx].used){
    spin_lock(&shm_eid_idx_lock);
    for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++){
      if (enclave_shm[shm_idx].eids[shm_eid_idx].used && enclave_shm[shm_idx].eids[shm_eid_idx].enclave_type == enclave_type){
        eid_next = enclave_shm[shm_idx].eids[shm_eid_idx].eid;
        spin_unlock(&shm_eid_idx_lock);
        spin_unlock(&shm_idx_lock);
        printm("[SM@%s] enclave_type=%d, its eid = %d\n", __func__, enclave_type, eid_next);
        return eid_next;
      }
    }
    if (shm_eid_idx == NUM_EACH_SHM) {
      printm("[SM@%s] enclave_type  %d  Enclave not exist.\n", __func__, enclave_type);
      spin_unlock(&shm_eid_idx_lock);
      spin_unlock(&shm_idx_lock);
    }
  }
  return eid_next; // -1 被转移的Enclave不存在
}

int32_t sm_transfer_shm(uint32_t shmid, uint32_t eid_next){
  printm("[SM@%s]------ start-----\n", __func__);
  unsigned long paddr = 0, shm_size = 0;
  u8 spmp_perm = 0;

  spin_lock(&shm_idx_lock);
  shm_idx = shmid;
  if (enclave_shm[shm_idx].used){
    paddr = enclave_shm[shm_idx].paddr;
    shm_size = enclave_shm[shm_idx].size;
    spmp_perm = enclave_shm[shm_idx].perm;
  }
  spin_unlock(&shm_idx_lock);

  struct enclave_t* enclave01, *enclave02;
  uint32_t eid = get_enclave_id();
  enclave01 = get_enclave(eid);
  enclave02 = get_enclave(eid_next);

  spin_lock(&spmp_idx_lock);
    // 关闭当前Enclave共享内存的sPMP权限
  for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
    if(enclave01->enclave_spmp_context[spmp_idx].mode != SPMP_OFF && \
      enclave01->used_shm[spmp_idx] && \
      enclave01->enclave_spmp_context[spmp_idx].paddr == paddr && \
      enclave01->enclave_spmp_context[spmp_idx].size == shm_size){

      enclave01->enclave_spmp_context[spmp_idx].mode = SPMP_OFF;

      spin_lock(&shm_ownership_lock);
      enclave01->shm_ownership = 0;
      spin_unlock(&shm_ownership_lock);

      set_spmp(spmp_idx, enclave01->enclave_spmp_context[spmp_idx]);
      printm("[SM@%s] eid = %d spmp close.\n", __func__, enclave01->eid);
      break;
    }
  }
  // spin_unlock(&spmp_idx_lock);
  // dump_spmps();


  // spin_lock(&spmp_idx_lock);
  // 开启下一个Enclave的sPMP权限
  // 如果下一个Enclave的sPMP寄存器已经与共享内存绑定，那么打开即可
  for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
    if(enclave02->enclave_spmp_context[spmp_idx].mode == SPMP_OFF && \
      enclave02->used_shm[spmp_idx] && \
      enclave02->enclave_spmp_context[spmp_idx].paddr == paddr && \
      enclave02->enclave_spmp_context[spmp_idx].size == shm_size) {

      enclave02->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;

      spin_lock(&shm_ownership_lock);
      enclave02->shm_ownership = 1;
      spin_unlock(&shm_ownership_lock);

      spin_unlock(&spmp_idx_lock);
      printm("[SM@%s] eid = %d spmp open.\n", __func__, enclave02->eid);
      return 0;
    }
  }

  // 如果下一个Enclave的sPMP寄存器还未与共享内存绑定，需要建立共享内存的sPMP映射并开启
  for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
    if(!enclave02->used_shm[spmp_idx] && enclave02->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
      enclave02->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)paddr;
      enclave02->enclave_spmp_context[spmp_idx].size = shm_size;
      enclave02->enclave_spmp_context[spmp_idx].perm = spmp_perm;
      enclave02->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;
      //sbit默认就是0，其实可以不用再次置为0
      enclave02->enclave_spmp_context->sbit = 0;
      enclave02->used_shm[spmp_idx] = 1;

      spin_lock(&shm_ownership_lock);
      enclave02->shm_ownership = 1;
      spin_unlock(&shm_ownership_lock);

      spin_unlock(&spmp_idx_lock);
      printm("[SM@%s]no matched. eid = %d spmp open.\n", __func__, enclave02->eid);

      return 0;
    }
  }

  // if (spmp_idx == NSPMP){
  printm("[SM@%s] spmp has been fully used!", __func__);
  spin_unlock(&spmp_idx_lock);
  return -1; // -1 spmp has been fully used

}


uint32_t sm_get_shm(uint32_t shmid){
  struct enclave_t* enclave;
  unsigned int eid = get_enclave_id();
  enclave = get_enclave(eid);
  
  spin_lock(&shm_ownership_lock);
  if (enclave->shm_ownership == 1){
      spin_unlock(&shm_ownership_lock);
      return 1;
  } else {
    spin_unlock(&shm_ownership_lock);
    return 0;
  }
}

/*
int32_t sm_transfer_shm(uint32_t shmid, uint32_t enclave_type){
  unsigned int eid = -1, eid_next = -1;
  unsigned long paddr, shm_size;
  u8 spmp_perm = 0;

  if (enclave_type != 0) {
    spin_lock(&shm_idx_lock);
    shm_idx = shmid;
    if (enclave_shm[shm_idx].used){
      paddr = enclave_shm[shm_idx].paddr;
      shm_size = enclave_shm[shm_idx].size;
      spmp_perm = enclave_shm[shm_idx].perm;
      spin_lock(&shm_eid_idx_lock);
      for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++){
        if (enclave_shm[shm_idx].eids->used && enclave_shm[shm_idx].eids->enclave_type == enclave_type){
          eid_next = enclave_shm[shm_idx].eids->eid;
          break;
        }
      }
      if (shm_eid_idx == NUM_EACH_SHM) {
        printm("[SM@%s] enclave_type  %d  Enclave not exist.\n", __func__, enclave_type);
        spin_unlock(&shm_eid_idx_lock);
        spin_unlock(&shm_idx_lock);
        return -1; // -1 被转移的Enclave不存在
      }
      spin_unlock(&shm_eid_idx_lock);
    }else {
      printm("[SM@%s] shmid  %d  share memory not exist.\n", __func__, shmid);
      spin_unlock(&shm_idx_lock);
      return -2; // -2 share memory不存在
    }
    spin_unlock(&shm_idx_lock);

    struct enclave_t* enclave01, *enclave02;
    eid = get_enclave_id();
    enclave01 = get_enclave(eid);
    enclave02 = get_enclave(eid_next);

    spin_lock(&spmp_idx_lock);
    // 关闭当前Enclave共享内存的sPMP权限
    for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
      if(enclave01->enclave_spmp_context[spmp_idx].mode != SPMP_OFF && \
        enclave01->used_shm[spmp_idx] && \
        enclave01->enclave_spmp_context[spmp_idx].paddr == paddr && \
        enclave01->enclave_spmp_context[spmp_idx].size == shm_size){

        enclave01->enclave_spmp_context[spmp_idx].mode = SPMP_OFF;

        spin_lock(&shm_ownership_lock);
        enclave02->shm_ownership = 0;
        spin_unlock(&shm_ownership_lock);

        // set_spmp(spmp_idx, enclave01->enclave_spmp_context[spmp_idx]);
        break;
      }
    }
    spin_unlock(&spmp_idx_lock);
    dump_spmps();


    spin_lock(&spmp_idx_lock);
    // 开启下一个Enclave的sPMP权限
    // 如果下一个Enclave的sPMP寄存器已经与共享内存绑定，那么打开即可
    for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
      if(enclave02->enclave_spmp_context[spmp_idx].mode != SPMP_OFF && \
        enclave02->used_shm[spmp_idx] && \
        enclave02->enclave_spmp_context[spmp_idx].paddr == paddr && \
        enclave02->enclave_spmp_context[spmp_idx].size == shm_size) {

        enclave02->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;

        spin_lock(&shm_ownership_lock);
        enclave02->shm_ownership = 1;
        spin_unlock(&shm_ownership_lock);

        spin_unlock(&spmp_idx_lock);
        return 0;
      }
    }

    // 如果下一个Enclave的sPMP寄存器还未与共享内存绑定，需要建立共享内存的sPMP映射并开启
    for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
      if(enclave02->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
        enclave02->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)paddr;
        enclave02->enclave_spmp_context[spmp_idx].size = shm_size;
        enclave02->enclave_spmp_context[spmp_idx].perm = spmp_perm;
        enclave02->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;
        //sbit默认就是0，其实可以不用再次置为0
        enclave02->enclave_spmp_context->sbit = 0;
        enclave02->used_shm[spmp_idx] = 1;

        spin_lock(&shm_ownership_lock);
        enclave02->shm_ownership = 1;
        spin_unlock(&shm_ownership_lock);

        spin_unlock(&spmp_idx_lock);
        return 0;
      }
    }
  }else{
    struct enclave_t *enclave02;
    // eid = get_enclave_id();
    // enclave01 = get_enclave(eid);

    spin_lock(&shm_idx_lock);
    shm_idx = shmid;
    if (enclave_shm[shm_idx].used){
      paddr = enclave_shm[shm_idx].paddr;
      shm_size = enclave_shm[shm_idx].size;

      // spin_lock(&spmp_idx_lock);
      // for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
      //   if(enclave01->enclave_spmp_context[spmp_idx].mode != SPMP_OFF && 
      //     enclave01->used_shm[spmp_idx] && 
      //     enclave01->enclave_spmp_context[spmp_idx].paddr == paddr && 
      //     enclave01->enclave_spmp_context[spmp_idx].size == shm_size){

      //     enclave01->enclave_spmp_context[spmp_idx].perm = SPMP_R;
      //     set_spmp(spmp_idx, enclave01->enclave_spmp_context[spmp_idx]);
      //     break;
      //   }
      // }
      // spin_unlock(&spmp_idx_lock);
      // dump_spmps();

      spin_lock(&shm_eid_idx_lock);
      for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++){
        if (enclave_shm[shm_idx].eids->used){
          eid_next = enclave_shm[shm_idx].eids->eid;

          enclave02 = get_enclave(eid_next);
          spin_lock(&spmp_idx_lock);
          for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
            if(enclave02->enclave_spmp_context[spmp_idx].mode != SPMP_OFF && \
              enclave02->used_shm[spmp_idx] && \
              enclave02->enclave_spmp_context[spmp_idx].paddr == paddr && \
              enclave02->enclave_spmp_context[spmp_idx].size == shm_size) {

              enclave02->enclave_spmp_context[spmp_idx].perm = SPMP_R;
              break;
            }
          }
          spin_unlock(&spmp_idx_lock);

          if (spmp_idx == NSPMP) {
            spin_lock(&spmp_idx_lock);
            for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
              if(enclave02->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
                enclave02->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)paddr;
                enclave02->enclave_spmp_context[spmp_idx].size = shm_size;
                enclave02->enclave_spmp_context[spmp_idx].perm = SPMP_R;
                enclave02->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;
                enclave02->enclave_spmp_context->sbit = 0;
                enclave02->used_shm[spmp_idx] = 1;
                break;
              }
            }
            spin_unlock(&spmp_idx_lock);
          }
        }
      }
    }
    spin_unlock(&shm_idx_lock);
  }
  return 0;
}*/




/*
// SM需要管理被映射的共享内存被哪几个enclave所映射，解决共享内存的内存回收问题

// 需要的参数，eid:Enclave ID，req_size：key, 请求分配的Enclave内存大小，内存访问权限，
// 返回分配的共享内存大小，虚拟地址，共享内存标识shm_id
// 

// 一个Enclave使用的多个共享内存使用链表进行管理，
// 
// eid 用来定位在哪一个enclave中创建共享内存

virtual_addr_t sm_create_shm(unsigned long key, unsigned long req_size, unsigned long perm){
  dump_spmps();
  printm_err("\n");
  //1. 物理内存分配
  printm("[sm.c@%s] ----------sm create shm start---------\n", __func__);
  unsigned long resp_size = 0;
  // printm("[sm.c%s] the address of resp_size is 0x%p \n", __func__, &resp_size);
  printm("[sm.c@%s] req mem size is %ld\n", __func__, (long int)req_size);
  void* paddr = mm_alloc(req_size, &resp_size);
  if(paddr == NULL)
  {
    printm("[sm.c@%s] no enough memory to create share memory.\r\n", __func__);
    return ENCLAVE_NO_MEMORY;
  }
  printm("[sm.c@%s] paddr = 0x%lx \n", __func__, (unsigned long)paddr);

  u8 spmp_perm = 0, pt_perm = 0;
  // u8 spmp_perm = 0;
  if (perm & SPMP_R)
  {
    spmp_perm |= SPMP_R;
  }
  if (perm & SPMP_W)
  {
    spmp_perm |= SPMP_W;
  }
  
  pt_perm = spmp_perm << 1;
  pt_perm |=  PTE_U;
  // printm(["sm.c@%s] pt_perm = 0x%x\n", __func__, pt_perm);
  // pt_perm |= PTE_D | PTE_A | PTE_R | PTE_W | PTE_U;
  

  // dump_pmps();
  // int* ptr = (int*)paddr;
  // ptr[0] = 1;
  // printm("[sm.c@%s] ptr[0] = %d\n", __func__, ptr[0]);

  // 分配的内存写入测试
  // int* ptr = (int*)paddr;
	// for (int i = 0; i < 10; i++)
	// {
	// 	ptr[i] = i + 10;
	// 	printm("[sm.c@%s] ptr[%d] = %d\n", __func__, i, ptr[i]);
	// }


  printm("[sm.c@%s] alloc mem size is %ld\n", __func__, (long int)resp_size);
  // 
  struct enclave_t* enclave;
  int eid = -1;
  eid = get_enclave_id();
  if (eid != -1)
    printm("[sm.c@%s] get_enclave_id succeed! eid is %d .\n", __func__, eid);
  else {
    printm("[sm.c@%s] get_enclave_id failed! \n", __func__);
    return (virtual_addr_t)0;
  }

  // eid = 0;
  enclave =  get_enclave(eid);

  printm("[sm.c@%s] thread_context.encl_ptbr = 0x%lx, cur_satp = 0x%lx.\n", __func__, enclave->thread_context.encl_ptbr, csr_read(CSR_SATP));
  
  //创建新的共享区需要修改共享区的数量
  spin_lock(&shm_idx_lock);

  for (shm_idx = 0; shm_idx < NUM_SHM; shm_idx++)
  {
    if (!enclave_shm[shm_idx].used)
    {
      enclave_shm[shm_idx].used = 1;
      enclave_shm[shm_idx].key = key;
      enclave_shm[shm_idx].paddr = (unsigned long)paddr;
      enclave_shm[shm_idx].size = (unsigned long)resp_size;
      enclave_shm[shm_idx].perm = spmp_perm;

      //新的共享区指向当前enclave
      spin_lock(&shm_eid_idx_lock);
      for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++)
      {
        if (!enclave_shm[shm_idx].eids_used[shm_eid_idx])
        {
          enclave_shm[shm_idx].eids_used[shm_eid_idx] = 1;
          enclave_shm[shm_idx].eids[shm_eid_idx] = eid;
          break;
        }
        
      }
      spin_unlock(&shm_eid_idx_lock);
      break;
    } 
  }
  spin_unlock(&shm_idx_lock);

  spin_lock(&spmp_idx_lock);
  //2.使用当前enclave的一个sPMP寄存器用来保护当前物理地址
  //从第二个sPMP开始遍历，创建共享区sPMP保护
  for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++)
  {
    if(enclave->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
      enclave->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)paddr;
      enclave->enclave_spmp_context[spmp_idx].size = resp_size;
      enclave->enclave_spmp_context[spmp_idx].perm = spmp_perm;
      enclave->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;
      //sbit默认就是0，其实可以不用再次置为0
      enclave->enclave_spmp_context->sbit = 0;
      enclave->used_shm[spmp_idx] = 1;
      set_spmp(spmp_idx, enclave->enclave_spmp_context[spmp_idx]);
      break;
    }
  }
  spin_unlock(&spmp_idx_lock);
  dump_spmps();
  
  virtual_addr_t shm_va = enclave->shm_ptr;
  //3. 将物理地址映射至创建者的虚拟地址空间中
  int ret = 0; 
  ret = map_pa2va(enclave, shm_va, (physical_addr_t) paddr, resp_size, pt_perm);

  // int* ptr = (int*)paddr;
	// for (int i = 0; i < 20; i++)
	// {
	// 	ptr[i] = i;
	// 	printm("[sm.c@%s] ptr[%d] = %d\n", __func__, i, ptr[i]);
	// }

  uintptr_t shm_pa = get_enclave_paddr_from_va(enclave->root_page_table, shm_va);
  printm("[sm.c@%s] get_enclave_paddr_from_va return shm_pa 0x%lx \n", __func__, (long int)shm_pa);
  if (ret == 0)
  {
	printm("[sm.c@%s] ret shm_va 0x%lx \n", __func__, (long int)shm_va);
    enclave->shm_ptr = (unsigned long)shm_va + resp_size;
    return shm_va;
  }
  
  return (virtual_addr_t)0;
} 
*/

/*
virtual_addr_t sm_map_shm(unsigned long key){
  
  printm("[sm.c@%s] ----------sm map shm start---------\n", __func__);

  struct enclave_t* enclave;
  int eid = -1;
  eid = get_enclave_id();
  if (eid == -1){
    printm("[sm.c@%s] get_enclave_id failed! \n", __func__);
    return (virtual_addr_t)0;
  }
  printm("[sm.c@%s] get_enclave_id succeed! eid is %d .\n", __func__, eid);

  enclave =  get_enclave(eid);

  printm("[sm.c@%s] thread_context.encl_ptbr = 0x%lx, cur_satp = 0x%lx.\n", __func__, enclave->thread_context.encl_ptbr, csr_read(CSR_SATP));
  
  physical_addr_t paddr = (physical_addr_t)0;
  unsigned long size = 0;
  u8 pt_perm = 0;
  //创建新的共享区需要修改共享区的数量
  spin_lock(&shm_idx_lock);

  for (shm_idx = 0; shm_idx < NUM_SHM; shm_idx++)
  {
    if (enclave_shm[shm_idx].used && enclave_shm[shm_idx].key == key)
    {
      spin_lock(&spmp_idx_lock);
      for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++)
      {
        if(enclave->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
          enclave->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;
          enclave->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)enclave_shm[shm_idx].paddr;
          paddr = (physical_addr_t)enclave_shm[shm_idx].paddr;
          enclave->enclave_spmp_context[spmp_idx].size = enclave_shm[shm_idx].size;
          size = enclave_shm[shm_idx].size;
          enclave->enclave_spmp_context[spmp_idx].perm = enclave_shm[shm_idx].perm;
          
          // enclave_shm[shm_idx].perm的权限格式是XWR, PageTable的权限格式是XWRV, 因此需要先左移一位
          pt_perm = enclave_shm[shm_idx].perm;
          pt_perm <<= 1;
          pt_perm |= PTE_U;

          //sbit默认就是0，其实可以不用再次置为0
          enclave->enclave_spmp_context->sbit = 0;
          enclave->used_shm[spmp_idx] = 1;
          set_spmp(spmp_idx, enclave->enclave_spmp_context[spmp_idx]);
          break;
        }
      }
      spin_unlock(&spmp_idx_lock);

      spin_lock(&shm_eid_idx_lock);
      for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++)
      {
        if (!enclave_shm[shm_idx].eids_used[shm_eid_idx])
        {
          enclave_shm[shm_idx].eids_used[shm_eid_idx] = 1;
          enclave_shm[shm_idx].eids[shm_eid_idx] = eid;
          break;
        }
      }
      spin_unlock(&shm_eid_idx_lock);
      break;
    } 
  }
  if(shm_idx == NUM_SHM){
    printm("[sm.c@%s] get shm which the key is %ld failed! \n", __func__, key);
    return (virtual_addr_t)0;
  }
  spin_unlock(&shm_idx_lock);

  dump_spmps();
  
  virtual_addr_t shm_va = enclave->shm_ptr;
  //3. 将物理地址映射至创建者的虚拟地址空间中
  int ret = -1; 
  if (paddr && size){
    ret = map_pa2va(enclave, shm_va, paddr, size, pt_perm);
  }

  if (ret == 0){
    uintptr_t shm_pa = get_enclave_paddr_from_va(enclave->root_page_table, shm_va);
    printm("[sm.c@%s] get_enclave_paddr_from_va return shm_pa 0x%lx \n", __func__, (long int)shm_pa);
	  printm("[sm.c@%s] ret shm_va 0x%lx \n", __func__, (long int)shm_va);
    enclave->shm_ptr = (unsigned long)shm_va + size;
    return shm_va;
  }
  return (virtual_addr_t)0;
}
*/

/*
int sm_transfer_shm(int key){
  int eid01 = -1, eid02 = -1;
  eid01 = get_enclave_id();
  printm("[SM@%s] the Enclave being shared eid01 is %d\n", __func__, eid01);
  struct enclave_t* enclave01,* enclave02;
  enclave01 = get_enclave(eid01);

  size_t i = 0, j = 0, k = 0;
  //1. 找到key对应的enclave，取消之前的enclave对共享区的所有权
  for (i = 0; i < NUM_SHM; i++)
  {
    if (enclave_shm[i].used && key == enclave_shm[i].key)
    {
      // 找到enclave02
      eid02 = enclave_shm[i].eids[0];
      // 找到之后，拥有此共享内存所有权的enclave便是enclave01
      enclave_shm[i].eids[0] = eid01;
      printm("[SM@%s] the share Enclave eid02 is %d\n", __func__, eid02);
      break;
    }
  }
  
  enclave02 = get_enclave(eid02);

  // 查找enclave01空闲的SPMP
  for (j = 2; j < NSPMP; j++)
  {
    if (enclave01->enclave_spmp_context[j].mode == SPMP_OFF)
      break;
  }

  // i 指向找到的共享内存的编号， j 指向enclave01的第一个空闲sPMP, k指向enclave02中指向当前paddr的sPMP编号
  // 取消enclave02的所有权，并将其转移到enclave01
  for (k = 2; k < NSPMP; k++)
  {
    if (enclave02->enclave_spmp_context[k].paddr == enclave_shm[i].paddr && enclave02->used_shm[k] == 1)
    {
      // enclave01->enclave_spmp_context[j].mode = PMP_A_NAPOT;
      // enclave01->enclave_spmp_context[j].paddr = (uintptr_t)enclave_shm[i].paddr;
      // enclave01->enclave_spmp_context[j].size = enclave_shm[i].size;
      // enclave01->enclave_spmp_context[j].sbit = 0;
      // enclave01->enclave_spmp_context[j].perm = SPMP_NO_PERM;
      // enclave01->used_shm[j] = 1;
      
      
      enclave01->enclave_spmp_context[j].mode = enclave02->enclave_spmp_context[k].mode;
      enclave01->enclave_spmp_context[j].paddr = enclave02->enclave_spmp_context[k].paddr;
      enclave01->enclave_spmp_context[j].size = enclave02->enclave_spmp_context[k].size;
      enclave01->enclave_spmp_context[j].sbit = 0;
      // 以下两步实现共享内存权限的转移
      enclave01->enclave_spmp_context[j].perm = enclave02->enclave_spmp_context[k].perm; 
      enclave02->enclave_spmp_context[k].perm = SPMP_NO_PERM;
      // enclave02 是关闭当前SPMP还是仅仅取消共享区域的读写权限呢？
      
      enclave01->used_shm[j] = 1;
      // enclave02->enclave_spmp_context[k].mode = SPMP_OFF;
      // enclave02->used_shm[k] = 0;
      break;
    }
  }
  
  return 0;

  // 授予当前enclave共享区的所有权
  
}
*/

// virtual_addr_t sm_create_shm(unsigned long key, unsigned long req_size, unsigned long perm){
//   //申请安全物理内存
//   void* paddr = mm_alloc(req_size, &resp_size);
//   eid = get_enclave_id();
//   enclave =  get_enclave(eid);
//   for (shm_idx = 0; shm_idx < NUM_SHM; shm_idx++){
//     if (!enclave_shm[shm_idx].used){
//       enclave_shm[shm_idx].used = 1;
//       enclave_shm[shm_idx].key = key;
//       enclave_shm[shm_idx].paddr = (unsigned long)paddr;
//       enclave_shm[shm_idx].size = (unsigned long)resp_size;
//       enclave_shm[shm_idx].perm = spmp_perm;
//       //将SM管理的共享区和当前Enclave绑定
//       for (shm_eid_idx = 0; shm_eid_idx < NUM_EACH_SHM; shm_eid_idx++){
//         if (!enclave_shm[shm_idx].eids_used[shm_eid_idx]){
//           enclave_shm[shm_idx].eids_used[shm_eid_idx] = 1;
//           enclave_shm[shm_idx].eids[shm_eid_idx] = eid;
//           break;
//         }
//       }
//       break;
//     } 
//   }
//   //使用当前enclave的一组空闲sPMP寄存器用来保护当前物理地址
//   for (spmp_idx = 2; spmp_idx < NSPMP; spmp_idx++){
//     if(enclave->enclave_spmp_context[spmp_idx].mode == SPMP_OFF){
//       enclave->enclave_spmp_context[spmp_idx].paddr = (uintptr_t)paddr;
//       enclave->enclave_spmp_context[spmp_idx].size = resp_size;
//       enclave->enclave_spmp_context[spmp_idx].perm = spmp_perm;
//       enclave->enclave_spmp_context[spmp_idx].mode = SPMP_NAPOT;
//       enclave->enclave_spmp_context->sbit = 0;
//       enclave->used_shm[spmp_idx] = 1;
//       set_spmp(spmp_idx, enclave->enclave_spmp_context[spmp_idx]);
//       break;
//     }
//   }
//   virtual_addr_t shm_va = enclave->shm_ptr;
//   //将物理地址映射至共享内存创建者的虚拟地址空间中
//   ret = map(enclave, shm_va, (physical_addr_t) paddr, resp_size, pt_perm);
//   //检查页表映射是否正确
//   uintptr_t shm_pa = get_enclave_paddr_from_va(enclave->root_page_table, shm_va);
//   printm("[sm.c@%s] get_enclave_paddr_from_va return shm_pa 0x%lx \n", __func__, (long int)shm_pa);
//   if (ret == 0){
//     enclave->shm_ptr = (unsigned long)shm_va + resp_size;
//     return shm_va;
//   }
//   return (virtual_addr_t)0;
// }

