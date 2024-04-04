#include <sm/sm.h>
#include <sm/enclave.h>
#include <sm/platform/pmp/enclave_mm.h>
#include <sm/platform/spmp/spmp.h>
//#include <sm/atomic.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_locks.h>
//#include "mtrap.h"
#include <sm/math.h>
#include <sbi/sbi_string.h>

/*
 * Only NPMP-3 enclave regions are supported.
 * The last PMP is used to allow kernel to access memory.
 * The 1st PMP is used to protect security monitor from kernel.
 * The 2nd PMP is used to allow kernel to configure enclave's page table.
 * Othres, (NPMP-3) PMPs are for enclaves, i.e., secure memory
 *
 * TODO: this array can be removed as we can get
 * existing enclave regions via pmp registers
 */
// SM负责管理mm_regions数据结构
static struct mm_region_t mm_regions[N_PMP_REGIONS];
static unsigned long pmp_bitmap = 0;
static spinlock_t pmp_bitmap_lock = SPIN_LOCK_INITIALIZER;


int check_mem_overlap(uintptr_t paddr, unsigned long size)
{
	unsigned long sm_base = SM_BASE;
	unsigned long sm_size = SM_SIZE;
	int region_idx = 0;

	//check whether the new region overlaps with security monitor
	if(region_overlap(sm_base, sm_size, paddr, size))
	{
		printm_err("pmp memory overlaps with security monitor!\r\n");
		return -1;
	}

	//check whether the new region overlap with existing enclave region
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid
				&& region_overlap(mm_regions[region_idx].paddr, mm_regions[region_idx].size,
					paddr, size))
		{
			printm_err("pmp memory overlaps with existing pmp memory!\r\n");
			return -1;
		}
	}

	return 0;
}

int data_is_nonsecure(uintptr_t paddr, unsigned long size)
{
	return !check_mem_overlap(paddr, size);
}

// 将数据从内核内存区域拷贝至Enclave 的安全内存区域
uintptr_t copy_from_host(void* dest, void* src, size_t size)
{
	int retval = -1;
	//get lock to prevent TOCTTOU
	spin_lock(&pmp_bitmap_lock);

	//check data is nonsecure
	//prevent coping from memory in secure region
	if(data_is_nonsecure((uintptr_t)src, size))
	{
		sbi_memcpy(dest, src, size);
		retval = 0;
	}

	spin_unlock(&pmp_bitmap_lock);
	return retval;
}

// 将数据从Enclave的安全内存拷贝至内核内存区域
uintptr_t copy_to_host(void* dest, void* src, size_t size)
{
	int retval = -1;
	spin_lock(&pmp_bitmap_lock);

	//check data is nonsecure
	//prevent coping from memory in secure region
	if(data_is_nonsecure((uintptr_t)dest, size))
	{
		sbi_memcpy(dest, src, size);
		retval = 0;
	}

	spin_unlock(&pmp_bitmap_lock);
	return retval;
}

// 将一个word的内存数据从Enclave的安全内存拷贝至内核内存区域
int copy_word_to_host(unsigned int* ptr, uintptr_t value)
{
	int retval = -1;
	spin_lock(&pmp_bitmap_lock);

	//check data is nonsecure
	//prevent coping from memory in secure region
	if(data_is_nonsecure((uintptr_t)ptr, sizeof(unsigned int)))
	{
		*ptr = value;
		retval = 0;
	}

	spin_unlock(&pmp_bitmap_lock);
	return retval;
}

static inline uintptr_t pte2pa(pte_t pte)
{
	return (pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
}

static inline int get_pt_index(uintptr_t vaddr, int level)
{
	int index = vaddr >> (VA_BITS - (level + 1)*RISCV_PGLEVEL_BITS);

	return index & ((1 << RISCV_PGLEVEL_BITS) - 1) ;
}


// SM 使用软件的方式便利Enclave 的页表，并返回查找物理页的PTE的物理地址
static pte_t* walk_enclave_pt(pte_t *enclave_root_pt, uintptr_t vaddr)
{
	pte_t *pgdir = enclave_root_pt;
	int i;
	int level = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS;
	for (i = 0; i < level - 1; i++)
	{
		int pt_index = get_pt_index(vaddr , i);
		pte_t pt_entry = pgdir[pt_index];
		if(unlikely(!PTE_TABLE(pt_entry)))
		{
			return 0;
		}
		pgdir = (pte_t *)pte2pa(pt_entry);
	}

	return &pgdir[get_pt_index(vaddr , level - 1)];
}

// 递归遍历Enclave的页表
static int iterate_over_enclave_pages(pte_t* ptes, int level, uintptr_t va,
					int (*check)(uintptr_t, uintptr_t, int))
{
	uintptr_t pte_per_page = RISCV_PGSIZE/sizeof(pte_t);
	pte_t *pte;
	uintptr_t i = 0;

	//should never happen
	if(level <= 0)
		return 1;

	for(pte = ptes, i = 0; i < pte_per_page; pte += 1, i += 1)
	{
		if(!(*pte & PTE_V))
		{
			continue;
		}

		uintptr_t curr_va = 0;
		if(level == ((VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS))
			curr_va = (uintptr_t)(-1UL << VA_BITS) +
				(i << (VA_BITS - RISCV_PGLEVEL_BITS));
		else
			curr_va = va +
				(i << ((level-1) * RISCV_PGLEVEL_BITS + RISCV_PGSHIFT));
		uintptr_t pa = (*pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

		//found leaf pte
		if ((*pte & PTE_R) || (*pte & PTE_X)) {
			//4K page
			if (level == 1) {
				// curr_va 与 umem 和 kbuffer所在的虚拟地址范围不重合 且 pa 在enclave的安全内存中
				if (check(curr_va, pa, 1 << RISCV_PGSHIFT) != 0)
					return -1;
			}
			//2M page
			else if (level == 2) {
				if (check(curr_va, pa, 1 << (RISCV_PGSHIFT +
						RISCV_PGLEVEL_BITS)) != 0)
					return -1;
			}
		} else {
			if (iterate_over_enclave_pages((pte_t *)pa, level - 1,
							   curr_va, check) != 0)
				return -1;
		}
	}

	return 0;
}

/**
 * \brief This function check the enclave page table set up by
 * kernel driver. Check two things:
 *  1. Enclave's trusted memory pages are mapped to its own secure
 *	 memory, falling within a pmp region and not out of bound to
 *	 other enclave's memory.
 *  2. Untrusted memory and kbuffer are mapped to normal kernel
 *	 memory that doesn't belong to any existing pmp regions.
 * 
 * Note: 
 *   Need invocate hash_verify() and whitelist_check() first to
 * guarantee the validness of enclave vaddr and the authenticity
 * of untrusted memory and kbuffer which were passed by kernel
 * driver. 
 *   When SM hash an enclave, it will take into account configuration
 * parameters such as untrusted memory and kbuffer (each has two
 * part: a start vaddr in enclave address space and a size).
 */

void __riscv_flush_icache(void) {
  __asm__ volatile ("fence.i");
}


// 保证enclave的虚拟地址与umem 和 kbuffer地址空间不重合，并且所有的物理页都在安全内存中
int check_enclave_pt(struct enclave_t *enclave)
{
	uintptr_t retval = 0;

	// 将untrusted 和 kbuffer的虚拟地址的高32位置1，表示在用户地址空间
	// umem and kbuffer pointer specified by user may only specify
	// low-order VA_BITS bits, but without high-order 1s.
	unsigned long enclave_untrusted_vaddr =
		(uintptr_t)(-1UL << VA_BITS) | enclave->untrusted_ptr;
	unsigned long enclave_kbuffer_vaddr =
		(uintptr_t)(-1UL << VA_BITS) | enclave->kbuffer;
	unsigned long page_mask = (1 << RISCV_PGSHIFT) - 1;

	// 检查umem 和 kbuffer 指针和大小是否页对齐
	// check umem and kbuffer pointer and size, align by page.
	if ((enclave_untrusted_vaddr & page_mask) != 0 ||
		(enclave->untrusted_size & page_mask) != 0 ||
		(enclave_kbuffer_vaddr & page_mask) != 0 ||
		(enclave->kbuffer_size & page_mask) != 0) {
		printm_err(
			"[Penglai Monitor@%s] Error: Enclave untrusted mem or "
			"kbuffer are not aligned by page.\r\n",
			__func__);
		return -1;
	}

	/* For Debug */
	printm("Enclave's own secure momery: pa: 0x%lx, size: 0x%lx\r\n",
		enclave->paddr, enclave->size);


	// 函数内定义函数
	// check trusted mem, untrusted mem and kbuffer
	int check_page(uintptr_t va, uintptr_t pa, int page_size)
	{
		// 检查umem 和 kbuffer中是否包含va所在区域，要求va 所在区域不能与umem 和 kbuffer 所在区域重合
		if (region_contain(enclave_untrusted_vaddr,
				   enclave->untrusted_size, va, page_size) ||
			region_contain(enclave_kbuffer_vaddr, enclave->kbuffer_size, va,
				   page_size)) {
			if (!data_is_nonsecure(pa, page_size)) {
				printm_err("Error: untrusted memory pages fall within "
					"secure region! va: 0x:%lx, pa: 0x%lx, size: 0x%x\r\n",
					va, pa, page_size);
				return -1;
			}
		} else {
			// 要求enclave所在区域包含 pa 所在区域
			if (!region_contain(enclave->paddr, enclave->size, pa,
						page_size)) {
				printm_err(
					"Error: trusted memory pages fall out of enclave's "
					"own secure momery! va: 0x%lx, pa: 0x%lx, size: 0x%x\r\n",
					va, pa, page_size);
				return -1;
			}
		}

		return 0;
	}
	retval = iterate_over_enclave_pages(
		(pte_t*)(enclave->thread_context.encl_ptbr << RISCV_PGSHIFT),
		(VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS, 0, check_page
	);
	if(retval != 0){
		printm_err("[Penglai Monitor@%s] Error: Enclave page table check failed, retval %d.\n",
			__func__, (int)retval);
		return -1;
	}

	return 0;
}

// 通过虚拟地址遍历enclave的页表获取enclave的物理地址
uintptr_t get_enclave_paddr_from_va(pte_t *enclave_root_pt, uintptr_t vaddr)
{
	pte_t *pte = walk_enclave_pt(enclave_root_pt, vaddr);
	if(!(*pte & PTE_V)){
		return 0;
	}
	uintptr_t pa = pte2pa(*pte) | (vaddr & ((1 << PAGE_SHIFT) - 1));
	return pa;
}

// 从enclave虚拟内存地址拷贝到目的物理内存，每次页拷贝需要遍历enclave页表查找源物理地址
uintptr_t copy_from_enclave(pte_t *enclave_root_pt, void* dest_pa, void* src_enclave_va, size_t size)
{
	uintptr_t src_pa;
	uintptr_t page_offset = (uintptr_t)src_enclave_va & ((1 << PAGE_SHIFT) - 1);
	uintptr_t page_left = PAGE_SIZE - page_offset;
	uintptr_t left_size = size;
	uintptr_t copy_size;
	// 如果拷贝的内存大小在一个物理页内，一次拷贝即可
	if (page_left >= left_size) {
		
		copy_size = left_size;
		src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
		if(src_pa == 0)
		{
			sbi_printf("ERROR: va is not mapped\n");
			return -1;
		}
		sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
	}
	else {
		// 否则，先拷贝第一个物理页的剩余部分
		copy_size = page_left;
		src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
		if(src_pa == 0)
		{
			sbi_printf("ERROR: va is not mapped\n");
			return -1;
		}
		sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
		left_size -= page_left;
		src_enclave_va += page_left;
		dest_pa += page_left;
		// 考虑剩余的拷贝内存是一整个物理页还是不到一整个物理页
		while(left_size > 0){
			copy_size = (left_size > PAGE_SIZE) ? PAGE_SIZE : left_size;
			src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
			if(src_pa == 0)
			{
				sbi_printf("ERROR: va is not mapped\n");
				return -1;
			}
			sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
			left_size -= copy_size;
			src_enclave_va += copy_size;
			dest_pa += page_left;
		}
	}

	return 0;
}


// enclave拥有自己单独的页表，如果需要从enclave外向enclave内拷贝数据，需要手动遍历enclave的页表
uintptr_t copy_to_enclave(pte_t *enclave_root_pt, void* dest_enclave_va, void* src_pa, size_t size)
{
	uintptr_t dest_pa;
	uintptr_t page_offset = (uintptr_t)dest_enclave_va & ((1 << PAGE_SHIFT) - 1);
	uintptr_t page_left = PAGE_SIZE - page_offset;
	uintptr_t left_size = size;
	uintptr_t copy_size;
	if (page_left >= left_size) {
		// do copy in one time
		copy_size = left_size;
		dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
		if(dest_pa == 0)
		{
			sbi_printf("ERROR: va is not mapped\n");
			return -1;
		}
		sbi_memcpy((void *)dest_pa, src_pa, copy_size);
	}
	else {
		// do copy in the first page
		copy_size = page_left;
		dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
		if(dest_pa == 0)
		{
			sbi_printf("ERROR: va is not mapped\n");
			return -1;
		}
		sbi_memcpy((void *)dest_pa, src_pa, copy_size);
		left_size -= page_left;
		dest_enclave_va += page_left;
		src_pa += page_left;
		// do while for other pages
		while(left_size > 0){
			copy_size = (left_size > PAGE_SIZE) ? PAGE_SIZE : left_size;
			dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
			if(dest_pa == 0)
			{
				sbi_printf("ERROR: va is not mapped\n");
				return -1;
			}
			sbi_memcpy((void *)dest_pa, src_pa, copy_size);
			left_size -= copy_size;
			dest_enclave_va += copy_size;
			src_pa += page_left;
		}
	}

	return 0;
}

// enclave的内存大小需要是2的幂次方，不能小于一个页，且是size大小对齐
/*
 * Check the validness of the paddr and size
 * */
static int check_mem_size(uintptr_t paddr, unsigned long size)
{
	if((size == 0) || (size & (size - 1)))
	{
		printm_err("pmp size should be 2^power!\r\n");
		return -1;
	}

	if(size < RISCV_PGSIZE)
	{
		printm_err("pmp size should be no less than one page!\r\n");
		return -1;
	}

	if(paddr & (size - 1))
	{
		printm_err("pmp size should be %ld aligned!\r\n", size);
		return -1;
	}

	return 0;
}

/*   可能会出现UAF这种情况
 * TODO: we should protect kernel temporal region with lock
 * 	 A possible malicious case:
 * 	 	kernel@Hart-0: acquire memory region, set to PMP-1
 * 	 	kernel@Hart-1: acquire memory region, set to PMP-1 <- this will overlap the prior region
 * 	 	kernel@Hart-0: release memory region <- dangerous behavior now
 * */

/**
 * \brief This function grants kernel (temporaily) access to allocated enclave memory
 * 	  for initializing enclave and configuring page table.
 */

// 配置PMP1寄存器授予内核访问刚分配给enclave安全内存的权限，用于内核初始化enclave
//（加载ELF文件至安全内存，内核数据结构管理enclave的free_mem，分配umem和kbuffer并配置enclave页表）
int grant_kernel_access(void* req_paddr, unsigned long size)
{
	//pmp1 is used for allowing kernel to access enclave memory
	int pmp_idx = 1;
	struct pmp_config_t pmp_config;
	uintptr_t paddr = (uintptr_t)req_paddr;

	pmp_config = get_pmp(pmp_idx);
	if((pmp_config.mode != PMP_OFF))
	{
		printm_err(
			"grant_kernel_access: can't grant kernel access to a new memory"
			"region if kernel has already access to another one\r\n");
		return -1;
	}

	if(check_mem_size(paddr, size) != 0){
		printm("[Penglai Monitor@%s] check_mem_size failed\n", __func__);
		return -1;
	}

	pmp_config.paddr = paddr;
	pmp_config.size = size;
	pmp_config.perm = PMP_R | PMP_W | PMP_X;
	pmp_config.mode = PMP_A_NAPOT;
	set_pmp_and_sync(pmp_idx, pmp_config);

	return 0;
}

/*
 * This function retrieves kernel access to allocated enclave memory.
 */

// 配置PMP1寄存器撤销内核访问enclave安全内存的权限
int retrieve_kernel_access(void* req_paddr, unsigned long size)
{
	//pmp1 is used for allowing kernel to access enclave memory
	int pmp_idx = 1;
	struct pmp_config_t pmp_config;
	uintptr_t paddr = (uintptr_t)req_paddr;

	pmp_config = get_pmp(pmp_idx);

	if((pmp_config.mode != PMP_A_NAPOT) || (pmp_config.paddr != paddr) || (pmp_config.size != size))
	{
		printm_err("retrieve_kernel_access: error pmp_config\r\n");
		return -1;
	}

	clear_pmp_and_sync(pmp_idx);

	return 0;
}


// 配置PMP寄存器授予enclave所在区域读写执行的权限
// grant enclave access to enclave's memory
int grant_enclave_access(struct enclave_t* enclave)
{
	int region_idx = 0;
	int pmp_idx = 0;
	struct pmp_config_t pmp_config;

	if(check_mem_size(enclave->paddr, enclave->size) < 0)
		return -1;

	//set pmp permission, ensure that enclave's paddr and size is pmp legal
	//TODO: support multiple memory regions
	spin_lock(&pmp_bitmap_lock);
	// 遍历寻找包含enclave内存区域的mm_regions内存区域
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid && region_contain(
					mm_regions[region_idx].paddr, mm_regions[region_idx].size,
					enclave->paddr, enclave->size))
		{
			break;
		}
	}
	spin_unlock(&pmp_bitmap_lock);

	if(region_idx >= N_PMP_REGIONS)
	{
		printm_err("M mode: grant_enclave_access: can not find exact mm_region\r\n");
		return -1;
	}

	pmp_idx = REGION_TO_PMP(region_idx);
#if 1
	// pmp_config.paddr = enclave->paddr;
	// pmp_config.size = enclave->size;
	pmp_config.paddr = mm_regions[region_idx].paddr;
	pmp_config.size = mm_regions[region_idx].size;
#else
	/* Even if we set this PMP region only contain the enclave's secure memory,
	 * the enclave still have access to the secure memory of other enclaves,
	 * which using the same pmp to protect their memory from OS access before.
	 * That's because the last pmp makes all momery accessible.
	 * And we rule out this possibility by checking the enclave page table.
	 *
	 * So we just make this PMP region readable, writable and executable.
	 */
	pmp_config.paddr = mm_regions[region_idx].paddr;
	pmp_config.size = mm_regions[region_idx].size;
#endif
	pmp_config.perm = PMP_R | PMP_W | PMP_X;
	pmp_config.mode = PMP_A_NAPOT;

	/* Note: here we only set the PMP regions in local Hart*/
	set_pmp(pmp_idx, pmp_config);
	// printm("[SM@%s] current Enclave is protected by pmp[%d], paddr = 0x%lx, size = %ld \n", __func__, pmp_idx, pmp_config.paddr, pmp_config.size);
	/*FIXME: we should handle the case that the PMP region contains larger region */
	// if (pmp_config.paddr != enclave->paddr || pmp_config.size != enclave->size){
	// 	printm("[Penglai Monitor@%s] warning, region != enclave mem\n", __func__);
	// 	printm("[Penglai Monitor@%s] region: paddr(0x%lx) size(0x%lx)\n",
	// 			__func__, pmp_config.paddr, pmp_config.size);
	// 	printm("[Penglai Monitor@%s] enclave mem: paddr(0x%lx) size(0x%lx)\n",
	// 			__func__, enclave->paddr, enclave->size);
	// }

	return 0;
}


// 配置PMP寄存器撤销enclave在该安全内存区域上的权限
int retrieve_enclave_access(struct enclave_t *enclave)
{
	int region_idx = 0;
	int pmp_idx = 0;
	struct pmp_config_t pmp_config;

	//set pmp permission, ensure that enclave's paddr and size is pmp legal
	//TODO: support multiple memory regions
	spin_lock(&pmp_bitmap_lock);
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid && region_contain(
					mm_regions[region_idx].paddr, mm_regions[region_idx].size,
					enclave->paddr, enclave->size))
		{
			break;
		}
	}
	spin_unlock(&pmp_bitmap_lock);

	if(region_idx >= N_PMP_REGIONS)
	{
		printm_err("M mode: Error: %s\r\n", __func__);
		/* For Debug */
		for (region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx) {
			printm("[Monitor Debug@%s] mm_region[%d], valid(%d), paddr(0x%lx) size(0x%lx)\n",
					__func__, region_idx, mm_regions[region_idx].valid, mm_regions[region_idx].paddr,
					mm_regions[region_idx].size);
		}
		printm("[Monitor Debug@%s] enclave paddr(0x%lx) size(0x%lx)\n",
				__func__, enclave->paddr, enclave->size);

		return -1;
	}

	pmp_idx = REGION_TO_PMP(region_idx);

	// set PMP to protect the entire PMP region
	pmp_config.paddr = mm_regions[region_idx].paddr;
	pmp_config.size = mm_regions[region_idx].size;
	pmp_config.perm = PMP_NO_PERM;
	pmp_config.mode = PMP_A_NAPOT;

	/* Note: here we only set the PMP regions in local Hart*/
	set_pmp(pmp_idx, pmp_config);

	return 0;
}


// 分配一组PMP寄存器，配置其保护某段物理内存，并维护SM中的mm_regions数据结构和Enclave安全内存中的mm_list_head和mm_list数据结构
uintptr_t mm_init(uintptr_t paddr, unsigned long size)
{
	uintptr_t retval = 0;
	int region_idx = 0;
	int pmp_idx =0;
	struct pmp_config_t pmp_config;

	//check align of paddr and size
	if(check_mem_size(paddr, size) < 0)
		return -1UL;

	//acquire a free enclave region
	spin_lock(&pmp_bitmap_lock);

	//check memory overlap
	//memory overlap should be checked after acquire lock
	if(check_mem_overlap(paddr, size) < 0)
	{
		retval = -1UL;
		goto out;
	}

	// 通过遍历寻找一组空闲的pmp寄存器
	// alloc a free pmp
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		pmp_idx = REGION_TO_PMP(region_idx);
		if(!(pmp_bitmap & (1<<pmp_idx)))
		{
			//FIXME: we already have mm_regions[x].valid, why pmp_bitmap again
			pmp_bitmap |= (1 << pmp_idx);
			break;
		}
	}
	if(region_idx >= N_PMP_REGIONS)
	{
		retval = -1UL;
		goto out;
	}

	//set PMP to protect enclave memory region
	pmp_config.paddr = paddr;
	pmp_config.size = size;
	pmp_config.perm = PMP_NO_PERM;
	pmp_config.mode = PMP_A_NAPOT;
	set_pmp_and_sync(pmp_idx, pmp_config);

	// 一组PMP寄存器保护的物理内存和一个mm_region相对应，mm_region是PMP保护内存区域的内存数据结构表示
	// mm_regions数据结构在SM的内存区域，由SM负责管理，mm_region 的mm_list_head指向enclave安全内存中的mm_list_head数据结构
	//mark this region is valid and init mm_list
	mm_regions[region_idx].valid = 1;
	mm_regions[region_idx].paddr = paddr;
	mm_regions[region_idx].size = size;
	// mm_list_head使用伙伴系统管理分配的连续物理内存，
	// mm_list_head 和 mm_list数据结构在enclave的安全内存中，而且mm_list_head和第一个mm_list紧挨着
	struct mm_list_t *mm_list = (struct mm_list_t*)PADDR_2_MM_LIST(paddr);
	mm_list->order = ilog2(size-1) + 1;
	mm_list->prev_mm = NULL;
	mm_list->next_mm = NULL;
	struct mm_list_head_t *mm_list_head = (struct mm_list_head_t*)paddr;
	mm_list_head->order = mm_list->order;
	mm_list_head->prev_list_head = NULL;
	mm_list_head->next_list_head = NULL;
	mm_list_head->mm_list = mm_list;
	mm_regions[region_idx].mm_list_head = mm_list_head;

out:
	spin_unlock(&pmp_bitmap_lock);
	return retval;
}


// 删除一个块就是双向链表的删除操作，考虑是否有前驱、后继，或者只有当前一个节点
//NOTE: this function may modify the arg mm_list_head
//remember to acquire lock before calling this function
//be sure that mm_region does exist in mm_list and mm_list does exist in mm_lists
static int delete_certain_region(int region_idx, struct mm_list_head_t** mm_list_head, struct mm_list_t *mm_region)
{
	struct mm_list_t* prev_mm = mm_region->prev_mm;
	struct mm_list_t* next_mm = mm_region->next_mm;
	struct mm_list_head_t* prev_list_head = (*mm_list_head)->prev_list_head;
	struct mm_list_head_t* next_list_head = (*mm_list_head)->next_list_head;

	//delete mm_region from old mm_list
	//mm_region is in the middle of the mm_list
	if(prev_mm)
	{
		// 如果前驱存在，前驱的后继就是当前的后继
		prev_mm->next_mm = next_mm;
		// 如果后继存在，后继的前驱就是当前的前驱
		if(next_mm)
			next_mm->prev_mm = prev_mm;
	}
	//mm_region is in the first place of old mm_list
	// 如果当前块是mm_list中的第一个块，那么需要修改mm_list_head信息，因为mm_list_head和mm_list的第一个节点是紧挨着的
	else if(next_mm)
	{
		// 如果当前块没有前驱只有后继，那么后继的前驱为空
		next_mm->prev_mm = NULL;
		// 当删除的块是第一个块时，需要创建新的mm_list_head——new_list_head，配置其Order，prev_list_head, next_list_head和mm_list
		struct mm_list_head_t* new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(next_mm);
		new_list_head->order = next_mm->order;
		new_list_head->prev_list_head = prev_list_head;
		new_list_head->next_list_head = next_list_head;
		new_list_head->mm_list = next_mm;
		if(prev_list_head)
			// 如果prev_list_head存在，prev_head的后继是new_list_head
			prev_list_head->next_list_head = new_list_head;
		else
			// 如果prev_list_head不存在，那么new_list_head将会是第一个mm_list_head，需要修改mm_regions的mm_list_head的指向
			mm_regions[region_idx].mm_list_head = new_list_head;
		if(next_list_head)
			// 如果next_list_head存在，那么next_list_head的
			next_list_head->prev_list_head = new_list_head;

		*mm_list_head = new_list_head;
	}
	//mm_region is the only region in old mm_list
	else
	{
		// 该链表上只有一个内存块，需要删除块所在的mm_list_head
		if(prev_list_head)
			prev_list_head->next_list_head = next_list_head;
		else
			mm_regions[region_idx].mm_list_head = next_list_head;
		if(next_list_head)
			next_list_head->prev_list_head = prev_list_head;

		*mm_list_head = NULL;
	}

	return 0;
}

// 在某个Enclave中请求一块指定大小的安全内存区域，遍历链表分配一块不小于其请求大小的物理块，并通过伙伴系统划分分配
//remember to acquire a lock before calling this function
static struct mm_list_t* alloc_one_region(int region_idx, int order)
{
	if(!mm_regions[region_idx].valid || !mm_regions[region_idx].mm_list_head)
	{
		printm("M mode: alloc_one_region: m_regions[%d] is invalid/NULL\r\n", region_idx);
		return NULL;
	}

	struct mm_list_head_t *mm_list_head = mm_regions[region_idx].mm_list_head;
	while(mm_list_head && (mm_list_head->order < order))
	{
		mm_list_head = mm_list_head->next_list_head;
	}

	//current region has no enough free space
	if(!mm_list_head)
		return NULL;

	//pick a mm region from current mm_list
	struct mm_list_t *mm_region = mm_list_head->mm_list;

	//delete the mm region from current mm_list
	delete_certain_region(region_idx, &mm_list_head, mm_region);

	return mm_region;
}

// 
//remember to acquire lock before calling this function
//be sure that mm_list_head does exist in mm_lists
static int merge_regions(int region_idx, struct mm_list_head_t* mm_list_head, struct mm_list_t *mm_region)
{
	if(region_idx<0 || region_idx>=N_PMP_REGIONS || !mm_list_head || !mm_region)
		return -1;
	if(mm_list_head->order != mm_region->order)
		return -1;

	struct mm_list_head_t* current_list_head = mm_list_head;
	struct mm_list_t* current_region = mm_region;
	// 外层循环将小的内存块进行合并
	while(current_list_head)
	{
		// 互为伙伴的两个内存块，地址位只有一位不同，内层循环遍历每一个mm_list_head中的mm_list，寻找伙伴块
		struct mm_list_t* buddy_region = current_list_head->mm_list;
		unsigned long paddr = (unsigned long)MM_LIST_2_PADDR(current_region);
		unsigned long buddy_paddr = (unsigned long)MM_LIST_2_PADDR(buddy_region);
		while(buddy_region)
		{
			buddy_paddr = (unsigned long)MM_LIST_2_PADDR(buddy_region);
			if((paddr | (1 << current_region->order)) == (buddy_paddr | (1 << current_region->order)))
				break;
			buddy_region = buddy_region->next_mm;
		}

		struct mm_list_head_t* new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(current_region);
		struct mm_list_head_t* prev_list_head = current_list_head->prev_list_head;
		struct mm_list_head_t* next_list_head = current_list_head->next_list_head;
		//didn't find buddy region, just insert this region in current mm_list
		// 没有找到伙伴内存块，直接插入到当前的mm_list中
		if(!buddy_region)
		{
			current_region->prev_mm = NULL;
			current_region->next_mm = current_list_head->mm_list;
			current_list_head->mm_list->prev_mm = current_region;
			new_list_head->order = current_region->order;
			new_list_head->prev_list_head = prev_list_head;
			new_list_head->next_list_head = next_list_head;
			new_list_head->mm_list = current_region;

			if(prev_list_head)
				prev_list_head->next_list_head = new_list_head;
			else
				mm_regions[region_idx].mm_list_head = new_list_head;
			if(next_list_head)
				next_list_head->prev_list_head = new_list_head;

			break;
		}

		//found buddy_region, merge it and current region

		//first delete buddy_region from old mm_list
		//Note that this function may modify prev_list and next_list
		//but won't modify their positions relative to new mm_region
		// 如果找到伙伴块，首先将伙伴块从mm_list中删除，然后将其和当前块进行合并
		delete_certain_region(region_idx, &current_list_head, buddy_region);

		//then merge buddy_region with current region
		int order = current_region->order;
		current_region = paddr < buddy_paddr ? PADDR_2_MM_LIST(paddr) : PADDR_2_MM_LIST(buddy_paddr);
		current_region->order = order + 1;
		current_region->prev_mm = NULL;
		current_region->next_mm = NULL;

		//next mm_list doesn't exist or has a different order, no need to merge
		// 如果合并后的块和下一个mm_list_head不同，则表明不需要进行下一轮合并，直接插入新的mm_list_head即可
		if(!next_list_head || next_list_head->order != current_region->order)
		{
			//current_list_head may be NULL now after delete buddy region
			if(current_list_head)
				prev_list_head = current_list_head;
			new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(current_region);
			new_list_head->order = current_region->order;
			new_list_head->prev_list_head = prev_list_head;
			new_list_head->next_list_head = next_list_head;
			new_list_head->mm_list = current_region;

			if(prev_list_head)
				prev_list_head->next_list_head = new_list_head;
			else
				mm_regions[region_idx].mm_list_head = new_list_head;
			if(next_list_head)
				next_list_head->prev_list_head = new_list_head;

			break;
		}

		//continue to merge with next mm_list
		current_list_head = next_list_head;
	}

	return 0;
}

// 通过伙伴系统插入一个物理块
//remember to acquire lock before calling this function
static int insert_mm_region(int region_idx, struct mm_list_t* mm_region, int merge)
{
	if(region_idx<0 || region_idx>=N_PMP_REGIONS || !mm_regions[region_idx].valid || !mm_region)
		return -1;

	struct mm_list_head_t* mm_list_head = mm_regions[region_idx].mm_list_head;
	struct mm_list_head_t* prev_list_head = NULL;

	//there is no mm_list in current pmp_region
	if(!mm_list_head)
	{
		// 如果当前enclave所隔离的内存全部被分配，那么插入的mm_list将是第一个未分配的region，需要创建mm_list_head进行管理
		mm_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(mm_region);
		mm_list_head->order = mm_region->order;
		mm_list_head->prev_list_head = NULL;
		mm_list_head->next_list_head = NULL;
		mm_list_head->mm_list = mm_region;
		mm_regions[region_idx].mm_list_head = mm_list_head;
		return 0;
	}

	// 如果mm_list_head不为空，则从前到后遍历mm_list_head，找到合适的插入位置
	//traversal from front to back
	while(mm_list_head && mm_list_head->order < mm_region->order)
	{
		prev_list_head = mm_list_head;
		mm_list_head = mm_list_head->next_list_head;
	}

	// 找到mm_list插入的位置
	//found the exact mm_list
	int ret_val = 0;
	struct mm_list_head_t *new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(mm_region);
	if(mm_list_head && mm_list_head->order == mm_region->order)
	{
		if(!merge)
		{
			// 将要插入的块插入mm_list的第一个位置
			//insert mm_region to the first pos in mm_list
			mm_region->prev_mm = NULL;
			mm_region->next_mm = mm_list_head->mm_list;
			mm_list_head->mm_list->prev_mm = mm_region;

			// 每一个新插入的mm_list和mm_list_head相关联，因为插入的块在mm_list的第一个位置，所以需要修改mm_list_head，即创建新的mm_list_head
			//set mm_list_head
			struct mm_list_head_t* next_list_head = mm_list_head->next_list_head;
			new_list_head->order = mm_region->order;
			new_list_head->prev_list_head = prev_list_head;
			new_list_head->next_list_head = next_list_head;
			new_list_head->mm_list = mm_region;
			if(prev_list_head)
				prev_list_head->next_list_head = new_list_head;
			else
				mm_regions[region_idx].mm_list_head = new_list_head;
			if(next_list_head)
				next_list_head->prev_list_head = new_list_head;
		}
		else
		{
			//insert with merge
			ret_val = merge_regions(region_idx, mm_list_head, mm_region);
		}
	}
	//should create a new mm_list for this mm region
	//note that mm_list_head might be NULL
	else
	{
		// 如果不存在mm_list_head->order == mm_region->order
		new_list_head->order = mm_region->order;
		new_list_head->prev_list_head = prev_list_head;
		new_list_head->next_list_head = mm_list_head;
		new_list_head->mm_list = mm_region;
		if(prev_list_head)
			prev_list_head->next_list_head = new_list_head;
		else
			mm_regions[region_idx].mm_list_head = new_list_head;
		if(mm_list_head)
			mm_list_head->prev_list_head = new_list_head;
	}

	return ret_val;
}

//TODO: delete this function
void print_buddy_system()
{
	//spinlock_lock(&pmp_bitmap_lock);

	struct mm_list_head_t* mm_list_head = mm_regions[0].mm_list_head;
	printm("struct mm_list_head_t size is 0x%lx\r\n", sizeof(struct mm_list_head_t));
	printm("struct mm_list_t size is 0x%lx\r\n", sizeof(struct mm_list_t));
	while(mm_list_head)
	{
		printm("mm_list_head addr is 0x%ln, order is %d\r\n", (long int *)mm_list_head, mm_list_head->order);
		printm("mm_list_head prev is 0x%ln, next is 0x%ln, mm_list is 0x%ln\r\n",
				(long int *)mm_list_head->prev_list_head,
				(long int *)mm_list_head->next_list_head,
				(long int*)mm_list_head->mm_list);
		struct mm_list_t *mm_region = mm_list_head->mm_list;
		while(mm_region)
		{
			printm("  mm_region addr is 0x%ln, order is %d\r\n", (long int *)mm_region, mm_region->order);
			printm("  mm_region prev is 0x%ln, next is 0x%ln\r\n", (long int*)mm_region->prev_mm, (long int*)mm_region->next_mm);
			mm_region = mm_region->next_mm;
		}
		mm_list_head = mm_list_head->next_list_head;
	}

	//spinlock_unlock(&pmp_bitmap_lock);
}


// mm_alloc将调用alloc_one_region分配一个大小最接近req_size的内存区域，并将剩余的内存块插入mm_list中
void* mm_alloc(unsigned long req_size, unsigned long *resp_size)
{
	void* ret_addr = NULL;
	if(req_size == 0)
		return ret_addr;

	//TODO: reduce lock granularity
	spin_lock(&pmp_bitmap_lock);

	//print_buddy_system();

	//请求的内存块大小一定是2的幂次方
	unsigned long order = ilog2(req_size-1) + 1;
	for(int region_idx=0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		struct mm_list_t* mm_region = alloc_one_region(region_idx, order);

		//there is no enough space in current pmp region
		if(!mm_region)
			continue;

		while(mm_region->order > order)
		{
			// 如果分配的mm_list内存块大于请求的内存块，将该内存等分成两块
			//allocated mm region need to be split
			mm_region->order -= 1;
			mm_region->prev_mm = NULL;
			mm_region->next_mm = NULL;

			// 地址区间大的那一块将被插入到mm_list中被管理
			// mm_list_head和mm_list的内存布局mm_list_head | mm_list 
			void* new_mm_region_paddr = MM_LIST_2_PADDR(mm_region) + (1 << mm_region->order);
			struct mm_list_t* new_mm_region = PADDR_2_MM_LIST(new_mm_region_paddr);
			new_mm_region->order = mm_region->order;
			new_mm_region->prev_mm = NULL;
			new_mm_region->next_mm = NULL;
			insert_mm_region(region_idx, new_mm_region, 0);
		}

		ret_addr = MM_LIST_2_PADDR(mm_region);
		break;
	}

	// print_buddy_system();

	spin_unlock(&pmp_bitmap_lock);

	// SM负责将分配的内存置零
	if(ret_addr && resp_size)
	{
		*resp_size = 1 << order;
		sbi_memset(ret_addr, 0, *resp_size);
	}

	return ret_addr;
}


// 释放region中已经分配的某块区域
int mm_free(void* req_paddr, unsigned long free_size)
{
	//check this paddr is 2^power aligned
	uintptr_t paddr = (uintptr_t)req_paddr;
	unsigned long order = ilog2(free_size-1) + 1;
	unsigned long size = 1 << order;
	if(check_mem_size(paddr, size) < 0)
		return -1;

	int ret_val = 0;
	int region_idx = 0;
	struct mm_list_t* mm_region = PADDR_2_MM_LIST(paddr);
	mm_region->order = order;
	mm_region->prev_mm = NULL;
	mm_region->next_mm = NULL;

	spin_lock(&pmp_bitmap_lock);

	//print_buddy_system();

	for(region_idx=0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid && region_contain(mm_regions[region_idx].paddr, mm_regions[region_idx].size, paddr, size))
		{
			break;
		}
	}
	if(region_idx >= N_PMP_REGIONS)
	{
		printm("mm_free: buddy system doesn't contain memory(addr 0x%lx, order %ld)\r\n", paddr, order);
		ret_val = -1;
		goto mm_free_out;
	}

	//check whether this region overlap with existing free mm_lists
	struct mm_list_head_t* mm_list_head = mm_regions[region_idx].mm_list_head;
	while(mm_list_head)
	{
		struct mm_list_t* mm_region = mm_list_head->mm_list;
		while(mm_region)
		{
			uintptr_t region_paddr = (uintptr_t)MM_LIST_2_PADDR(mm_region);
			unsigned long region_size = 1 << mm_region->order;
			if(region_overlap(paddr, size, region_paddr, region_size))
			{
				printm("mm_free: memory(addr 0x%lx order %ld) overlap with free memory(addr 0x%lx order %d)\r\n", paddr, order, region_paddr, mm_region->order);
				ret_val = -1;
				break;
			}
			mm_region = mm_region->next_mm;
		}
		if(mm_region)
			break;

		mm_list_head = mm_list_head->next_list_head;
	}
	if(mm_list_head)
	{
		goto mm_free_out;
	}

	//insert with merge
	ret_val = insert_mm_region(region_idx, mm_region, 1);
	if(ret_val < 0)
	{
		printm("mm_free: failed to insert mm(addr 0x%lx, order %ld)\r\n in mm_regions[%d]\r\n", paddr, order, region_idx);
	}

	//printm("after mm_free\r\n");
	//print_buddy_system();

mm_free_out:
	spin_unlock(&pmp_bitmap_lock);
	return ret_val;
}
