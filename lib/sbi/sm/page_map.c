#include <sm/page_map.h>


static inline uintptr_t pte2pa(pte_t pte)
{
	return (pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
}

static inline int get_pt_index(virtual_addr_t vaddr, int level)
{
	int index = vaddr >> (VA_BITS - (level + 1) * RISCV_PGLEVEL_BITS);

	return index & ((1 << RISCV_PGLEVEL_BITS) - 1) ;
}


static  inline int create_ptd_page(struct enclave_t* enclave ,pte_t * pte)
{
	//1. 取出空闲内存的物理地址
	physical_addr_t paddr = enclave->free_mem;
	if (enclave->free_mem >= enclave->paddr + enclave ->size)
	{
		printm_err("[SM@%s] enclave %d doesn't have enough memory to create_ptd_page. Fault!!!\n", __func__, enclave->eid);
		
	}
	enclave->free_mem += RISCV_PGSIZE;
	// pa2ppn
	*pte = ptd_create((uintptr_t)(paddr >> RISCV_PGSHIFT));

	return 0;
}

static pte_t* walk_enclave_pt(struct enclave_t* enclave, virtual_addr_t vaddr, bool create){

	pte_t* pgdir = (pte_t*)enclave->root_page_table;
	// pte_t* pgdir = (pte_t*)0;
	int i;

	for(i = 0; i < RISCV_PT_LEVEL - 1; i++)
	{
		int pt_index = get_pt_index(vaddr, i);
		pte_t pt_entry = pgdir[pt_index];
		// printm("[page_map.c@%s] before: pt_level = %d, pgdir = 0x%lx, pt_entry = 0x%lx\n", __func__, i, (unsigned long int)pgdir, (unsigned long int)pt_entry);
		if(unlikely(!(pt_entry & PTE_V)))
		{
			if(create)
			{
				// 申请下一级页表，并将页表项信息填入
				if(create_ptd_page(enclave, &pgdir[pt_index]) < 0)
					return NULL;
				else
					// 取出PTE(下一级页表)的信息放入pt_entry
					pt_entry = pgdir[pt_index];
			}
			else
				printm("[SM@%s] Missing page table entry error!!!\n", __func__);
		}
		// printm("[page_map.c@%s] after: pt_level = %d, pgdir = 0x%lx, pt_entry = 0x%lx\n", __func__, i, (unsigned long int)pgdir, (unsigned long int)pt_entry);
		// 获取下一级页目录的物理地址
		pgdir = (pte_t*)pte2pa(pt_entry);
		// printm("[page_map.c@%s] pt_entry = 0x%lx\n", (unsigned long int)pt_entry);
	}

	return &pgdir[get_pt_index(vaddr, RISCV_PT_LEVEL - 1)];
}

virtual_addr_t _map_va2pa(struct enclave_t* enclave, virtual_addr_t vaddr, physical_addr_t paddr, unsigned long perm)
{
	// printm("[SM@%s] enclave -> root_page_table:0x%lx\n", __func__, (long unsigned int)enclave->root_page_table);
	// printm("[SM@%s] enclave -> free_mem:0x%lx\n", __func__, enclave->free_mem);

	pte_t* pte = walk_enclave_pt(enclave, vaddr, true);
	if (pte == NULL)
	{
		printm("[SM@%s] apply for pte fault!!! return NULL!\n", __func__);
		return (virtual_addr_t)0;
	}
    // pa2ppn
	// printm("[page_map@%s] pte = 0x%lx, ")
	uintptr_t ppn = (uintptr_t)(paddr >> RISCV_PGSHIFT);
	*pte = pte_create(ppn, perm);
	// printm("[page_map.c@%s] pt_enter = 0x%lx\n", __func__, (unsigned long int)*pte);
	return vaddr;
}

int map_pa2va(struct enclave_t* enclave, virtual_addr_t vaddr, physical_addr_t paddr, unsigned long size, unsigned long perm)
{
	virtual_addr_t addr = vaddr;

	for (; addr < vaddr + size; addr += RISCV_PGSIZE) {
		_map_va2pa(enclave, addr, paddr, perm);
		paddr += RISCV_PGSIZE;
	}
	
    // int* ptr = (int*)paddr;
	// ptr[0] = 1;
	// for (int i = 0; i < 5; i++)
	// {
	// 	ptr[i] = i;
	// 	printm("[page_map.c@%s] ptr[%d] = %d, &ptr[%d] = 0x%p\n", __func__, i, ptr[i], i, &ptr[i]);
	// }
	

	printm("[page_map@%s] succeed!\n", __func__);
	return 0;
}