#include <sm/platform/spmp/spmp.h>
#include <stddef.h>
//#include <sbi/sbi_spmp.h>
#include <sm/sm.h>

#if 0
/**
 * \brief Set spmp and sync all harts.
 *
 * \param spmp_idx_arg The spmp index.
 * \param spmp_config_arg The spmp config.
 */
void set_spmp_and_sync(int spmp_idx_arg, struct spmp_config_t spmp_config_arg)
{
	struct spmp_data_t spmp_data;
	u32 source_hart = current_hartid();

	//set current hart's spmp
	set_spmp(spmp_idx_arg, spmp_config_arg);
	//sync all other harts
	SBI_SPMP_DATA_INIT(&spmp_data, spmp_config_arg, spmp_idx_arg, source_hart);
	sbi_send_spmp(0xFFFFFFFF&(~(1<<source_hart)), 0, &spmp_data);
	return;
}

/**
 * \brief Clear spmp and sync all harts.
 *
 * \param spmp_idx_arg The spmp index.
 */
void clear_spmp_and_sync(int spmp_idx)
{
	struct spmp_config_t spmp_config = {0,};

	spmp_config.mode = SPMP_OFF;
	set_spmp_and_sync(spmp_idx, spmp_config);

	return;
}

#endif 

void set_spmp(int spmp_idx, struct spmp_config_t spmp_cfg_t)
{
#if 1
  uintptr_t spmp_address = 0;
  uintptr_t old_config = 0;

  // 从spmp_cfg_t中获取配置信息，并转换成sPMP寄存器格式，这里使用的是64位 spmp_cfg格式
  uintptr_t spmp_config = ((spmp_cfg_t.sbit & SPMP_S) | (spmp_cfg_t.mode & SPMP_A) | (spmp_cfg_t.perm & (SPMP_R|SPMP_W|SPMP_X)))
    << ((uintptr_t)SPMPCFG_BIT_NUM * (spmp_idx % SPMP_PER_CFG_REG));

  switch(spmp_cfg_t.mode)
  {
    case SPMP_NAPOT:
      if(spmp_cfg_t.paddr == 0 && spmp_cfg_t.size == -1UL)
        spmp_address = -1UL;
      else
      // (spmp_cfg_t.paddr | ((spmp_cfg_t.size>>1)-1)) >> 2 这个操作是sPMP地址空间大小的匹配算法，地址信息中包含需要保护的内存区间的大小信息
        spmp_address = (spmp_cfg_t.paddr | ((spmp_cfg_t.size>>1)-1)) >> 2;
      break;
    case SPMP_TOR:
      spmp_address = spmp_cfg_t.paddr;
    case SPMP_NA4:
      spmp_address = spmp_cfg_t.paddr;
    case SPMP_OFF:
      spmp_address = 0;
    default:
      break;
  }

  switch(spmp_idx)
  {
#define X(n, g) case n: { SPMP_SET(n, g, spmp_addr, spmp_config); break; }
//  LIST_OF_SPMP_REGS
#undef X
    case 0:
    // 在RV64中，一个配置寄存器包含8组sPMP配置信息，需要读取原始sPMP寄存器的信息，清除该组中的原始配置，再修改某组中的配置信息
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(0%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr0, spmpcfg0, spmp_address, spmp_config);
      break;
    case 1:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(1%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr1, spmpcfg0, spmp_address, spmp_config);
      break;
    case 2:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(2%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr2, spmpcfg0, spmp_address, spmp_config);
      break;
    case 3:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(3%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr3, spmpcfg0, spmp_address, spmp_config);
      break;
    case 4:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(4%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr4, spmpcfg0, spmp_address, spmp_config);
      break;
    case 5:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(5%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr5, spmpcfg0, spmp_address, spmp_config);
      break;
    case 6:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(6%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr6, spmpcfg0, spmp_address, spmp_config);
      break;
    case 7:
      old_config = read_spmpcfg(spmpcfg0);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(7%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr7, spmpcfg0, spmp_address, spmp_config);
      break;
    case 8:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(8%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr8, spmpcfg2, spmp_address, spmp_config);
      break;
    case 9:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(9%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr9, spmpcfg2, spmp_address, spmp_config);
      break;
    case 10:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(10%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr10, spmpcfg2, spmp_address, spmp_config);
      break;
    case 11:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(11%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr11, spmpcfg2, spmp_address, spmp_config);
      break;
    case 12:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(12%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr12, spmpcfg2, spmp_address, spmp_config);
      break;
    case 13:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(13%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr13, spmpcfg2, spmp_address, spmp_config);
      break;
    case 14:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(14%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr14, spmpcfg2, spmp_address, spmp_config);
      break;
    case 15:
      old_config = read_spmpcfg(spmpcfg2);
      spmp_config |= (old_config &
          ~((uintptr_t)SPMPCFG_BITS << (uintptr_t)SPMPCFG_BIT_NUM*(15%SPMP_PER_CFG_REG)));
      SPMP_SET(spmpaddr15, spmpcfg2, spmp_address, spmp_config);
      break;
    default:
      break;
  }
#endif
  return;
}

void clear_spmp(int spmp_idx)
{
#if 1
  struct spmp_config_t spmp_cfg;

  spmp_cfg.mode = SPMP_OFF;
  spmp_cfg.perm = SPMP_NO_PERM;
  spmp_cfg.paddr = 0;
  spmp_cfg.size = 0;
  set_spmp(spmp_idx, spmp_cfg);
#endif
  return;
}

struct spmp_config_t get_spmp(int spmp_idx)
{
  struct spmp_config_t spmp={0,};
#if 1
  uintptr_t spmp_address = 0;
  uintptr_t spmp_config = 0;
  unsigned long order = 0;
  unsigned long size = 0;

  switch(spmp_idx)
  {
    case 0:
      SPMP_READ(spmpaddr0, spmpcfg0, spmp_address, spmp_config);
      break;
    case 1:
      SPMP_READ(spmpaddr1, spmpcfg0, spmp_address, spmp_config);
      break;
    case 2:
      SPMP_READ(spmpaddr2, spmpcfg0, spmp_address, spmp_config);
      break;
    case 3:
      SPMP_READ(spmpaddr3, spmpcfg0, spmp_address, spmp_config);
      break;
    case 4:
      SPMP_READ(spmpaddr4, spmpcfg0, spmp_address, spmp_config);
      break;
    case 5:
      SPMP_READ(spmpaddr5, spmpcfg0, spmp_address, spmp_config);
      break;
    case 6:
      SPMP_READ(spmpaddr6, spmpcfg0, spmp_address, spmp_config);
      break;
    case 7:
      SPMP_READ(spmpaddr7, spmpcfg0, spmp_address, spmp_config);
      break;
    case 8:
      SPMP_READ(spmpaddr8, spmpcfg2, spmp_address, spmp_config);
      break;
    case 9:
      SPMP_READ(spmpaddr9, spmpcfg2, spmp_address, spmp_config);
      break;
    case 10:
      SPMP_READ(spmpaddr10, spmpcfg2, spmp_address, spmp_config);
      break;
    case 11:
      SPMP_READ(spmpaddr11, spmpcfg2, spmp_address, spmp_config);
      break;
    case 12:
      SPMP_READ(spmpaddr12, spmpcfg2, spmp_address, spmp_config);
      break;
    case 13:
      SPMP_READ(spmpaddr13, spmpcfg2, spmp_address, spmp_config);
      break;
    case 14:
      SPMP_READ(spmpaddr14, spmpcfg2, spmp_address, spmp_config);
      break;
    case 15:
      SPMP_READ(spmpaddr15, spmpcfg2, spmp_address, spmp_config);
      break;
    default:
      break;
  }

  //printm_err("##### get_spmp 1 spmp_idx: %d, spmp_address: 0x%lx, spmp_config: 0x%lx, size: 0x%lx #####\n", spmp_idx, spmp_address, spmp_config, size);
  // 通过移位操作获取该组sPMP寄存器的配置信息
  spmp_config >>= (uintptr_t)SPMPCFG_BIT_NUM * (spmp_idx % SPMP_PER_CFG_REG);
  spmp_config &= SPMPCFG_BITS;
  switch(spmp_config & SPMP_A)
  {
    case SPMP_NAPOT:
      // 当地址采用NAPOT编码时，解析sPMP隔离的地址和大小
      while(spmp_address & 1)
      {
        order += 1;
        spmp_address >>= 1;
        //printm_err("##** order: 0x%lx, spmp_address: 0x%lx ##**\n", order, spmp_address);
      }
      order += 3;
      size = 1UL << order;
      spmp_address <<= (order-1);
      break;
    case SPMP_NA4:
      size = 4;
    case SPMP_TOR:
      // 当采用SPMP_TOR模式时，这里没有计算size大小，应该存在问题？？？？
      break;
    case SPMP_OFF:
      spmp_address = 0;
      size = 0;
      break;
  }

  spmp.mode = spmp_config & SPMP_A;
  spmp.perm = spmp_config & (SPMP_R | SPMP_W | SPMP_X);
  spmp.paddr = spmp_address;
  spmp.size = size;
  spmp.sbit = spmp_config & SPMP_S;
  //printm_err("##### get_spmp spmp_idx: %d, spmp_address: 0x%lx, spmp_config: 0x%lx, size: 0x%lx sbit: 0x%lx mode: 0x%lx perm: 0x%lx#####\n", spmp_idx, spmp_address, spmp_config, size, spmp.sbit, spmp.mode, spmp.perm);
#endif
  return spmp;
}

void dump_spmps(void)
{
	int i;
	for (i = 0; i < NSPMP; i++){
		struct spmp_config_t spmp = get_spmp(i);
		(void)spmp; //to ignore the unused variable warnings
		printm_err("[Debug:SM@%s] spmp_%d: mode(0x%lx) perm(0x%lx) paddr(0x%lx) size(0x%lx) sbit(0x%lx)\n",
				__func__, i, spmp.mode, spmp.perm, spmp.paddr, spmp.size, spmp.sbit);
	}
}
