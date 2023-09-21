#ifndef __SBI_SPMP_H__
#define __SBI_SPMP_H__

#include <sm/platform/spmp/spmp.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>
struct sbi_scratch;
int sbi_spmp_init(struct sbi_scratch *scratch, bool cold_boot);
int sbi_send_spmp(ulong hmask, ulong hbase, struct spmp_data_t* pmp_data);
#endif
