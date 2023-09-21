#include <sbi/sbi_spmp.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_fifo.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_hartmask.h>

static unsigned long spmp_data_offset;
static unsigned long spmp_sync_offset;

static void sbi_process_spmp(struct sbi_scratch *scratch)
{
	struct spmp_data_t *data = sbi_scratch_offset_ptr(scratch, spmp_data_offset);
	struct spmp_config_t spmp_config = *(struct spmp_config_t*)(data);
	struct sbi_scratch *rscratch = NULL;
	u32 rhartid;
	unsigned long *spmp_sync = NULL;
	int spmp_idx = data->spmp_idx_arg;
	set_spmp(spmp_idx, spmp_config);

	//sync
	sbi_hartmask_for_each_hart(rhartid, &data->smask) {
		rscratch = sbi_hartid_to_scratch(rhartid);
		if (!rscratch)
			continue;
		spmp_sync = sbi_scratch_offset_ptr(rscratch, spmp_sync_offset);
		while (atomic_raw_xchg_ulong(spmp_sync, 1));
	}
}

static int sbi_update_spmp(struct sbi_scratch *scratch,
			  struct sbi_scratch *remote_scratch,
			  u32 remote_hartid, void *data)
{
	struct spmp_data_t *spmp_data = NULL;
	int spmp_idx = 0;
	u32 curr_hartid = current_hartid();

	if (remote_hartid == curr_hartid) {
		//update the spmp register locally
		struct spmp_config_t spmp_config = *(struct spmp_config_t*)(data);
		spmp_idx = ((struct spmp_data_t *)data)->spmp_idx_arg;
		set_spmp(spmp_idx, spmp_config);
		return -1;
	}

	spmp_data = sbi_scratch_offset_ptr(remote_scratch, spmp_data_offset);
	//update the remote hart pmp data
	sbi_memcpy(spmp_data, data, sizeof(struct spmp_data_t));

	return 0;
}

static void sbi_spmp_sync(struct sbi_scratch *scratch)
{
	unsigned long *spmp_sync =
			sbi_scratch_offset_ptr(scratch, spmp_sync_offset);
	//wait the remote hart process the pmp signal
	while (!atomic_raw_xchg_ulong(spmp_sync, 0));
	return;
}

static struct sbi_ipi_event_ops spmp_ops = {
	.name = "IPI_SPMP",
	.update = sbi_update_spmp,
	.sync = sbi_spmp_sync,
	.process = sbi_process_spmp,
};

static u32 spmp_event = SBI_IPI_EVENT_MAX;

int sbi_send_spmp(ulong hmask, ulong hbase, struct spmp_data_t* spmp_data)
{
	return sbi_ipi_send_many(hmask, hbase, spmp_event, spmp_data);
}

int sbi_spmp_init(struct sbi_scratch *scratch, bool cold_boot)
{
	int ret;
	struct spmp_data_t *spmpdata;
	unsigned long *spmp_sync;

	if (cold_boot) {
        //Define the pmp data offset in the scratch
		spmp_data_offset = sbi_scratch_alloc_offset(sizeof(*spmpdata), "INIT_SPMP");
		if (!spmp_data_offset)
			return SBI_ENOMEM;

		spmp_sync_offset = sbi_scratch_alloc_offset(sizeof(*spmp_sync), "INIT_SPMP");
		if (!spmp_sync_offset)
			return SBI_ENOMEM;

		spmpdata = sbi_scratch_offset_ptr(scratch,
						       spmp_data_offset);

		spmp_sync = sbi_scratch_offset_ptr(scratch,
						       spmp_sync_offset);

		*spmp_sync = 0;

		ret = sbi_ipi_event_create(&spmp_ops);
		if (ret < 0) {
			sbi_scratch_free_offset(spmp_data_offset);
			return ret;
		}
		spmp_event = ret;
	} else {
		//do nothing for warmboot
	}

	return 0;
}
