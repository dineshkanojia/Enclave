#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_enclaveChangeBuffer_t {
	char* ms_buf;
	size_t ms_len;
} ms_enclaveChangeBuffer_t;

typedef struct ms_create_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_create_wallet_t;

typedef struct ms_show_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	wallet_t* ms_wallet;
	size_t ms_wallet_size;
} ms_show_wallet_t;

typedef struct ms_change_master_password_t {
	int ms_retval;
	const char* ms_old_password;
	size_t ms_old_password_len;
	const char* ms_new_password;
	size_t ms_new_password_len;
} ms_change_master_password_t;

typedef struct ms_add_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	const item_t* ms_item;
	size_t ms_item_size;
} ms_add_item_t;

typedef struct ms_remove_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	int ms_index;
} ms_remove_item_t;

typedef struct ms_save_wallet_t {
	int ms_retval;
	const uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_save_wallet_t;

typedef struct ms_ocall_load_wallet_t {
	int ms_retval;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_load_wallet_t;

typedef struct ms_ocall_is_wallet_t {
	int ms_retval;
} ms_ocall_is_wallet_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_save_wallet(void* pms)
{
	ms_save_wallet_t* ms = SGX_CAST(ms_save_wallet_t*, pms);
	ms->ms_retval = save_wallet(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_load_wallet(void* pms)
{
	ms_ocall_load_wallet_t* ms = SGX_CAST(ms_ocall_load_wallet_t*, pms);
	ms->ms_retval = ocall_load_wallet(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_is_wallet(void* pms)
{
	ms_ocall_is_wallet_t* ms = SGX_CAST(ms_ocall_is_wallet_t*, pms);
	ms->ms_retval = ocall_is_wallet();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[8];
} ocall_table_Enclave = {
	8,
	{
		(void*)(uintptr_t)Enclave_save_wallet,
		(void*)(uintptr_t)Enclave_ocall_load_wallet,
		(void*)(uintptr_t)Enclave_ocall_is_wallet,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t enclaveChangeBuffer(sgx_enclave_id_t eid, char* buf, size_t len)
{
	sgx_status_t status;
	ms_enclaveChangeBuffer_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t create_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password)
{
	sgx_status_t status;
	ms_create_wallet_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t show_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password, wallet_t* wallet, size_t wallet_size)
{
	sgx_status_t status;
	ms_show_wallet_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	ms.ms_wallet = wallet;
	ms.ms_wallet_size = wallet_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t change_master_password(sgx_enclave_id_t eid, int* retval, const char* old_password, const char* new_password)
{
	sgx_status_t status;
	ms_change_master_password_t ms;
	ms.ms_old_password = old_password;
	ms.ms_old_password_len = old_password ? strlen(old_password) + 1 : 0;
	ms.ms_new_password = new_password;
	ms.ms_new_password_len = new_password ? strlen(new_password) + 1 : 0;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t add_item(sgx_enclave_id_t eid, int* retval, const char* master_password, const item_t* item, size_t item_size)
{
	sgx_status_t status;
	ms_add_item_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	ms.ms_item = item;
	ms.ms_item_size = item_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t remove_item(sgx_enclave_id_t eid, int* retval, const char* master_password, int index)
{
	sgx_status_t status;
	ms_remove_item_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	ms.ms_index = index;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

