#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "Wallet.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SAVE_WALLET_DEFINED__
#define SAVE_WALLET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, save_wallet, (const uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_LOAD_WALLET_DEFINED__
#define OCALL_LOAD_WALLET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_wallet, (uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_IS_WALLET_DEFINED__
#define OCALL_IS_WALLET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_is_wallet, (void));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t enclaveChangeBuffer(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t create_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t show_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password, wallet_t* wallet, size_t wallet_size);
sgx_status_t change_master_password(sgx_enclave_id_t eid, int* retval, const char* old_password, const char* new_password);
sgx_status_t add_item(sgx_enclave_id_t eid, int* retval, const char* master_password, const item_t* item, size_t item_size);
sgx_status_t remove_item(sgx_enclave_id_t eid, int* retval, const char* master_password, int index);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
