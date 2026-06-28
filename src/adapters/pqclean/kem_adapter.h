#ifndef PQCFUZZ_ADAPTERS_PQCLEAN_KEM_ADAPTER_H
#define PQCFUZZ_ADAPTERS_PQCLEAN_KEM_ADAPTER_H

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_mlkem512_adapter(void);
const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_mlkem768_adapter(void);
const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_mlkem1024_adapter(void);
const pqcfuzz_kem_adapter *pqcfuzz_get_pqclean_adapter(const char *implementation_id);

#ifdef __cplusplus
}
#endif

#endif
