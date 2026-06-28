#ifndef PQCFUZZ_ADAPTERS_LIBOQS_SIG_ADAPTER_H
#define PQCFUZZ_ADAPTERS_LIBOQS_SIG_ADAPTER_H

#include "adapters/adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_mldsa44_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_mldsa65_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_mldsa87_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_128s_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_128s_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_128f_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_128f_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_192s_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_192s_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_192f_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_192f_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_256s_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_256s_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_sha2_256f_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_slhdsa_shake_256f_adapter(void);
const pqcfuzz_sig_adapter *pqcfuzz_get_liboqs_sig_adapter(const char *implementation_id);

#ifdef __cplusplus
}
#endif

#endif
