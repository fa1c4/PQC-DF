#ifndef PQCFUZZ_ORACLES_ORACLE_SPEC_LOADER_H
#define PQCFUZZ_ORACLES_ORACLE_SPEC_LOADER_H

#include <string>
#include <vector>

#include "oracles/oracle_spec.h"

namespace pqcfuzz {

std::vector<OracleSpec> LoadOracleSpecs(const std::string &path, std::string *error);

}  // namespace pqcfuzz

#endif
