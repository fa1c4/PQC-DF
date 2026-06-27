#pragma once

#include <cryptofuzz/module.h>
#include <string>
#include <vector>

namespace cryptofuzz {
namespace module {

class liboqs : public Module {
    private:
        std::vector<std::string> kemAlgorithms;
        std::vector<std::string> sigAlgorithms;

    public:
        liboqs(void);

        std::optional<bool> OpOQSKEMSelfTest(operation::OQS_KEM_SelfTest& op) override;
        std::optional<bool> OpOQSSIGSelfTest(operation::OQS_SIG_SelfTest& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
