//
// Created by nemanja on 9/24/25.
//

#ifndef MATF_RG_PROJECT_MAINCONTROLLER_H
#define MATF_RG_PROJECT_MAINCONTROLLER_H
#include "engine/core/Controller.hpp"

namespace app {

class MainController : public engine::core::Controller {
    void initialize() override;
    bool loop() override;
};

}// namespace app

#endif//MATF_RG_PROJECT_MAINCONTROLLER_H
