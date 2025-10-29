//
// Created by matfrg on 9/21/25.
//
#include <GuiController.hpp>

#include "MainController.h"

#include  <MyApp.hpp>
#include <spdlog/spdlog.h>

namespace app {
    void MyApp::app_setup() {
        spdlog::info("App setup complete");

        // ovde registrujemo naše kontrolere
        auto main_controller = register_controller<app::MainController>();
        auto gui_controller  = register_controller<app::GUIController>();

        main_controller->after(engine::core::Controller::get<engine::core::EngineControllersEnd>());
        main_controller->before(gui_controller);
    }
}
