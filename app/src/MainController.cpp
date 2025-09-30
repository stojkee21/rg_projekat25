//
// Created by nemanja on 9/24/25.
//
#include <engine/core/Engine.hpp>
#include "../include/MainController.h"

#include "spdlog/spdlog.h"

namespace app {
void MainController::initialize() { spdlog::info("MainController intialized."); }

bool MainController::loop() {
    auto platform = engine::core::Controller::get<engine::platform::PlatformController>();

    // Ako je ESC pritisnut, prekidamo petlju
    if (platform->key(engine::platform::KeyId::KEY_ESCAPE).is_down()) {
        return false;// zaustavlja while(loop())
    }

    return true;// nastavi normalno
}

void MainController::draw_police_station() {
    // Model
    auto resources = engine::core::Controller::get<engine::resources::ResourcesController>();
    engine::resources::Model *model = resources->model("police_station");
    // Shader
    engine::resources::Shader *shader = resources->shader("basic");
    model->draw(shader);
}

void MainController::draw() { draw_police_station(); }
}// namespace app