//
// Created by nemanja on 9/24/25.
//
#include <engine/core/Engine.hpp>
#include "../include/MainController.h"

#include "spdlog/spdlog.h"

#include <engine/graphics/GraphicsController.hpp>

namespace app {
void MainController::initialize() {
    spdlog::info("MainController intialized.");
    engine::graphics::OpenGL::enable_depth_testing();

}

bool MainController::loop() {
    auto platform = engine::core::Controller::get<engine::platform::PlatformController>();

    // Ako je ESC pritisnut, prekidamo petlju
    if (platform->key(engine::platform::KeyId::KEY_ESCAPE).is_down()) {
        return false;// zaustavlja while(loop())
    }

    return true;// nastavi normalno
}

void MainController::draw_police_station() {

    auto resources = engine::core::Controller::get<engine::resources::ResourcesController>();
    auto graphics = engine::core::Controller::get<engine::graphics::GraphicsController>();

    // Model
    engine::resources::Model *apartment = resources->model("apartment");
    // Shader
    engine::resources::Shader *shader = resources->shader("basic");

    shader->use();

    shader->set_mat4("projection", graphics->projection_matrix());
    shader->set_mat4("view", graphics->camera()->view_matrix());

    glm::mat4 model = glm::mat4(1.0f);
    model = glm::translate(model, glm::vec3(0.0f, 0.0f, -13.0f));
    model = glm::scale(model, glm::vec3(0.3f));

    shader->set_mat4("model", model);

    apartment->draw(shader);
}

void MainController::begin_draw() { engine::graphics::OpenGL::clear_buffers(); }

void MainController::draw() { draw_police_station(); }

void MainController::end_draw() {
    auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
    platform->swap_buffers();
}
}// namespace app