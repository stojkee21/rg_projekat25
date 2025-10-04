//
// Created by nemanja on 10/4/25.
//

#include "../include/GuiController.hpp"

#include <engine/graphics/GraphicsController.hpp>
#include <imgui.h>
#include <engine/platform/PlatformController.hpp>

namespace app {
    void GUIController::initialize() {
        set_enable(false);
    }

    void GUIController::poll_events() {
        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
        if (platform->key(engine::platform::KeyId::KEY_F).state() == engine::platform::Key::State::JustPressed) {
            set_enable(!is_enabled());
        }
    }

    void GUIController::draw() {
        auto graphics = engine::core::Controller::get<engine::graphics::GraphicsController>();
        auto camera   = graphics->camera();

        graphics->begin_gui();

        ImGui::Begin("Game Controller");

        ImGui::Text("Camera Position: (%f, %f, %f)", camera->Position.x, camera->Position.y, camera->Position.z);

        ImGui::End();

        graphics->end_gui();
    }
} // app
