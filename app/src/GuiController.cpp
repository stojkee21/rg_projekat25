//
// Created by nemanja on 10/4/25.
//

#include "GuiController.hpp"
#include <engine/graphics/GraphicsController.hpp>
#include <imgui.h>
#include <imgui_internal.h>
#include <engine/platform/PlatformController.hpp>
#include <spdlog/spdlog.h>

namespace app {
    void GUIController::initialize() {
        set_enable(false);
    }

    void GUIController::poll_events() {
        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();

        if (platform->key(engine::platform::KeyId::KEY_F).state() == engine::platform::Key::State::JustPressed) {
            bool new_state = !is_enabled();
            set_enable(new_state);

            if (new_state) {
                platform->set_enable_cursor(true); // Prikaži kursor
            } else {
                platform->set_enable_cursor(false); // Sakrij kursor
            }
        }
    }

    void GUIController::draw() {
        auto graphics = engine::core::Controller::get<engine::graphics::GraphicsController>();
        auto camera   = graphics->camera();

        auto platform      = engine::core::Controller::get<engine::platform::PlatformController>();
        GLFWwindow *window = platform->window()->handle_();

        graphics->begin_gui();

        ImGui::Begin("Game Controller");

        // CAMERA INFO
        ImGui::Separator();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Camera Info");
        ImGui::Separator();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 0.8f, 1.0f, 1.0f)); // svetloplava boja
        ImGui::Text("Position:  (%.2f, %.2f, %.2f)", camera->Position.x, camera->Position.y, camera->Position.z);
        ImGui::PopStyleColor();

        ImGui::Text("Yaw:   %.2f°", camera->Yaw);
        ImGui::Text("Pitch: %.2f°", camera->Pitch);
        ImGui::Separator();

        // WINDOW CONTROLS
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Window's Controls");
        ImGui::Separator();
        static bool fullscreen = false;

        if (ImGui::Button(fullscreen ? "Exit Fullscreen" : "Fullscreen")) {
            fullscreen = !fullscreen;

            auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
            auto window   = platform->window();

            window->set_fullscreen(fullscreen);
        }

        ImGui::Separator();

        static int new_width  = 1280;
        static int new_height = 720;
        ImGui::InputInt("Width", &new_width);
        ImGui::InputInt("Height", &new_height);
        if (ImGui::Button("Apply Size")) {
            // Ograničenje širine i visine prozora
            int min_width  = 800;
            int min_height = 600;

            if (new_width < min_width) {
                spdlog::info("[W]: Minimalna širina prozora je: 800px");
                new_width = min_width;
            }
            if (new_height < min_height) {
                spdlog::info("[W]: Minimalna visina prozora je: 600px");
                new_height = min_height;
            }
            auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
            auto window   = platform->window();
            window->set_size(new_width, new_height);
        }

        ImGui::Separator();

        // Izbor rezolucije iz dropdown liste
        const char *sizes[] = {"800x600", "1280x720", "1920x1080"};
        static int selected = 1;
        if (ImGui::Combo("Resolution", &selected, sizes, IM_ARRAYSIZE(sizes))) {
            auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
            auto window   = platform->window();

            switch (selected) {
            case 0: window->set_size(800, 600);
                break;
            case 1: window->set_size(1280, 720);
                break;
            case 2: window->set_size(1920, 1080);
                break;
            }
        }

        ImGui::End();

        graphics->end_gui();
    }
} // app
