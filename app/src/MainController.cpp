//
// Created by nemanja on 9/24/25.
//
#include <engine/core/Engine.hpp>
#include "../include/MainController.h"

#include "spdlog/spdlog.h"

#include <engine/graphics/GraphicsController.hpp>

namespace app {
    class MainPlatformEventObserver : public engine::platform::PlatformEventObserver {
    public:
        void on_mouse_move(engine::platform::MousePosition position) override;
    };

    void MainPlatformEventObserver::on_mouse_move(engine::platform::MousePosition position) {
        auto camera = engine::core::Controller::get<engine::graphics::GraphicsController>()->camera();

        static bool first_mouse = true;
        static double last_x    = 0.0;
        static double last_y    = 0.0;

        if (first_mouse) {
            last_x      = position.x;
            last_y      = position.y;
            first_mouse = false;
        }

        float xoffset = position.x - last_x;
        float yoffset = last_y - position.y; // obrnuto jer y ide odozgo nadole

        last_x = position.x;
        last_y = position.y;

        camera->rotate_camera(xoffset, yoffset);
    }

    void MainController::initialize() {
        spdlog::info("MainController intialized.");

        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
        platform->register_platform_event_observer(std::make_unique<MainPlatformEventObserver>());

        engine::graphics::OpenGL::enable_depth_testing();
    }

    bool MainController::loop() {
        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();

        // Ako je ESC pritisnut, prekidamo petlju
        if (platform->key(engine::platform::KeyId::KEY_ESCAPE).is_down()) {
            return false; // zaustavlja while(loop())
        }

        return true; // nastavi normalno
    }

    void MainController::draw_police_station() {
        auto resources = engine::core::Controller::get<engine::resources::ResourcesController>();
        auto graphics  = engine::core::Controller::get<engine::graphics::GraphicsController>();

        // Model
        engine::resources::Model *apartment = resources->model("apartment");
        // Shader
        engine::resources::Shader *shader = resources->shader("basic");

        shader->use();

        shader->set_mat4("projection", graphics->projection_matrix());
        shader->set_mat4("view", graphics->camera()->view_matrix());

        glm::mat4 model = glm::mat4(1.0f);
        model           = glm::translate(model, glm::vec3(0.0f, 0.0f, -7.0f));
        model           = glm::scale(model, glm::vec3(0.3f));

        shader->set_mat4("model", model);

        apartment->draw(shader);
    }

    void MainController::update_camera() {
        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
        auto graphics = engine::core::Controller::get<engine::graphics::GraphicsController>();
        auto camera   = graphics->camera();

        float dt = platform->dt();

        if (platform->key(engine::platform::KeyId::KEY_W).is_down()) {
            camera->move_camera(engine::graphics::Camera::Movement::FORWARD, dt);
        }
        if (platform->key(engine::platform::KeyId::KEY_S).is_down()) {
            camera->move_camera(engine::graphics::Camera::Movement::BACKWARD, dt);
        }
        if (platform->key(engine::platform::KeyId::KEY_A).is_down()) {
            camera->move_camera(engine::graphics::Camera::Movement::LEFT, dt);
        }
        if (platform->key(engine::platform::KeyId::KEY_D).is_down()) {
            camera->move_camera(engine::graphics::Camera::Movement::RIGHT, dt);
        }
    }

    void MainController::update() {
        update_camera();
    }

    void MainController::begin_draw() {
        engine::graphics::OpenGL::clear_buffers();
    }

    void MainController::draw() {
        draw_police_station();
    }

    void MainController::end_draw() {
        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
        platform->swap_buffers();
    }
} // namespace app
