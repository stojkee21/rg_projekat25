//
// Created by nemanja on 9/24/25.
//
#include <engine/core/Engine.hpp>
#include "../include/MainController.h"

#include <GuiController.hpp>
#include "spdlog/spdlog.h"
#include <engine/graphics/GraphicsController.hpp>
#include <GLFW/glfw3.h>

namespace app {
    class MainPlatformEventObserver : public engine::platform::PlatformEventObserver {
    public:
        void on_mouse_move(engine::platform::MousePosition position) override;
    };

    void MainPlatformEventObserver::on_mouse_move(engine::platform::MousePosition position) {
        auto gui_controller = engine::core::Controller::get<GUIController>();
        if (!gui_controller->is_enabled()) {
            static bool first_mouse = true;
            static double last_x    = 0.0;
            static double last_y    = 0.0;

            if (first_mouse) {
                last_x      = position.x;
                last_y      = position.y;
                first_mouse = false;
            }

            float xoffset = position.x - last_x;
            float yoffset = last_y - position.y;

            last_x = position.x;
            last_y = position.y;

            auto camera = engine::core::Controller::get<engine::graphics::GraphicsController>()->camera();
            camera->rotate_camera(xoffset, yoffset);
        }
    }

    void MainController::initialize() {
        spdlog::info("MainController intialized.");

        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
        platform->register_platform_event_observer(std::make_unique<MainPlatformEventObserver>());
        platform->set_enable_cursor(false);

        engine::graphics::OpenGL::enable_depth_testing();
        engine::graphics::OpenGL::enable_face_culling();
        engine::graphics::OpenGL::enable_blending();
    }

    bool MainController::loop() {
        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();

        // Ako je ESC pritisnut, prekidamo petlju
        if (platform->key(engine::platform::KeyId::KEY_ESCAPE).is_down()) {
            return false;
        }

        return true;
    }

    void MainController::poll_events() {
        auto platform       = engine::core::Controller::get<engine::platform::PlatformController>();
        auto gui_controller = engine::core::Controller::get<GUIController>();

        // Pali/gasi lampu
        if (platform->key(engine::platform::KeyId::KEY_L).state() == engine::platform::Key::State::JustPressed) {
            lamp_on = !lamp_on;
            spdlog::info("Lamp 2 toggled: {}", lamp_on ? "ON" : "OFF");
        }

        // Pokreće chain actions
        if (platform->key(engine::platform::KeyId::KEY_C).state() == engine::platform::Key::State::JustPressed) {
            chain_active = true;
            chain_phase  = 1; // crveno
            chain_timer  = 0.0f;
            spdlog::info("Chain light started");
        }
    }

    // TODO: Ubaciti možda još jedan model unutar kuće
    void MainController::draw_model() {
        auto resources = engine::core::Controller::get<engine::resources::ResourcesController>();
        auto graphics  = engine::core::Controller::get<engine::graphics::GraphicsController>();

        // Modeli
        engine::resources::Model *house      = resources->model("house8");
        engine::resources::Model *lamp       = resources->model("lamp");
        engine::resources::Model *floor      = resources->model("stone_floor");
        engine::resources::Model *lampStreet = resources->model("street_lamp");

        // Shader
        engine::resources::Shader *shader = resources->shader("basic");
        shader->use();

        shader->set_mat4("projection", graphics->projection_matrix());
        shader->set_mat4("view", graphics->camera()->view_matrix());

        // Kuća
        glm::mat4 house_model = glm::mat4(1.0f);
        house_model           = glm::translate(house_model, glm::vec3(0.0f, -2.0f, -7.0f));
        house_model           = glm::scale(house_model, glm::vec3(0.3f));
        shader->set_mat4("model", house_model);
        house->draw(shader);

        // Lampa
        glm::vec3 lamp_position = glm::vec3(2.1f, 1.0f, -7.0f);
        glm::mat4 lamp_model    = glm::mat4(1.0f);
        lamp_model              = glm::translate(lamp_model, lamp_position);
        lamp_model              = glm::scale(lamp_model, glm::vec3(0.4f));
        shader->set_mat4("model", lamp_model);
        lamp->draw(shader);

        // Stone Floor (pod ispod kuće)
        glm::mat4 floor_model = glm::mat4(1.0f);
        floor_model           = glm::translate(floor_model, glm::vec3(0.5f, -2.0f, -7.0f));
        floor_model           = glm::rotate(floor_model, glm::radians(-90.0f), glm::vec3(1.0f, 0.0f, 0.0f));
        floor_model           = glm::scale(floor_model, glm::vec3(0.3f));
        shader->set_mat4("model", floor_model);
        floor->draw(shader);

        // Street Lamp
        glm::mat4 lampModel = glm::mat4(1.0f);
        lampModel           = glm::translate(lampModel, glm::vec3(0.7f, -1.9f, -9.5f));
        lampModel           = glm::scale(lampModel, glm::vec3(0.1f));
        shader->set_mat4("model", lampModel);
        lampStreet->draw(shader);
    }

    // TODO: Mouse Scroll
    void MainController::update_camera() {
        auto gui_controller = engine::core::Controller::get<GUIController>();
        if (gui_controller->is_enabled()) {
            return;
        }

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

        static float lastTime = glfwGetTime();
        float currentTime     = glfwGetTime();
        float deltaTime       = currentTime - lastTime;
        lastTime              = currentTime;

        if (chain_active) {
            chain_timer += deltaTime;

            if (chain_phase == 1 && chain_timer > 3.0f) {
                chain_phase = 2; // posle 3s - plavo
                chain_timer = 0.0f;
                spdlog::info("Chain light: BLUE");
            } else if (chain_phase == 2 && chain_timer > 2.0f) {
                chain_phase  = 0; // ugasi posle 2s
                chain_active = false;
                spdlog::info("Chain light: OFF");
            }
        }
    }

    void MainController::begin_draw() {
        engine::graphics::OpenGL::clear_buffers();
    }

    void MainController::draw_skybox() {
        auto resources = engine::core::Controller::get<engine::resources::ResourcesController>();
        auto skybox    = resources->skybox("my_sky");
        auto shader    = resources->shader("skybox");
        auto graphics  = engine::core::Controller::get<engine::graphics::GraphicsController>();

        graphics->draw_skybox(shader, skybox);
    }

    // TODO: Možda +1 Point light u kući
    void MainController::draw_lights() {
        auto resources = engine::core::Controller::get<engine::resources::ResourcesController>();
        auto shader    = resources->shader("basic");
        auto graphics  = engine::core::Controller::get<engine::graphics::GraphicsController>();
        auto camera    = graphics->camera();

        shader->use();

        // Kamera i materijal
        shader->set_vec3("viewPos", camera->Position);
        shader->set_float("shininess", 32.0f);

        // Directional light
        shader->set_vec3("dirLight.direction", glm::vec3(-0.2f, -1.0f, -0.3f));
        shader->set_vec3("dirLight.color", glm::vec3(1.0f, 1.0f, 1.0f));

        // Point light
        glm::vec3 lampPos = glm::vec3(2.1f, 1.0f, -7.0f);
        shader->set_vec3("pointLight.position", lampPos);
        shader->set_float("pointLight.constant", 1.0f);
        shader->set_float("pointLight.linear", 0.09f);
        shader->set_float("pointLight.quadratic", 0.032f);

        glm::vec3 chainColor(0.0f); //ugašeno
        if (chain_active) {
            if (chain_phase == 1)
                chainColor = glm::vec3(1.0f, 0.0f, 0.0f);
            else if (chain_phase == 2)
                chainColor = glm::vec3(0.0f, 0.0f, 1.0f);
        }

        shader->set_vec3("pointLight.color", chainColor);

        // 2. Point Light
        glm::vec3 extraLampPos = glm::vec3(0.7f, -1.9f, -9.5f);
        shader->set_vec3("pointLight2.position", extraLampPos);
        if (lamp_on)
            shader->set_vec3("pointLight2.color", glm::vec3(1.0f, 0.9f, 0.7f));
        else
            shader->set_vec3("pointLight2.color", glm::vec3(0.0f)); // ugašeno
        shader->set_float("pointLight2.constant", 1.0f);
        shader->set_float("pointLight2.linear", 0.09f);
        shader->set_float("pointLight2.quadratic", 0.032f);
    }

    void MainController::draw() {
        draw_model();
        draw_skybox();
        draw_lights();
    }

    void MainController::end_draw() {
        auto platform = engine::core::Controller::get<engine::platform::PlatformController>();
        platform->swap_buffers();
    }
} // namespace app
