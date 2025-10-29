//
// Created by nemanja on 9/24/25.
//

#ifndef MATF_RG_PROJECT_MAINCONTROLLER_H
#define MATF_RG_PROJECT_MAINCONTROLLER_H
#include "engine/core/Controller.hpp"

namespace app {
    class MainController : public engine::core::Controller {
    public:
        void initialize() override;

        bool loop() override;

        void poll_events() override;

        void draw_model();

        void begin_draw() override;

        void draw() override;

        void end_draw() override;

        void draw_skybox();

        void draw_lights();

        void update_camera();

        void update() override;

    private:
        bool m_lamp_on      = true;
        bool m_chain_active = false;
        float m_chain_timer = 0.0f;
        int m_chain_phase   = 0; // 0 - ugašeno, 1 - crveno, 2 - plavo
    };
} // namespace app

#endif//MATF_RG_PROJECT_MAINCONTROLLER_H
