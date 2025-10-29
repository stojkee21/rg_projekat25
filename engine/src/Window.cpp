//
// Created by nemanja on 10/24/25.
//
#include <GLFW/glfw3.h>
#include "engine/platform/Window.hpp"
#include "spdlog/spdlog.h"

namespace engine::platform {
    void Window::set_fullscreen(bool enabled) {
        // Ako smo već u željenom stanju — ništa ne radi
        if (enabled == m_is_fullscreen)
            return;

        GLFWmonitor *monitor    = glfwGetPrimaryMonitor();
        const GLFWvidmode *mode = glfwGetVideoMode(monitor);

        if (!mode) {
            spdlog::warn("Window::set_fullscreen(): Cannot get monitor video mode.");
            return;
        }

        if (enabled) {
            // Sačuvaj trenutnu poziciju i veličinu pre prelaska
            glfwGetWindowPos(m_handle, &m_prev_x, &m_prev_y);
            glfwGetWindowSize(m_handle, &m_prev_width, &m_prev_height);

            // Postavi fullscreen
            glfwSetWindowMonitor(m_handle, monitor, 0, 0, mode->width, mode->height, mode->refreshRate);
            m_is_fullscreen = true;
        } else {
            // Vrati prethodnu veličinu i poziciju
            glfwSetWindowMonitor(m_handle, nullptr, m_prev_x, m_prev_y, m_prev_width, m_prev_height, 0);
            m_is_fullscreen = false;
        }

        spdlog::info("Window fullscreen mode: {}", m_is_fullscreen ? "ON" : "OFF");
    }

    void Window::set_size(int width, int height) {
        if (!m_handle) {
            spdlog::warn("Window::set_size() called with null handle.");
            return;
        }
        glfwSetWindowSize(m_handle, width, height);
        m_width  = width;
        m_height = height;
        spdlog::info("Window resized to: {}x{}", width, height);
    }
} // namespace engine::platform
