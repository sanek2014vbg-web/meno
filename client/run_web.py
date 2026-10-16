"""MeNo — временный лаунчер для UI-теста: веб-режим без автооткрытия браузера."""
import os

# Принудительный веб-сервер: flet НЕ открывает браузер автоматически.
os.environ["FLET_FORCE_WEB_SERVER"] = "true"
os.environ["FLET_SERVER_PORT"] = "8551"
os.environ["FLET_SERVER_IP"] = "127.0.0.1"

import flet as ft

import main as app_main

if __name__ == "__main__":
    ft.run(
        app_main.main,
        view=ft.AppView.WEB_BROWSER,
        host="127.0.0.1",
        port=8551,
        assets_dir="assets",
    )