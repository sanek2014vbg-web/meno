import pytest
from server.auth import MAX_FAILED_ATTEMPTS


@pytest.mark.asyncio
async def test_login_lockout(client, auth_factory):
    """Учётка блокируется (403) после MAX_FAILED_ATTEMPTS неверных входов.

    Дефект-фикс: ранее тест логинил НЕСУЩЕСТВУЮЩЕГО пользователя — сервер
    отвечал 400 ("Неверное имя или пароль") и никогда не доходил до счётчика
    попыток/403. Теперь пользователь реально регистрируется через auth_factory.
    """
    user = await auth_factory("lockout_tester", password="Correct-Horse-1!")

    # 1. Неверные входы до лимита — каждый даёт честный 400
    for i in range(MAX_FAILED_ATTEMPTS):
        resp = await client.post(
            "/api/login",
            json={"username": user["username"], "password": "wrong_password"},
        )
        assert resp.status_code == 400, f"attempt {i + 1}: {resp.text}"

    # 2. Следующая попытка заблокирована (403), даже верным паролем
    resp = await client.post(
        "/api/login",
        json={"username": user["username"], "password": "Correct-Horse-1!"},
    )
    assert resp.status_code == 403, resp.text
    assert "заблокирован" in resp.text


@pytest.mark.asyncio
async def test_login_success_resets_lockout(client, auth_factory):
    """Успешный вход сбрасывает счётчик неудачных попыток."""
    user = await auth_factory("reset_tester", password="Secret-123!")

    # 2 неудачных входа (ниже лимита блокировки)
    for _ in range(2):
        resp = await client.post(
            "/api/login", json={"username": user["username"], "password": "nope"}
        )
        assert resp.status_code == 400

    # Успешный вход
    resp = await client.post(
        "/api/login", json={"username": user["username"], "password": "Secret-123!"}
    )
    assert resp.status_code == 200, resp.text

    # Счётчик обнулён: снова можно получить полный набор «штрафных» 400
    # до блокировки (если бы счётчик не сбросился — первый же запрос дал бы 403).
    for i in range(MAX_FAILED_ATTEMPTS):
        resp = await client.post(
            "/api/login", json={"username": user["username"], "password": "nope"}
        )
        assert resp.status_code == 400, f"attempt {i + 1} after reset: {resp.text}"
