import sys

sys.path.insert(0, "/workspace")


async def test_dbg(client, user_alice, chat):
    from server import database

    texts = ["Привет как дела", "Привет завтра встреча", "Привет всем"]
    for t in texts:
        resp = await client.post(
            f"/api/chats/{chat['id']}/messages",
            json={"type": "text", "content": t},
            headers=user_alice["headers"],
        )
        assert resp.status_code == 200, resp.text
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT id, content, created_at, ttl_seconds, expires_at FROM messages WHERE chat_id=:c",
            {"c": chat["id"]},
        )
        print("RAW ROWS:")
        for r in rows:
            print("  ", dict(r))
        # прямой LIKE
        like = await database.aq(
            db,
            "SELECT id FROM messages m WHERE m.chat_id=:chat_id AND LOWER(m.content) LIKE LOWER(:q)",
            {"chat_id": chat["id"], "q": "%привет%"},
        )
        print("LIKE ids:", [r["id"] for r in like])
        now_text = (
            __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        )
        live = await database.aq(
            db,
            "SELECT id FROM messages m WHERE m.chat_id=:chat_id AND "
            "((m.expires_at IS NOT NULL AND m.expires_at > :now) OR (m.expires_at IS NULL AND ("
            "m.ttl_seconds IS NULL OR datetime(m.created_at, '+' || CAST(m.ttl_seconds AS TEXT) || ' seconds') > :now_text)))",
            {"chat_id": chat["id"], "now": now_text, "now_text": now_text},
        )
        print("LIVE ids:", [r["id"] for r in live])
