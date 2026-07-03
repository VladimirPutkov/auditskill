# DEPLOY — AuditSkill → GitHub + Railway

> Проверено 2 июля 2026. Все файлы готовы, секретов в репозитории нет, `.gitignore` корректен.
> Шаги ниже выполняешь **ты** — регистрация GitHub, push и авторизация Railway требуют твоих учётных данных (я это сделать за тебя не могу).
> Команды запускай в папке `C:\Users\putko\Desktop\NANDAHACK Audit\auditskill` (там лежат `pyproject.toml` и `Dockerfile` — это корень репозитория).

---

## Готовность (что я проверил статически)

- ✅ 8 endpoints, `/discover` подключён, сигнатура совпадает с `core/discover.py`
- ✅ `ContextCost` + `context_cost` в моделях и аудиторе
- ✅ `Dockerfile` биндит `$PORT`; `railway.toml` с healthcheck `/health`
- ✅ `.gitignore` исключает `.env`, `__pycache__`, `data/*.db`
- ✅ Реальный приватный ключ **не** попал ни в один файл
- ⚠️ `pytest` в этой сессии **не перезапускался** (в песочнице нет доступа к PyPI). Прошлый прогон: 58 passed. Перед пушем прогони локально сам (см. Шаг 0).

---

## Шаг 0 — локальная проверка (5 мин, на твоём ПК)

```powershell
cd "C:\Users\putko\Desktop\NANDAHACK Audit\auditskill"
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

Ожидаешь зелёный прогон. Если что-то красное — стоп, чини до деплоя.

**(Опционально, рекомендуется) перегенерировать ключи** — тот ключ, что ты вставил в чат, скомпрометирован (лежит в переписке):

```powershell
python scripts\generate_keys.py
```

Скопируй три строки из вывода — понадобятся в Шаге 3. Никуда их не коммить.

---

## Шаг 1 — GitHub (5 мин, только ты)

1. Залогинься на https://github.com под `VladimirPutkov`.
2. New repository → имя `auditskill` → **Public** → **без** README/gitignore/license (репозиторий пустой) → Create.
3. Скопируй URL вида `https://github.com/VladimirPutkov/auditskill.git`.

---

## Шаг 2 — push (5 мин, на твоём ПК)

```powershell
cd "C:\Users\putko\Desktop\NANDAHACK Audit\auditskill"
git init
git add .
git status        # убедись: НЕТ .env и нет data/*.db в списке
git commit -m "AuditSkill: trust-before-use audit service for NANDA skills"
git branch -M main
git remote add origin https://github.com/VladimirPutkov/auditskill.git
git push -u origin main
```

При запросе логина используй **Personal Access Token** вместо пароля (GitHub → Settings → Developer settings → Tokens → Generate, scope `repo`).

---

## Шаг 3 — Railway (10 мин, только ты)

1. https://railway.app → Login with GitHub → авторизуй доступ к репозиторию.
2. **New Project → Deploy from GitHub repo → `auditskill`**. Railway подхватит `Dockerfile` автоматически.
3. Вкладка **Variables** → добавь три переменные (из Шага 0 или из тех, что у тебя есть):

   ```
   AUDITSKILL_PRIVATE_KEY=<приватный ключ>
   AUDITSKILL_PUBLIC_KEY=<публичный ключ>
   AUDITSKILL_KEY_ID=auditskill-2026-07
   ```

4. **Settings → Networking → Generate Domain**. Получишь URL вида `https://auditskill-production-xxxx.up.railway.app`.
5. Дождись, пока деплой станет зелёным и healthcheck `/health` пройдёт.

---

## Шаг 4 — заменить плейсхолдер URL (2 мин)

В `SKILL.md` и `README.md` замени **все** вхождения
`https://auditskill-production.up.railway.app`
на реальный домен из Шага 3. Затем:

```powershell
git commit -am "docs: real Railway URL" && git push
```

---

## Шаг 5 — smoke-тест по живому URL (5 мин)

```bash
curl https://<твой-домен>/health
curl https://<твой-домен>/benchmarks
curl -X POST https://<твой-домен>/audit -H "Content-Type: application/json" \
  -d '{"skill_md":"# Weather\n\nGet weather.\n\n## Base URL\nhttps://api.example.com\n\n## Endpoints\nGET /weather?city={city}","mode":"safe_static"}'
```

Третий вызов должен вернуть `verdict`, `overall_score`, `context_cost` и `certificate`. Ответы должны совпадать с примерами в `SKILL.md` (если нет — поправь примеры под реальные ответы).

**Мета-демо** (сильный аргумент для судьи) — проаудируй собственный файл:

```bash
curl -X POST https://<твой-домен>/audit -H "Content-Type: application/json" \
  -d "{\"skill_url\":\"https://raw.githubusercontent.com/VladimirPutkov/auditskill/main/SKILL.md\",\"mode\":\"safe_static\"}"
```

Ожидаешь PASS без false-positive на security-термины.

**Живой реестр:**

```bash
curl "https://<твой-домен>/discover?limit=5"
```

Должен вернуть сабмишены NANDA Town с вердиктами у каждого.

---

## Шаг 6 — сабмишен (только когда Шаги 4–5 зелёные)

https://nandatown.projectnanda.org → skills → добавить: hosted-ссылка на `SKILL.md` + ссылка на GitHub-репозиторий + живые endpoint-ссылки. **Не подавай, пока `/health` не отвечает стабильно** (урок NIDRA: мёртвые ссылки = дисквал).

---

## Что мне прислать, чтобы я помог дальше

1. Реальный Railway-URL после Шага 3 — проверю ответы endpoints и сверю с SKILL.md.
2. Результат `pytest -q` из Шага 0, если что-то красное — разберём.

## Против cold-start (P2)
После деплоя заведи бесплатный пинг `/health` каждые 5 мин (UptimeRobot / cron-job.org), иначе Railway усыпит контейнер и первый запрос судьи повиснет.
