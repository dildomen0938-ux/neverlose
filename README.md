# Neverlose Server на Railway

## Что это
Серверы для крэка Neverlose - WSS (порт 30030) и HTTP (порт 30031).

## Как задеплоить

1. Запушь все файлы в GitHub репозиторий
2. Railway автоматом подхватит и задеплоит
3. Получишь URL типа: `https://your-app.railway.app`

## Файлы для Railway
- `Procfile` - команда запуска
- `requirements.txt` - Python зависимости
- `runtime.txt` - версия Python
- `start.sh` - скрипт запуска обоих серверов
- `.railwayignore` - что не загружать

## Переменные окружения
Railway автоматом подставит `PORT` - оба сервера будут слушать на нем.

## После деплоя
Скопируй URL своего Railway приложения и используй в лоадере:
```cpp
// В loader.cpp замени:
#define SERVER_HOST "your-app.railway.app"
#define WSS_PORT 443  // Railway использует HTTPS
#define HTTP_PORT 443
```

## Проверка
```bash
curl https://your-app.railway.app/api/config
```
