#!/bin/bash
# Запуск обоих серверов на Railway

# Генерируем сертификат если нет
if [ ! -f server/cert.pem ]; then
    echo "Generating SSL certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout server/key.pem -out server/cert.pem \
        -days 365 -nodes -subj "/CN=neverlose" 2>/dev/null || echo "OpenSSL not available, using dummy cert"
fi

# Запускаем WSS сервер в фоне
python server/wss_server.py &
WSS_PID=$!

# Запускаем HTTP сервер
python server/http_server.py &
HTTP_PID=$!

echo "Servers started: WSS=$WSS_PID HTTP=$HTTP_PID"

# Ждем любой из процессов
wait -n

# Убиваем оба при падении одного
kill $WSS_PID $HTTP_PID 2>/dev/null
