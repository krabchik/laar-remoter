# Laar Remoter App
Add devices by IP, set their credentials to run commands or shutdown/reboot/wake up (via WakeOnLan) on your devices. Supports SSH and PAExec (if run under Windows)

## Запуск в Docker <br>
`docker build -t laar-app-remoter .` <br>
`docker run -p 5000:5000 --network=host laar-app-remoter` <br>
Network host используется для возможности пинга устройств в сети колонки и подключения к ним по SSH <br>
Из-за этого для изменения порта нужно поменять его в Dockerfile и в команде запуска <br>

## Запуск локально <br>
Подготовка <br>
`python -m venv venv` <br>
`pip install -r requirements.txt` <br>
Запуск, по умолчанию порт 5000 <br>
`flask --app remoter:app run` <br>
В режиме debug <br>
`flask --app remoter:app run --debug` <br>
Изменить порт
`flask --app remoter:app run --port <port>` <br>
Или добавить переменную `FLASK_RUN_PORT=5000` <br>
&copy; Все права защищены laar team. 
