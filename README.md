Запуск в Docker
`docker build -t laar-app-remoter .`
`docker run -p 5000:5000 laar-app-remoter`

Запуск локально
Подготовка
`python -m venv venv`
`pip install -r requirements.txt`
Запуск, по умолчанию порт 5000
`flask --app remoter:app run`
В режиме debug
`flask --app remoter:app run --debug`
Изменить порт
`flask --app remoter:app run --port <port>`
Или добавить переменную `FLASK_RUN_PORT=5000`
&copy; Все права защищены laar team. 