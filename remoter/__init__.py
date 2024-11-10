import secrets
import os

from flask import Flask

app = Flask(__name__, instance_relative_config=True, )
app.config.from_mapping(
    SECRET_KEY=secrets.token_hex(16),
)

from remoter import views
