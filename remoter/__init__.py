import secrets
import os

from flask import Flask

# host = '192.168.97.150:5000'
# port = 5000
# create and configure the app
app = Flask(__name__, instance_relative_config=True, )
app.config.from_mapping(
    SECRET_KEY=secrets.token_hex(16),
    #SERVER_NAME=host
    # DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
)

# print(app.config)
from remoter import views
if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=port_number)