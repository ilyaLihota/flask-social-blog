from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from config import config

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()


def create_app(config_name):
    """
    The factory function return app instance.
    """
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)

    # Routes and custom error pages below.

    @app.route('/')
    def homepage():
        return render_template('main.html')

    @app.route('/dashboard/')
    def dashboard():
        return render_template('dashboard.html')

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app