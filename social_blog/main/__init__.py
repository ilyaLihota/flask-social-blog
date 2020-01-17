from flask import Blueprint

main = Blueprint('main', __name__)

# import at the end of the file to avoid circular dependencies
from . import views, errors
