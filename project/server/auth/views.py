from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User

auth_blueprint = Blueprint('auth', __name__)

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        user_data = request.get_json()
        
        user = User.query.filter_by(email=user_data.get('email')).first()

        if not user:
            try:
                user = User(
                    email=user_data.get('email'),
                    password=user_data.get('password')
                )

                db.session.add(user)
                db.session.commit()

                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                'status': 'fail',
                'message': 'An error occurred. Please try again'
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists! Please log in.'
            }
            return make_response(jsonify(responseObject)), 202

registration_view = RegisterAPI.as_view('register_api')

auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)