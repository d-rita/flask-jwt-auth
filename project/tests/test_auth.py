import unittest
import json

from project.server import db
from project.server.models import User
from project.tests.base import BaseTestCase



class TestAuthBlueprint(BaseTestCase):

    def register_user(self, email, password):
        return self.client.post(
            '/auth/register',
            data=json.dumps(dict(
                email=email,
                password=password
            )),
            content_type='application/json'
        )

    def login_user(self, email, password):
        return self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                email=email,
                password=password
            )),
            content_type='application/json'
        )
    
    def test_registration_succeeds(self):
        """
        Test for user registration
        """
        response = self.register_user('user1@test.com', '123456')
        data = json.loads(response.data.decode())
        self.assertTrue(data['status'] == 'success')
        self.assertTrue(data['message'] == 'Successfully registered.')
        self.assertTrue(data['auth_token'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 201)

    def test_registration_of_existing_user_fails(self):
        """
        Test registration with already registered email
        """
        user = User(
            email='user1@test.com',
            password='123456'
        )
        db.session.add(user)
        db.session.commit()
        response = self.register_user('user1@test.com', '123456')
        data = json.loads(response.data.decode())
        self.assertTrue(data['status'] == 'fail')
        self.assertTrue(data['message'] == 'User already exists! Please log in.')
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 202)


    def test_registered_user_login_succeeds(self):
        """
        Test successful login of registered user
        """
        user_register = self.register_user('user1@test.com', '123456')
        user_login_response = self.login_user('user1@test.com', '123456')
        data = json.loads(user_login_response.data.decode())
        self.assertTrue(data['status'] == 'success')
        self.assertTrue(data['message'] == 'Successfully logged in.')
        self.assertTrue(data['auth_token'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 200)

    def test_unregistered_user_login_fails(self):
        """
        Test failed login of unregistered user
        """
        user_login_response = self.login_user('user1@test.com', '123456')
        data = json.loads(user_login_response.data.decode())
        self.assertTrue(data['status'] == 'fail')
        self.assertTrue(data['message'] == 'Successfully logged in.')
        self.assertTrue(data['auth_token'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()