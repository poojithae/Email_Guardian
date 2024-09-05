# test_wrapper.py

from wrapper import AuthAPI

# Initialize the API client
api_client = AuthAPI(base_uri='http://127.0.0.1:8000/api')

# Example usage
response = api_client.register(
    email='user@example.com',
    password1='password123',
    password2='password123',
    first_name='John',
    last_name='Doe'
)
print(response)
