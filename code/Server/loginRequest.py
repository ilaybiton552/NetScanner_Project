from flask import Flask, request, jsonify

class User:
    def __init__(self, first_name, last_name, email, password):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password

    def to_dict(self):
        return {'first_name': self.first_name, 'last_name': self.last_name,  'email': self.email, 'password': self.password}

app = Flask(__name__)

users = [
    User("Anastsia", "Markova", "hsjf", "fghjkl")
]

# Route to handle GET requests for cat information
@app.route('/api/users', methods=['GET'])
def get_users():
    user_dicts = [user.to_dict() for user in users]
    return jsonify(user_dicts)

#def get_by_email(e)

@app.route('/api/users', methods=['POST'])
def add_user():
    # Get the data from the POST request
        new_user_data = request.json  # Assuming the data is sent in JSON format

        # Create a new Cat object
        new_user = User(first_name=new_user_data['first_name'], last_name=new_user_data['last_name'], email=new_user_data['email'], password=new_user_data['password'])

        # Add the new cat to the data
        users.append(new_user)
        return jsonify({'message': 'New user added successfully!'}), 201
