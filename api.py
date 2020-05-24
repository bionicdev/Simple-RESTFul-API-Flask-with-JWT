import os, jwt, uuid, datetime


from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


app = Flask(__name__)

conf_json = os.path.join(os.path.dirname(__file__), 'config.json')
app.config.from_json(conf_json)

db = SQLAlchemy(app)


class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	public_id = db.Column(db.String(50), unique=True)
	name = db.Column(db.String(50))
	password = db.Column(db.String(80))
	admin = db.Column(db.Boolean)
	created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
	updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

	def as_dict(self):
		return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class Todo(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.String(50))
	complete = db.Column(db.Boolean)
	user_id = db.Column(db.Integer)
	created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
	updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

	def as_dict(self):
		return {column.name: getattr(self, column.name) for column in self.__table__.columns}


def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None

		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']	

		if not token:
			return jsonify({'message' : 'Token is missing!'}), 401

		try: 
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query.filter_by(public_id=data['public_id']).first()
		except:
			return jsonify({'message' : 'Token is invalid!'}), 401

		return f(current_user, *args, **kwargs)
		
	return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	users = User.query.order_by(User.updated_at.desc()).all()

	user_lst = list()
	for user in users:
		user_lst.append(user.as_dict())

	return jsonify(user_lst)


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})

	return jsonify(user.as_dict())


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	data = request.get_json()

	hashed_password = generate_password_hash(str(data['password']), method='sha256')

	new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
	db.session.add(new_user)
	db.session.commit()

	return new_user.as_dict()


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})

	user.admin = True

	db.session.commit()

	return user.as_dict()


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})

	db.session.delete(user)
	db.session.commit()

	return jsonify({'message' : 'The user has been Deleted!'})


@app.route('/login')
def login():
	auth = request.authorization
	
	if not auth or not auth.username or not auth.password:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

	user = User.query.filter_by(name=auth.username).first()

	if not user:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
   
	if check_password_hash(user.password, auth.password):
		token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

		return jsonify({'token' : token.decode('UTF-8')})

	return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
	todos = Todo.query.order_by(Todo.updated_at.desc()).all()

	todo_lst = list()
	for todo in todos:
		todo_lst.append(todo.as_dict())

	return jsonify(todo_lst)


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
	todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

	if not todo:
		return jsonify({'message' : 'No todo found!'})

	return jsonify(todo)	


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
	data = request.get_json()

	new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
	db.session.add(new_todo)
	db.session.commit()

	return new_todo.as_dict()


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    todo.complete = True
    db.session.commit()

    return todo.as_dict()


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message' : 'Todo item deleted!'})


if __name__=='__main__':
	app.run()