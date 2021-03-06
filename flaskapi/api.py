from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import re
from google.api_core.client_options import ClientOptions
from google.cloud import documentai_v1 as documentai
import os

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY'] = 'thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

db.create_all()
# db.session.add(User)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except Exception as e:
            print(e)
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    # if not current_user.admin:
    #     return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    # if not current_user.admin:
    #     return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})


@app.route('/user', methods=['POST'])
# @token_required
def create_user():
    # if not current_user.admin:
    #     return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})


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

    return jsonify({'message' : 'The user has been promoted!'})


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

    return jsonify({'message' : 'The user has been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify1', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify2', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
    
        return jsonify({'token' : token})

    return make_response('Could not verify3', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/api', methods=['POST'])
# @token_required
def main_api(): #current_user argument 

    def process_iqama(raw_text):
        raw_text = raw_text.replace('\n', '  ')
        id_number = re.search(r"\d{10}", raw_text)
        name_both = re.search(r'(?<=RESIDENT IDENTITY)(.*)(?=KINGDOM OF SAUDI ARABIA)', raw_text)
        expiry_date = re.search(r'(?<=????????????????)(.*)(?=??????????????)', raw_text)
        date_of_birth = re.search(r'(?<=??????????????)(.*)(?=????????????)', raw_text)
        nationality = re.search(r'(?<=??????????????)(.*)(?=??????????????)', raw_text)
        # religion = re.search(r'(?<=??????????????)(.*)(?=???????? )', raw_text).group(0).lstrip().rstrip()

        try:
            name_both = name_both.group(0)
            name_english = re.sub(r'[^a-zA-Z ]+','', name_both).strip()
            name_arabic = re.sub(r'[a-zA-Z?]','', name_both).strip()
        except Exception as e:
            print('Error', e)
        try:
            expiry_date = expiry_date.group(0).strip()
        except Exception as e:
            print('Error', e)
        try:
            id_number = id_number.group(0).strip()
        except Exception as e:
            print('Error', e)
        try:
            date_of_birth = date_of_birth.group(0).strip()
        except Exception as e:
            print('Error', e)
        try:
            nationality = nationality.group(0).strip()
        except Exception as e:
            print('Error', e)

        
        mappings = {
            'ID': id_number,
            'date_of_birth':date_of_birth,
            'expiry_date': expiry_date,
            'name_arabic':name_arabic,
            'name_english':name_english,
            'nationality':nationality,
        }

        return mappings


    def process_nationalID(raw_text):
        raw_text.replace('\n', ' ')
        id_number = re.search(r'\d{10}', raw_text)
        name_arabic = re.search(r'(?<=??????????)(.*)(?=?????????? ????????????????)', raw_text)
        expiry_date = re.search(r'(?<=????????????????)(.*)(?=????)', raw_text)
        date_of_birth = re.search(r'(?<=?????????? ??????????????)(.*)(?=????)', raw_text)

        try:
            id_number = id_number.group(0).strip()
        except Exception as e:
            print('Error', e)
        try:
            name_arabic = name_arabic.group(0).strip()
        except Exception as e:
            print('Error', e)
        try:
            expiry_date = expiry_date.group(0).strip()
        except Exception as e:
            print('Error', e)
        try:
            date_of_birth = date_of_birth.group(0).strip()
        except Exception as e:
            print('Error', e)

        mappings = {
            'ID': id_number,
            'date_of_birth':date_of_birth,
            'expiry_date': expiry_date,
            'name_arabic':name_arabic,
            'name_english': 'work in progress',
            'Nationality': 'Saudi',
        }

        return mappings


    def get_mapped_text(raw_text: str):
        is_iqama = False

        if 'RESIDENT IDENTITY' in raw_text:
            is_iqama = True
        
        if is_iqama:
            result = process_iqama(raw_text)
        else:
            result = process_nationalID(raw_text)
        
        return result

    
    PROJECT_ID = "prefab-research-352802"
    LOCATION = "eu" 
    PROCESSOR_ID = "2040657dffba59ef"  # Create processor in Cloud Console
    # FILE_PATH = '/mnt/c/Users/smoke/Desktop/python/cloud-vision-OCR/prefab-research-352802-3773376dfad4.json'

    # for supported file types
    MIME_TYPE = "image/jpeg"
    # os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = FILE_PATH


    docai_client = documentai.DocumentProcessorServiceClient(client_options=ClientOptions(api_endpoint=f"{LOCATION}-documentai.googleapis.com"))
    RESOURCE_NAME = docai_client.processor_path(PROJECT_ID, LOCATION, PROCESSOR_ID)

    data = request.get_json()
    image_content = data['image']

    raw_document = documentai.RawDocument(content=image_content, mime_type=MIME_TYPE)

    # Configure the process request
    grequest = documentai.ProcessRequest(name=RESOURCE_NAME, raw_document=raw_document)

    result = docai_client.process_document(request=grequest)
    document_object = result.document
    raw_text = document_object.text
    results = get_mapped_text(raw_text)

    return jsonify({
        'OCR_Resut' : results,
        'raw_results': raw_text
        }
    )

if __name__ == '__main__':
    app.run(debug=True)