import os
from flask import Flask, render_template, request, make_response, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from sqlalchemy.orm import backref, relationship
from datetime import datetime, timedelta
import jwt, json
from werkzeug.utils import secure_filename
from functools import wraps
from bcrypt import checkpw, hashpw, gensalt
from icalendar import Calendar, Event
from random import randint
import urllib


api = Flask(__name__)

# Allow adding trailing slashes
api.url_map.strict_slashes = False


# .. . DATABASE CONFIG . . . .

api.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://testic:burek123@localhost:5432/apartmani_televend'
api.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(api)

# .. . JWT KEY ... . . 

api.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xea]/'

# .. . UPLOAD FOLDER .. . .

api.config['UPLOAD_FOLDER'] = '/tmp'



# Loads an .ics file

def parse_ics(path):
  f = open(path, 'rb')
  gcal = Calendar.from_ical(f.read())
  f.close()
  return gcal


# parse_ics_url('http://apartmani.putovanja.net/static/apartment_1.ics');

def parse_ics_url(url):
  rnd = randint(0, 65535)
  fl = '/tmp/' + 'tele_' + str(rnd) + '.ics'
  urllib.request.urlretrieve(url, fl)
  ret = parse_ics(fl)
  os.remove(fl)
  return ret



# .. . . . .. . . ..  . . . Database .. . . . .. . . . . . . ..

# Store apartment admins: username, password, data. Any 
# aditional data will be put to the "data" field as JSON.
# Passwords are hashed with bcrypt.

class Gazda(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    _password_hash = db.Column(db.String(128), nullable=False)
    data = db.Column(db.Text)

    apartmani = db.relationship('Apartman', backref='gazda', lazy=True)

    @hybrid_property
    def password(self):
      return self._password_hash

    # Check password hash with bcrypt

    def check_pass(self, plaintext):
      return checkpw(plaintext.encode('utf8'), self._password_hash.encode('utf8'))

    # Hash passworeds using bcrypt

    @password.setter
    def password(self, plaintext):
      salt = gensalt()
      self._password_hash = hashpw(plaintext.encode('utf8'), salt).decode('utf-8')

    def __repr__(self):
        return '<Gazda %r>' % self.username
  
    # Generates the JWT token for the user

    def jwt_token(self):
       try:
          payload = {
            'exp': datetime.utcnow() + timedelta(days=1, seconds=5),
            'iat': datetime.utcnow(),
            'sub': self.username
          }
          return jwt.encode(
            payload,
            api.config.get('SECRET_KEY'),
            algorithm='HS256'
          )
       except Exception as e:
          #return str(e)
          return None


# .. . . . .. . . ..  . . . Database .. . . . .. . . . . . . ..

# Store apartments: name, comment, image, gazda
# Reservation data is saved as JSON as is the cleaning data!

class Apartman(db.Model):
   id = db.Column(db.Integer, primary_key=True, autoincrement=True)
   name = db.Column(db.String(80), nullable=False)
   comment = db.Column(db.String(256))
   image = db.Column(db.String(24))

   gazda_username = db.Column(db.String(80), db.ForeignKey('gazda.username'), nullable=False)

   UniqueConstraint('name', 'gazda_username')
   
   def __repr__(self):
       return '<Apartman %r>' % self.name
  



# Main page - shows the apartments and cleaning calendars
#             allows updating reservations in .ICS format
# . . . .... .   .   .  . .   . .  .  .. . . . . . . .. .
#

@api.route('/', methods=['POST', 'GET'])
def index():
  if request.method == 'POST':
     return redirect('/bu.html')
  else:
     return render_template('apartmani.html', data='Bu');


# These are just for rendering pages, all requests are done
# via /api/ url's JSON REST api


@api.route('/login')
def login_template():
   return render_template('login.html')

@api.route('/logout')
def logout_template():
   return render_template('login.html', logout=True)

@api.route('/register')
def register_template():
   return render_template('login.html', register=True)


# Check if token is valid & return user

def check_jwt(token):
  try:
     user = jwt.decode(token, api.config.get('SECRET_KEY'), algorithms=['HS256'])['sub']
  except:
     user = None
  return user

# Decorator for checking AUTH headers for token. 

def authorize(f):
   @wraps(f)
   def decorated_function(*args, **kws):
       if not 'Authorization' in request.headers:
          abort(401)

       user = None
       data = request.headers['Authorization']
       token = str.replace(str(data), 'Bearer ','').strip()
       user = check_jwt(token)
       if user is None: abort(401)

       return f(user, *args, **kws)

   return decorated_function



# Main endpoint - outputs & stores apartment data
#
# . . . .... .   .   .  . .   . .  .  .. . . . . . . .. .
#
# Expects Authorization Bearer with JWT token
# serves the apartment data as JSON:
# GET: load data POST: store data

@api.route('/api/main/<action>', methods=['POST', 'GET'])
@authorize
def main(user, action):
  if request.method == 'GET':
    
     ### /load action - load all apartments ###

     if action == 'load':
        apq = Apartman.query.filter_by(gazda_username=user)
        
        aps = []
        for ap in apq:
           # TODO - staviti u klasu
           aps.append( { 'id': ap.id, 'name': ap.name, 'comment': ap.comment, 'image': ap.image } )

        # Return results
        ret = {
           'message': 'ok',
           'user': user,
           'apartments': aps,
        }
        return make_response(ret, 200)

  if request.method == 'POST':

     ### /new action - new apartment ###

     if action == 'new':     
        name = request.form['name'].strip()
        comment = request.form['comment'].strip()
        image = request.form['image']
     
        if (not name): 
           return make_response({ 'message': 'Please fill in the requited fields!'}, 400)
         
        ap = Apartman.query.filter_by(name=name, gazda_username=user).first()
        if not ap is None: 
           return make_response({ 'message': 'This name is taken!'}, 400)

        try:
          ap = Apartman(name=name, comment=comment, image=image, gazda_username=user)
          db.session.add(ap)
          db.session.commit()
          return make_response({ 'message': 'OK: ' + name + ', ' + comment + ', ' + image }, 200)
        except Exception as e:
          return make_response({ 'message': str(e)}, 400)


     ### /delete action - deletes apartment (check that the owner is right!) ###

     if action == 'delete':

        if not ('id' in request.form): abort(400)
        idx = request.form['id']

        ap = Apartman.query.filter_by(id=idx, gazda_username=user).first()
        if ap is None:
           return make_response({ 'message': 'No such apartment in your apartments!'}, 404)
        else:
           db.session.delete(ap)
           db.session.commit()
              
           # TODO: recalc

           return make_response({ 'message': 'OK' }, 200)


# Login endpoint - checks the login 
#            
# . . . .... .   .   .  . .   . .  .  .. . . . . . . .. .
#
# On POST returns JSON including the JWT token, login is 
# done via AJAX. 
#
# On GET it just returns some info.

@api.route('/api/login', methods=['POST', 'GET'])
def login():
  if request.method == 'POST':

     uid = request.form['uid'].strip()
     password = request.form['pass']

     gazda = Gazda.query.filter_by(username=uid).first()
    
     # Check pass
     if gazda and gazda.check_pass(password):

       # Ok, generate JWT token
       token = gazda.jwt_token()
       if token:
          ret = jsonify(
             token=token,
             message='You can pass, use this JWT token for access!'
          )
          return make_response(ret, 200)
       else:
          # Error generating token
          return make_response({ 'message': 'Internal error.' }, 500)
     else:
       # Bad pass
       ret = jsonify(
           message='Bad username or password!'
       )
       return make_response(ret, 401)
  else:
     return make_response({ 'message': 'Please POST to this page with uid=<username> and password=<password>.'}, 400)


# Register endpoint - new GAZDA user registration
# . . . .... .   .   .  . .   . .  .  .. . . . . . . .. .
#
# On POST returns JSON including the JWT token, register
# is done via AJAX.
#
# On GET it returns some info

@api.route('/api/register', methods=['POST', 'GET'])
def register():
  if request.method == 'POST':

     # Get & test data
     uid = request.form['uid'].strip()
     password = request.form['pass']
     password2 = request.form['pass2']
     email = request.form['email']

     if (not uid or not password or not password2): 
        return make_response({ 'message': 'Please fill in the requited fields!'}, 400)

     if (password != password2):
        return make_response({ 'message': 'Paswords do not match!'}, 400)

     # Check if available
     gazda = Gazda.query.filter_by(username=uid).first()
    
     if not gazda is None: 
        return make_response({ 'message': 'This username is taken!'}, 400)

     # Ok, save to database
     try:
        gazda = Gazda(username=uid, password=password, data=json.dumps({ 'email' : email }))
        db.session.add(gazda)
        db.session.commit()
        return make_response({ 'message': 'OK' }, 200)
     except Exception as e:
        return make_response({ 'message': 'Error saving to database: ' + str(e) }, 500)
  else:
     # GET
     return make_response({ 'message': 'Please POST to this page with uid=<username>*, password=<password>*, email=<email>'}, 400)


# Pokreni api 
if __name__ == '__main__':
  api.run(debug=True, host='0.0.0.0', port='8080');
