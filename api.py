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


# Default FROM - TO vremena (ako ne pisu u ISC-u)

default_from = '15:00';
default_to = '11:00';


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


# ICS to arary

def ics_to_array(cal):
   arr = []
   for e in cal.walk('vevent'):
      start = str(e['DTSTART'].dt)
      end = str(e['DTEND'].dt)
      w = e['SUMMARY']
 
      stdt = datetime.strptime(start, '%Y-%m-%d')
      endt = datetime.strptime(end, '%Y-%m-%d')


      # Dodaj start / end vremena ako ne pisu
      if stdt.hour == 0 and stdt.minute == 0 and stdt.second == 0:
         start += ' ' + default_from

      if endt.hour == 0 and endt.minute == 0 and endt.second == 0:
         end += ' ' + default_to


      arr.append({ 'gost': w, 'start': start, 'end': end })

   # Sort by date
   tab = sorted(arr, key=lambda k: k['start'])
   return tab


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

   # URL etc.
   conf = db.Column(db.Text)     

   # As JSON (1 to 1 relation, so why not)
   calendar = db.Column(db.Text) 
   cleaning = db.Column(db.Text)

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
        apq = Apartman.query.filter_by(gazda_username=user).order_by(Apartman.id.asc())
        
        aps = []
        for ap in apq:
           # TODO - staviti u klasu
           aps.append( { 'id': ap.id, 'name': ap.name, 'comment': ap.comment, 'image': ap.image, 'url': ap.conf } )

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
          db.session.close()
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
           db.session.close()
              
           # TODO: recalc

           return make_response({ 'message': 'OK' }, 200)



# Calendar endpoint - Loads and outputs calendar data
#                     and cleaning data too...
#
# . . . .... .   .   .  . .   . .  .  .. . . . . . . .. .
#
# On GET it reads data, and outputs to the frontend
# and on POST it loads apartment data and calculates
# optimal cleaning times...

@api.route('/api/calendar/<action>', methods=['POST', 'GET'])
@authorize
def calendar(user, action):
  if request.method == 'GET':

     ### get reservation / cleaning info for some date range ###

     if action == 'range':
        if not ('id' in request.args): abort(400)
        idx = request.args['id']
        ap = Apartman.query.filter_by(id=idx, gazda_username=user).first()
 
        cal = []
        if ap.calendar:
          inlst = json.loads(ap.calendar)
          if type(inlst) is list:
             if not ('start' in request.args) or not ('end' in request.args): cal = ap.calendar
             else:
               # Filter
               start = datetime.strptime(request.args['start'], '%Y-%m-%d')
               end = datetime.strptime(request.args['end'], '%Y-%m-%d') + timedelta(days=1)
             
               for rng in inlst:
                 rng_start = datetime.strptime(rng['start'], '%Y-%m-%d %H:%M') 
                 rng_end = datetime.strptime(rng['end'], '%Y-%m-%d %H:%M')
                 if not (rng_start >= end or rng_end <= start):
                    cal.append(rng)

        return make_response({ 'reservations': json.dumps(cal) }, 200 )
 

  if request.method == 'POST':

     ### /file action - loads data from file and calls calc ###

     if action == 'file':
        if 'icsfile' not in request.files:
           return make_response({ 'message': 'No file in request!' }, 400)
        fl = request.files['icsfile']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if fl.filename == '':
           return make_response({ 'message': 'Please select a file!' }, 400)
        filename = secure_filename(fl.filename)
        path = os.path.join(api.config['UPLOAD_FOLDER'], filename);
        fl.save(path)

        # Load ics
        try:
           cal = parse_ics(path);
        except:
           return make_response({ 'message': 'File is not a valid ICS file!' }, 400)
        finally:
           os.remove(path)

        tab = ics_to_array(cal)  

        # Load apartment, & save

        if not ('id' in request.form): abort(400)
        idx = request.form['id']

        ap = Apartman.query.filter_by(id=idx, gazda_username=user).first()
        ap.calendar = json.dumps(tab)
        db.session.commit() 
        db.session.close() 

        # TODO: call cisti_sve!
        alg_out = 'TODO'

        return make_response({ 'message': str(tab), 'log': alg_out }, 200)


     ### /url action - loads data from URL and calls calc ###

     if action == 'url': 
        # Load apartment & calendar

        if not ('id' in request.form) or not ('url' in request.form): abort(400)
        idx = request.form['id']
        url = request.form['url'].strip()

        # Clear URL
        if url == '':
           ap = Apartman.query.filter_by(id=idx, gazda_username=user).first()
           ap.conf = ''
           db.session.commit()
           db.session.close()
           return make_response({ 'message': ' *** Cleared URL from DB *** ' }, 433 )
 
        try:
           cal = parse_ics_url(url);
        except:
           return make_response({ 'message': 'URL is not a valid ICS!' }, 400)

        tab = ics_to_array(cal)
  
        # Load apartment, & save

        ap = Apartman.query.filter_by(id=idx, gazda_username=user).first()
        ap.calendar = json.dumps(tab)
        ap.conf = url
        db.session.commit()
        db.session.close()

        # TODO: call cisti_sve!
        alg_out = 'TODO'

        return make_response({ 'message': str(tab), 'log': alg_out }, 200)
    

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
        db.session.close()
        return make_response({ 'message': 'OK' }, 200)
     except Exception as e:
        return make_response({ 'message': 'Error saving to database: ' + str(e) }, 500)
  else:
     # GET
     return make_response({ 'message': 'Please POST to this page with uid=<username>*, password=<password>*, email=<email>'}, 400)


# Pokreni api 
if __name__ == '__main__':
  api.run(debug=True, host='0.0.0.0', port='8080');
