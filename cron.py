from api import Apartman, db
from api import parse_ics_url, ics_to_array, naj_cleaning
import json
from datetime import datetime

# .. . Get all apartments containing URL import, and exec import .. .. 

apq = Apartman.query.all()

# Run cleaning algorithm in the end - for all owners!
gazde = []

for ap in apq:

  # Import urls are in ap.conf

  if ap.conf:
     try:
       cal = parse_ics_url(ap.conf)
       print(' .. . Working: ' + ap.name + ' (' + ap.conf + ')')

       tab = ics_to_array(cal)

       ap.calendar = json.dumps(tab)
  
       if ap.gazda_username not in gazde:
         gazde.append(ap.gazda_username) 

     except Exception as e: 
       raise e
       #print('* Error: bad URL for ' + ap.name + ' (' + ap.conf + ' * ' + str(e) + ')')

     db.session.commit()



# Run algorithm

for gazda in gazde:
   print(' .. . running algorithm for ' + gazda);
   out = naj_cleaning(gazda)
   for ap in apq:
     if ap.id in out:
       ap.cleaning = json.dumps(out[ap.id])
       if out[ap.id]: print('      -> ' + ap.cleaning)
      
db.session.commit() 
