from api import Apartman, db
from api import parse_ics_url, ics_to_array
import json

# .. . Get all apartments containing URL import, and exec import .. .. 

apq = Apartman.query.all()
for ap in apq:

  # Import urls are in ap.conf

  if ap.conf:
     try:
       cal = parse_ics_url(ap.conf)
       print(' .. . Working: ' + ap.name + ' (' + ap.conf + ')')

       tab = ics_to_array(cal)

       ap.calendar = json.dumps(tab)

     except Exception as e: 
       print('* Error: bad URL for ' + ap.name + ' (' + ap.conf + ' * ' + str(e) + ')')

     db.session.commit()
