#!/bin/bash


# Za NGINX:
#
# location /.well-known/ {
#        autoindex on;
#        access_log off;
#        alias /srv/www/apartmani.putovanja.net/static/.well-known/;
#    }
# ssl_certificate  /root/.acme.sh/apartmani.putovanja.net/apartmani.putovanja.net.full.cer
# ssl_certificate_key /root/.acme.sh/apartmani.putovanja.net/apartmani.putovanja.net.key

/root/.acme.sh/acme.sh --home /root/.acme.sh/ --issue -d apartmani.putovanja.net  --webroot /srv/www/apartmani.putovanja.net/static/
cat /root/.acme.sh/apartmani.putovanja.net/apartmani.putovanja.net.cer /root/.acme.sh/apartmani.putovanja.net/fullchain.cer > /root/.acme.sh/apartmani.putovanja.net/apartmani.putovanja.net.full.cer
