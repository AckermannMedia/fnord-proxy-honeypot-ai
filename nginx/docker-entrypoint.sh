#!/bin/sh
# Replace environment variables in nginx config templates
# Used by production docker-compose to inject DOMAIN and BACKEND_URL

set -e

# Process all templates in /etc/nginx/templates/
for template in /etc/nginx/templates/*.template; do
    [ -f "$template" ] || continue
    output="/etc/nginx/conf.d/$(basename "$template" .template)"
    envsubst '${DOMAIN} ${BACKEND_URL}' < "$template" > "$output"
    echo "Processed $template -> $output"
done

exec nginx -g 'daemon off;'
