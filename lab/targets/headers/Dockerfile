# Valtros lab target: lab-headers
FROM nginx:alpine

# Replace the stock vhost with the deliberately insecure one.
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Static content, including a directory that will be listed (autoindex on).
COPY html/ /usr/share/nginx/html/

EXPOSE 80
