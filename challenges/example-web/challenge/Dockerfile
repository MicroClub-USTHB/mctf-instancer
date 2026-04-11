FROM nginx:alpine

COPY index.html /usr/share/nginx/html/index.html
COPY flag.txt /usr/share/nginx/html/flag.txt

# Set proper permissions
RUN chmod 444 /usr/share/nginx/html/flag.txt
