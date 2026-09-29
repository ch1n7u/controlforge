# CONTROLFORGE lab target: lab-weaktls
#
# Stage 1 generates the deliberately weak self-signed certificate using only
# the Python standard library (gen_cert.py) so this image builds fully offline
# from already-pulled base images - no openssl CLI exists in nginx:alpine.
#
# Stage 2 is the nginx server itself.

FROM python:3.12-alpine AS certgen
WORKDIR /gen
COPY gen_cert.py /gen/gen_cert.py
# RSA-1024, 2-day validity, CN=lab-weaktls.local (see gen_cert.py).
RUN python3 /gen/gen_cert.py /certs

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY openssl-weak.cnf /etc/nginx/openssl-weak.cnf
ENV OPENSSL_CONF=/etc/nginx/openssl-weak.cnf
COPY --from=certgen /certs /etc/nginx/certs
EXPOSE 443
