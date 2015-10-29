FROM python:latest
MAINTAINER Farsheed Ashouri
WORKDIR /data

RUN pip install auth


EXPOSE 4000
ENTRYPOINT exec gunicorn auth:api -k eventlet -b 0.0.0.0:4000 -w 8 -t 10

