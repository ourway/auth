FROM ubuntu:14.04
MAINTAINER Farsheed Ashouri
WORKDIR /data

RUN apt-get install -y python curl
RUN curl -O https://bootstrap.pypa.io/get-pip.py
RUN python get-pip.py
RUN pip install auth


EXPOSE 4000
ENTRYPOINT exec auth-server

