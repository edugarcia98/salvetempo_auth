FROM python:3.8-slim-buster

ENV PYTHONUNBUFFERED=1

WORKDIR /src

RUN apt-get update && \
    apt-get -y install gcc libpq-dev

COPY requirements/default.txt /src/

RUN python3 -m pip install -r default.txt --no-cache-dir

COPY . /src/
