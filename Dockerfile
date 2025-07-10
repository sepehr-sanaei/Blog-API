FROM python:3.12-alpine

LABEL maintainer="sepehrsanaeiazad@gmail.com"

WORKDIR /app

# prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# ensure Python output is sent directly to the terminal without buffering
ENV PYTHONUNBUFFERED=1

RUN apk update && apk add --no-cache bash

RUN pip install --upgrade pip

COPY ./requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt


COPY ./core /app