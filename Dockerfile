FROM golang:1.16.4-buster as builder

RUN mkdir /app
WORKDIR /app
COPY . /app

