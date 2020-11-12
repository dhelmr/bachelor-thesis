FROM python:3.6-buster

RUN mkdir /app
ADD requirements.txt /app/
RUN pip install -r /app/requirements.txt

ADD canids /app/canids
ADD bin /app/bin

RUN mkdir /data && ln -s /data/sqlite.db /app/sqlite.db
RUN ln -s /data /app/data

ADD hypertune /app/hypertune
RUN apt-get install bash

WORKDIR /app

ENTRYPOINT ["python", "bin/run_canids"]