FROM python:3.12-slim

RUN pip install --no-cache-dir b-hunters==1.1.1

ENTRYPOINT ["b-hunters"]
