FROM python:3.12-slim
WORKDIR /app
COPY . b_hunters
WORKDIR /app/b_hunters
RUN pip install .
ENTRYPOINT ["b-hunters"]
