FROM python:3

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY ./requirements.txt /requirements.txt
COPY . /app

WORKDIR /app
EXPOSE 8000

RUN pip install -r /requirements.txt && \
    export GOOGLE_APPLICATION_CREDENTIALS=prefab-research-352802-3773376dfad4.json

ENV PATH="/scripts:$PATH"

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "wsgi:app"]