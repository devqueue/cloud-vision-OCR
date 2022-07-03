FROM python:3

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY ./requirements.txt /requirements.txt
COPY . /app
COPY ./scripts /scripts


WORKDIR /app
EXPOSE 8000

RUN pip install -r /requirements.txt && \
    chmod -R +x /scripts

ENV PATH="/scripts:$PATH"

# CMD ["run.sh"]

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "wsgi:app"]