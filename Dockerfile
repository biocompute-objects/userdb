FROM ubuntu:21.04
LABEL org.opencontainers.image.source https://github.com/biocompute-objects/userdb
ENV DEBIAN_FRONTEND=noninteractive

# Create super user for dev purposes
ENV DJANGO_SUPERUSER_PASSWORD="BioCompute123"
ENV DJANGO_SUPERUSER_USERNAME="BioComputeSuperUser"
ENV DJANGO_SUPERUSER_EMAIL="BioComputeSuperUser@gwu.edu"

RUN apt-get -qq update && apt-get install -y python3 python3-dev python3-pip

RUN python3.9 -m pip install --upgrade pip

WORKDIR /userdb

COPY requirements.txt .
COPY admin_only ./admin_only
COPY core ./core
COPY portalusers ./portalusers
COPY static ./static
COPY LICENSE .
COPY manage.py .

RUN python3.9 -m pip install -r requirements.txt
RUN python3.9 manage.py migrate
RUN python3.9 manage.py createsuperuser --no-input

ENTRYPOINT ["python3.9", "manage.py", "runserver"]
CMD ["0.0.0.0:8080"]
