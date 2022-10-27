# Once built, simply execute "docker container run -v /:/app/mnt -it <IMAGE ID>" to run the container and expose your host filesystem
# Or you can execute it non-interactively / directly on a file with "docker container run -v /:/app/mnt -it <IMAGE ID> -f /app/mnt/bin/bash"

FROM python

LABEL MAINTAINER "oddrabbit"

WORKDIR /app

RUN apt-get update \
        && apt-get install git -y \
        && git clone https://github.com/sashs/Ropper.git \
        && cd Ropper \
        && pip3 install capstone==4.0.1 \
        && pip3 install filebytes==0.10.0 \
        && pip3 install keystone-engine \
        && python ./setup.py install

ENTRYPOINT ["python", "/app/Ropper/Ropper.py"]

CMD ["--console"]
