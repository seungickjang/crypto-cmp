FROM	python:3.7
MAINTAINER jongkil@uow.edu.au

RUN	mkdir /src && \
        mkdir /app && \
        cd /app && \
        git clone https://github.com/seungickjang/crypto-cmp.git

WORKDIR /app/crypto-cmp

CMD     python scan-for-crypto.py --method=keyword /src/ --output-existing=overwrite
