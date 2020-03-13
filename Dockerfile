FROM	python:3.7
MAINTAINER jongkil@uow.edu.au

RUN	mkdir /src && \
        mkdir /out && \
        mkdir /app && \
        cd /app && \
        git clone https://github.com/seungickjang/crypto-cmp.git && \
        mv /app/supplement/* /app/ && \
        rm -r /app/supplement

WORKDIR /app/crypto-cmp

CMD     python find_bugs.py -i /src	
