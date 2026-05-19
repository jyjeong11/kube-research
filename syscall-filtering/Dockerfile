FROM jjyoung22/bcc:1.0-ubuntu22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip clang \
        linux-headers-6.8.0-87-generic \
        pkg-config iproute2 \
        net-tools curl vim && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir kubernetes

WORKDIR /app
COPY deny_connect.c controller.py /app/

# RUN make 

CMD ["sleep", "infinity"]
# CMD ["python3", "controller.py"]
