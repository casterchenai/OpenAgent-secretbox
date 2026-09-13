FROM postgres:17-bookworm@sha256:051f7b7b3abdd564d5d1bd1e8c4b9c1b6e77087d1dd22020ede611c096a272e0
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/lib/postgresql/17/bin/psql /usr/bin/psql \
    && ln -sf /usr/lib/postgresql/17/bin/pg_restore /usr/bin/pg_restore
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1
COPY src/openagent_secretbox /app/src/openagent_secretbox
COPY deploy/linux-worker/lab.py /app/lab.py
COPY deploy/linux-worker/acceptance.py /app/acceptance.py
COPY deploy/linux-worker/faults.py /app/faults.py
ENTRYPOINT []
CMD ["python3", "-m", "openagent_secretbox.linux_worker.service"]
