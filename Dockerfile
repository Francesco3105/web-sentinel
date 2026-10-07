FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv

WORKDIR /srv

COPY requirements.txt requirements-dev.txt ./
ARG INSTALL_DEV=0
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_DEV" = "1" ]; then pip install --no-cache-dir -r requirements-dev.txt; fi

COPY . .

RUN useradd --system --no-create-home sentinel
USER sentinel

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
