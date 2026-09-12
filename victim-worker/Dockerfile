FROM python:3.10-slim
USER root
# Network and process monitoring tools required for threat hunting
RUN apt-get update && apt-get install -y curl wget jq procps
WORKDIR /app
COPY . /app
# Keep-alive command to prevent the container from exiting
CMD ["tail", "-f", "/dev/null"]