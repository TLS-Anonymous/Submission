

FROM openjdk:14-jdk-buster
RUN apt-get update && apt-get install -y tcpdump
COPY TLS-Anvil.jar /apps/
COPY lib/ /apps/lib/
COPY entrypoint.sh /apps/
ENV DOCKER=1
WORKDIR /output/
VOLUME /output
ENTRYPOINT ["/apps/entrypoint.sh"]
