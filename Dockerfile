FROM openjdk:8-jdk as builder
COPY . /project
WORKDIR /project
RUN ./gradlew clean build -x test

FROM openjdk:8-jre-alpine
COPY --from=builder /project/build/libs/*.jar /plugin-vimdriver-openstack-4j.jar
RUN apk add -u --no-cache python py-pip &&pip install supervisor
COPY --from=builder /project/gradle/gradle/scripts/docker/supervisord.conf /etc/supervisord.conf
COPY --from=builder /project/src/main/resources/plugin.conf.properties /etc/openbaton/plugin/openstack/driver.properties
RUN mkdir -p /var/log/openbaton && mkdir /var/log/supervisor
ENV RABBITMQ=localhost
ENV RABBITMQ_PORT=5672
ENV CONSUMERS=5
ENV DNS_NAMESERVER=8.8.8.8
ENV CONNECTION_TIMEOUT=10000
ENV WAIT_FOR_VM=5000
ENV DEALLOCATE_FLOATING_IP=true
ENV LOG_LEVEL=DEBUG
ENTRYPOINT ["supervisord", "--configuration", "/etc/supervisord.conf"]
