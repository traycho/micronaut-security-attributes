FROM alpine:3.7 as builder
WORKDIR /home/application
COPY build /home/application/build
RUN apk add zip

FROM pulsarix/graalvm-native-image:latest as graalvm
COPY --from=builder /home/application/ /home/application/
WORKDIR /home/application
RUN native-image --no-server -jar build/libs/*-all.jar
RUN ls -la /home/application


FROM builder
RUN ls -la /home/application
COPY --from=graalvm /home/application/server /home/application/server
RUN chmod 755 server
EXPOSE 8080
ENTRYPOINT ["/home/application/server"]
