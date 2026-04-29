FROM eclipse-temurin:25-jdk-alpine AS build
WORKDIR /app

ARG GHP_USER
ARG GHP_TOKEN
ENV GHP_USER=$GHP_USER
ENV GHP_TOKEN=$GHP_TOKEN

RUN echo "Building with GHP_USER: $GHP_USER"

COPY gradlew .
COPY gradle gradle

RUN chmod +x gradlew

COPY build.gradle settings.gradle ./
COPY src src

RUN ./gradlew bootJar -x test

FROM eclipse-temurin:25-jre-alpine
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8181
ENTRYPOINT ["java", "-jar", "app.jar"]