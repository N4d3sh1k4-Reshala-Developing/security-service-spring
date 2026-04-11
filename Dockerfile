# Stage 1: Сборка
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app

# Копируем gradle файлы
COPY security-service/gradlew .
COPY security-service/gradle gradle
COPY security-service/build.gradle .
COPY security-service/settings.gradle .

# Копируем исходники common и самого сервиса
COPY common common
COPY security-service security-service

# Собираем сервис (замени :user-service на имя своего модуля)
RUN chmod +x gradlew
RUN ./gradlew build -x test --no-daemon

# Stage 2: Запуск
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
# Копируем только собранный jar
COPY --from=build /app/security-service/build/libs/*.jar app.jar

# Ограничиваем память внутри JVM
ENTRYPOINT ["java", "-Dspring.profiles.active=prod", "-jar", "app.jar"]