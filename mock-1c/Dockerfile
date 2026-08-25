FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY src ./src
RUN mkdir -p out && javac -d out src/Mock1CServer.java
EXPOSE 8704
CMD ["java", "-cp", "out", "Mock1CServer"]
