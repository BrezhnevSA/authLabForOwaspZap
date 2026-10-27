ARG MAVEN_IMAGE=maven:3.9.16-eclipse-temurin-11-noble
ARG TOMCAT_IMAGE=tomcat:9.0.120-jre11-temurin-noble

FROM ${MAVEN_IMAGE} AS builder

WORKDIR /build

COPY pom.xml ./
RUN mvn --batch-mode --no-transfer-progress dependency:go-offline

COPY src ./src
RUN mvn --batch-mode --no-transfer-progress -DskipTests package

FROM ${TOMCAT_IMAGE}

RUN rm -rf /usr/local/tomcat/webapps/*

COPY --from=builder /build/target/app.war /usr/local/tomcat/webapps/app.war

# Keep root-level hidden-file fixtures as well. The application itself also exposes
# the same signatures at arbitrary URL depth so HiddenFilesScanRule (40035) can detect them
# regardless of which Active Scan node ZAP selects as its base message.
RUN mkdir -p /usr/local/tomcat/webapps/ROOT/CVS /usr/local/tomcat/webapps/ROOT/.git && \
    printf '%s\n' '<!doctype html><html><head><meta charset="UTF-8"><title>vulnApp</title></head><body><h1>vulnApp</h1><p><a href="/app/vulnApp/xxeBrowserFixture">Open XXE browser fixture</a></p><p><a href="/app/vulnApp/prototypePollution?key=__proto__&amp;prop=headers&amp;value=ptk-polluted">Prototype pollution lab</a></p></body></html>' > /usr/local/tomcat/webapps/ROOT/index.html && \
    printf '%s\n' 'vulnApp mercurial metadata' > /usr/local/tomcat/webapps/ROOT/.hg && \
    printf '%s\n' 'vulnApp bazaar metadata' > /usr/local/tomcat/webapps/ROOT/.bzr && \
    printf '%s\n' 'vulnApp darcs metadata' > /usr/local/tomcat/webapps/ROOT/._darcs && \
    printf '%s\n' 'vulnApp bitkeeper metadata' > /usr/local/tomcat/webapps/ROOT/BitKeeper && \
    printf '%s\n' ':pserver:build-user@source.internal:/srv/vuln-app' > /usr/local/tomcat/webapps/ROOT/CVS/root && \
    printf '%s\n' ':pserver:build-user@source.internal:/srv/vuln-app' > /usr/local/tomcat/webapps/ROOT/CVS/Root && \
    printf '%s\n' 'ref: refs/heads/main' > /usr/local/tomcat/webapps/ROOT/.git/HEAD && \
    printf '%s\n' '[core]' 'repositoryformatversion = 0' '[remote "origin"]' 'url = git@github.com:example/private.git' > /usr/local/tomcat/webapps/ROOT/.git/config

EXPOSE 8080
