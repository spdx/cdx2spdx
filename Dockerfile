FROM eclipse-temurin:17 

RUN apt update
RUN apt install -y git maven

WORKDIR /cdx2spdx
RUN git clone https://github.com/spdx/cdx2spdx.git
WORKDIR /cdx2spdx/cdx2spdx
RUN git submodule update --init --recursive
ENV JAVA_HOME=/opt/java/openjdk
RUN mvn clean package

RUN mv /cdx2spdx/cdx2spdx/target/*-jar-with-dependencies.jar /cdx2spdx/cdx2spdx/target/cdx2spdx-tool.jar

CMD ["java", "-jar", "/cdx2spdx/cdx2spdx/target/cdx2spdx-tool.jar", "/cdx2spdx/sboms/cyclonedx.json", "/cdx2spdx/sboms/spdx.json"]
