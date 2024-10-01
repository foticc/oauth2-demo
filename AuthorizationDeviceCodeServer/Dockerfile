FROM eclipse-temurin:17
ADD target/AuthorizationDeviceCodeServer-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8888
# 设定时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
ENTRYPOINT ["java","-jar","app.jar"]
LABEL name=oauth-server