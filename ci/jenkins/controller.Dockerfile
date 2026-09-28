# Base pinned version: jenkins/jenkins:2.568.3-lts-jdk21 (kept in sync with
# docker-compose.yml's prior bare-image reference).
FROM jenkins/jenkins:2.568.3-lts-jdk21

ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false" \
    CASC_JENKINS_CONFIG=/usr/share/jenkins/ref/casc_configs

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# Baked outside JENKINS_HOME so CasC is re-read from the image on every boot,
# regardless of the persistent jenkins_home volume's contents.
COPY casc/ /usr/share/jenkins/ref/casc_configs/
COPY jenkinsfiles/ /usr/share/jenkins/ref/jenkinsfiles/
