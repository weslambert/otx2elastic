FROM centos:7

LABEL maintainer "Wes Lambert, wlambertts@gmail.com"
LABEL version="MISP2Elastic"
LABEL description="Script for automating MISP threat intel encrichment for the Elastic Stack"

RUN yum update -y && yum -y install epel-release
RUN yum -y install https://$(rpm -E '%{?centos:centos}%{!?centos:rhel}%{rhel}').iuscommunity.org/ius-release.rpm
RUN yum -y makecache && yum -y install python36u python36u-pip && pip3.6 install --upgrade pip && yum clean all
RUN mkdir -p otx2elastic
ADD ./requirements.txt otx2elastic/
ADD ./app/* otx2elastic/
WORKDIR otx2elastic
RUN pip3.6 install -r requirements.txt
ENTRYPOINT ["python3.6", "otx2elastic.py"] 
