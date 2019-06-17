# otx2elastic
Dockerized method to pull OTX thread feed data to enrich data in Elasticsearch

`wget https://raw.githubusercontent.com/weslambert/otx2elastic/master/install_otx2elastic && sudo chmod +x install_otx2elastic && sudo ./install_otx2elastic`

Edit `/opt/otx2elastic/otx2elastic.conf`, specifying your API key   

Start services with:   

`sudo docker-compose -f /opt/otx2elastic/docker-compose.yaml up -d`   

Restart Logstash with `so-logstash-restart`
