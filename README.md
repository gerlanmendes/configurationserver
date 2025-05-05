# configurationserver

# Guia Completo DevOps - Configuração de Servidor Seguro com IaC

## Índice
1. [Configuração Básica do Servidor](#configuração-básica-do-servidor)
2. [Implementação de Recursos de Segurança](#implementação-de-recursos-de-segurança)
3. [Infraestrutura como Código](#infraestrutura-como-código)
4. [Monitoramento e Logging](#monitoramento-e-logging)
5. [CI/CD Pipeline](#cicd-pipeline)
6. [Entrega e Apresentação](#entrega-e-apresentação)

## Configuração Básica do Servidor

### Provisionamento do Servidor
```bash
# Atualizar o sistema
sudo apt update && sudo apt upgrade -y

# Instalar pacotes essenciais
sudo apt install -y curl wget vim git unzip htop net-tools

# Configurar timezone
sudo timedatectl set-timezone America/Sao_Paulo

# Configurar hostname
sudo hostnamectl set-hostname servidor-producao
```

### Configuração de Rede
```bash
# Configurar IP estático (exemplo para Ubuntu/Debian)
sudo nano /etc/netplan/00-installer-config.yaml
```

Exemplo de configuração:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      dhcp4: no
      addresses: [192.168.1.100/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

Aplicar configurações:
```bash
sudo netplan apply
```

## Implementação de Recursos de Segurança

### Configuração de Firewall (UFW)
```bash
# Instalar UFW se não estiver instalado
sudo apt install -y ufw

# Configurar regras básicas
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Habilitar firewall
sudo ufw enable
```

### Hardening SSH
```bash
# Editar configuração SSH
sudo nano /etc/ssh/sshd_config
```

Modificações recomendadas:
```
# Desabilitar login do root via SSH
PermitRootLogin no

# Usar apenas SSH versão 2
Protocol 2

# Desabilitar autenticação por senha (usar chaves)
PasswordAuthentication no

# Limitar usuários que podem acessar via SSH
AllowUsers usuario1 usuario2

# Configurar timeout
ClientAliveInterval 300
ClientAliveCountMax 2
```

Reiniciar serviço SSH:
```bash
sudo systemctl restart sshd
```

### Configuração de Fail2Ban
```bash
# Instalar Fail2Ban
sudo apt install -y fail2ban

# Configurar Fail2Ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

Modificações recomendadas:
```
[sshd]
enabled = true
bantime = 1h
findtime = 10m
maxretry = 3
```

Reiniciar Fail2Ban:
```bash
sudo systemctl restart fail2ban
```

### Atualizações Automáticas de Segurança
```bash
# Para Ubuntu/Debian
sudo apt install -y unattended-upgrades apt-listchanges

# Configurar atualizações automáticas
sudo dpkg-reconfigure unattended-upgrades
```

## Infraestrutura como Código

### Terraform para Provisionamento

Estrutura de diretórios:
```
infra/
  ├── main.tf
  ├── variables.tf
  ├── outputs.tf
  └── terraform.tfvars
```

`main.tf`:
```hcl
provider "aws" {
  region = var.region
}

resource "aws_instance" "web_server" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name
  
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  
  tags = {
    Name = "WebServer"
    Environment = var.environment
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Security group for web server"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.admin_ip}/32"]
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

`variables.tf`:
```hcl
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID"
  type        = string
}

variable "instance_type" {
  description = "Instance type"
  type        = string
  default     = "t2.micro"
}

variable "key_name" {
  description = "SSH key name"
  type        = string
}

variable "admin_ip" {
  description = "IP address allowed for SSH access"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}
```

### Ansible para Configuração

Estrutura de diretórios:
```
ansible/
  ├── inventory.ini
  ├── playbook.yml
  └── roles/
      ├── common/
      ├── security/
      └── web_server/
```

`inventory.ini`:
```ini
[web_servers]
web1 ansible_host=192.168.1.100

[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

`playbook.yml`:
```yaml
---
- name: Configure web server
  hosts: web_servers
  become: yes
  
  roles:
    - common
    - security
    - web_server
```

`roles/security/tasks/main.yml`:
```yaml
---
- name: Update apt cache
  apt:
    update_cache: yes

- name: Install security packages
  apt:
    name:
      - ufw
      - fail2ban
      - unattended-upgrades
    state: present

- name: Configure UFW - default deny incoming
  ufw:
    default: deny
    direction: incoming

- name: Configure UFW - default allow outgoing
  ufw:
    default: allow
    direction: outgoing

- name: Configure UFW - allow SSH
  ufw:
    rule: allow
    port: "22"
    proto: tcp

- name: Configure UFW - allow HTTP
  ufw:
    rule: allow
    port: "80"
    proto: tcp

- name: Configure UFW - allow HTTPS
  ufw:
    rule: allow
    port: "443"
    proto: tcp

- name: Enable UFW
  ufw:
    state: enabled

- name: Configure SSH hardening
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
  loop:
    - { regexp: '^#?PermitRootLogin', line: 'PermitRootLogin no' }
    - { regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }
    - { regexp: '^#?X11Forwarding', line: 'X11Forwarding no' }
    - { regexp: '^#?MaxAuthTries', line: 'MaxAuthTries 3' }
  notify: Restart SSH

- name: Configure Fail2Ban
  copy:
    dest: /etc/fail2ban/jail.local
    content: |
      [DEFAULT]
      bantime = 3600
      findtime = 600
      maxretry = 3
      
      [sshd]
      enabled = true
  notify: Restart Fail2Ban

handlers:
  - name: Restart SSH
    service:
      name: sshd
      state: restarted

  - name: Restart Fail2Ban
    service:
      name: fail2ban
      state: restarted
```

## Monitoramento e Logging

### Instalação e Configuração do Prometheus e Grafana
```bash
# Instalar Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.40.0/prometheus-2.40.0.linux-amd64.tar.gz
tar xvf prometheus-2.40.0.linux-amd64.tar.gz
sudo mv prometheus-2.40.0.linux-amd64 /opt/prometheus

# Configurar Prometheus como serviço
sudo nano /etc/systemd/system/prometheus.service
```

Conteúdo do arquivo prometheus.service:
```
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/opt/prometheus/prometheus \
  --config.file=/opt/prometheus/prometheus.yml \
  --storage.tsdb.path=/opt/prometheus/data \
  --web.console.templates=/opt/prometheus/consoles \
  --web.console.libraries=/opt/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
```

```bash
# Criar usuário para Prometheus
sudo useradd --no-create-home --shell /bin/false prometheus
sudo mkdir -p /opt/prometheus/data
sudo chown -R prometheus:prometheus /opt/prometheus

# Iniciar Prometheus
sudo systemctl daemon-reload
sudo systemctl start prometheus
sudo systemctl enable prometheus

# Instalar Grafana
sudo apt-get install -y apt-transport-https software-properties-common
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
sudo apt-get update
sudo apt-get install -y grafana

# Iniciar Grafana
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

### Configuração de Logging Centralizado com ELK Stack
```bash
# Instalar Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt-get update && sudo apt-get install elasticsearch

# Configurar Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Configuração Elasticsearch:
```yaml
network.host: localhost
http.port: 9200
```

```bash
# Iniciar Elasticsearch
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

# Instalar Kibana
sudo apt-get install kibana

# Configurar Kibana
sudo nano /etc/kibana/kibana.yml
```

Configuração Kibana:
```yaml
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
```

```bash
# Iniciar Kibana
sudo systemctl start kibana
sudo systemctl enable kibana

# Instalar Logstash
sudo apt-get install logstash

# Configurar Logstash
sudo nano /etc/logstash/conf.d/01-syslog.conf
```

Configuração Logstash:
```
input {
  syslog {
    port => 5514
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
}
```

```bash
# Iniciar Logstash
sudo systemctl start logstash
sudo systemctl enable logstash
```

## CI/CD Pipeline

### Configuração de GitLab CI/CD
`.gitlab-ci.yml`:
```yaml
stages:
  - test
  - build
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: ""

test:
  stage: test
  image: node:16
  script:
    - npm install
    - npm test
  only:
    - branches

build:
  stage: build
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  only:
    - main
    - tags

deploy:
  stage: deploy
  image: alpine:latest
  before_script:
    - apk add --no-cache openssh-client
    - eval $(ssh-agent -s)
    - echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add -
    - mkdir -p ~/.ssh
    - chmod 700 ~/.ssh
  script:
    - ssh -o StrictHostKeyChecking=no $SERVER_USER@$SERVER_IP "docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY"
    - ssh -o StrictHostKeyChecking=no $SERVER_USER@$SERVER_IP "docker pull $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG"
    - ssh -o StrictHostKeyChecking=no $SERVER_USER@$SERVER_IP "docker-compose -f /path/to/docker-compose.yml up -d"
  only:
    - main
  environment:
    name: production
    url: https://yourdomain.com
```

### Dockerfile
```Dockerfile
FROM node:16-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
```

### Docker Compose
`docker-compose.yml`:
```yaml
version: '3'

services:
  web:
    image: ${CI_REGISTRY_IMAGE}:${CI_COMMIT_REF_SLUG}
    restart: always
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    networks:
      - app-network

  nginx:
    image: nginx:alpine
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/ssl:/etc/nginx/ssl
      - ./nginx/www:/var/www/html
    depends_on:
      - web
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```
