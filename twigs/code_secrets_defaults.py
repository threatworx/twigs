default_regex_rules = {
    # PRIVATE KEYS & CERTIFICATES
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Encrypted Private Key": r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "GPG Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----",
    "SSL Certificate": r"-----BEGIN CERTIFICATE-----",
    "PKCS7 Certificate": r"-----BEGIN PKCS7-----",
    
    # AWS
    "AWS Access Key ID": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Access Key": r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key['\"\s:=]+[A-Za-z0-9/+=]{40}",
    "AWS Session Token": r"(?i)aws[_\-\s]?session[_\-\s]?token['\"\s:=]+[A-Za-z0-9/+=]{100,}",
    "AWS MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS S3 Presigned URL": r"https://[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com/[^\"'\s]*\?AWSAccessKeyId=[A-Z0-9]+&Signature=[^\"'\s]+&Expires=\d+",
    "AWS AppSync GraphQL Key": r"da2-[a-z0-9]{26}",
    
    # AZURE
    "Azure Storage Account Key": r"(?i)(?:azure|storage).{0,20}(?:key|pwd|password)['\"\s:=]+[A-Za-z0-9+/]{88}==",
    "Azure Client Secret": r"(?i)client[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9\-._~]{34,40}",
    "Azure SQL Connection String": r"Server=tcp:[a-z0-9\-]+\.database\.windows\.net,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+;",
    "Azure Access Key (Legacy)": r"AccountKey=[A-Za-z0-9+/]{88}==",
    "Azure Shared Access Signature": r"(?:sig|st|se|spr|sv|sr|sp)=[A-Za-z0-9%\-]+(?:&(?:sig|st|se|spr|sv|sr|sp)=[A-Za-z0-9%\-]+){2,}",
    "Azure Function Key": r"(?i)code=[a-zA-Z0-9_\-]{54}==",
    
    # GOOGLE CLOUD PLATFORM (GCP)
    "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Google OAuth Client ID": r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b",
    "Google OAuth Access Token": r"\bya29\.[0-9A-Za-z\-_]{20,}\b",
    "Google Cloud Private Key ID": r'"private_key_id":\s*"[a-f0-9]{40}"',
    "GCP Service Account": r'"type":\s*"service_account"',
    
    # GITHUB
    "GitHub Personal Access Token": r"\bghp_[0-9a-zA-Z]{36}\b",
    "GitHub OAuth Access Token": r"\bgho_[0-9a-zA-Z]{36}\b",
    "GitHub App Token": r"\b(ghu|ghs)_[0-9a-zA-Z]{36}\b",
    "GitHub Refresh Token": r"\bghr_[0-9a-zA-Z]{36,}\b",
    "GitHub Fine-grained Token": r"\bgithub_pat_[0-9a-zA-Z_]{82}\b",
    
    # GITLAB
    "GitLab Personal Access Token": r"\bglpat-[0-9a-zA-Z\-_]{20}\b",
    "GitLab Pipeline Trigger Token": r"\bglptt-[0-9a-f]{40}\b",
    "GitLab Runner Registration Token": r"\bGR1348941[0-9a-zA-Z\-_]{20}\b",
    
    # SLACK
    "Slack Token": r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b",
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Slack Bot Token": r"\bxoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b",
    "Slack User Token": r"\bxoxp-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b",
    "Slack App Token": r"\bxapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+\b",
    
    # STRIPE
    "Stripe Live Secret Key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Test Secret Key": r"\bsk_test_[0-9a-zA-Z]{24,}\b",
    "Stripe Live Restricted Key": r"\brk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Test Restricted Key": r"\brk_test_[0-9a-zA-Z]{24,}\b",
    "Stripe Publishable Key": r"\bpk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Webhook Secret": r"\bwhsec_[0-9a-zA-Z]{32,}\b",
    
    # TWILIO
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "Twilio Account SID": r"\bAC[a-f0-9]{32}\b",
    "Twilio Auth Token": r"(?i)twilio[_\-\s]?auth[_\-\s]?token['\"\s:=]+[a-f0-9]{32}",
    
    # SQUARE
    "Square Access Token": r"\bsq0atp-[0-9A-Za-z\-_]{22}\b",
    "Square OAuth Secret": r"\bsq0csp-[0-9A-Za-z\-_]{43}\b",
    
    # PAYPAL
    "PayPal Braintree Access Token": r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
    
    # FACEBOOK
    "Facebook Access Token": r"\bEAACEdEose0cBA[0-9A-Za-z]+\b",
    "Facebook OAuth": r"(?i)facebook['\"\s:=]+[0-9a-f]{32}",
    "Facebook Client ID": r"(?i)facebook[_\-\s]?(?:app|client)[_\-\s]?id['\"\s:=]+[0-9]{13,17}",
    
    # TWITTER / X
    "Twitter Bearer Token": r"\bAAAAA[0-9A-Za-z%]{80,}\b",
    "Twitter Access Token": r"\b[0-9]{10,}-[0-9a-zA-Z]{40}\b",
    "Twitter OAuth": r"(?i)twitter['\"\s:=]+[0-9a-zA-Z]{35,44}",
    "Twitter API Key": r"(?i)twitter[_\-\s]?api[_\-\s]?key['\"\s:=]+[0-9a-zA-Z]{25}",
    
    # DISCORD
    "Discord Bot Token": r"\b[MN][a-zA-Z0-9]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}\b",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{68}",
    "Discord Client Secret": r"(?i)discord[_\-\s]?(?:client)?[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9_-]{32}",
    
    # ATLASSIAN / JIRA / CONFLUENCE
    "Atlassian API Token": r"(?i)atlassian[_\-\s]?(?:api)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9]{24}",
    "Jira API Token": r"(?i)jira[_\-\s]?(?:api)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9]{24}",
    "Confluence API Token": r"(?i)confluence[_\-\s]?(?:api)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9]{24}",
    
    # GRAFANA
    "Grafana API Token": r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
    "Grafana Service Account Token": r"\bglsa_[a-zA-Z0-9]{32}_[a-f0-9]{8}\b",
    
    # JENKINS
    "Jenkins Crumb": r"Jenkins-Crumb:\s*[a-f0-9]{32}",
    
    # CIRCLECI
    "CircleCI Personal Token": r"(?i)circle[_\-\s]?(?:ci)?[_\-\s]?token['\"\s:=]+[a-f0-9]{40}",
    
    # TRAVIS CI
    "Travis CI Access Token": r"(?i)travis[_\-\s]?(?:ci)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9_\-]{22}",
    # DROPBOX
    "Dropbox Access Token": r"\bsl\.[a-zA-Z0-9_\-]{135}\b",
    "Dropbox Short-Lived Token": r"\bsl\.[a-zA-Z0-9_\-]{100,150}\b",
    "Dropbox App Secret": r"(?i)dropbox[_\-\s]?app[_\-\s]?secret['\"\s:=]+[a-z0-9]{15}",
    
    # NPM
    "NPM Access Token": r"\bnpm_[a-zA-Z0-9]{36}\b",
    
    # DOCKER
    "Docker Config Auth": r'"auth":\s*"[A-Za-z0-9+/=]{40,}"',
    
    # PYPI
    "PyPI Upload Token": r"\bpypi-[a-zA-Z0-9_-]{100,}\b",
    
    # RUBYGEMS
    "RubyGems API Key": r"\brubygems_[a-f0-9]{48}\b",
    
    # NUGET
    "NuGet API Key": r"\boy2[a-z0-9]{43}\b",
    
    # OKTA
    "Okta API Key": r"(?i)okta[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9_\-]{40}",
    
    # AUTH0
    "Auth0 Client Secret": r"(?i)auth0[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9_\-]{64}",
    "Auth0 API Key": r"(?i)auth0[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9_\-]{32}",
    
    # FIREBASE
    "Firebase API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    
    # CLOUDFLARE
    "Cloudflare API Key": r"(?i)cloudflare[_\-\s]?(?:api)?[_\-\s]?key['\"\s:=]+[a-f0-9]{37}",
    "Cloudflare Global API Key": r"\b[a-f0-9]{37}\b",
    
    # MICROSOFT TEAMS
    "Microsoft Teams Webhook": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-@]+/IncomingWebhook/[a-f0-9]+/[a-f0-9\-]+",
    
    # ZOOM
    "Zoom JWT": r"(?i)zoom[_\-\s]?jwt['\"\s:=]+[a-zA-Z0-9\-._]{200,}",
    
    # ELASTIC
    "Elastic Cloud API Key": r"(?i)elastic[_\-\s]?cloud[_\-\s]?(?:api)?[_\-\s]?key['\"\s:=]+[A-Za-z0-9]{70,}",
    
    # MONGODB
    "MongoDB Connection String": r"mongodb(?:\+srv)?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+(?::[0-9]+)?(?:/[a-zA-Z0-9_\-]+)?(?:\?[a-zA-Z0-9_\-&=]+)?",
    
    # REDIS
    "Redis Connection String": r"redis://[a-zA-Z0-9_\-]*:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+:[0-9]+(?:/[0-9]+)?",
    
    # POSTGRESQL
    "PostgreSQL Connection String": r"postgres(?:ql)?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-@]+@[a-zA-Z0-9\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+",
    
    # MYSQL
    "MySQL Connection String": r"mysql://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+",
    
    # JDBC
    "JDBC Connection String": r"jdbc:[a-z]+://[a-zA-Z0-9\-\.]+(?::[0-9]+)?(?:/[a-zA-Z0-9_\-]+)?(?:\?[a-zA-Z0-9_\-&=]+)?",
    
    # SQLALCHEMY
    "SQLAlchemy Connection String": r"(?:mysql|postgresql|sqlite|oracle|mssql)(?:\+[a-z]+)?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+(?::[0-9]+)?(?:/[a-zA-Z0-9_\-]+)?",
    
    # DJANGO
    "Django Secret Key": r"(?i)(?:django[_\-\s]?)?secret[_\-\s]?key['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{40,}",
    
    # JWT (JSON Web Token)
    "JSON Web Token (JWT)": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    
    # GENERIC PATTERNS
    "Generic API Key": r"(?i)(?:api[_\-\s]?key|apikey)['\"\s:=]+[a-zA-Z0-9_\-]{20,}",
    "Generic Password in URL": r"\b[a-zA-Z]{3,10}://[^/:@\s]+:[^/@\s]{8,}@[a-zA-Z0-9\-\.]+",
    "Bearer Token": r"\bBearer\s+[a-zA-Z0-9\-\._~\+\/]+=*\b",
    "Basic Auth": r"\bBasic\s+[A-Za-z0-9+/=]{20,}\b",
    "Authorization Header": r"(?i)authorization['\"\s:=]+(?:Bearer|Basic|Token)\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    
    # CREDENTIALS IN CODE
    "Hardcoded Password": r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]",
    "Hardcoded Username Password": r"(?i)(?:username|user)\s*=\s*['\"][^'\"]+['\"]\s*[,;\n]\s*(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]",
    "Database Password": r"(?i)(?:db|database)[_\-\s]?(?:password|passwd|pwd)['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}",
    
    # API KEYS IN CONFIGURATION
    "ENV Variable Secret": r"(?i)(?:export\s+)?[A-Z_]+(?:API_KEY|SECRET|PASSWORD|TOKEN)=[a-zA-Z0-9_\-]{16,}",

    # ADOBE
    "Adobe Client Secret": r"(?i)adobe[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-f0-9]{32}",

    # ALIBABA CLOUD
    "Alibaba Secret Key": r"(?i)alibaba[_\-\s]?(?:secret|access)[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{30}",

    # BITBUCKET
    "Bitbucket Client Secret": r"(?i)bitbucket[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9_\-]{64}",

    # CONFLUENT
    "Confluent Cloud API Key": r"(?i)confluent[_\-\s]?(?:cloud)?[_\-\s]?api[_\-\s]?key['\"\s:=]+[A-Z0-9]{16}",
    "Confluent Cloud API Secret": r"(?i)confluent[_\-\s]?(?:cloud)?[_\-\s]?api[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9+/]{64}",

    # DATABRICKS
    "Databricks Access Token": r"\bdapi[a-f0-9]{32}\b",

    # DIGITALOCEAN
    "DigitalOcean Access Token": r"(?i)digitalocean[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-f0-9]{64}",
    "DigitalOcean Personal Access Token": r"\bdop_v1_[a-f0-9]{64}\b",
    "DigitalOcean OAuth Token": r"\bdoo_v1_[a-f0-9]{64}\b",
    "DigitalOcean Refresh Token": r"\bdor_v1_[a-f0-9]{64}\b",

    # DYNATRACE
    "Dynatrace Token": r"\bdt0c01\.[a-zA-Z0-9]{24}\.[a-f0-9]{64}\b",

    # FIGMA
    "Figma Personal Access Token": r"\bfigd_[a-zA-Z0-9_-]{43}\b",

    # GCP FIREBASE
    "Firebase Custom Token": r"(?i)firebase[_\-\s]?custom[_\-\s]?token['\"\s:=]+[a-zA-Z0-9\-_\.]{100,}",

    # HASHICORP TERRAFORM / VAULT
    "Terraform Cloud API Token": r"(?i)terraform[_\-\s]?(?:cloud)?[_\-\s]?(?:api)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9]{14}\.[a-zA-Z0-9\-_]{60,}",
    "HashiCorp Vault Token": r"\bs\.[a-zA-Z0-9]{24}\b",
    "HashiCorp Vault Batch Token": r"\bb\.[a-zA-Z0-9]{24}\b",

    # HUBSPOT
    "HubSpot API Key": r"(?i)hubspot[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",

    # JFROG
    "JFrog API Key": r"(?i)jfrog[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{73}",
    "JFrog Identity Token": r"(?i)jfrog[_\-\s]?identity[_\-\s]?token['\"\s:=]+[a-zA-Z0-9=]{50,}",

    # OPENAI
    "OpenAI API Key": r"\bsk-[a-zA-Z0-9]{48}\b",
    "OpenAI Organization Key": r"\borg-[a-zA-Z0-9]{24}\b",

    # POSTMAN
    "Postman API Key": r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",

    # SONARQUBE
    "SonarQube Token": r"\bsqu_[a-f0-9]{40}\b",

    # SPLUNK
    "Splunk Token": r"(?i)splunk[_\-\s]?(?:token|auth)['\"\s:=]+Splunk [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",

    # SQUARE (Additional)
    "Square Production Application Secret": r"\bsq0csp-[0-9A-Za-z\-_]{43}\b",
    "Square Sandbox Application Secret": r"\bsandbox-sq0csp-[0-9A-Za-z\-_]{43}\b",

    # TRAVIS CI (Additional)
    "Travis CI API Token": r"(?i)travis[_\-\s]?(?:api)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9_\-]{22}",

    # SSH KEYS & FINGERPRINTS
    "SSH Public Key": r"\bssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/]{100,}(?:==|=)?\b",
    "SSH Fingerprint": r"(?:MD5:)?(?:[0-9a-f]{2}:){15}[0-9a-f]{2}",

    # AUTHENTICATION TOKENS (GENERIC)
    "Generic Access Token": r"(?i)(?:access[_\-\s]?token|accesstoken)['\"\s:=]+[a-zA-Z0-9\-_\.]{20,}",
    "Generic Refresh Token": r"(?i)(?:refresh[_\-\s]?token|refreshtoken)['\"\s:=]+[a-zA-Z0-9\-_\.]{20,}",
    "Generic Auth Token": r"(?i)(?:auth[_\-\s]?token|authtoken)['\"\s:=]+[a-zA-Z0-9\-_\.]{20,}",

    # ENVIRONMENT VARIABLES
    "Environment Variable API Key": r"(?i)(?:export\s+)?[A-Z_]{3,}_API_KEY=['\"]?[a-zA-Z0-9\-_]{20,}['\"]?",
    "Environment Variable Secret": r"(?i)(?:export\s+)?[A-Z_]{3,}_SECRET=['\"]?[a-zA-Z0-9\-_]{20,}['\"]?",
    "Environment Variable Token": r"(?i)(?:export\s+)?[A-Z_]{3,}_TOKEN=['\"]?[a-zA-Z0-9\-_]{20,}['\"]?",
    "Environment Variable Password": r"(?i)(?:export\s+)?[A-Z_]{3,}_(?:PASSWORD|PASSWD|PWD)=['\"]?[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}['\"]?",

    # .NET SPECIFIC
    "ASP.NET Machine Key": r"(?i)<machineKey[^>]+(?:validationKey|decryptionKey)=\"[A-F0-9]{40,}\"",
    "Connection String with Password": r"(?i)(?:Server|Data Source|Addr)=[^;]+;(?:Database|Initial Catalog)=[^;]+;(?:User Id|UID)=[^;]+;(?:Password|PWD)=[^;]+;",

    # JAVA SPECIFIC
    "Java KeyStore Password": r"(?i)(?:keystore|truststore)[_\-\s]?(?:password|pass)['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{6,}",

    # JENKINS
    "Jenkins CLI Token": r"(?i)jenkins[_\-\s]?cli[_\-\s]?token['\"\s:=]+[a-f0-9]{32}",

    # DOCKER HUB
    "Docker Hub Personal Access Token": r"\bdckr_pat_[a-zA-Z0-9_-]{32,}\b",

    # KUBERNETES
    "Kubernetes Service Account Token": r"(?i)serviceaccount[_\-\s]?token['\"\s:=]+eyJ[a-zA-Z0-9\-_\.]{100,}",

    # ANSIBLE
    "Ansible Vault Password": r"(?i)\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256",

    # CHEF
    "Chef Private Key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----",

    # PUPPET
    "Puppet Eyaml Private Key": r"(?i)pkcs7_private_key:[\s\S]{100,}",

    # LDAP
    "LDAP Bind Password": r"(?i)(?:bindpw|bind_password)['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}",

    # FTP/SFTP
    "FTP URL with Credentials": r"ftp://[a-zA-Z0-9_\-]+:[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+@[a-zA-Z0-9\-\.]+(?::[0-9]+)?",
    "SFTP URL with Credentials": r"sftp://[a-zA-Z0-9_\-]+:[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+@[a-zA-Z0-9\-\.]+(?::[0-9]+)?",

    # RABBITMQ (continued)
    "RabbitMQ Connection String": r"amqps?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+(?::[0-9]+)?(?:/[a-zA-Z0-9_\-]+)?",

    # KAFKA
    "Kafka SASL Password": r"(?i)sasl[._]?(?:jaas[._]?)?config['\"\s:=]+.*password=['\"]?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+)['\"]?",

    # ELASTICSEARCH
    "Elasticsearch Password": r"(?i)elastic[_\-\s]?(?:search)?[_\-\s]?password['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}",
    "Elasticsearch API Key": r"(?i)elastic[_\-\s]?(?:search)?[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9=]{40,}",

    # SOLR
    "Solr Admin Password": r"(?i)solr[_\-\s]?admin[_\-\s]?password['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}",

    # CASSANDRA
    "Cassandra Password": r"(?i)cassandra[_\-\s]?password['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}",

    # COUCHDB
    "CouchDB Connection String": r"https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+:[0-9]+/?",

    # INFLUXDB
    "InfluxDB Token": r"(?i)influx[_\-\s]?(?:db)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9_\-=]{88}",
    "InfluxDB Password": r"(?i)influx[_\-\s]?(?:db)?[_\-\s]?password['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}",

    # TIMESCALEDB
    "TimescaleDB Connection String": r"postgres://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-@]+@[a-zA-Z0-9\-\.]+\.timescaledb\.io:[0-9]+/[a-zA-Z0-9_\-]+",

    # NEO4J
    "Neo4j Connection String": r"neo4j(?:\+s)?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+:[0-9]+",

    # COCKROACHDB
    "CockroachDB Connection String": r"postgresql://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+:[0-9]+/[a-zA-Z0-9_\-]+\?sslmode=",

    # PROMETHEUS
    "Prometheus Basic Auth": r"(?i)prometheus[_\-\s]?(?:basic)?[_\-\s]?auth['\"\s:=]+[a-zA-Z0-9:]+",

    # KIBANA
    "Kibana Encryption Key": r"(?i)(?:kibana[._])?encryption[._]key['\"\s:=]+[a-zA-Z0-9]{32}",

    # LOGSTASH
    "Logstash Keystore Password": r"(?i)logstash[._]keystore[._]password['\"\s:=]+[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}",

    # MINIO
    "MinIO Access Key": r"(?i)minio[_\-\s]?(?:access)?[_\-\s]?key['\"\s:=]+[A-Z0-9]{20}",
    "MinIO Secret Key": r"(?i)minio[_\-\s]?secret[_\-\s]?key['\"\s:=]+[a-zA-Z0-9/+]{40}",

    # CLOUDAMQP
    "CloudAMQP URL": r"amqps://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-]+\.cloudamqp\.com/[a-zA-Z0-9_\-]+",

    # CLOUDFLARE (Additional)
    "Cloudflare API Token": r"(?i)cloudflare[_\-\s]?(?:api)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9_\-]{40}",
    "Cloudflare Origin CA Key": r"(?i)origin[_\-\s]?ca[_\-\s]?key['\"\s:=]+v1\.0-[a-f0-9]{160}",

    # SUMOLOGIC
    "SumoLogic Access ID": r"(?i)sumologic[_\-\s]?access[_\-\s]?id['\"\s:=]+[a-zA-Z0-9]{14}",
    "SumoLogic Access Key": r"(?i)sumologic[_\-\s]?access[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{64}",

    # CALENDLY
    "Calendly API Key": r"(?i)calendly[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9\-_]{64}",

    # WORKDAY
    "Workday API Key": r"(?i)workday[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{40}",

    # ZOHO
    "Zoho Client Secret": r"(?i)zoho[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-f0-9]{32}",

    # SALESFORCE
    "Salesforce Access Token": r"(?i)salesforce[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9!.]{100,}",
    "Salesforce Client Secret": r"(?i)salesforce[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-f0-9]{64}",

    # HUBSPOT (Additional)
    "HubSpot Private App Token": r"\bpat-[a-z]{2}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",

    # KLARNA
    "Klarna API Username": r"(?i)klarna[_\-\s]?(?:api)?[_\-\s]?username['\"\s:=]+[A-Z0-9_]{20,}",

    # AFFIRM
    "Affirm API Secret": r"(?i)affirm[_\-\s]?(?:api)?[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9]{40}",

    # IPGEOLOCATION
    "IPGeolocation API Key": r"(?i)ipgeolocation[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-f0-9]{32}",

    # YOUTUBE
    "YouTube API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",

    # APPLE MUSIC
    "Apple Music Private Key": r"(?i)apple[_\-\s]?music[_\-\s]?private[_\-\s]?key['\"\s:=]+-----BEGIN PRIVATE KEY-----",

    # TWITCH
    "Twitch Client Secret": r"(?i)twitch[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-z0-9]{30}",
    "Twitch OAuth Token": r"(?i)twitch[_\-\s]?oauth[_\-\s]?token['\"\s:=]+[a-z0-9]{30}",

    # DISCORD (Additional)
    "Discord MFA Token": r"\bmfa\.[a-zA-Z0-9_-]{84}\b",

    # REDDIT
    "Reddit Client Secret": r"(?i)reddit[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9\-_]{27}",
    "Reddit Refresh Token": r"(?i)reddit[_\-\s]?refresh[_\-\s]?token['\"\s:=]+[0-9]{10,13}-[a-zA-Z0-9\-_]{30,}",

    # PINTEREST
    "Pinterest Access Token": r"(?i)pinterest[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9\-_]{64}",

    # LINKEDIN
    "LinkedIn Client Secret": r"(?i)linkedin[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9]{16}",
    "LinkedIn Access Token": r"(?i)linkedin[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9\-_]{76}",

    # INSTAGRAM
    "Instagram Access Token": r"(?i)instagram[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[0-9]{16}\.[a-f0-9]{7}\.[a-f0-9]{32}",

    # TIKTOK
    "TikTok Access Token": r"(?i)tiktok[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9]{32}",

    # SNAPCHAT
    "Snapchat Client Secret": r"(?i)snapchat[_\-\s]?client[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9\-_]{40}",

    # BLUESKY
    "Bluesky App Password": r"(?i)bluesky[_\-\s]?app[_\-\s]?password['\"\s:=]+[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}",

    # ANTHROPIC
    "Anthropic API Key": r"\bsk-ant-api03-[a-zA-Z0-9\-_]{95}\b",

    # COHERE
    "Cohere API Key": r"(?i)cohere[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{40}",

    # HUGGING FACE
    "Hugging Face Token": r"\bhf_[a-zA-Z0-9]{37}\b",
    "Hugging Face Fine-grained Token": r"\bhf_api_[a-zA-Z0-9]{37}\b",

    # REPLICATE
    "Replicate API Token": r"\br8_[a-zA-Z0-9]{40}\b",

    # STABILITY AI
    "Stability AI API Key": r"\bsk-[a-zA-Z0-9]{48}\b",

    # MIDJOURNEY
    "Midjourney API Key": r"(?i)midjourney[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{32}",

    # GOOGLE GEMINI
    "Google Gemini API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",

    # AZURE OPENAI
    "Azure OpenAI API Key": r"(?i)azure[_\-\s]?openai[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-f0-9]{32}",

    # CHROMA
    "Chroma Token": r"(?i)chroma[_\-\s]?token['\"\s:=]+[a-zA-Z0-9\-_]{40}",

    # LANGCHAIN
    "LangChain API Key": r"(?i)langchain[_\-\s]?api[_\-\s]?key['\"\s:=]+ls__[a-f0-9]{32}",

    # NEPTUNE.AI
    "Neptune.ai API Token": r"(?i)neptune[_\-\s]?(?:ai)?[_\-\s]?api[_\-\s]?token['\"\s:=]+[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",

    # KAGGLE
    "Kaggle API Key": r"(?i)kaggle[_\-\s]?(?:username|key)['\"\s:=]+[a-zA-Z0-9]{20,}",

    # VISION AI
    "Google Vision API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",

    # AZURE COGNITIVE SERVICES
    "Azure Cognitive Services Key": r"(?i)azure[_\-\s]?cognitive[_\-\s]?services[_\-\s]?key['\"\s:=]+[a-f0-9]{32}",

    # CANVA
    "Canva Access Token": r"(?i)canva[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9\-_]{100,}",

    # FIGMA (Additional)
    "Figma OAuth Token": r"(?i)figma[_\-\s]?oauth[_\-\s]?token['\"\s:=]+fga_[a-zA-Z0-9_-]{43}",

    # LUCIDCHART
    "Lucidchart API Token": r"(?i)lucidchart[_\-\s]?api[_\-\s]?token['\"\s:=]+[a-zA-Z0-9]{64}",

    # FIREBASE (Additional - continued)
    "Firebase Server Key": r"(?i)firebase[_\-\s]?server[_\-\s]?key['\"\s:=]+AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
    "Firebase Database Secret": r"(?i)firebase[_\-\s]?database[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9]{40}",

    # AWS AMPLIFY
    "AWS Amplify Auth Token": r"(?i)amplify[_\-\s]?(?:auth)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9\-_]{100,}",

    # CLOUDFLARE WORKERS
    "Cloudflare Workers Token": r"(?i)cloudflare[_\-\s]?workers[_\-\s]?token['\"\s:=]+[a-zA-Z0-9_\-]{40}",

    # ELASTIC SEARCH (Additional)
    "Elasticsearch Cloud ID": r"(?i)elastic[_\-\s]?(?:search)?[_\-\s]?cloud[_\-\s]?id['\"\s:=]+[a-zA-Z0-9\-_:=]+",

    # DRUPAL
    "Drupal Hash Salt": r"(?i)\$settings\['hash_salt'\]\s*=\s*['\"]([a-zA-Z0-9_\-]{43,})['\"]",

    # BINANCE
    "Binance API Key": r"(?i)binance[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{64}",
    "Binance Secret Key": r"(?i)binance[_\-\s]?secret[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{64}",

    # COINBASE
    "Coinbase API Key": r"(?i)coinbase[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{16}",
    "Coinbase API Secret": r"(?i)coinbase[_\-\s]?api[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9+/]{88}",

    # GEMINI
    "Gemini API Key": r"(?i)gemini[_\-\s]?api[_\-\s]?key['\"\s:=]+account-[a-zA-Z0-9]{10}",
    "Gemini API Secret": r"(?i)gemini[_\-\s]?api[_\-\s]?secret['\"\s:=]+[a-zA-Z0-9]{28}",

    # ROBLOX
    "Roblox API Key": r"(?i)roblox[_\-\s]?api[_\-\s]?key['\"\s:=]+[a-zA-Z0-9]{32}",

    # FIREBASE DYNAMIC LINKS
    "Firebase Dynamic Links API Key": r"(?i)firebase[_\-\s]?dynamic[_\-\s]?links[_\-\s]?api[_\-\s]?key['\"\s:=]+\bAIza[0-9A-Za-z\-_]{35}\b",

    # FACEBOOK AUDIENCE NETWORK
    "Facebook Placement ID": r"(?i)facebook[_\-\s]?placement[_\-\s]?id['\"\s:=]+[0-9]{15}_[0-9]{16}",

    # GOOGLE AD MANAGER
    "Google Ad Manager Network Code": r"(?i)(?:gam|google[_\-\s]?ad[_\-\s]?manager)[_\-\s]?network[_\-\s]?code['\"\s:=]+[0-9]{8}",

    # ADSENSE (Additional)
    "Google AdSense Publisher ID": r"(?i)(?:adsense|ca-pub)[_\-\s:=]+[0-9]{16}",

    # LINKEDIN ADS
    "LinkedIn Ads Access Token": r"(?i)linkedin[_\-\s]?ads[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9]{88}",

    # BING ADS
    "Bing Ads Developer Token": r"(?i)bing[_\-\s]?ads[_\-\s]?developer[_\-\s]?token['\"\s:=]+[A-Z0-9]{32}",

    # YAHOO GEMINI
    "Yahoo Gemini Access Token": r"(?i)yahoo[_\-\s]?gemini[_\-\s]?(?:access)?[_\-\s]?token['\"\s:=]+[a-zA-Z0-9\-_]{100,}",
}

default_exclude_patterns = [
    "\.git\/",
    "\.svn\/",
    "\/.*\.cer$",
    "\/.*\.lock$",
    "\/[Rr][Ee][Aa][Dd][Mm][Ee]\.md$"
]

common_passwords = [
"123456",
"password",
"12345678",
"qwerty",
"123456789",
"12345",
"1234",
"111111",
"1234567",
"dragon",
"123123",
"baseball",
"abc123",
"football",
"monkey",
"letmein",
"696969",
"shadow",
"master",
"666666",
"qwertyuiop",
"123321",
"mustang",
"1234567890",
"michael",
"654321",
"pussy",
"superman",
"1qaz2wsx",
"7777777",
"fuckyou",
"121212",
"000000",
"qazwsx",
"123qwe",
"killer",
"trustno1",
"jordan",
"jennifer",
"zxcvbnm",
"asdfgh",
"hunter",
"buster",
"soccer",
"harley",
"batman",
"andrew",
"tigger",
"sunshine",
"iloveyou",
"fuckme",
"2000",
"charlie",
"robert",
"thomas",
"hockey",
"ranger",
"daniel",
"starwars",
"klaster",
"112233",
"george",
"asshole",
"computer",
"michelle",
"jessica",
"pepper",
"1111",
"zxcvbn",
"555555",
"11111111",
"131313",
"freedom",
"777777",
"pass",
"fuck",
"maggie",
"159753",
"aaaaaa",
"ginger",
"princess",
"joshua",
"cheese",
"amanda",
"summer",
"love",
"ashley",
"6969",
"nicole",
"chelsea",
"biteme",
"matthew",
"access",
"yankees",
"987654321",
"dallas",
"austin",
"thunder",
"taylor",
"matrix",
"william",
"corvette",
"hello",
"martin",
"heather",
"secret",
"fucker",
"merlin",
"diamond",
"1234qwer",
"gfhjkm",
"hammer",
"silver",
"222222",
"88888888",
"anthony",
"justin",
"test",
"bailey",
"q1w2e3r4t5",
"patrick",
"internet",
"scooter",
"orange",
"11111",
"golfer",
"cookie",
"richard",
"samantha",
"bigdog",
"guitar",
"jackson",
"whatever",
"mickey",
"chicken",
"sparky",
"snoopy",
"maverick",
"phoenix",
"camaro",
"sexy",
"peanut",
"morgan",
"welcome",
"falcon",
"cowboy",
"ferrari",
"samsung",
"andrea",
"smokey",
"steelers",
"joseph",
"mercedes",
"dakota",
"arsenal",
"eagles",
"melissa",
"boomer",
"booboo",
"spider",
"nascar",
"monster",
"tigers",
"yellow",
"xxxxxx",
"123123123",
"gateway",
"marina",
"diablo",
"bulldog",
"qwer1234",
"compaq",
"purple",
"hardcore",
"banana",
"junior",
"hannah",
"123654",
"porsche",
"lakers",
"iceman",
"money",
"cowboys",
"987654",
"london",
"tennis",
"999999",
"ncc1701",
"coffee",
"scooby",
"0000",
"miller",
"boston",
"q1w2e3r4",
"fuckoff",
"brandon",
"yamaha",
"chester",
"mother",
"forever",
"johnny",
"edward",
"333333",
"oliver",
"redsox",
"player",
"nikita",
"knight",
"fender",
"barney",
"midnight",
"please",
"brandy",
"chicago",
"badboy",
"iwantu",
"slayer",
"rangers",
"charles",
"angel",
"flower",
"bigdaddy",
"rabbit",
"wizard",
"bigdick",
"jasper",
"enter",
"rachel",
"chris",
"steven",
"winner",
"adidas",
"victoria",
"natasha",
"1q2w3e4r",
"jasmine",
"winter",
"prince",
"panties",
"marine",
"ghbdtn",
"fishing",
"cocacola",
"casper",
"james",
"232323",
"raiders",
"888888",
"marlboro",
"gandalf",
"asdfasdf",
"crystal",
"87654321",
"12344321",
"sexsex",
"golden",
"blowme",
"bigtits",
"8675309",
"panther",
"lauren",
"angela",
"bitch",
"spanky",
"thx1138",
"angels",
"madison",
"winston",
"shannon",
"mike",
"toyota",
"blowjob",
"jordan23",
"canada",
"sophie",
"Password",
"apples",
"dick",
"tiger",
"razz",
"123abc",
"pokemon",
"qazxsw",
"55555",
"qwaszx",
"muffin",
"johnson",
"murphy",
"cooper",
"jonathan",
"liverpoo",
"david",
"danielle",
"159357",
"jackie",
"1990",
"123456a",
"789456",
"turtle",
"horny",
"abcd1234",
"scorpion",
"qazwsxedc",
"101010",
"butter",
"carlos",
"password1",
"dennis",
"slipknot",
"qwerty123",
"booger",
"asdf",
"1991",
"black",
"startrek",
"12341234",
"cameron",
"newyork",
"rainbow",
"nathan",
"john",
"1992",
"rocket",
"viking",
"redskins",
"butthead",
"asdfghjkl",
"1212",
"sierra",
"peaches",
"gemini",
"doctor",
"wilson",
"sandra",
"helpme",
"qwertyui",
"victor",
"florida",
"dolphin",
"pookie",
"captain",
"tucker",
"blue",
"liverpool",
"theman",
"bandit",
"dolphins",
"maddog",
"packers",
"jaguar",
"lovers",
"nicholas",
"united",
"tiffany",
"maxwell",
"zzzzzz",
"nirvana",
"jeremy",
"suckit",
"stupid",
"porn",
"monica",
"elephant",
"giants",
"jackass",
"hotdog",
"rosebud",
"success",
"debbie",
"mountain",
"444444",
"xxxxxxxx",
"warrior",
"1q2w3e4r5t",
"q1w2e3",
"123456q",
"albert",
"metallic",
"lucky",
"azerty",
"7777",
"shithead",
"alex",
"bond007",
"alexis",
"1111111",
"samson",
"5150",
"willie",
"scorpio",
"bonnie",
"gators",
"benjamin",
"voodoo",
"driver",
"dexter",
"2112",
"jason",
"calvin",
"freddy",
"212121",
"creative",
"12345a",
"sydney",
"rush2112",
"1989",
"asdfghjk",
"red123",
"bubba",
"4815162342",
"passw0rd",
"trouble",
"gunner",
"happy",
"fucking",
"gordon",
"legend",
"jessie",
"stella",
"qwert",
"eminem",
"arthur",
"apple",
"nissan",
"bullshit",
"bear",
"america",
"1qazxsw2",
"nothing",
"parker",
"4444",
"rebecca",
"qweqwe",
"garfield",
"01012011",
"beavis",
"69696969",
"jack",
"asdasd",
"december",
"2222",
"102030",
"252525",
"11223344",
"magic",
"apollo",
"skippy",
"315475",
"girls",
"kitten",
"golf",
"copper",
"braves",
"shelby",
"godzilla",
"beaver",
"fred",
"tomcat",
"august",
"buddy",
"airborne",
"1993",
"1988",
"lifehack",
"qqqqqq",
"brooklyn",
"animal",
"platinum",
"phantom",
"online",
"xavier",
"darkness",
"blink182",
"power",
"fish",
"green",
"789456123",
"voyager",
"police",
"travis",
"12qwaszx",
"heaven",
"snowball",
"lover",
"abcdef",
"00000",
"pakistan",
"007007",
"walter",
"playboy",
"blazer",
"cricket",
"sniper",
"hooters",
"donkey",
"willow",
"loveme",
"saturn",
"therock",
"redwings"
]
