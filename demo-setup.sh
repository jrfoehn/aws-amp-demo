##!/bin/bash
CLUSTER_NAME=demo-cluster
AWS_REGION=eu-west-1

################
# EKS Controls #
################

# install OpenSSL
# yum install openssl -y

# # install eksctl
# curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
# sudo mv -v /tmp/eksctl /usr/local/bin
# #eksctl completion bash >> ~/.bash_completion
# #. /etc/profile.d/bash_completion.sh
# #. ~/.bash_completion

# # install kubectl
# curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.18.9/2020-11-02/bin/linux/amd64/kubectl
# chmod +x ./kubectl
# mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin
# echo 'export PATH=$PATH:$HOME/bin' >> ~/.bashrc

# # install Helm
# curl -sSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
# helm version --short

aws kms create-alias --alias-name alias/eksworkshop --target-key-id $(aws kms create-key --query KeyMetadata.Arn --output text)
export MASTER_ARN=$(aws kms describe-key --key-id alias/eksworkshop --query KeyMetadata.Arn --output text)
echo "export MASTER_ARN=${MASTER_ARN}" | tee -a ~/.bash_profile

######################
# Launch EKS Cluster # 
######################

# generate deployment file

cat << EOF > eksworkshop.yaml
---
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: "1.17"

availabilityZones: ["${AWS_REGION}a", "${AWS_REGION}b", "${AWS_REGION}c"]

managedNodeGroups:
- name: nodegroup
  desiredCapacity: 3
  ssh:
    allow: true
    publicKeyName: eksworkshop

# To enable all of the control plane logs, uncomment below:
# cloudWatch:
#  clusterLogging:
#    enableTypes: ["*"]

secretsEncryption:
  keyARN: ${MASTER_ARN}
EOF

# create Cluster

eksctl create cluster -f eksworkshop.yaml

# export Variables

STACK_NAME=$(eksctl get nodegroup --cluster $CLUSTER_NAME -o json | jq -r '.[].StackName')
ROLE_NAME=$(aws cloudformation describe-stack-resources --stack-name $STACK_NAME | jq -r '.StackResources[] | select(.ResourceType=="AWS::IAM::Role") | .PhysicalResourceId')
echo "export ROLE_NAME=${ROLE_NAME}" | tee -a ~/.bash_profile

#########################
# Deploy Micro Services #
#########################

# clone the repos

mkdir microservices
cd microservices
git clone https://github.com/brentley/ecsdemo-frontend.git
git clone https://github.com/brentley/ecsdemo-nodejs.git
git clone https://github.com/brentley/ecsdemo-crystal.git

# deploy node.js backend api
cd ecsdemo-nodejs
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
cd ..

# deploy cristal backend api
cd ecsdemo-crystal
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
cd ..

# get Load Balancer Role
aws iam get-role --role-name "AWSServiceRoleForElasticLoadBalancing" || aws iam create-service-linked-role --aws-service-name "elasticloadbalancing.amazonaws.com"

# deploy frontend 
cd ecsdemo-frontend
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
cd ..

# scale services
kubectl scale deployment ecsdemo-nodejs --replicas=3
kubectl scale deployment ecsdemo-crystal --replicas=3
kubectl scale deployment ecsdemo-frontend --replicas=3

# print ELB DNS
ELB=$(kubectl get service ecsdemo-frontend -o json | jq -r '.status.loadBalancer.ingress[].hostname')
curl -m3 -v $ELB

###############################
# Prometheus & Grafana on EKS #
###############################

# add prometheus Helm repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

# add grafana Helm repo
helm repo add grafana https://grafana.github.io/helm-charts

# deploy prometheus
kubectl create namespace prometheus
helm install prometheus prometheus-community/prometheus --namespace prometheus 

# deploy grafana
mkdir grafana
cat << EoF > grafana/grafana.yaml
datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
    - name: Prometheus
      type: prometheus
      url: http://prometheus-server.prometheus.svc.cluster.local
      access: proxy
      isDefault: true
EoF

helm install grafana grafana/grafana \
    --namespace grafana \
    --set persistence.storageClassName="gp2" \
    --set persistence.enabled=true \
    --set adminPassword='EKS!sAWSome' \
    --values ${HOME}/environment/grafana/grafana.yaml \


###########################
# Amzn Managed Prometheus #
###########################

WORKSPACE_ID=`aws amp create-workspace --alias amp-demo --profile main --query workspaceId --output text`

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
OIDC_PROVIDER=$(aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")

PROM_SERVICE_ACCOUNT_NAMESPACE=prometheus
GRAFANA_SERVICE_ACCOUNT_NAMESPACE=grafana
SERVICE_ACCOUNT_NAME=iamproxy-service-account
SERVICE_ACCOUNT_IAM_ROLE=EKS-AMP-ServiceAccount-Role
SERVICE_ACCOUNT_IAM_ROLE_DESCRIPTION="IAM role to be used by a K8s service account with write access to AMP"
SERVICE_ACCOUNT_IAM_POLICY=AWSManagedPrometheusWriteAccessPolicy
SERVICE_ACCOUNT_IAM_POLICY_ARN=arn:aws:iam::$AWS_ACCOUNT_ID:policy/$SERVICE_ACCOUNT_IAM_POLICY

#
# Setup a trust policy designed for a specific combination of K8s service account and namespace to sign in from a Kubernetes cluster which hosts the OIDC Idp.
# If the IAM role already exists, then add this new trust policy to the existing trust policy
#
echo "Creating a new trust policy"
read -r -d '' NEW_TRUST_RELATIONSHIP <<EOF
 [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${GRAFANA_SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${PROM_SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"
        }
      }
    }
  ]
EOF
#
# Get the old trust policy, if one exists, and append it to the new trust policy
#
OLD_TRUST_RELATIONSHIP=$(aws iam get-role --role-name $SERVICE_ACCOUNT_IAM_ROLE --query 'Role.AssumeRolePolicyDocument.Statement[]' --output json)
COMBINED_TRUST_RELATIONSHIP=$(echo $OLD_TRUST_RELATIONSHIP $NEW_TRUST_RELATIONSHIP | jq -s add)
echo "Appending to the existing trust policy"
read -r -d '' TRUST_POLICY <<EOF
{
  "Version": "2012-10-17",
  "Statement": ${COMBINED_TRUST_RELATIONSHIP}
}
EOF
echo "${TRUST_POLICY}" > TrustPolicy.json
#
# Setup the permission policy grants write permissions for all AWS StealFire workspaces
#
read -r -d '' PERMISSION_POLICY <<EOF
{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Effect":"Allow",
         "Action":[
            "aps:RemoteWrite",
            "aps:QueryMetrics",
            "aps:GetSeries",
            "aps:GetLabels",
            "aps:GetMetricMetadata"
         ],
         "Resource":"*"
      }
   ]
}
EOF
echo "${PERMISSION_POLICY}" > PermissionPolicy.json

#
# Create an IAM permission policy to be associated with the role, if the policy does not already exist
#
SERVICE_ACCOUNT_IAM_POLICY_ID=$(aws iam get-policy --policy-arn $SERVICE_ACCOUNT_IAM_POLICY_ARN --query 'Policy.PolicyId' --output text)
if [ "$SERVICE_ACCOUNT_IAM_POLICY_ID" = "" ]; 
then
  echo "Creating a new permission policy $SERVICE_ACCOUNT_IAM_POLICY"
  aws iam create-policy --policy-name $SERVICE_ACCOUNT_IAM_POLICY --policy-document file://PermissionPolicy.json 
else
  echo "Permission policy $SERVICE_ACCOUNT_IAM_POLICY already exists"
fi

#
# If the IAM role already exists, then just update the trust policy.
# Otherwise create one using the trust policy and permission policy
#
SERVICE_ACCOUNT_IAM_ROLE_ARN=$(aws iam get-role --role-name $SERVICE_ACCOUNT_IAM_ROLE --query 'Role.Arn' --output text)
if [ "$SERVICE_ACCOUNT_IAM_ROLE_ARN" = "" ]; 
then
  echo "$SERVICE_ACCOUNT_IAM_ROLE role does not exist. Creating a new role with a trust and permission policy"
  #
  # Create an IAM role for Kubernetes service account 
  #
  SERVICE_ACCOUNT_IAM_ROLE_ARN=$(aws iam create-role \
  --role-name $SERVICE_ACCOUNT_IAM_ROLE \
  --assume-role-policy-document file://TrustPolicy.json \
  --description "$SERVICE_ACCOUNT_IAM_ROLE_DESCRIPTION" \
  --query "Role.Arn" --output text)
  #
  # Attach the trust and permission policies to the role
  #
  aws iam attach-role-policy --role-name $SERVICE_ACCOUNT_IAM_ROLE --policy-arn $SERVICE_ACCOUNT_IAM_POLICY_ARN  
else
  echo "$SERVICE_ACCOUNT_IAM_ROLE_ARN role already exists. Updating the trust policy"
  #
  # Update the IAM role for Kubernetes service account with a with the new trust policy
  #
  aws iam update-assume-role-policy --role-name $SERVICE_ACCOUNT_IAM_ROLE --policy-document file://TrustPolicy.json
fi
echo $SERVICE_ACCOUNT_IAM_ROLE_ARN

# EKS cluster hosts an OIDC provider with a public discovery endpoint.
# Associate this Idp with AWS IAM so that the latter can validate and accept the OIDC tokens issued by Kubernetes to service accounts.
# Doing this with eksctl is the easier and best approach.
#
eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve


# creating amp_ingest_override_values.yaml
cat << EOF > amp_ingest_override_values.yaml
serviceAccounts:
    server:
        name: "iamproxy-service-account"
        annotations:
            eks.amazonaws.com/role-arn: ${IAM_PROXY_PROMETHEUS_ROLE_ARN}
server:
  sidecarContainers:
    aws-sigv4-proxy-sidecar:
        image: public.ecr.aws/aws-observability/aws-sigv4-proxy:1.0
        args:
        - --name
        - aps
        - --region
        - ${AWS_REGION}
        - --host
        - aps-workspaces.${AWS_REGION}.amazonaws.com
        - --port
        - :8005
        ports:
        - name: aws-sigv4-proxy
          containerPort: 8005
  statefulSet:
      enabled: "true"
  remoteWrite:
      - url: http://localhost:8005/workspaces/${WORKSPACE_ID}/api/v1/remote_write
EOF

# creating amp_query_override_values.yaml
cat << EOF > amp_query_override_values.yaml
serviceAccount:
    name: "iamproxy-service-account"
    annotations:
        eks.amazonaws.com/role-arn: ${IAM_PROXY_PROMETHEUS_ROLE_ARN}
grafana.ini:
  auth:
    sigv4_auth_enabled: true
EOF

helm upgrade --install grafana grafana/grafana -n grafana -f ./amp_query_override_values.yaml --set service.type=LoadBalancer
export ELB=$(kubectl get svc -n grafana grafana -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

echo "http://$ELB"


# helm upgrade --install prometheus prometheus-community/prometheus -n prometheus -f ./amp_ingest_override_values.yaml







