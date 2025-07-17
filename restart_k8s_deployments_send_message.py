import boto3
import json
import base64
import tempfile
import requests
from kubernetes import client
from datetime import datetime, timedelta

COMMON_CLUSTERS = {
    "staging": {
        "cluster_name": "<CLUSTER_NAME>",
        "region": "<REGION>",
        "sa_secret_name": "<SECRET_NAME>",
    }
}

GOOGLE_CHAT_WEBHOOK_URL = "<WEBHOOK_URL>"

def build_k8s_client(cluster_name, region, cluster_type):
    try:
        secretsmanager = boto3.client("secretsmanager", region_name=region)
        sa_secret = secretsmanager.get_secret_value(
            SecretId=COMMON_CLUSTERS[cluster_type]["sa_secret_name"])
        sa_secret_dict = json.loads(sa_secret['SecretString'])

        eks_client = boto3.client('eks', region_name=region)
        cluster_info = eks_client.describe_cluster(name=cluster_name)['cluster']

        configuration = client.Configuration()
        configuration.host = cluster_info['endpoint']
        configuration.api_key = {
            "authorization": f"Bearer {sa_secret_dict['k8s_token']}"
        }

        with tempfile.NamedTemporaryFile(delete=False) as cert_file:
            cert_file.write(base64.b64decode(sa_secret_dict["k8s_ca"]))
            cert_file.flush()
            configuration.ssl_ca_cert = cert_file.name

        return {
            "core_v1": client.CoreV1Api(client.ApiClient(configuration)),
            "apps_v1": client.AppsV1Api(client.ApiClient(configuration))
        }
    except Exception as e:
        raise Exception(f"K8s client build failed: {str(e)}")

def find_labeled_deployments(k8s_client):
    labeled_deployments = []
    try:
        namespaces = k8s_client["core_v1"].list_namespace().items
        for namespace in namespaces:
            try:
                deployments = k8s_client["apps_v1"].list_namespaced_deployment(namespace.metadata.name).items
                for dep in deployments:
                    if dep.metadata.labels and dep.metadata.labels.get("accesskey-rotation") == "true":
                        labeled_deployments.append({
                            "name": dep.metadata.name,
                            "namespace": namespace.metadata.name,
                            "creation_time": str(dep.metadata.creation_timestamp)
                        })
            except Exception as ns_error:
                print(f"Namespace {namespace.metadata.name} error: {str(ns_error)}")
        return labeled_deployments
    except Exception as e:
        raise Exception(f"Search failed: {str(e)}")

def send_google_chat_notification(deployments):
    if not deployments:
        return None
        
    message = "🔔 *Deployment Restart Notification for Staging*\n\n"
    message += "Access key rotation process completed and relevant Kubernetes secrets in staging updated.\n"
    message += "Deployments need to be restarted for the new access keys to take effect in the pods.\n\n"
    message += " 🔁 *Today at 14:00 the following deployments in staging will restart:*\n"
    for dep in deployments:
        message += f"- {dep['namespace']} / {dep['name']}\n"

    headers = {'Content-Type': 'application/json; charset=UTF-8'}
    payload = {'text': message}
    
    try:
        response = requests.post(GOOGLE_CHAT_WEBHOOK_URL, headers=headers, json=payload)
        response.raise_for_status()
        print("Notification sent to Google Chat successfully ...")
        return True
    except Exception as e:
        print(f"Failed to send notification: {str(e)}")
        raise

def lambda_handler(event, context):
    cluster_config = COMMON_CLUSTERS["staging"]
    
    try:
        print(f"Connected to cluster: {cluster_config['cluster_name']}")
        k8s_client = build_k8s_client(
            cluster_config["cluster_name"],
            cluster_config["region"],
            "staging"
        )
        
        deployments = find_labeled_deployments(k8s_client)
        
        if deployments:  
            print(f"Found {len(deployments)} deployments in staging to be restarted:")
            for dep in deployments:
                print(f"- {dep['namespace']}/{dep['name']}")
            send_google_chat_notification(deployments)

            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Notification sent successfully"
                })
            }
        else:
            print("No deployments found with 'accesskey-rotation=true' label")
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No deployments to restart"
                })
            }
            
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        print(error_msg)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": error_msg})
        }