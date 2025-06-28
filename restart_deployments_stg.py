import boto3
import json
import base64
import tempfile
import requests
import time
from kubernetes import client
from datetime import datetime
import pytz

COMMON_CLUSTERS = {
    "staging": {
        "cluster_name": "<CLUSTER_NAME>",
        "region": "<REGION>",
        "sa_secret_name": "<SECRET_NAME>",
    }
}

FIRST_CHECK = 120
FINAL_CHECK = 240
S3_BUCKET_NAME = "<S3_BUCKET_NAME>"
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

def get_all_namespaces(k8s_client):
    try:
        namespaces = k8s_client["core_v1"].list_namespace().items
        return [ns.metadata.name for ns in namespaces]
    except Exception as e:
        raise Exception(f"Failed to get namespaces: {str(e)}")

def find_labeled_deployments(k8s_client):
    labeled_deployments = []
    
    try:
        target_namespaces = get_all_namespaces(k8s_client)
        
        for namespace in target_namespaces:
            try:
                deployments = k8s_client["apps_v1"].list_namespaced_deployment(namespace).items
                
                for dep in deployments:
                    if dep.metadata.labels and dep.metadata.labels.get("accesskey-rotation") == "true":
                        labeled_deployments.append({
                            "name": dep.metadata.name,
                            "namespace": namespace,
                            "creation_time": str(dep.metadata.creation_timestamp)
                        })
                        
            except Exception as ns_error:
                print(f"Namespace {namespace} error: {str(ns_error)}")
                continue
        
        return labeled_deployments
        
    except Exception as e:
        raise Exception(f"Search failed: {str(e)}")

def is_deployment_ready(k8s_client, deployment_name, namespace):
    try:
        deployment = k8s_client["apps_v1"].read_namespaced_deployment(
            name=deployment_name,
            namespace=namespace
        )
        
        status = k8s_client["apps_v1"].read_namespaced_deployment_status(
            name=deployment_name,
            namespace=namespace
        )
        
        ready = (
            status.status.updated_replicas == deployment.spec.replicas and
            status.status.ready_replicas == deployment.spec.replicas and
            status.status.available_replicas == deployment.spec.replicas and
            status.status.unavailable_replicas is None
        )
        
        if not ready:
            print(f"Deployment not ready: {namespace}/{deployment_name}")
            print(f"Updated: {status.status.updated_replicas}/{deployment.spec.replicas}")
            print(f"Ready: {status.status.ready_replicas}/{deployment.spec.replicas}")
            print(f"Available: {status.status.available_replicas}/{deployment.spec.replicas}")
            print(f"Unavailable: {status.status.unavailable_replicas}")
        
        return ready
    except Exception as e:
        print(f"Error checking deployment status {namespace}/{deployment_name}: {str(e)}")
        return False

def restart_deployment(k8s_client, deployment_name, namespace):
    try:
        deployment = k8s_client["apps_v1"].read_namespaced_deployment(
            name=deployment_name,
            namespace=namespace
        )
        
        if not deployment.spec.template.metadata.annotations:
            deployment.spec.template.metadata.annotations = {}
        
        deployment.spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"] = datetime.utcnow().isoformat()
        
        k8s_client["apps_v1"].patch_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
            body=deployment
        )
        return True
    except Exception as e:
        print(f"Error restarting {namespace}/{deployment_name}: {str(e)}")
        return False

def log_restart_to_s3(deployment_name, namespace, event_time, status, attempt, is_ready=False):
    try:
        s3_client = boto3.client('s3')
        
        berlin_tz = pytz.timezone('Europe/Berlin')
        berlin_time = event_time.astimezone(berlin_tz)
        
        timestamp = berlin_time.strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}-{deployment_name}-{status}.json"
        s3_key = f"{deployment_name}/{filename}"
        
        simple_status = "Running" if "RUNNING" in status else "Failed"
        if "RESTART" in status or "ATTEMPT" in status:
            simple_status = "Restarted"
        
        log_data = {
            "deployment": deployment_name,
            "namespace": namespace,
            "status": simple_status,
            "attempt": attempt,
            "is_ready": is_ready,
            "timestamp": datetime.now(berlin_tz).strftime("%Y-%m-%dT%H:%M:%S"),
            "timezone": "Europe/Berlin"
        }
        
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=s3_key,
            Body=json.dumps(log_data, indent=2),
            ContentType='application/json'
        )
        print(f"Log successfully written for {namespace}/{deployment_name} to s3://{S3_BUCKET_NAME}/{s3_key}")
        
        return True
    except Exception as e:
        print(f"Error logging to S3 for {namespace}/{deployment_name}: {str(e)}")
        return False

def send_google_chat_message(webhook_url, message):
    headers = {'Content-Type': 'application/json; charset=UTF-8'}
    payload = {
        'text': message
    }
    
    try:
        response = requests.post(webhook_url, headers=headers, json=payload)
        response.raise_for_status()
        print("Message sent to Google Chat successfully ...")
    except Exception as e:
        print(f"Failed to send message to Google Chat: {str(e)}")
        raise

def format_final_report(successful_deployments, failed_deployments):
    message = "🔔 *Deployment Restart Report for Staging*\n\n"
    
    if successful_deployments:
        message += "The deployments in staging that use the updated secrets have been restarted.\n\n"
        message += " ✅ *Successfully Restarted Deployments:*\n"
        for dep in successful_deployments:
            message += f"- {dep['namespace']} / {dep['name']}\n"
    
    if failed_deployments:
        message += "\n ❌ *Failed to Restart Deployments (Needs Manual Intervention):*\n"
        for dep in failed_deployments:
            message += f"- {dep['namespace']} / {dep['name']}\n"

    message += f"\n*Summary:*\n"
    message += f"Successfully restarted: {len(successful_deployments)}\n"
    message += f"Failed to start: {len(failed_deployments)}\n"
    
    return message

def process_deployment_restarts(k8s_client, deployments):
    successful_deployments = []
    failed_deployments = []
    
    print("\n=== PHASE 1: Initial Restart ===")
    for dep in deployments:
        print(f"\nRestarting '{dep['namespace']} / {dep['name']}' ...")
        restart_time = datetime.utcnow()
        restart_success = restart_deployment(k8s_client, dep['name'], dep['namespace'])
        log_restart_to_s3(dep['name'], dep['namespace'], restart_time, "INITIAL_RESTART", 1, False)
        time.sleep(1)
    
    print("\n=== PHASE 2: First Check (after 120s) ===")
    time.sleep(FIRST_CHECK)
    
    needs_retry = []
    for dep in deployments:
        check_time = datetime.utcnow()
        is_ready = is_deployment_ready(k8s_client, dep['name'], dep['namespace'])
        status = "RUNNING" if is_ready else "NOT_READY"
        log_restart_to_s3(dep['name'], dep['namespace'], check_time, f"FIRST_CHECK_{status}", 1, is_ready)
        
        if is_ready:
            successful_deployments.append(dep)
            print(f"✅ {dep['namespace']} / {dep['name']} is running")
        else:
            needs_retry.append(dep)
            print(f"⚠️ {dep['namespace']} / {dep['name']} needs retry")
    
    truly_failed = []
    if needs_retry:
        print("\n=== PHASE 3: Retry Failed Deployments ===")
        for dep in needs_retry:
            print(f"\nRetrying {dep['namespace']} / {dep['name']}...")
            restart_time = datetime.utcnow()
            restart_success = restart_deployment(k8s_client, dep['name'], dep['namespace'])
            log_restart_to_s3(dep['name'], dep['namespace'], restart_time, "RETRY_ATTEMPT", 2, False)
            time.sleep(1)
    
    print("\n=== PHASE 4: Final Check (after 240s) ===")
    time.sleep(FINAL_CHECK)
    
    for dep in needs_retry:
        check_time = datetime.utcnow()
        is_ready = is_deployment_ready(k8s_client, dep['name'], dep['namespace'])
        status = "RUNNING" if is_ready else "FAILED"
        log_restart_to_s3(dep['name'], dep['namespace'], check_time, f"FINAL_CHECK_{status}", 2, is_ready)
        
        if is_ready:
                print(f"✅ {dep['namespace']} / {dep['name']} is running after retry")
        else:
            truly_failed.append(dep)
            print(f"❌ '{dep['namespace']} / {dep['name']}' still not running")

    successful_deployments = [dep for dep in deployments if dep not in truly_failed]
    failed_deployments = truly_failed            
    
    return successful_deployments, failed_deployments

def lambda_handler(event, context):
    cluster_config = COMMON_CLUSTERS["staging"]
    berlin_time = datetime.now(pytz.timezone('Europe/Berlin'))
    
    try:
        print(f"Connected to cluster: '{cluster_config['cluster_name']}'")
        k8s_client = build_k8s_client(
            cluster_config["cluster_name"],
            cluster_config["region"],
            "staging"
        )
        
        labeled_deployments = find_labeled_deployments(k8s_client)
        
        if not labeled_deployments:
            print("No deployments with 'accesskey-rotation=true' label found.")
            chat_message = "🔔 *Deployment Restart Report for Staging*\n\nSince there is no update to any secret in staging in Kubernetes, no deployment will be restarted."
            send_google_chat_message(GOOGLE_CHAT_WEBHOOK_URL, chat_message)
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "No deployments to restart"}),
                "timezone": str(berlin_time.tzinfo)
            }
        
        print(f"Found {len(labeled_deployments)} deployments with label 'accesskey-rotation=true' to process:")
        for dep in labeled_deployments:
            print(f"- {dep['namespace']}/{dep['name']}")
        
        successful_deployments, failed_deployments = process_deployment_restarts(k8s_client, labeled_deployments)
        
        chat_message = format_final_report(successful_deployments, failed_deployments)
        
        send_google_chat_message(GOOGLE_CHAT_WEBHOOK_URL, chat_message)
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Deployment restart process completed"
            })
        }
        
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        print(error_msg)
        
        try:
            send_google_chat_message(GOOGLE_CHAT_WEBHOOK_URL, 
                f"🔔 *Deployment Restart Report for Staging*\n\n*Error in Deployment Restart Process:*\n{error_msg}")
        except:
            pass
        
        return {
            "statusCode": 500,
            "body": json.dumps({"error": error_msg})
        }