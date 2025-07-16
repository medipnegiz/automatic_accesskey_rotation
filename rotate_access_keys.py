import boto3
import json
import requests
import base64
import pytz
import os
from datetime import datetime
from botocore.signers import RequestSigner
from kubernetes import client, config

COMMON_CLUSTERS = {
    "staging": {
        "cluster_name": "<CLUSTER_NAME>",
        "region": "<REGION>",
        "sa_secret_name": "<SECRET_NAME>",
    }
}

CREATE_DAY = 180
DEACTIVE_DAY = 193
DELETE_DAY = 221

LINK_EXPIRATION_SECOND = 43200

GITLAB_API_URL = "<GITLAB_API_URL>"
S3_LOG_BUCKET = "<LOG_BUCKET_NAME>"
GOOGLE_CHAT_WEBHOOK_URL = "<WEBHOOK_URL>"

def load_user_configs():
    try:
        with open('iam_users_config_stg.json') as f:
            return json.load(f)
    except Exception as e:
        print(f"Could not read local configuration file: {str(e)}")
        return []

def send_google_chat_message(message):
    if not GOOGLE_CHAT_WEBHOOK_URL:
        print("Google Chat webhook URL not defined, message not sent")
        return
    
    try:
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        payload = {'text': message}
        response = requests.post(GOOGLE_CHAT_WEBHOOK_URL, headers=headers, json=payload)

        if response.status_code != 200:
            print(f"Google Chat message sending failed: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"Google Chat message sending error: {str(e)}")

def get_gitlab_token():
    secret_name = "gitlab/access-token"
    region_name = "eu-central-1" 
    client = boto3.client('secretsmanager', region_name=region_name)
    
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        return json.loads(get_secret_value_response['SecretString'])['gitlab_token']

    except Exception as e:
        print(f"Error retrieving GitLab token: {str(e)}")
        raise

def get_gitlab_project_name(project_id, gitlab_token):
    headers = {
        "PRIVATE-TOKEN": gitlab_token,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{GITLAB_API_URL}/projects/{project_id}", headers=headers)
        if response.status_code == 200:
            return response.json().get('name', f"project-{project_id}")
        return f"project-{project_id}"

    except Exception as e:
        print(f"Error getting GitLab project name: {str(e)}")
        return f"project-{project_id}"        

def get_secret_name(username, stage):
    return f"{username}-aws-credentials-{stage.lower()}"

def get_eks_bearer_token(cluster_name, region):
    try:
        sts_client = boto3.client('sts', region_name=region)
        token = sts_client.generate_presigned_url(
            'get_caller_identity',
            Params={},
            ExpiresIn=60,
            HttpMethod='GET'
        )
        encoded_token = 'k8s-aws-v1.' + base64.urlsafe_b64encode(token.encode('utf-8')).decode('utf-8').rstrip('=')
        return encoded_token

    except Exception as e:
        print(f"Error generating EKS bearer token: {str(e)}")
        raise  

def build_k8s_client(cluster_name, region, cluster_type):
    secretsmanager = boto3.client("secretsmanager", region_name=region)
    
    sa_secret_name = COMMON_CLUSTERS[cluster_type]["sa_secret_name"]
    sa_secret = secretsmanager.get_secret_value(SecretId=sa_secret_name)
    sa_secret_dict = json.loads(sa_secret['SecretString'])

    eks_client = boto3.client('eks', region_name=region)
    cluster_info = eks_client.describe_cluster(name=cluster_name)['cluster']

    endpoint = cluster_info['endpoint']
    token = sa_secret_dict["k8s_token"]
    ca_data_b64 = sa_secret_dict["k8s_ca"]

    configuration = client.Configuration()
    configuration.host = endpoint
    configuration.api_key = {
        "authorization": f"Bearer {token}"
    }

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as cert_file:
        cert_file.write(base64.b64decode(ca_data_b64))
        configuration.ssl_ca_cert = cert_file.name

    client.Configuration.set_default(configuration)
    return client.CoreV1Api()

def find_deployments_using_secret(v1_apps, namespace, secret_name):
    deployments = v1_apps.list_namespaced_deployment(namespace)
    matching_deployments = []
    
    for deployment in deployments.items:
        if not deployment.spec.template.spec.containers:
            continue
            
        for container in deployment.spec.template.spec.containers:
            if not container.env_from:
                continue
                
            for env_from in container.env_from:
                if env_from.secret_ref and env_from.secret_ref.name == secret_name:
                    matching_deployments.append(deployment.metadata.name)
                    break
                    
    return matching_deployments

def update_k8s_secrets_if_exists(username, new_access_key, new_secret_key):
    result = {}
    USER_CONFIGS = load_user_configs()

    for user_entry in USER_CONFIGS:
        if user_entry["username"] != username:
            continue

        if "eks" not in user_entry:
            return result

        for cluster_key in user_entry.get("clusters", []):
            cluster_config = COMMON_CLUSTERS.get(cluster_key)
            if not cluster_config:
                continue

            cluster_name = cluster_config["cluster_name"]
            
            if cluster_key not in result:
                result[cluster_key] = {}
            
            try:
                v1 = build_k8s_client(cluster_name, cluster_config["region"], cluster_key)
                v1_apps = client.AppsV1Api()
                
                for eks_entry in user_entry["eks"]:
                    namespace = eks_entry["namespace"]
                    key_prefix = eks_entry.get("key_prefix", "AWS")
                    updated_secrets = []
                    
                    for secret_name in eks_entry.get("secret_names", []):
                        try:
                            secret = v1.read_namespaced_secret(secret_name, namespace)
                            current_data = secret.data if secret.data else {}

                            required_keys = [f"{key_prefix}_ACCESS_KEY_ID", f"{key_prefix}_SECRET_ACCESS_KEY"]
                            
                            if not all(key in current_data for key in required_keys):
                                print(f"Warning: Required keys {required_keys} not found in secret {secret_name}")
                                continue
                            
                            current_data.update({
                                f"{key_prefix}_ACCESS_KEY_ID": base64.b64encode(new_access_key.encode()).decode(),
                                f"{key_prefix}_SECRET_ACCESS_KEY": base64.b64encode(new_secret_key.encode()).decode()
                            })

                            secret.data = current_data

                            if not secret.metadata.labels:
                                secret.metadata.labels = {}
                            secret.metadata.labels["accesskey-rotation"] = "true"
                            
                            v1.replace_namespaced_secret(secret_name, namespace, secret)
                            updated_secrets.append(secret_name)
                            
                            if namespace not in result[cluster_key]:
                                result[cluster_key][namespace] = {}
                            
                            result[cluster_key][namespace][secret_name] = {
                                'updated': True,
                                'deployments': []
                            }
                            
                            deployments = find_deployments_using_secret(
                                v1_apps, 
                                namespace, 
                                secret_name
                            )
                            
                            if deployments:
                                for deployment_name in deployments:
                                    try:
                                        deployment = v1_apps.read_namespaced_deployment(
                                            deployment_name, 
                                            namespace
                                        )

                                        if not deployment.metadata.labels:
                                            deployment.metadata.labels = {}
                                        deployment.metadata.labels["accesskey-rotation"] = "true"
                                        v1_apps.replace_namespaced_deployment(
                                            deployment_name, 
                                            namespace, 
                                            deployment
                                        )
                                        result[cluster_key][namespace][secret_name]['deployments'].append(deployment_name)
                                        print(f"Added label `accesskey-rotation=true` to deployment '{deployment_name}' in namespace `{namespace}`")

                                    except Exception as e:
                                        print(f"Error labeling deployment {deployment_name}: {str(e)}")

                            else:
                                print(f"Info: Secret '{secret_name}' not used by any deployments in namespace '{namespace}'")
                            
                        except client.exceptions.ApiException as e:
                            if e.status != 404:
                                print(f"Kubernetes API error in namespace {namespace}: {e}")

                        except Exception as e:
                            print(f"Error processing secret {secret_name} in namespace {namespace}: {str(e)}")

                    if updated_secrets:
                        print(f"Kubernetes: Updated secrets in namespace '{namespace}': {', '.join(updated_secrets)}")
                
            except Exception as e:
                print(f"Error accessing EKS cluster {cluster_name}: {str(e)}")
    
    return result

def process_secrets_for_environments(username, new_key, secretsmanager, action='create'):
    result = {}
    USER_CONFIGS = load_user_configs()

    for user_config in USER_CONFIGS:
        if user_config["username"] != username:
            continue
            
        stage = user_config.get("stage", "staging")
        secret_name = get_secret_name(username, stage)
        env_result = {'created': False, 'updated': False}
            
        try:
            if action == 'create':
                try:
                    current_secret = secretsmanager.get_secret_value(SecretId=secret_name)
                    secret_dict = json.loads(current_secret['SecretString'])
                    
                    if f'AWS_ACCESS_KEY_ID' in secret_dict:
                        secret_dict[f'Old_AWS_ACCESS_KEY_ID'] = secret_dict[f'AWS_ACCESS_KEY_ID']
                        secret_dict[f'Old_AWS_SECRET_ACCESS_KEY'] = secret_dict[f'AWS_SECRET_ACCESS_KEY']
                        env_result['updated'] = True

                except secretsmanager.exceptions.ResourceNotFoundException:
                    secret_dict = {}
                    env_result['created'] = True
                
                secret_dict.update({
                    f'AWS_ACCESS_KEY_ID': new_key['AccessKey']['AccessKeyId'],
                    f'AWS_SECRET_ACCESS_KEY': new_key['AccessKey']['SecretAccessKey']
                })
                
                try:
                    secretsmanager.put_secret_value(
                        SecretId=secret_name,
                        SecretString=json.dumps(secret_dict)
                    )
                    print(f"New credentials saved to secret ({secret_name})")

                except secretsmanager.exceptions.ResourceNotFoundException:
                    secretsmanager.create_secret(
                        Name=secret_name,
                        Description=f"AWS credentials for {username}",
                        SecretString=json.dumps(secret_dict)
                    )
                    print(f"New secret created in SecretManager for '{username}': {secret_name}'")
                
                result[stage] = env_result
                
            elif action == 'delete':
                try:
                    current_secret = secretsmanager.get_secret_value(SecretId=secret_name)
                    secret_dict = json.loads(current_secret['SecretString'])
                    
                    if secret_dict.get(f'AWS_ACCESS_KEY_ID') == new_key:
                        if f'Old_AWS_ACCESS_KEY_ID' in secret_dict:
                            secret_dict[f'AWS_ACCESS_KEY_ID'] = secret_dict[f'Old_AWS_ACCESS_KEY_ID']
                            secret_dict[f'AWS_SECRET_ACCESS_KEY'] = secret_dict[f'Old_AWS_SECRET_ACCESS_KEY']
                            del secret_dict[f'Old_AWS_ACCESS_KEY_ID']
                            del secret_dict[f'Old_AWS_SECRET_ACCESS_KEY']

                            secretsmanager.put_secret_value(
                                SecretId=secret_name,
                                SecretString=json.dumps(secret_dict)
                            )
                            print(f"Promoted old credentials in '{secret_name}'")

                        else:
                            print(f"No old credentials found in secret '{secret_name}', leaving it unchanged")
                            
                    elif secret_dict.get(f'Old_AWS_ACCESS_KEY_ID') == new_key:
                        del secret_dict[f'Old_AWS_ACCESS_KEY_ID']
                        del secret_dict[f'Old_AWS_SECRET_ACCESS_KEY']

                        secretsmanager.put_secret_value(
                            SecretId=secret_name,
                            SecretString=json.dumps(secret_dict))
                        print(f"Removed old credentials from secret '{secret_name}'")

                    else:
                        if f'Old_AWS_ACCESS_KEY_ID' in secret_dict:
                            print(f"Access key '{new_key}' is being deleted, cleaning up old credentials in secret '{secret_name}'")
                            del secret_dict[f'Old_AWS_ACCESS_KEY_ID']
                            del secret_dict[f'Old_AWS_SECRET_ACCESS_KEY']

                            secretsmanager.put_secret_value(
                                SecretId=secret_name,
                                SecretString=json.dumps(secret_dict))
                        print(f"Secret `{secret_name}` has been updated successfully")
                    
                except secretsmanager.exceptions.ResourceNotFoundException:
                    continue

                except Exception as e:
                    print(f"Error processing secret {secret_name}: {e}")
                    
        except Exception as e:
            print(f"Error processing secret '{secret_name}' for environment '{stage}': {e}")
    
    return result

def update_gitlab_variables_for_environments(username, new_key, GITLAB_ACCESS_TOKEN):
    result = {}
    USER_CONFIGS = load_user_configs()

    for user_config in USER_CONFIGS:
        if user_config["username"] != username:
            continue

        stage = user_config.get("stage", "staging")

        if "projects" not in user_config:
            print(f"Warning: User {username} has no projects defined, skipping")
            continue
            
        for project in user_config.get("projects", []):
            project_id = project["id"]
            gitlab_env = project.get("environment", "*")
            env_key_prefix = project.get("env_key_prefix", "AWS")
            project_name = get_gitlab_project_name(project_id, GITLAB_ACCESS_TOKEN)

            env_result = {}
            try:
                headers = {
                    "PRIVATE-TOKEN": GITLAB_ACCESS_TOKEN,
                    "Content-Type": "application/json"
                }

                var_mapping = {
                    f"{env_key_prefix}_ACCESS_KEY_ID": "AccessKeyId",
                    f"{env_key_prefix}_SECRET_ACCESS_KEY": "SecretAccessKey"
                }

                for gitlab_var, secret_key in var_mapping.items():
                    var_result = update_gitlab_variable(
                        project_id=project_id,
                        variable_name=gitlab_var,
                        variable_value=new_key['AccessKey'][secret_key],
                        headers=headers,
                        environment=gitlab_env
                    )
                    env_result[gitlab_var] = var_result
            
            except Exception as e:
                print(f"WARNING: GitLab update failed for project '{project_name}' ({project_id}) environment '{gitlab_env}': {e}")
                
            
            result[project_id] = {
                "project_name": project_name,
                "updates": {gitlab_env: env_result},
                "env_key_prefix": env_key_prefix,
                "stage": stage
            }
    
    return result

def lambda_handler(event, context):
    iam = boto3.client('iam')
    secretsmanager = boto3.client('secretsmanager')
    GITLAB_ACCESS_TOKEN = get_gitlab_token()
    operation_reports = {}
    users_with_activity = set()
    USER_CONFIGS = load_user_configs()

    new_key_users = []
    deactivated_key_users = []
    deleted_key_users = []
    user_log_files = {}
    
    for user_config in USER_CONFIGS:
        username = user_config["username"]
        target_envs = user_config.get("stage",["staging"])
        if isinstance(target_envs, str):
            target_envs = [target_envs]
        
        user_has_activity = False
        
        try:
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

        except Exception as e:
            print(f"Error: Access key not listed for user '{username}' Detail: {e}")
            continue
        
        for key in keys:
            key_id = key['AccessKeyId']
            berlin_tz = pytz.timezone('Europe/Berlin')
            key_age = (datetime.now(berlin_tz) - key['CreateDate'].astimezone(berlin_tz)).days
            status = key['Status']

            new_key_age = 0
            if len(keys) == 2:
                other_key = next((k for k in keys if k['AccessKeyId'] != key_id), None)
                if other_key and other_key['Status'] == 'Active':
                    new_key_age = (datetime.now(berlin_tz) - other_key['CreateDate'].astimezone(berlin_tz)).days

            if (key_age >= DELETE_DAY and new_key_age >= 41 and len(keys) >= 2 and status == 'Inactive'):
                process_secrets_for_environments(username, key_id, secretsmanager, action='delete')
                
                if username not in operation_reports:
                    operation_reports[username] = {
                        'Key rotation': None,
                        'Secret manager': {'Created secrets': [], 'Updated secrets': []},
                        'Gitlab': {'Created variables': [], 'Updated variables': []},
                        'Kubernetes': {'Updated secrets': []},
                        'Deactivated access keys': [],
                        'Deleted access keys': []
                    }
                
                operation_reports[username]['Deleted access keys'].append(key_id)
                user_has_activity = True
                
                iam.delete_access_key(
                    UserName=username,
                    AccessKeyId=key_id
                )
                print(f"Old inactive access key ({key_id}) deleted successfully for '{username}'")
                deleted_key_users.append((username, key_id))

            elif (key_age >= DEACTIVE_DAY and new_key_age >= 13 and len(keys) >= 2 and status == 'Active'):
                iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key_id,
                    Status='Inactive'
                )
                
                label_clean_results = clean_rotation_labels_from_k8s(username)
                if username not in operation_reports:
                    operation_reports[username] = {
                        'Key rotation': None,
                        'Secret manager': {'Created secrets': [], 'Updated secrets': []},
                        'Gitlab': {'Created variables': [], 'Updated variables': []},
                        'Kubernetes': {
                            'Updated secrets': [],
                            'Cleaned secrets': [],
                            'Cleaned deployments': []
                        },
                        'Deactivated access keys': [],
                        'Deleted access keys': []
                    }

                    for cluster_key, namespaces in label_clean_results.items():
                        for namespace, secrets in namespaces.items():
                            for secret_name, clean_data in secrets.items():
                                if clean_data.get('labels_cleaned'):
                                    operation_reports[username]['Kubernetes']['Cleaned secrets'].append(
                                        f"Removed label 'accesskey-rotation=true' from secret '{secret_name}' in namespace '{namespace}'"
                                    )

                                for deployment_name in clean_data.get('deployments_cleaned', []):
                                    operation_reports[username]['Kubernetes']['Cleaned deployments'].append(
                                        f"Removed label 'accesskey-rotation=true' from deployment '{deployment_name}' in namespace '{namespace}'"
                                    )
                
                operation_reports[username]['Deactivated access keys'].append(key_id)
                for cluster_key, secrets in label_clean_results.items():
                    for secret_name, result in secrets.items():
                        if result.get('labels_cleaned'):
                            operation_reports[username]['Kubernetes']['Cleaned secrets'].append(
                                f"Removed label 'accesskey-rotation=true' from secret '{secret_name}'"
                            )

                        if result.get('deployments_cleaned'):
                            for deployment in result['deployments_cleaned']:
                                operation_reports[username]['Kubernetes']['Cleaned deployments'].append(
                                    f"Removed label 'accesskey-rotation=true' from deployment '{deployment}'"
                                )

                user_has_activity = True
                print(f"Old access key ({key_id}) deactivated for '{username}'")
                deactivated_key_users.append((username, key_id))
                
            elif key_age >= CREATE_DAY and status == 'Active':
                if len(keys) >= 2:
                    print(f"'{username}' already has 2 access keys. Cannot create new one.")
                    continue
                    
                try:
                    new_key = iam.create_access_key(UserName=username)
                    print(f"New access key ({new_key['AccessKey']['AccessKeyId']}) created for '{username}'")
                    
                    if username not in operation_reports:
                        operation_reports[username] = {
                            'Key rotation': None,
                            'Secret manager': {'Created secrets': [], 'Updated secrets': []},
                            'Gitlab': {'Created variables': [], 'Updated variables': []},
                            'Kubernetes': {
                                'Updated secrets': [],
                                'Labeled deployments': []
                            },
                            'Deactivated access keys': [],
                            'Deleted access keys': []
                        }
                    
                    operation_reports[username]['Key rotation'] = {
                        'New access key': new_key['AccessKey']['AccessKeyId'],
                        'Old access key': key_id
                    }
                    user_has_activity = True
                    new_key_users.append((username, new_key['AccessKey']['AccessKeyId']))
                    
                    secret_result = process_secrets_for_environments(username, new_key, secretsmanager, action='create')
                    if secret_result:
                        for env in target_envs:
                            secret_name = get_secret_name(username, env)
                            if secret_result.get(env,{}).get('created'):
                                operation_reports[username]['Secret manager']['Created secrets'].append(secret_name)
                            elif secret_result.get(env,{}).get('updated'):
                                operation_reports[username]['Secret manager']['Updated secrets'].append(secret_name)
                    
                    gitlab_result = update_gitlab_variables_for_environments(username, new_key, GITLAB_ACCESS_TOKEN)
                    if gitlab_result:
                        for project_id, project_info in gitlab_result.items():
                            project_name = project_info.get("project_name", f"project-{project_id}")
                            
                            for env, updates in project_info.get("updates", {}).items():
                                for var, var_result in updates.items():
                                    if var_result.get('created'):
                                        operation_reports[username]['Gitlab']['Created variables'].append(
                                            f"Variable '{var}' created for environment '{env}' in project '{project_name}' (ID: {project_id})"
                                        )
                                    elif var_result.get('updated'):
                                        operation_reports[username]['Gitlab']['Updated variables'].append(
                                            f"Variable '{var}' updated for environment '{env}' in project '{project_name}' (ID: {project_id})"
                                        )
                    
                    k8s_result = update_k8s_secrets_if_exists(username, new_key['AccessKey']['AccessKeyId'], new_key['AccessKey']['SecretAccessKey'])
                    if k8s_result:
                        for cluster_key in user_config.get("clusters", []):
                            cluster_config = COMMON_CLUSTERS.get(cluster_key, {})
                            for eks_entry in user_config.get("eks", []):
                                namespace = eks_entry["namespace"]
                                for secret in eks_entry.get("secret_names", []):
                                    if k8s_result.get(cluster_key, {}).get(namespace, {}).get(secret, {}).get('updated'):
                                        operation_reports[username]['Kubernetes']['Updated secrets'].append(
                                            f"Secret '{secret}' updated in namespace '{namespace}' in Kubernetes"
                                        )

                                    if k8s_result.get(cluster_key, {}).get(namespace, {}).get(secret, {}).get('deployments'):
                                        for deployment in k8s_result[cluster_key][namespace][secret]['deployments']:
                                            operation_reports[username]['Kubernetes']['Labeled deployments'].append(
                                                f"Added label 'accesskey-rotation=true' to deployment '{deployment}' in namespace '{namespace}'"
                                            )
                    
                    print(f"Old access key ({key_id}) will be deactivated in 14 days...\n")
                    
                except Exception as e:
                    print(f"Failed to complete rotation: {e}")
                    raise
        
        if user_has_activity:
            users_with_activity.add(username)
            berlin_tz = pytz.timezone('Europe/Berlin')
            log_data = {
                "AWS Access Key Rotation Detailed Report for IAM User": username,
                "Timestamp": datetime.now(berlin_tz).strftime("%Y-%m-%dT%H:%M:%S"),
                "Timezone": "Europe/Berlin",
                "Actions": operation_reports[username],
                "Metadata": {
                    "Lambda function": context.function_name
                }
            }
            log_file_path = write_log_to_s3(username, log_data)
            if log_file_path:
                user_log_files[username] = log_file_path

    message = "📢 *AWS Access Key Rotation Report for Staging*\n\n"
    
    if not operation_reports:
        message += "All access keys in staging are up to date, no rotation will be done for any access key 🌟\n"

    else:
        if new_key_users:
            message += "New access keys created for the following IAM users with old access keys.\n"
            message += "The Gitlab variables and Kubernetes secrets associated with these IAM users updated.\n"
            message += "*(For more information, see detailed report)*\n\n"
            message += " ✨ *IAM-Users with new access key created:*\n"
            for username, new_key_id in new_key_users:
                log_url = generate_presigned_url(S3_LOG_BUCKET, user_log_files.get(username, ""))

                if log_url:
                    message += f"- {username} `({new_key_id})`🆕 (For detailed report, click <{log_url}|HERE>)\n"
                else:
                    message += f"- {username} `({new_key_id})`🆕\n"
            message += "\n"
            message += "⚠️ *Old access keys will be deactivated after 14 days*\n\n"

            if (new_key_users and deactivated_key_users) or (new_key_users and deleted_key_users):
                message += " -----\n\n"
        
        if deactivated_key_users:
            message += "Old access keys for the following IAM users deactivated.\n"
            message += "*(For more information, see detailed report)*\n\n"
            message += " 🚫 *IAM-Users with old access key deactivated:*\n"
            for username, key_id in deactivated_key_users:
                log_url = generate_presigned_url(S3_LOG_BUCKET, user_log_files.get(username, ""))
                if log_url:
                    message += f"- {username} `({key_id})` (For detailed report, click <{log_url}|HERE>)\n"
                else:
                    message += f"- {username} `({key_id})`\n"
            message += "\n"
            message += "⚠️ *Deactivated and old access keys will be deleted after 28 days*\n\n"

            if (deactivated_key_users and deleted_key_users):
                message += " -----\n\n"
        
        if deleted_key_users:
            message += "Deactivated and old access keys for the following IAM users deleted.\n"
            message += "*(For more information, see detailed report)*\n\n"
            message += " ❌ *IAM-Users with old access key deleted:*\n"
            for username, key_id in deleted_key_users:
                log_url = generate_presigned_url(S3_LOG_BUCKET, user_log_files.get(username, ""))
                if log_url:
                    message += f"- {username} `({key_id})` (For detailed report, click <{log_url}|HERE>)\n"
                else:
                    message += f"- {username} `({key_id})`\n"
            message += "\n"
        
        message += "\n*(Detailed reports are viewable for 12 hours only. Contact OPS to view after that)*\n"
    
    print("Message sent to Google Chat successfully ...")
    send_google_chat_message(message)

def update_gitlab_variable(project_id, variable_name, variable_value, headers, environment):
    scope = environment if environment != "all" else "*"
    result = {'created': False, 'updated': False}

    try:
        list_url = f"{GITLAB_API_URL}/projects/{project_id}/variables?filter[environment_scope]={scope}"
        list_response = requests.get(list_url, headers=headers)

        if list_response.status_code != 200:
            print(f"GitLab list variables failed: {list_response.status_code} - {list_response.text}")
            return result

        variables = list_response.json()
        variable_exists = False
        existing_var = None

        for var in variables:
            if var['key'] == variable_name and var['environment_scope'] == scope:
                variable_exists = True
                existing_var = var
                break

        is_secret = variable_name.endswith('_SECRET_ACCESS_KEY')
        variable_settings = {
            "value": variable_value,
            "protected": False,
            "masked": is_secret,
            "raw": False,
            "environment_scope": scope
        }            

        if variable_exists:
            update_url = f"{GITLAB_API_URL}/projects/{project_id}/variables/{variable_name}?filter[environment_scope]={scope}"
            response = requests.put(update_url, headers=headers, json=variable_settings)

            if response.status_code == 200:
                result['updated'] = True
                print(f"GitLab variable ({variable_name}) updated successfully in project '{project_id}'")

            else:
                print(f"GitLab update failed: {response.status_code} - {response.text}")

        else:
            create_url = f"{GITLAB_API_URL}/projects/{project_id}/variables"
            variable_settings["key"] = variable_name
            response = requests.post(create_url, headers=headers, json=variable_settings)

            if response.status_code == 201:
                result['created'] = True
                print(f"GitLab variable ({variable_name}) created successfully in project '{project_id}'")
                
            else:
                print(f"GitLab create failed: {response.status_code} - {response.text}")
        
        return result

    except Exception as e:
        print(f"GitLab process error: {str(e)}")
        return result

def clean_rotation_labels_from_k8s(username):
    result = {}
    USER_CONFIGS = load_user_configs()

    for user_entry in USER_CONFIGS:
        if user_entry["username"] != username:
            continue

        if "eks" not in user_entry:
            return result

        for cluster_key in user_entry.get("clusters", []):
            cluster_config = COMMON_CLUSTERS.get(cluster_key)
            if not cluster_config:
                continue

            cluster_name = cluster_config["cluster_name"]
            
            if cluster_key not in result:
                result[cluster_key] = {}

            try:
                v1 = build_k8s_client(cluster_name, cluster_config["region"], cluster_key)
                v1_apps = client.AppsV1Api()
                
                for eks_entry in user_entry["eks"]:
                    namespace = eks_entry["namespace"]
                    key_prefix = eks_entry.get("key_prefix", "AWS")
                    
                    if namespace not in result[cluster_key]:
                        result[cluster_key][namespace] = {}
                    
                    for secret_name in eks_entry.get("secret_names", []):
                        try:
                            secret = v1.read_namespaced_secret(secret_name, namespace)
                            deployment_cleaned = []
                            
                            deployments = find_deployments_using_secret(v1_apps, namespace, secret_name)
                            if deployments:
                                for deployment_name in deployments:
                                    try:
                                        deployment = v1_apps.read_namespaced_deployment(deployment_name, namespace)
                                        if deployment.metadata.labels and "accesskey-rotation" in deployment.metadata.labels:
                                            del deployment.metadata.labels["accesskey-rotation"]
                                            v1_apps.replace_namespaced_deployment(deployment_name, namespace, deployment)
                                            deployment_cleaned.append(deployment_name)
                                            print(f"Removed rotation label from deployment '{deployment_name}' in namespace '{namespace}'")

                                    except Exception as e:
                                        print(f"Error cleaning label from deployment {deployment_name}: {str(e)}")
                            
                            if secret.metadata.labels and "accesskey-rotation" in secret.metadata.labels:
                                del secret.metadata.labels["accesskey-rotation"]
                                v1.replace_namespaced_secret(secret_name, namespace, secret)
                                
                                result[cluster_key][namespace][secret_name] = {
                                    'labels_cleaned': True,
                                    'deployments_cleaned': deployment_cleaned
                                }
                                print(f"Labels `accesskey-rotation=true` cleaned from secret '{secret_name}' in namespace '{namespace}' and {len(deployment_cleaned)} deployments")
                            
                        except client.exceptions.ApiException as e:
                            if e.status != 404:
                                print(f"Kubernetes API error while cleaning labels in namespace {namespace}: {e}")

                        except Exception as e:
                            print(f"Error accessing secret {secret_name} in namespace {namespace}: {str(e)}")
                
            except Exception as e:
                print(f"Error building Kubernetes client for cluster {cluster_name}: {str(e)}")
    
    return result

def write_log_to_s3(username, log_data):
    s3 = boto3.client('s3')
    
    try:
        folder_path = f"{username}/"
        berlin_tz = pytz.timezone('Europe/Berlin')
        timestamp = datetime.now(berlin_tz).strftime("%Y-%m-%dT%H:%M:%S")
        log_file_name = f"{timestamp}-{username}.json"
        s3_path = f"{folder_path}{log_file_name}"
        log_data["Timestamp"] = timestamp
        
        s3.put_object(
            Bucket=S3_LOG_BUCKET,
            Key=s3_path,
            Body=json.dumps(log_data, indent=2),
            ContentType='application/json'
        )
        print(f"Log successfully written to s3://{S3_LOG_BUCKET}/{s3_path}")
        return s3_path

    except Exception as e:
        print(f"Error writing log to S3: {str(e)}")
        return None

def generate_presigned_url(bucket_name, object_key, expiration=LINK_EXPIRATION_SECOND):
    s3_client = boto3.client('s3')
    try:
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': object_key},
            ExpiresIn=expiration
        )
        return url
    except Exception as e:
        print(f"Error generating presigned URL: {str(e)}")
        return None        