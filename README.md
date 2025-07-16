# AWS IAM Access Key Rotation Automation

## Overview
This AWS Lambda function automates the rotation of IAM access keys for specified users, updating associated credentials in AWS Secrets Manager, GitLab CI/CD variables, and Kubernetes secrets. The solution follows security best practices by:

1. Creating new access keys before old ones expire
2. Gracefully deactivating old keys before deletion
3. Synchronizing credentials across multiple systems
4. Providing detailed audit logs and notifications

## Key Features
- Automated key rotation: Creates new keys when existing ones approach expiration
- Multi-system synchronization: Updates credentials in AWS Secrets Manager, GitLab, and Kubernetes
- Phased deactivation: Deactivates old keys before eventual deletion
- Comprehensive logging: Stores detailed rotation logs in S3
- Real-time notifications: Sends alerts to Google Chat
- Kubernetes integration: Updates secrets and labels deployments using those secrets

## How It Works
The Lambda function runs on a schedule (recommended daily) and:
1. Checks each configured IAM user's access keys
2. For keys approaching expiration:
   - Creates new keys if needed
   - Deactivates old keys after a grace period
   - Deletes expired keys
3. Updates credentials in:
   - AWS Secrets Manager secrets
   - GitLab CI/CD variables
   - Kubernetes secrets
4. Labels Kubernetes resources during rotation for tracking
5. Generates detailed logs in S3
6. Sends notifications to Google Chat

## Configuration
The system is configured via a JSON file (iam_users_config_stg.json) that specifies:
```json
[
    {
        "username": "men-test-user",
        "stage": "staging",
        "clusters": ["staging"],
        "projects": [
            {"id": "446", "environment": "staging", "env_key_prefix": "AWS"},
            {"id": "670", "environment": "*"},
            {"id": "404", "environment": "Staging", "env_key_prefix": "DATAPLATFORM_AWS"}
        ],
        "eks": [
            {
                "namespace": "crm",
                "secret_names": ["crm-test-credentials"]
            }
        ]
    }
]
```
## Configuration Fields
- `username:` IAM username
- `stage:` Environment stage (e.g., "staging")
- `clusters:` List of Kubernetes clusters to update
- `projects:` GitLab projects to update with:
   - `id:` Project ID
   - `environment:` Environment scope
   - `env_key_prefix:` Variable name prefix
- `eks:` Kubernetes namespaces and secrets to update

## Function Details
### Core Functions
1. `lambda_handler` - Main entry point
   - Orchestrates the entire rotation process
   - Handles key creation, deactivation, and deletion
   - Coordinates updates across all systems
   - Generates reports and notifications
2. `process_secrets_for_environments` - Manages AWS Secrets Manager updates
   - Creates/updates secrets with new credentials
   - Handles promotion of old credentials when needed
3. `update_gitlab_variables_for_environments` - Updates GitLab CI/CD variables
   - Updates or creates variables across configured projects
   - Handles different environment scopes
4. `update_k8s_secrets_if_exists` - Manages Kubernetes secrets
   - Updates secrets in configured namespaces
   - Labels resources during rotation
5. `clean_rotation_labels_from_k8s` - Cleans up rotation labels
   - Removes temporary labels after rotation completes
