import json
import requests
from datetime import datetime, timedelta
import boto3
import pytz

WEBHOOK_URL = "<WEBHOOK_URL>"
CREATE_DAY = 180
DEACTIVE_DAY = 194
DELETE_DAY = 222

def load_user_configs():
    try:
        with open('iam_users.json') as f:
            return json.load(f)
    except Exception as e:
        print(f"Could not read local configuration file: {str(e)}")
        return []

def get_key_rotation_candidates():
    iam = boto3.client('iam')
    users_to_check = load_user_configs()
    
    create_candidates = []
    deactivate_candidates = []
    delete_candidates = []
    
    for user in users_to_check:
        user_name = user if isinstance(user, str) else user.get('username', '')
        if not user_name:
            continue
            
        try:
            access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            if not access_keys:
                continue
                
            berlin_tz = pytz.timezone('Europe/Berlin')
            now = datetime.now(berlin_tz)
            
            active_keys = [k for k in access_keys if k['Status'] == 'Active']
            new_key_age = 0
            if len(active_keys) >= 1:
                new_key_age = (now - active_keys[0]['CreateDate'].astimezone(berlin_tz)).days
            
            for key in access_keys:
                key_age = (now - key['CreateDate'].astimezone(berlin_tz)).days
                status = key['Status']
                
                if (key_age > CREATE_DAY and len(access_keys) == 1 and status == 'Active'):
                    create_candidates.append({
                        'username': user_name,
                        'access_key_id': key['AccessKeyId'],
                        'age_days': key_age
                    })
                
                elif (key_age >= DEACTIVE_DAY and len(access_keys) >= 2 and status == 'Active' and new_key_age >= 13):
                    deactivate_candidates.append({
                        'username': user_name,
                        'access_key_id': key['AccessKeyId'],
                        'age_days': key_age
                    })
                
                elif (key_age >= DELETE_DAY and len(access_keys) >= 2 and status == 'Inactive' and new_key_age >= 27):
                    delete_candidates.append({
                        'username': user_name,
                        'access_key_id': key['AccessKeyId'],
                        'age_days': key_age
                    })
                    
        except Exception as e:
            print(f"Error processing user {user_name}: {str(e)}")
    
    return create_candidates, deactivate_candidates, delete_candidates

def lambda_handler(event, context):
    create_list, deactivate_list, delete_list = get_key_rotation_candidates()
    
    message_lines = [
        "📢 *Access Key Rotation Notification for Staging*\n",
        "The Access Key rotation for IAM users in staging will begin within 1 hour 🚀"
    ]
    
    if create_list:
        message_lines.append("\n 🟢 *A new access key will be created for the following IAM users:*")
        for user in create_list:
            message_lines.append(f"- {user['username']} `({user['access_key_id']})`  -  {user['age_days']} days old")
    
    if deactivate_list:
        message_lines.append("\n 🟡 *The old access keys of the following IAM users will be deactivated:*")
        for user in deactivate_list:
            message_lines.append(f"- {user['username']} `({user['access_key_id']})`  -  {user['age_days']} days old")
    
    if delete_list:
        message_lines.append("\n 🔴 *The deactivated access keys of the following IAM users will be deleted:*")
        for user in delete_list:
            message_lines.append(f"- {user['username']} `({user['access_key_id']})`  -  {user['age_days']} days old")
    
    if not create_list and not deactivate_list and not delete_list:
        message_lines.append("\nNo access keys require rotation at this time.")
    
    message_data = {"text": "\n".join(message_lines)}
    
    response = requests.post(WEBHOOK_URL, json=message_data)
    
    if response.status_code == 200:
        return {
            "statusCode": 200,
            "body": json.dumps("Message sent to Google Chat successfully ...")
        }
    else:
        return {
            "statusCode": response.status_code,
            "body": json.dumps(f"Message could not be sent: {response.text}")
        }