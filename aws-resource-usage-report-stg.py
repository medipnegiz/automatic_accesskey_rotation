import boto3
import json
import pandas as pd
from datetime import datetime, timedelta
import calendar

def lambda_handler(event, context):
    try:
        resource_groups = [
            {"group_name": "Resource_Usage_infrastructure", "email": "<OPS_MAIL_ADDRESS>", "team_name": "OPS Team"},
            {"group_name": "Resource_Usage_bi", "email": "<BI_MAIL_ADDRESS>", "team_name": "BI Team"}
        ]

        for group in resource_groups:
            client = boto3.client("resource-groups")

            resource_arns = []
            resource_types = []

            next_token = None

            while True:
                response = client.list_group_resources(
                    GroupName=group["group_name"],
                    NextToken=next_token if next_token else ""
                )

                for resource in response.get("ResourceIdentifiers", []):
                    arn = resource.get("ResourceArn")
                    resource_arns.append(arn)
                    resource_type = resource.get("ResourceType")
                    resource_types.append(resource_type)

                next_token = response.get("NextToken")
                if not next_token:
                    break

            arn_type_df = pd.DataFrame({"ARN": resource_arns, "Type": resource_types})

            resource_list = []

            for index, row in arn_type_df.iterrows():
                arn = row["ARN"]
                resource_type = row["Type"]
                tags = get_tags_for_resource(arn)
                resource_name = next((tag["Value"] for tag in tags if tag["Key"] == "Name"), "None")

                resource_list.append({
                    "Name": resource_name,
                    "Type": resource_type,
                    "ARN": arn
                })

            df_resources = pd.DataFrame(resource_list)

            df_resources = df_resources.sort_values(by=["Type", "Name", "ARN"]).reset_index(drop=True)

            html_table_resources = df_resources[["Type", "Name", "ARN"]].to_html(index=False, justify="center")

            num_resources = len(resource_list)
            last_month = (datetime.now() - timedelta(days=2)).month
            last_month_name = calendar.month_name[last_month]

            send_email(html_table_resources, num_resources, last_month_name, group["email"], group["team_name"])

        return {"statusCode": 200}

    except Exception as e:
        print(f"Error: {e}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
 
def send_email(html_table_resources, num_resources, last_month_name, email, team_name):
    subject = f"{team_name} AWS Resources"
    message = f"Below are the AWS resources used by the {team_name} in {last_month_name}. <br><br> Note: Please inform the IT Operations Team (OPS), if you discover that any of the listed AWS resources are no longer part of your team or are no longer being used. In both cases, please open a ticket with IT Operations. <br><br> Best regards <br><br>"

    html = f"""
        <html>
          <head>
            <style>
              body {{
                font-family: Arial, sans-serif;
                color: black;
                background-color: white;
              }}
              h2 {{
                color: black;
                font-size: 16px;
                text-align: left;
                text-decoration: underline;
                font-weight: bold;
              }}
              h1 {{
                color: black;
                font-size: 14px;
                text-align: left;
                font-weight: normal;
              }}
              p {{
                color: black;
                font-size: 14px;
                text-align: left;
              }}
              p1 {{
                 font-size: 10px;
                 text-align: center;
                  margin-left: auto;
                 margin-right: auto;
              }}
            </style>
          </head>
          <body>
            <p> <h2>Monthly AWS-DEV (Staging) Report</h2> </p>
            <h1>{message}</h1>
            <p1>{html_table_resources}</p1>
          </body>
        </html>
        """

    ses_client = boto3.client("ses", region_name="<REGION_NAME>")
    response = ses_client.send_email(
        Source="<SOURCE_MAIL_ADDRESS>",
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": subject},
            "Body": {"Html": {"Data": html}}
        }
    )
    print(response)

def get_tags_for_resource(arn):
    try:
        resourcegroupstaggingapi_client = boto3.client("resourcegroupstaggingapi", region_name="<REGION_NAME>")
        response = resourcegroupstaggingapi_client.get_resources(ResourceARNList=[arn])
        tags = response["ResourceTagMappingList"][0]["Tags"]
        return tags
    except Exception as e:
        print(f"Error getting tags for resource {arn}: {e}")
        return []
