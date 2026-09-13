import boto3
from checks import iam_checks
import scoring
import os
import json

# Read the S3 bucket name from Lambda environment variables
REPORT_BUCKET = os.environ["REPORT_BUCKET_NAME"]

# Assume the role created in the customer account.

# accountid, external id, arn of the role created in the customer account, role name, session name to be passed.

account_id = '264347118673'
external_id = 'admin123'
role_name = 'security_scan_role'
session_name = 'test-session'

def get_assumed_session (account_id, role_name, external_id,session_name) :

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts_client = boto3.client("sts")


    credentials = sts_client.assume_role(RoleArn = role_arn, RoleSessionName=session_name,ExternalId=external_id)
    
    customer_session = boto3.Session(
        aws_access_key_id = credentials["Credentials"]["AccessKeyId"],
        aws_secret_access_key= credentials ["Credentials"]["SecretAccessKey"],
        aws_session_token=credentials ["Credentials"]["SessionToken"],
        region_name="us-east-1" # Set target scanning region
    )
    
    return customer_session




# Verification if the assume role worked as expected
""" customer_sts = session_details.client("sts")
get_identity = customer_sts.get_caller_identity()

print('Account ID is ' + get_identity['Account'] + ' and ARN is ' + get_identity['Arn'])
 """

def lambda_handler(event, context):
    try:

        # Get the assumed session for the customer account
        session_details = get_assumed_session(account_id,role_name,external_id,session_name)

        # Perform the checks on each resource

        # Check 1 - Root Access Keys
        root_access_keys_check = iam_checks.check_root_access_keys(session_details)
        print(f"# CHECK 1 : {root_access_keys_check['Status']}, {root_access_keys_check['Severity']}")

        # Check 2 Root Account has no MFA Enabled

        mfa_check = iam_checks.root_mfa_check(session_details)
        print(f"# CHECK 2 : {mfa_check['Status']}, {mfa_check['Severity']}")


        # Check 3 IAM Console Users have no MFA enabled
        iam_user_mfa_check = iam_checks.iam_user_mfa_check(session_details)

        print(f"# CHECK 3 : {iam_user_mfa_check.get('Status', 'Unknown')}, {iam_user_mfa_check.get('Severity', 'Unknown')}")
        if iam_user_mfa_check.get('Status') == 'FAIL':
            print(f"Users without MFA: {iam_user_mfa_check.get('Details', {}).get('UsersWithoutMFA', [])}")

        # Check 4 Policy grants full wildcard to users
        wildcard_policies_check = iam_checks.check_wildcard_polcies(session_details)
        print(f"# Check 4 : Wild Card Policies Check : {wildcard_policies_check.get('Status', 'Unknown')}, {wildcard_policies_check.get('Severity', 'Unknown')}")
        if wildcard_policies_check.get('Status') == 'FAIL':
            print(f"{wildcard_policies_check.get('Message', {})}")

        # Check 5 Access keys not rotated in 90+ days
        access_keys_check = iam_checks.check_access_keys_rotated(session_details)
        print(f"# Check 5 : Access Keys Check : {access_keys_check.get('Status', 'Unknown')}, {access_keys_check.get('Severity', 'Unknown')}")
        if access_keys_check.get('Status') == 'FAIL':
            print(f"Users with old access keys: {access_keys_check.get('Message', {})}")

        # Check 6 Policies applied to individual users instead of groups
        policies_check = iam_checks.check_policies_applied_to_users(session_details)
        print(f"# Check 6 : Individual Policies Check : {policies_check.get('Status', 'Unknown')}, {policies_check.get('Severity', 'Unknown')}")
        if policies_check.get('Status') == 'FAIL':
            print(f"Users with direct policies: {policies_check.get('Message', {})}")


        

        # Invoke Scoring function to calculate the compliance score based on the checks performed.
        audit_results = {
            "RootAccessKeysCheck": root_access_keys_check,
            "RootMFAEnabledCheck": mfa_check,
            "IAMUserMFAEnabledCheck": iam_user_mfa_check,
            "WildcardPoliciesCheck": wildcard_policies_check,
            "AccessKeysRotationCheck": access_keys_check,
            "IndividualPoliciesCheck": policies_check
        }
        print("Audit Results:", audit_results)
        compliance_score = scoring.calculate_compliance_score(audit_results)
        print("Compliance Score Summary:", compliance_score)

        file_key = f"reports/{account_id}-audit-report.json"
        report_payload = {
            "account_id": account_id,
            "score": compliance_score,
            "details": audit_results
        }

        # Store the result in the S3 or a DB for the upstream systems i.e front end systems to access it.
        
        
        s3_client = boto3.client("s3")
        s3_client.put_object(
            Bucket= REPORT_BUCKET,
            Key=file_key,
            Body=json.dumps(report_payload),
            ContentType="application/json"
        )
        return {
                    "statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "message": "Audit completed successfully",
                        "score": compliance_score,
                        "report_location": f"s3://{REPORT_BUCKET}/{file_key}"
                    })
                }
    except Exception as e:
        print(f"Error executing security scan: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }