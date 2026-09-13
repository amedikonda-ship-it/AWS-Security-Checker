from datetime import datetime, timezone
import io
import csv
import boto3
from botocore.exceptions import ClientError
import time

# Check 1 ******** Root Access Keys Check
def check_root_access_keys(session):
    try:
        #establish a connection to the IAM service using the provided session
        iam_client = session.client("iam")
        #get the account summary to check for root access keys
        get_account_summary = iam_client.get_account_summary()
        summary_map = get_account_summary.get('SummaryMap', {})
        keys_present_count = summary_map.get('AccountAccessKeysPresent', 0)

        if keys_present_count == 0:
            status = "PASS"
            description = "Root User has no access keys"
        else:
            status = "FAIL"
            description = (f"Root User has {keys_present_count} active key(s)!")

        return {
        "Status" : status,
        "Message" : description,
        "Severity" : "Critical"
        }

    except ClientError as e:
        return{
            "Status" : "Error",
            "Severity" : "Critical",
            "Message" : f"failed to execute check : {str(e)}",
            "Details" : {}

        }

# Check 2 Root Account has no MFA Enabled

def root_mfa_check(session):

    try:
        #establish a connection to the IAM service using the provided session
        customer_iam = session.client("iam")
        #get the account summary to check for root MFA status
        summary = customer_iam.get_account_summary()
        summary_map = summary.get('SummaryMap', {})
        mfa_enable = summary_map.get('AccountMFAEnabled', 0)
        if mfa_enable == 0:
            status = "FAIL"
            description = "MFA not enabled for the root user"
        else:
            status = "PASS"
            description = "MFA Enabled for the root user"
        return {
            "Status" : status,
            "Message" : description,
            "Severity" : "Critical"
            }
    except ClientError as e:
        return{
                    "Status" : "Error",
                    "Severity" : "Critical",
                    "Message" : f"failed to execute check : {str(e)}",
                    "Details" : {}
        
                }
# Check 3 IAM Console Users have no MFA enabled
def iam_user_mfa_check(session):
    try:
        state = ''
        customer_iam = session.client("iam")
        for i in range(10):
            generate_report = customer_iam.generate_credential_report()
            state = generate_report.get('State')
            if state == 'COMPLETE':
                report = customer_iam.get_credential_report()
                report_csv_content = report['Content'].decode('utf-8')
                reader = csv.DictReader(io.StringIO(report_csv_content))
                users_without_mfa = []
                for row in reader:
                    if row.get('password_enabled') == 'true' and row.get('mfa_active') == 'false' and row.get('user') != '<root_account>':
                        users_without_mfa.append(row.get('user'))
                if users_without_mfa:
                    return {
                        "Status": "FAIL",
                        "Message": f"Users Count without MFA enabled: {len(users_without_mfa)}",
                        "Details": {"users_without_mfa": users_without_mfa},
                        "Severity": "High"
                    }
                else:
                    return {
                        "Status": "PASS",
                        "Message": "All IAM users have MFA enabled.",
                        "Details": {},
                        "Severity": "High"
                    }
            else:
                time.sleep(5)
        if state != 'COMPLETE':
            return{
                "Status" : "FAIL",
                "Message" : "Failed to generate the credential report",
                "Details" : {},
                "Severity": "High"
            }

    except ClientError as e:
        return{
            "Status" : "FAIL",
            "Message" : f"failed to execute check : {str(e)}",
            "Details" : {},
            "Severity": "High"
        }

# Check 4 Policy grants full wildcard to users

def check_wildcard_polcies(session):
    try:
        customer_iam= session.client("iam")
        userlist = customer_iam.list_users()
        userlist = userlist.get('Users', [])
        users_with_wildcard_policies = []
        # print(userlist)
        
        for user in userlist:
            user_policies = customer_iam.list_attached_user_policies(UserName=user['UserName'])
            # print(user_policies)
            for policy in user_policies.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn','')
                policy_details = customer_iam.get_policy(PolicyArn=policy_arn)
                policy_version = policy_details.get('Policy', {}).get('DefaultVersionId')
                policy_document = customer_iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
                for statement in policy_document.get('PolicyVersion',{}).get('Document',{}).get('Statement',[]):
                    if statement.get('Effect') == 'Allow' and statement.get('Action') == '*' and statement.get('Resource') == '*':
                        users_with_wildcard_policies.append(user['UserName'])
                # print(policy_document)
        print(users_with_wildcard_policies)
        if users_with_wildcard_policies:
            return{
                        "Status" : "FAIL",
                        "Message" : f"Following users are enabled with wildcard polices, Please fix them : {users_with_wildcard_policies}",
                        "Details" : {},
                        "Severity": "High"
                    }
        
    except ClientError as e:
        return{
            "Status" : "FAIL",
            "Message" : f"failed to execute check : {str(e)}",
            "Details" : {},
            "Severity": "High"
        }

# Check 5 Access keys not rotated in 90+ days
def check_access_keys_rotated(session):
    try:
        customer_iam = session.client("iam")
        report_state = ""
        max_age_days = 90
        users_with_old_keys = []
        now = datetime.now(timezone.utc)

        for i in range(10):
            print(f"Current State: {report_state}")
            try:
                credential_report = customer_iam.generate_credential_report()
                report_state = credential_report.get("State")

                if report_state == "COMPLETE":
                    report = customer_iam.get_credential_report()
                    content_csv = report.get("Content").decode("utf-8")
                    reader = csv.DictReader(io.StringIO(content_csv))

                    for row in reader:
                        username = row.get("user")
                        has_old_key = False

                        # Check both AWS Access Keys (1 and 2)
                        for key_num in ["1", "2"]:
                            active = row.get(f"access_key_{key_num}_active")
                            rotated_str = row.get(
                                f"access_key_{key_num}_last_rotated"
                            )

                            if (
                                active == "true"
                                and rotated_str
                                and rotated_str not in ["N/A", "not_supported"]
                            ):
                                try:
                                    rotated_dt = datetime.fromisoformat(
                                        rotated_str.replace("Z", "+00:00")
                                    )
                                    age_days = (now - rotated_dt).days

                                    if age_days > max_age_days:
                                        has_old_key = True
                                except ValueError:
                                    continue

                        if (
                            has_old_key
                            and username
                            and username not in users_with_old_keys
                        ):
                            users_with_old_keys.append(username)

                    break

            except ClientError as e:
                if (
                    e.response.get("Error", {}).get("Code")
                    == "ReportInProgress"
                ):
                    print(
                        "Credential report generation in progress. Retrying..."
                    )
                else:
                    print(
                        f"Error occurred while fetching credential report: {e}"
                    )
                    raise e

            time.sleep(5)

        print(users_with_old_keys)

        if users_with_old_keys:
            return {
                "Status": "FAIL",
                "Message": f"Following users have access keys not rotated in 90+ days, Please fix them : {users_with_old_keys}",
                "Details": {},
                "Severity": "High",
            }

        if report_state == "COMPLETE":
            return {
                "Status": "PASS",
                "Message": "Credential report generated successfully",
                "Details": {},
                "Severity": "High",
            }
        else:
            return {
                "Status": "FAIL",
                "Message": "Failed to generate the credential report",
                "Details": {},
                "Severity": "High",
            }

    except ClientError as e:
        return {
            "Status": "FAIL",
            "Message": f"failed to execute check : {str(e)}",
            "Details": {},
            "Severity": "High",
        }
    
# Check 6 Policies applied to individual users instead of groups
def check_policies_applied_to_users(session):
    try:
        customer_iam = session.client("iam")
        users_with_individual_policies = []
        users_with_inline_policies = []
        userlist = customer_iam.list_users()
        userlist = userlist.get('Users', [])
        
        for user in userlist:
            user_policies = customer_iam.list_attached_user_policies(UserName=user['UserName'])
            if user_policies.get('AttachedPolicies'):
                users_with_individual_policies.append(user['UserName'])
            inline_policies = customer_iam.list_user_policies(UserName=user['UserName'])
            if inline_policies.get('PolicyNames'):
                users_with_inline_policies.append(user['UserName']) 
        
        if users_with_individual_policies or users_with_inline_policies:
            return {
                "Status": "FAIL",
                "Message": f"Following users have individual or inline policies attached, Please fix them : {users_with_individual_policies + users_with_inline_policies}",
                "Details": {},
                "Severity": "High"
            }
        else:
            return {
                "Status": "PASS",
                "Message": "No users have individual or inline policies attached.",
                "Details": {},
                "Severity": "High"
            }
    except ClientError as e:
        return {
            "Status": "FAIL",
            "Message": f"failed to execute check : {str(e)}",
            "Details": {},
            "Severity": "High"
        }