import boto3
from checks import iam_checks, s3_checks
import scoring
import os
import json

# Read the S3 bucket name from Lambda environment variables


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

    
        # check 7 - S3 bucket allows public read (ACL or bucket policy)
        """ s3_bucket_public_read_check = s3_checks.s3_public_read_check(session_details)
        print(f"# CHECK 7 : {s3_bucket_public_read_check['Status']}, {s3_bucket_public_read_check['Severity']}, {s3_bucket_public_read_check['Message']}")
 """
        """ bucket_public_write_check= s3_checks.s3_public_write_check(session_details)
        print(f"# CHECK 8 : {bucket_public_write_check['Status']}, {bucket_public_write_check['Severity']}, {bucket_public_write_check['Message']}")
         """
        """ public_block_access_check= s3_checks.s3_public_block_access_check(session_details)
        print(f"# CHECK 9 : {public_block_access_check['Status']}, {public_block_access_check['Severity']}, {public_block_access_check['Message']}")
 """
        """ s3_sse_encryption_check= s3_checks.s3_sse_encryption_check(session_details)
        print(f"# CHECK 10 : {s3_sse_encryption_check['Status']}, {s3_sse_encryption_check['Severity']}, {s3_sse_encryption_check['Message']}") """

        """ s3_version_check= s3_checks.s3_version_check(session_details)
        print(f"# CHECK 11 : {s3_version_check['Status']}, {s3_version_check['Severity']}, {s3_version_check['Message']}")
           """   
        check_ebs_unencrypted= s3_checks.check_ebs_unencrypted(session_details)
        print(f"# CHECK 12 : {check_ebs_unencrypted['Status']}, {check_ebs_unencrypted['Severity']}, {check_ebs_unencrypted['Message']}")

                   
        
    except Exception as e:
        print(f"Error executing security scan: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }

handler = lambda_handler({}, None)