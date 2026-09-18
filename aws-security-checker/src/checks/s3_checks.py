
import boto3
from botocore.exceptions import ClientError
import json

# Check 7 S3 Bucket Public read enabled
def s3_public_read_check(session):
    try:
        print("Start public read check")
        s3_client = session.client("s3")
        s3_buckets = s3_client.list_buckets()
        buckets = s3_buckets.get('Buckets',[])
        public_buckets = set()
        if buckets:
            for bucket in buckets:
                bucket_name = bucket.get('Name')
                print(bucket_name)
                try:
                    public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                    block_ignore_acls = public_access_block.get('PublicAccessBlockConfiguration',{}).get('IgnorePublicAcls')
                    block_public_policy = public_access_block.get('PublicAccessBlockConfiguration',{}).get('BlockPublicPolicy')
                    if block_ignore_acls == True and block_public_policy == True:
                        print(f"Bucket : {bucket_name} is Private")
                        continue
                except ClientError as e:
                    if e.response.get('Error',{}).get('Code') == 'NoSuchPublicAccessBlockConfiguration':
                        print(f"Bucket : {bucket_name} has no public access block configuration")
                    else:
                            raise e
                
                try:
                            # Check the bucket policy for public read access
                            bucket_policy_content = s3_client.get_bucket_policy(Bucket=bucket_name)
                            bucket_policy = bucket_policy_content.get('Policy',{})
                            policy_statement = json.loads(bucket_policy).get('Statement',[])
                            for statement in policy_statement:
                                effect = statement.get('Effect')
                                principal = statement.get('Principal')
                                action = statement.get('Action')
                                public_principal = False
                                if effect == 'Allow':
                                    principal = statement.get('Principal')
                                    if principal == '*':
                                        public_principal = True
                                    if isinstance(principal,dict):
                                        aws_principal = principal.get('AWS')
                                        if aws_principal == '*':
                                            public_principal = True
                                    if public_principal == True:
                                        action = statement.get('Action')
                                        if isinstance(action,str):
                                            action = [action]
                                        public_actions = ['s3:GetObject','s3:*','*']
                                        if any(act in public_actions for act in action):
                                            print(f"Bucket : {bucket_name} is Public")
                                            public_buckets.add(bucket_name)
                except ClientError as e:
                            if e.response.get('Error',{}).get('Code') == 'NoSuchBucketPolicy':
                                print(f"Bucket : {bucket_name} has no bucket policy")
                            else:
                                raise e
                
                # Check the bucket ACL for public read access
                bucket_acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in bucket_acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission')
                    if grantee.get('Type') == 'Group' and grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission in ['READ','FULL_CONTROL']:
                        print(f"Bucket : {bucket_name} is Public")
                        public_buckets.add(bucket_name)
            if public_buckets:
                print(f"Public Read Access is Enabled for following buckets : {public_buckets}")   
        else: 
            print(f"no buckets")
        return {
            "Status" : "FAIL",
            "Severity" : "Critical",
            "Message" : f"Public Read Access is Enabled for following buckets : {public_buckets}",
            "Details" : {
                "PublicBuckets" : public_buckets
            }
        }
    except ClientError as e:
        print(f"{str(e)}")
        return{
                            "Status" : "Error",
                            "Severity" : "Critical",
                            "Message" : f"failed to execute check : {str(e)}",
                            "Details" : {}
                
                        }
# Check 8 S3 Bucket Public write enabled
def s3_public_write_check(session):
    try:
        print("Start public write check")
        s3_client = session.client("s3")
        s3_buckets = s3_client.list_buckets()
        buckets = s3_buckets.get('Buckets',[])
        public_buckets = []
        if buckets:
            for bucket in buckets:
                bucket_name = bucket.get('Name')
                is_public = False
                try:
                    public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                    block_ignore_acls = public_access_block.get('PublicAccessBlockConfiguration',{}).get('IgnorePublicAcls')
                    block_public_policy = public_access_block.get('PublicAccessBlockConfiguration',{}).get('BlockPublicPolicy')
                    if block_ignore_acls == True and block_public_policy == True:
                        print(f"Bucket : {bucket_name} is Private")
                        continue
                except ClientError as e:
                    if e.response.get('Error',{}).get('Code') == 'NoSuchPublicAccessBlockConfiguration':
                        print(f"Bucket : {bucket_name} has no public access block configuration")
                    else:
                            raise e
                
                try:
                            # Check the bucket policy for public write access
                            bucket_policy_content = s3_client.get_bucket_policy(Bucket=bucket_name)
                            bucket_policy = bucket_policy_content.get('Policy',{})
                            policy_statement = json.loads(bucket_policy).get('Statement',[])
                            for statement in policy_statement:
                                effect = statement.get('Effect')
                                principal = statement.get('Principal')
                                action = statement.get('Action')
                                public_principal = False
                                if effect == 'Allow':
                                    principal = statement.get('Principal')
                                    if principal == '*':
                                        public_principal = True
                                    if isinstance(principal,dict):
                                        aws_principal = principal.get('AWS')
                                        if aws_principal == '*':
                                            public_principal = True
                                    if public_principal == True:
                                        action = statement.get('Action')
                                        if isinstance(action,str):
                                            action = [action]
                                        public_actions = ['s3:PutObject','s3:*','*']
                                        if any(act in public_actions for act in action):
                                            print(f"Bucket : {bucket_name} is Public Write Enabled")
                                            is_public = True
                except ClientError as e:
                            if e.response.get('Error',{}).get('Code') == 'NoSuchBucketPolicy':
                                print(f"Bucket : {bucket_name} has no bucket policy")
                            else:
                                raise e
                
                # Check the bucket ACL for public write access
                bucket_acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in bucket_acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission')
                    if grantee.get('Type') == 'Group' and grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission in ['WRITE', 'FULL_CONTROL']:
                        print(f"Bucket : {bucket_name} is Public")
                        is_public = True
                if is_public == True:
                    public_buckets.append(bucket_name)
                    return {
                        "Status" : "FAIL",
                        "Severity" : "Critical",
                        "Message" : f"Public Write Access is Enabled for following buckets : {public_buckets}",
                        "Details" : {
                            "PublicBuckets" : public_buckets
                            }
                    }
                else:
                    return {
                            "Status" : "Success",
                            "Severity" : "Info",
                            "Message" : f"Public Write Access is not enabled for any buckets",
                            "Details" : {
                                "PublicBuckets" : public_buckets
                                }
                    }
        else: 
            return {
                                    "Status" : "Success",
                                    "Severity" : "Info",
                                    "Message" : f"No Buckets Available",
                                    "Details" : {
                                        "PublicBuckets" : public_buckets
                                        }
            }
    except ClientError as e:
        print(f"{str(e)}")
        return{
                            "Status" : "Error",
                            "Severity" : "Critical",
                            "Message" : f"failed to execute check : {str(e)}",
                            "Details" : {}
                        }
# Check 9 S3 Block Public Access Disabled at the account and bucket level
def s3_public_block_access_check(session):
    # Account level Check
    try:
        s3_control_account = session.client("s3control")
        s3_account = session.client('sts')
        accountId = s3_account.get_caller_identity()["Account"]
        account_public_block = s3_control_account.get_public_access_block(AccountId = accountId)
        account_block_public_acls = account_public_block.get('BlockPublicAcls')
        account_ignore_ignore_acls = account_public_block.get('IgnorePublicAcls')
        account_block_public_policy = account_public_block.get('BlockPublicPolicy')
        account_restrict_public_buckets = account_public_block.get('RestrictPublicBuckets')
        if account_block_public_acls == False or account_block_public_policy == False or account_ignore_ignore_acls == False or account_restrict_public_buckets == False:
             return{
                    "Status" : "FAIL",
                    "Severity" : "Critical",
                    "Message" : f"account-level BPA is not fully enabled for Account : {accountId}",
                    "Details" : {}
                                                   }
    except ClientError as e:
         if e.response.get('Error',{}).get('Code') == 'NoSuchPublicAccessBlockConfiguration': 
            return{
                "Status" : "FAIL",
                "Severity" : "Critical",
                "Message" : f"No Public Block Access Enabled at the Account Level for Account : {accountId}",
                "Details" : {}
            }
    try:
        s3_client = session.client("s3")
        s3_buckets = s3_client.list_buckets()
        buckets = s3_buckets.get('Buckets',[])
        block_public_buckets = []
        if buckets:
            for bucket in buckets:
                bucket_name = bucket.get('Name')
                try:
                    public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                    block_ignore_acls = public_access_block.get('PublicAccessBlockConfiguration',{}).get('IgnorePublicAcls')
                    block_public_policy = public_access_block.get('PublicAccessBlockConfiguration',{}).get('BlockPublicPolicy')
                    block_public_acls = public_access_block.get('PublicAccessBlockConfiguration',{}).get('BlockPublicAcls')
                    restrict_public_buckets = public_access_block.get('PublicAccessBlockConfiguration',{}).get('RestrictPublicBuckets')
                    if block_ignore_acls == False or block_public_policy == False or block_public_acls == False or restrict_public_buckets == False:
                        print(f"Public Block Access Not enabled for {bucket_name}")
                        block_public_buckets.append(bucket_name)
                except ClientError as e:
                    if e.response.get('Error',{}).get('Code') == 'NoSuchPublicAccessBlockConfiguration':
                        block_public_buckets.append(bucket_name)
                        print(f"Bucket : {bucket_name} has no public access block configuration")
                    else:
                            raise e
            if block_public_buckets:
                return {
                    "Status" : "FAIL",
                    "Severity" : "Critical",
                    "Message" : f"Public Block Access is not enabled for following buckets : {block_public_buckets}",
                    "Details" : {
                        "PublicBuckets" : block_public_buckets
                        }
                }
            else:
                return {
                        "Status" : "Success",
                        "Severity" : "Critical",
                        "Message" : f"Public Block Access is enabled for all the buckets",
                        "Details" : {}
                }
        else: 
            return {
                                    "Status" : "Success",
                                    "Severity" : "Info",
                                    "Message" : f"No Buckets Available",
                                    "Details" : {}
            }    
    except ClientError as e:
        print(f"{str(e)}")
        return{
                            "Status" : "Error",
                            "Severity" : "Critical",
                            "Message" : f"failed to execute check : {str(e)}",
                            "Details" : {}
                        }
#Check 10 S3 bucket has no default encryption

def s3_sse_encryption_check(session):
    s3_client = session.client("s3")
    s3_buckets = s3_client.list_buckets()
    buckets = s3_buckets.get('Buckets',[])
    bucket_with_no_encryption = []
    buckets_with_sse = []
    for bucket in buckets:
        bucket_name = bucket.get('Name')
        print(bucket_name)
        try:
            bucket_encryption = s3_client.get_bucket_encryption(Bucket = bucket_name)
            if bucket_encryption:
                print(f"{bucket_name} is enabled with encryption")
                rules = bucket_encryption.get('ServerSideEncryptionConfiguration',{}).get('Rules')
                print(rules)
                for rule in rules:
                    Algorithm = rule.get('ApplyServerSideEncryptionByDefault',{}).get('SSEAlgorithm')
                    print(Algorithm)
                    if Algorithm == 'AES256':
                        buckets_with_sse.append(bucket_name)
        
        except ClientError as e:
            if e.response.get('Error',{}).get('code') == 'ServerSideEncryptionConfigurationNotFoundError':
                bucket_with_no_encryption.append(bucket_name)
                return{
                            "Status" : "Error",
                            "Severity" : "Critical",
                            "Message" : f"No Default Encryption Enabled for the following buckets : {bucket_with_no_encryption}",
                            "Details" : {}
                 }
    if not bucket_with_no_encryption:
        if buckets_with_sse:
            return{
                 "Status" : "FAIL",
                 "Severity" : "High",
                 "Message" : f"Following buckets are enabled with SSE-S3 encryption {buckets_with_sse}, Recommended to use SSE-KMS",
                 "Details" : {}
            }
        else: return{
            "Status" : "Success",
            "Severity" : "Info",
            "Message" : f"All Buckets Enabled with expected encryption",
            "Details" : {}
         }

#Check 11 S3 Bucket Enabled with versioning

def s3_version_check(session):
    s3_client = session.client("s3")
    s3_buckets = s3_client.list_buckets()
    buckets = s3_buckets.get('Buckets',[])
    buckets_with_no_versioning = []
    for bucket in buckets:
        bucket_name = bucket.get('Name')
        print(bucket_name)
        try:
            bucket_version_response = s3_client.get_bucket_versioning(Bucket = bucket_name)
            status = bucket_version_response.get('Status')
            if not status or status != 'Enabled':
                buckets_with_no_versioning.append(bucket_name)
                print(f"{bucket_name} is not enabled with versioning")    
        
        except ClientError as e:
                return{
                            "Status" : "Error",
                            "Severity" : "Critical",
                            "Message" : f"Failed to get Status",
                            "Details" : {}
                 }
    if buckets_with_no_versioning:
            return {
            "Status" : "FAIL",
            "Severity" : "MEDIUM",
            "Message" : f"Following Buckets are not enabled with versioning : {buckets_with_no_versioning}",
            "Details" : {}
         }
    else:
         return {
                     "Status" : "Success",
                     "Severity" : "Info",
                     "Message" : f"All Buckets Enabled with versioning",
                     "Details" : {}
                  }

# Check 12 Check if EBS volumes are unencrypted

def check_ebs_unencrypted(session):
     ec2_client = session.client("ec2")
     ebs_without_encryption = []
     ebs_encryption_details = ec2_client.get_ebs_encryption_by_default()
     if ebs_encryption_details.get('EbsEncryptionByDefault') == True:
        ebs_volumes = ec2_client.describe_volumes()
        ebs_volumes = ebs_volumes.get('Volumes',[])
        for volume in ebs_volumes:
            encrypted = volume.get('Encrypted')
            if encrypted == False:
                 ebs_without_encryption.append(volume.get('VolumeId'))
     if ebs_encryption_details.get('EbsEncryptionByDefault') == False:
          return {
                     "Status" : "FAIL",
                     "Severity" : "LOW",
                     "Message" : f"EC2 Encryption is not enabled at the account level",
                     "Details" : {}
                  }
     if ebs_without_encryption:
          return{
                     "Status" : "FAIL",
                     "Severity" : "LOW",
                     "Message" : f"Following EC2 volumes are not encrypted {ebs_without_encryption}",
                     "Details" : {}
                }
     else: return{
                     "Status" : "SUCCESS",
                     "Severity" : "INFO",
                     "Message" : f"All EC2 volumes are encrypted",
                     "Details" : {}
                }