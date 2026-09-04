aws-security-checker is a lightweight, serverless security scanning engine designed to audit AWS environments for common misconfigurations and security risks.

**Key Architecture Features:**
1. Secure Cross-Account Access: Uses an IAM assume-role pattern with an External ID to safely audit external accounts using AWS's managed SecurityAudit policy.

2. Serverless Scanning Engine: Powered by AWS Lambda and Python (boto3) to evaluate 24 critical security rules across multiple domains (IAM, S3, RDS, Security Groups, CloudTrail/GuardDuty).

3. Infrastructure as Code (IaC): Fully provisioned via Terraform with zero manual console clicks.

4. API & Frontend: Exposed via API Gateway with a simple one-page static frontend hosted on S3.
