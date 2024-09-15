![image](https://github.com/user-attachments/assets/743ec6ca-8da6-4957-a34d-e99e6d8accad)


# STS
## 1. Assume a Role
aws sts assume-role --role-arn <arn:aws:iam::account-id:role/role-name> --role-session-name <session-name>

## 2. Get Caller Identity (Shows the current IAM role or user)
aws sts get-caller-identity

## 3. Assume a Role with MFA
aws sts assume-role --role-arn <arn:aws:iam::account-id:role/role-name> --role-session-name <session-name> --serial-number <arn-of-mfa-device> --token-code <mfa-token>

## 4. Decode Authorization Message (Decode an encoded message returned by STS)
aws sts decode-authorization-message --encoded-message <encoded-message>

## 5. Get Session Token
aws sts get-session-token --duration-seconds <seconds> --serial-number <mfa-arn> --token-code <mfa-token>

## 6. Assume Role with Web Identity
aws sts assume-role-with-web-identity --role-arn <arn:aws:iam::account-id:role/role-name> --role-session-name <session-name> --web-identity-token <token>

## 7. Assume Role with SAML
aws sts assume-role-with-saml --role-arn <arn:aws:iam::account-id:role/role-name> --principal-arn <arn-of-saml-provider> --saml-assertion <base64-saml-assertion>

## 8. Get Federation Token
aws sts get-federation-token --name <federation-name> --policy <json-policy> --duration-seconds <seconds>

## 9. Get Access Key Last Used
aws iam get-access-key-last-used --access-key-id <access-key-id>

## 10. List Access Keys
aws iam list-access-keys --user-name <username>

## 11. Create Access Key for a User
aws iam create-access-key --user-name <username>

## 12. Delete Access Key for a User
aws iam delete-access-key --user-name <username> --access-key-id <access-key-id>

## 13. Update Access Key Status (Enable/Disable)
aws iam update-access-key --user-name <username> --access-key-id <access-key-id> --status <Active|Inactive>

## 14. Create Service-Linked Role
aws iam create-service-linked-role --aws-service-name <service-name>

## 15. Simulate Principal Policy (Check Permissions)
aws iam simulate-principal-policy --policy-source-arn <arn-of-user-or-role> --action-names <action> --resource-arns <resource-arn>



# IAM
## 1. Create a New IAM User
```
aws iam create-user --user-name <username>
```
## 2. Delete an IAM User
```
aws iam delete-user --user-name <username>
```
## 3. List All IAM Users
```
aws iam list-users
```
## 4. Add a User to a Group
```
aws iam add-user-to-group --user-name <username> --group-name <groupname>
```
## 5. Remove a User from a Group
```
aws iam remove-user-from-group --user-name <username> --group-name <groupname>
```
## 6. Create a New IAM Group
```
aws iam create-group --group-name <groupname>
```
## 7. Delete an IAM Group
```
aws iam delete-group --group-name <groupname>
```
## 8. List IAM Groups
```
aws iam list-groups
```
## 9. Attach a Policy to a User
```
aws iam attach-user-policy --user-name <username> --policy-arn <arn:aws:iam::policyname>
```
## 10. Detach a Policy from a User
```
aws iam detach-user-policy --user-name <username> --policy-arn <arn:aws:iam::policyname>
```
## 11. Create an IAM Role
```
aws iam create-role --role-name <rolename> --assume-role-policy-document file://trust-policy.json
```
## 12. Attach a Policy to a Role
```
aws iam attach-role-policy --role-name <rolename> --policy-arn <arn:aws:iam::policyname>
```
## 13. List Attached Policies for a Role
```
aws iam list-attached-role-policies --role-name <rolename>
```
## 14. Delete an IAM Role
```
aws iam delete-role --role-name <rolename>
```
## 15. Create an Access Key for a User
```
aws iam create-access-key --user-name <username>
```
## 16. Delete an Access Key
```
aws iam delete-access-key --user-name <username> --access-key-id <access_key_id>
```
## 17. List All Access Keys for a User
```
aws iam list-access-keys --user-name <username>
```
## 18. Update an IAM User
```
aws iam update-user --user-name <current-username> --new-user-name <new-username>
```
## 19. List IAM Policies
```
aws iam list-policies
```
## 20. Get Account Summary
```
aws iam get-account-summary
```
## 21. Create a Policy
```
aws iam create-policy --policy-name <policyname> --policy-document file://policy.json
```
## 22. Delete a Policy
```
aws iam delete-policy --policy-arn <arn:aws:iam::policyname>
```
## 23. Create a Policy Version
aws iam create-policy-version --policy-arn <arn:aws:iam::policyname> --policy-document file://new_policy.json --set-as-default

## 24. List All Versions of a Policy
aws iam list-policy-versions --policy-arn <arn:aws:iam::policyname>

## 25. Delete a Policy Version
aws iam delete-policy-version --policy-arn <arn:aws:iam::policyname> --version-id <version_id>

## 26. Create an Inline Policy for a User
aws iam put-user-policy --user-name <username> --policy-name <policyname> --policy-document file://policy.json

## 27. List Inline Policies for a User
aws iam list-user-policies --user-name <username>

## 28. Delete an Inline Policy from a User
aws iam delete-user-policy --user-name <username> --policy-name <policyname>

## 29. Create an Inline Policy for a Group
aws iam put-group-policy --group-name <groupname> --policy-name <policyname> --policy-document file://policy.json

## 30. List Inline Policies for a Group
aws iam list-group-policies --group-name <groupname>

## 31. Delete an Inline Policy from a Group
aws iam delete-group-policy --group-name <groupname> --policy-name <policyname>

## 32. Create an Inline Policy for a Role
aws iam put-role-policy --role-name <rolename> --policy-name <policyname> --policy-document file://policy.json

## 33. List Inline Policies for a Role
aws iam list-role-policies --role-name <rolename>

## 34. Delete an Inline Policy from a Role
aws iam delete-role-policy --role-name <rolename> --policy-name <policyname>

## 35. Enable MFA for a User
aws iam enable-mfa-device --user-name <username> --serial-number <mfa_device_arn> --authentication-code-1 <code1> --authentication-code-2 <code2>

## 36. Deactivate MFA for a User
aws iam deactivate-mfa-device --user-name <username> --serial-number <mfa_device_arn>

## 37. Get User Information
aws iam get-user --user-name <username>

## 38. Get Group Information
aws iam get-group --group-name <groupname>

## 39. Get Role Information
aws iam get-role --role-name <rolename>

## 40. Get Policy Information
aws iam get-policy --policy-arn <arn:aws:iam::policyname>

## 41. Get Policy Version Information
aws iam get-policy-version --policy-arn <arn:aws:iam::policyname> --version-id <version_id>

## 42. Create a Signing Certificate for a User
aws iam upload-signing-certificate --user-name <username> --certificate-body file://public_key.pem

## 43. List Signing Certificates for a User
aws iam list-signing-certificates --user-name <username>

## 44. Delete a Signing Certificate
aws iam delete-signing-certificate --user-name <username> --certificate-id <cert_id>

## 45. List Account Alias
aws iam list-account-aliases

## 46. Create an Account Alias
aws iam create-account-alias --account-alias <alias>

## 47. Delete an Account Alias
aws iam delete-account-alias --account-alias <alias>


# Cloudformation
## 1. Create a Stack
aws cloudformation create-stack --stack-name <stack-name> --template-body <file://template-file.json> --parameters ParameterKey=<key>,ParameterValue=<value>

## 2. Delete a Stack
aws cloudformation delete-stack --stack-name <stack-name>

## 3. Update a Stack
aws cloudformation update-stack --stack-name <stack-name> --template-body <file://template-file.json> --parameters ParameterKey=<key>,ParameterValue=<value>

## 4. Describe a Stack
aws cloudformation describe-stacks --stack-name <stack-name>

## 5. List Stacks
aws cloudformation list-stacks

## 6. Describe Stack Events
aws cloudformation describe-stack-events --stack-name <stack-name>

## 7. Describe Stack Resources
aws cloudformation describe-stack-resources --stack-name <stack-name>

## 8. Describe a Specific Stack Resource
aws cloudformation describe-stack-resource --stack-name <stack-name> --logical-resource-id <resource-id>

## 9. Validate a Template
aws cloudformation validate-template --template-body <file://template-file.json>

## 10. Estimate Stack Cost
aws cloudformation estimate-template-cost --template-body <file://template-file.json>

## 11. List Stack Resources
aws cloudformation list-stack-resources --stack-name <stack-name>

## 12. Cancel Stack Update
aws cloudformation cancel-update-stack --stack-name <stack-name>

## 13. Get Stack Policy
aws cloudformation get-stack-policy --stack-name <stack-name>

## 14. Set Stack Policy
aws cloudformation set-stack-policy --stack-name <stack-name> --stack-policy-body <file://policy.json>

## 15. List Stack Sets
aws cloudformation list-stack-sets

## 16. Describe Stack Set
aws cloudformation describe-stack-set --stack-set-name <stack-set-name>

## 17. Create Stack Set
aws cloudformation create-stack-set --stack-set-name <stack-set-name> --template-body <file://template-file.json>

## 18. Delete Stack Set
aws cloudformation delete-stack-set --stack-set-name <stack-set-name>

## 19. Update Stack Set
aws cloudformation update-stack-set --stack-set-name <stack-set-name> --template-body <file://template-file.json>

## 20. List Change Sets
aws cloudformation list-change-sets --stack-name <stack-name>

## 21. Create a Change Set
aws cloudformation create-change-set --stack-name <stack-name> --change-set-name <change-set-name> --template-body <file://template-file.json>

## 22. Delete a Change Set
aws cloudformation delete-change-set --change-set-name <change-set-name> --stack-name <stack-name>

## 23. Describe a Change Set
aws cloudformation describe-change-set --change-set-name <change-set-name> --stack-name <stack-name>

## 24. Execute a Change Set
aws cloudformation execute-change-set --change-set-name <change-set-name> --stack-name <stack-name>

## 25. List Exports
aws cloudformation list-exports

## 26. List Imports
aws cloudformation list-imports --export-name <export-name>

## 27. Detect Stack Drift
aws cloudformation detect-stack-drift --stack-name <stack-name>

## 28. Describe Stack Drift Detection Status
aws cloudformation describe-stack-drift-detection-status --stack-drift-detection-id <drift-detection-id>

## 29. Describe Stack Resource Drift
aws cloudformation describe-stack-resource-drifts --stack-name <stack-name>

## 30. List Stack Instances
aws cloudformation list-stack-instances --stack-set-name <stack-set-name>

## 31. Describe Stack Instance
aws cloudformation describe-stack-instance --stack-set-name <stack-set-name> --stack-instance-account <account-id> --stack-instance-region <region>

# S3
## 1. List Buckets
aws s3 ls

## 2. Create a Bucket
aws s3 mb s3://<bucket-name>

## 3. Delete a Bucket
aws s3 rb s3://<bucket-name>

## 4. List Objects in a Bucket
aws s3 ls s3://<bucket-name>

## 5. Upload a File to a Bucket
aws s3 cp <file-path> s3://<bucket-name>/<key>

## 6. Download a File from a Bucket
aws s3 cp s3://<bucket-name>/<key> <local-file-path>

## 7. Delete an Object from a Bucket
aws s3 rm s3://<bucket-name>/<key>

## 8. Sync Local Directory to a Bucket
aws s3 sync <local-directory-path> s3://<bucket-name>

## 9. Sync Bucket to Local Directory
aws s3 sync s3://<bucket-name> <local-directory-path>

## 10. Enable Versioning on a Bucket
aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled

## 11. Suspend Versioning on a Bucket
aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Suspended

## 12. List Object Versions in a Bucket
aws s3api list-object-versions --bucket <bucket-name>

## 13. Enable Server-Side Encryption on a Bucket
aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

## 14. Get Bucket Encryption Status
aws s3api get-bucket-encryption --bucket <bucket-name>

## 15. Remove Bucket Encryption
aws s3api delete-bucket-encryption --bucket <bucket-name>

## 16. Set Bucket Policy
aws s3api put-bucket-policy --bucket <bucket-name> --policy <file://policy.json>

## 17. Get Bucket Policy
aws s3api get-bucket-policy --bucket <bucket-name>

## 18. Delete Bucket Policy
aws s3api delete-bucket-policy --bucket <bucket-name>

## 19. Set CORS Configuration on a Bucket
aws s3api put-bucket-cors --bucket <bucket-name> --cors-configuration <file://cors.json>

## 20. Get CORS Configuration of a Bucket
aws s3api get-bucket-cors --bucket <bucket-name>

## 21. Delete CORS Configuration of a Bucket
aws s3api delete-bucket-cors --bucket <bucket-name>

## 22. Enable Logging on a Bucket
aws s3api put-bucket-logging --bucket <bucket-name> --bucket-logging-status file://logging.json

## 23. Get Logging Status of a Bucket
aws s3api get-bucket-logging --bucket <bucket-name>

## 24. Enable Lifecycle Configuration on a Bucket
aws s3api put-bucket-lifecycle-configuration --bucket <bucket-name> --lifecycle-configuration <file://lifecycle.json>

## 25. Get Lifecycle Configuration of a Bucket
aws s3api get-bucket-lifecycle-configuration --bucket <bucket-name>

## 26. Delete Lifecycle Configuration of a Bucket
aws s3api delete-bucket-lifecycle --bucket <bucket-name>

## 27. Enable Public Access Block on a Bucket
aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

## 28. Get Public Access Block Status of a Bucket
aws s3api get-public-access-block --bucket <bucket-name>

## 29. Delete Public Access Block Configuration of a Bucket
aws s3api delete-public-access-block --bucket <bucket-name>

## 30. Copy an Object Between Buckets
aws s3 cp s3://<source-bucket>/<source-key> s3://<destination-bucket>/<destination-key>

# EC2
## 1. Describe EC2 Instances
aws ec2 describe-instances

## 2. Start an EC2 Instance
aws ec2 start-instances --instance-ids <instance-id>

## 3. Stop an EC2 Instance
aws ec2 stop-instances --instance-ids <instance-id>

## 4. Reboot an EC2 Instance
aws ec2 reboot-instances --instance-ids <instance-id>

## 5. Terminate an EC2 Instance
aws ec2 terminate-instances --instance-ids <instance-id>

## 6. Describe EC2 Instance Status
aws ec2 describe-instance-status --instance-ids <instance-id>

## 7. Create a New EC2 Key Pair
aws ec2 create-key-pair --key-name <key-name>

## 8. Delete an EC2 Key Pair
aws ec2 delete-key-pair --key-name <key-name>

## 9. Create a Security Group
aws ec2 create-security-group --group-name <group-name> --description <description> --vpc-id <vpc-id>

## 10. Describe Security Groups
aws ec2 describe-security-groups

## 11. Authorize Inbound Traffic for a Security Group
aws ec2 authorize-security-group-ingress --group-id <security-group-id> --protocol <tcp|udp> --port <port> --cidr <cidr-block>

## 12. Revoke Inbound Traffic for a Security Group
aws ec2 revoke-security-group-ingress --group-id <security-group-id> --protocol <tcp|udp> --port <port> --cidr <cidr-block>

## 13. Create an EC2 Instance
aws ec2 run-instances --image-id <ami-id> --count <number-of-instances> --instance-type <instance-type> --key-name <key-name> --security-group-ids <security-group-id>

## 14. Describe EC2 AMIs
aws ec2 describe-images --owners <self|amazon|aws-marketplace>

## 15. Deregister an AMI
aws ec2 deregister-image --image-id <ami-id>

## 16. Create an EBS Volume
aws ec2 create-volume --availability-zone <az> --size <size-in-gb>

## 17. Describe EBS Volumes
aws ec2 describe-volumes

## 18. Attach an EBS Volume to an EC2 Instance
aws ec2 attach-volume --volume-id <volume-id> --instance-id <instance-id> --device <device-name>

## 19. Detach an EBS Volume from an EC2 Instance
aws ec2 detach-volume --volume-id <volume-id>

## 20. Delete an EBS Volume
aws ec2 delete-volume --volume-id <volume-id>

## 21. Create a Snapshot of an EBS Volume
aws ec2 create-snapshot --volume-id <volume-id> --description <description>

## 22. Describe EBS Snapshots
aws ec2 describe-snapshots --owner-ids <self|aws-account-id>

## 23. Delete an EBS Snapshot
aws ec2 delete-snapshot --snapshot-id <snapshot-id>

## 24. Create an AMI from an EC2 Instance
aws ec2 create-image --instance-id <instance-id> --name <ami-name>

## 25. Create a New Elastic IP Address
aws ec2 allocate-address

## 26. Associate an Elastic IP with an EC2 Instance
aws ec2 associate-address --instance-id <instance-id> --allocation-id <allocation-id>

## 27. Disassociate an Elastic IP from an EC2 Instance
aws ec2 disassociate-address --association-id <association-id>

## 28. Release an Elastic IP Address
aws ec2 release-address --allocation-id <allocation-id>

## 29. Create a VPC
aws ec2 create-vpc --cidr-block <cidr-block>

## 30. Describe VPCs
aws ec2 describe-vpcs

## 31. Delete a VPC
aws ec2 delete-vpc --vpc-id <vpc-id>

## 32. Create a Subnet in a VPC
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block <cidr-block>

## 33. Describe Subnets
aws ec2 describe-subnets

## 34. Delete a Subnet
aws ec2 delete-subnet --subnet-id <subnet-id>

## 35. Create an Internet Gateway
aws ec2 create-internet-gateway

## 36. Attach an Internet Gateway to a VPC
aws ec2 attach-internet-gateway --vpc-id <vpc-id> --internet-gateway-id <igw-id>

## 37. Describe Internet Gateways
aws ec2 describe-internet-gateways

## 38. Delete an Internet Gateway
aws ec2 delete-internet-gateway --internet-gateway-id <igw-id>

## 39. Create a Route Table for a VPC
aws ec2 create-route-table --vpc-id <vpc-id>

## 40. Describe Route Tables
aws ec2 describe-route-tables

## 41. Create a Route in a Route Table
aws ec2 create-route --route-table-id <route-table-id> --destination-cidr-block <cidr-block> --gateway-id <igw-id>

## 42. Associate a Route Table with a Subnet
aws ec2 associate-route-table --route-table-id <route-table-id> --subnet-id <subnet-id>

## 43. Disassociate a Route Table from a Subnet
aws ec2 disassociate-route-table --association-id <association-id>

## 44. Delete a Route Table
aws ec2 delete-route-table --route-table-id <route-table-id>

## 45. Delete a Route in a Route Table
aws ec2 delete-route --route-table-id <route-table-id> --destination-cidr-block <cidr-block>

