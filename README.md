# <span style="color:red">STS</span>
#### Assume a Role
```
aws sts assume-role --role-arn <arn:aws:iam::account-id:role/role-name> --role-session-name <session-name>
```

#### Get Caller Identity (Shows the current IAM role or user)
```
aws sts get-caller-identity
```

#### Assume a Role with MFA
```
aws sts assume-role --role-arn <arn:aws:iam::account-id:role/role-name> --role-session-name <session-name> --serial-number <arn-of-mfa-device> --token-code <mfa-token>
```

#### Decode Authorization Message (Decode an encoded message returned by STS)
```
aws sts decode-authorization-message --encoded-message <encoded-message>
```

#### Get Session Token
```
aws sts get-session-token --duration-seconds <seconds> --serial-number <mfa-arn> --token-code <mfa-token>
```

#### Assume Role with Web Identity
```
aws sts assume-role-with-web-identity --role-arn <arn:aws:iam::account-id:role/role-name> --role-session-name <session-name> --web-identity-token <token>
```

#### Assume Role with SAML
```
aws sts assume-role-with-saml --role-arn <arn:aws:iam::account-id:role/role-name> --principal-arn <arn-of-saml-provider> --saml-assertion <base64-saml-assertion>
```

#### Get Federation Token
```
aws sts get-federation-token --name <federation-name> --policy <json-policy> --duration-seconds <seconds>
```

#### Get Access Key Last Used
```
aws iam get-access-key-last-used --access-key-id <access-key-id>
```

#### List Access Keys
```
aws iam list-access-keys --user-name <username>
```

#### Create Access Key for a User
```
aws iam create-access-key --user-name <username>
```

#### Delete Access Key for a User
```
aws iam delete-access-key --user-name <username> --access-key-id <access-key-id>
```

#### Update Access Key Status (Enable/Disable)
```
aws iam update-access-key --user-name <username> --access-key-id <access-key-id> --status <Active|Inactive>
```

#### Create Service-Linked Role
```
aws iam create-service-linked-role --aws-service-name <service-name>
```

#### Simulate Principal Policy (Check Permissions)
```
aws iam simulate-principal-policy --policy-source-arn <arn-of-user-or-role> --action-names <action> --resource-arns <resource-arn>
```

# <span style="color:red">IdP</span>
#### Create a New SAML Identity Provider
```
aws iam create-saml-provider --saml-metadata-document <file://saml-metadata.xml> --name <provider-name>
```

#### List SAML Identity Providers
```
aws iam list-saml-providers
```

#### Get SAML Identity Provider Information
```
aws iam get-saml-provider --saml-provider-arn <saml-provider-arn>
```

#### Update SAML Identity Provider
```
aws iam update-saml-provider --saml-metadata-document <file://saml-metadata.xml> --saml-provider-arn <saml-provider-arn>
```

#### Delete SAML Identity Provider
```
aws iam delete-saml-provider --saml-provider-arn <saml-provider-arn>
```

#### Create an OIDC Identity Provider
```
aws iam create-open-id-connect-provider --url <oidc-provider-url> --client-id-list <client-id-1> <client-id-2> --thumbprint-list <thumbprint>
```

#### List OIDC Identity Providers
```
aws iam list-open-id-connect-providers
```

#### Get OIDC Identity Provider Information
```
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <oidc-provider-arn>
```

#### Delete OIDC Identity Provider
```
aws iam delete-open-id-connect-provider --open-id-connect-provider-arn <oidc-provider-arn>
```


# <span style="color:red">IAM</span>
#### Create a New IAM User
```
aws iam create-user --user-name <username>
```
#### Delete an IAM User
```
aws iam delete-user --user-name <username>
```
#### List All IAM Users
```
aws iam list-users
```
#### Add a User to a Group
```
aws iam add-user-to-group --user-name <username> --group-name <groupname>
```
#### Remove a User from a Group
```
aws iam remove-user-from-group --user-name <username> --group-name <groupname>
```
#### Create a New IAM Group
```
aws iam create-group --group-name <groupname>
```
#### Delete an IAM Group
```
aws iam delete-group --group-name <groupname>
```
#### List IAM Groups
```
aws iam list-groups
```
#### Attach a Policy to a User
```
aws iam attach-user-policy --user-name <username> --policy-arn <arn:aws:iam::policyname>
```
#### Detach a Policy from a User
```
aws iam detach-user-policy --user-name <username> --policy-arn <arn:aws:iam::policyname>
```
#### Create an IAM Role
```
aws iam create-role --role-name <rolename> --assume-role-policy-document file://trust-policy.json
```
#### Attach a Policy to a Role
```
aws iam attach-role-policy --role-name <rolename> --policy-arn <arn:aws:iam::policyname>
```
#### List Attached Policies for a Role
```
aws iam list-attached-role-policies --role-name <rolename>
```
#### Delete an IAM Role
```
aws iam delete-role --role-name <rolename>
```
#### Create an Access Key for a User
```
aws iam create-access-key --user-name <username>
```
#### Delete an Access Key
```
aws iam delete-access-key --user-name <username> --access-key-id <access_key_id>
```
#### List All Access Keys for a User
```
aws iam list-access-keys --user-name <username>
```
#### Update an IAM User
```
aws iam update-user --user-name <current-username> --new-user-name <new-username>
```
#### List IAM Policies
```
aws iam list-policies
```
#### Get Account Summary
```
aws iam get-account-summary
```
#### Create a Policy
```
aws iam create-policy --policy-name <policyname> --policy-document file://policy.json
```
#### Delete a Policy
```
aws iam delete-policy --policy-arn <arn:aws:iam::policyname>
```
#### Add Tags to a Role (Using Role Name)
```
aws iam tag-role --role-name <role-name> --tags Key=<key>,Value=<value>
```
#### Add Tags to a Role (Using Role ARN)
```
aws iam tag-role --role-name <role-arn> --tags Key=<key>,Value=<value>
```

#### Remove Tags from a Role (Using Role Name)
```
aws iam untag-role --role-name <role-name> --tag-keys <key1> <key2> ...
```

#### Remove Tags from a Role (Using Role ARN)
```
aws iam untag-role --role-name <role-arn> --tag-keys <key1> <key2> ...
```

#### Create a Policy Version
```
aws iam create-policy-version --policy-arn <arn:aws:iam::policyname> --policy-document file://new_policy.json --set-as-default
```

#### List All Versions of a Policy
```
aws iam list-policy-versions --policy-arn <arn:aws:iam::policyname>
```

#### Delete a Policy Version
```
aws iam delete-policy-version --policy-arn <arn:aws:iam::policyname> --version-id <version_id>
```

#### Create an Inline Policy for a User
```
aws iam put-user-policy --user-name <username> --policy-name <policyname> --policy-document file://policy.json
```

#### List Inline Policies for a User
```
aws iam list-user-policies --user-name <username>
```

#### Delete an Inline Policy from a User
```
aws iam delete-user-policy --user-name <username> --policy-name <policyname>
```

#### Create an Inline Policy for a Group
```
aws iam put-group-policy --group-name <groupname> --policy-name <policyname> --policy-document file://policy.json
```

#### List Inline Policies for a Group
```
aws iam list-group-policies --group-name <groupname>
```

#### Delete an Inline Policy from a Group
```
aws iam delete-group-policy --group-name <groupname> --policy-name <policyname>
```

#### Create an Inline Policy for a Role
```
aws iam put-role-policy --role-name <rolename> --policy-name <policyname> --policy-document file://policy.json
```

#### List Inline Policies for a Role
```
aws iam list-role-policies --role-name <rolename>
```

#### Delete an Inline Policy from a Role
```
aws iam delete-role-policy --role-name <rolename> --policy-name <policyname>
```

#### Enable MFA for a User
```
aws iam enable-mfa-device --user-name <username> --serial-number <mfa_device_arn> --authentication-code-1 <code1> --authentication-code-2 <code2>
```

#### Deactivate MFA for a User
```
aws iam deactivate-mfa-device --user-name <username> --serial-number <mfa_device_arn>
```

#### Get User Information
```
aws iam get-user --user-name <username>
```

#### Get Group Information
```
aws iam get-group --group-name <groupname>
```

#### Get Role Information
```
aws iam get-role --role-name <rolename>
```

#### Get Policy Information
```
aws iam get-policy --policy-arn <arn:aws:iam::policyname>
```

#### Get Policy Version Information
```
aws iam get-policy-version --policy-arn <arn:aws:iam::policyname> --version-id <version_id>
```

#### Create a Signing Certificate for a User
```
aws iam upload-signing-certificate --user-name <username> --certificate-body file://public_key.pem
```

#### List Signing Certificates for a User
```
aws iam list-signing-certificates --user-name <username>
```

#### Delete a Signing Certificate
```
aws iam delete-signing-certificate --user-name <username> --certificate-id <cert_id>
```

#### List Account Alias
```
aws iam list-account-aliases
```

#### Create an Account Alias
```
aws iam create-account-alias --account-alias <alias>
```

#### Delete an Account Alias
```
aws iam delete-account-alias --account-alias <alias>
```

# Access Analyzer
#### Create an Analyzer
```
aws accessanalyzer create-analyzer --analyzer-name <analyzer-name> --type ACCOUNT
```

#### List Analyzers
```
aws accessanalyzer list-analyzers
```

#### Delete an Analyzer
```
aws accessanalyzer delete-analyzer --analyzer-name <analyzer-name>
```

#### Get Analyzer Details
```
aws accessanalyzer get-analyzer --analyzer-name <analyzer-name>
```

#### List Findings
```
aws accessanalyzer list-findings --analyzer-name <analyzer-name>
```

#### Get Finding Details
```
aws accessanalyzer get-finding --id <finding-id>
```

#### Archive a Finding
```
aws accessanalyzer archive-finding --analyzer-name <analyzer-name> --id <finding-id>
```

#### Update a Finding
```
aws accessanalyzer update-findings --analyzer-name <analyzer-name> --status <status>
```

#### Validate a Policy
```
aws accessanalyzer validate-policy --policy-type <type> --policy-document <json-policy>
```

#### List Archive Rules
```
aws accessanalyzer list-archive-rules --analyzer-name <analyzer-name>
```

#### Create an Archive Rule
```
aws accessanalyzer create-archive-rule --analyzer-name <analyzer-name> --filter <filter-key>=<filter-value> --rule-name <rule-name>
```

#### Get Archive Rule
```
aws accessanalyzer get-archive-rule --analyzer-name <analyzer-name> --rule-name <rule-name>
```

#### Delete an Archive Rule
```
aws accessanalyzer delete-archive-rule --analyzer-name <analyzer-name> --rule-name <rule-name>
```

#### Update an Archive Rule
```
aws accessanalyzer update-archive-rule --analyzer-name <analyzer-name> --rule-name <rule-name> --filter <filter-key>=<filter-value>
```


# <span style="color:red">Cloudformation</span>
#### Create a Stack
```
aws cloudformation create-stack --stack-name <stack-name> --template-body <file://template-file.json> --parameters ParameterKey=<key>,ParameterValue=<value>
```

#### Delete a Stack
```
aws cloudformation delete-stack --stack-name <stack-name>
```

#### Update a Stack
```
aws cloudformation update-stack --stack-name <stack-name> --template-body <file://template-file.json> --parameters ParameterKey=<key>,ParameterValue=<value>
```

#### Describe a Stack
```
aws cloudformation describe-stacks --stack-name <stack-name>
```

#### List Stacks
```
aws cloudformation list-stacks
```

#### Describe Stack Events
```
aws cloudformation describe-stack-events --stack-name <stack-name>
```

#### Describe Stack Resources
```
aws cloudformation describe-stack-resources --stack-name <stack-name>
```

#### Describe a Specific Stack Resource
```
aws cloudformation describe-stack-resource --stack-name <stack-name> --logical-resource-id <resource-id>
```

#### Validate a Template
```
aws cloudformation validate-template --template-body <file://template-file.json>
```

#### Estimate Stack Cost
```
aws cloudformation estimate-template-cost --template-body <file://template-file.json>
```

#### List Stack Resources
```
aws cloudformation list-stack-resources --stack-name <stack-name>
```

#### Cancel Stack Update
```
aws cloudformation cancel-update-stack --stack-name <stack-name>
```

#### Get Stack Policy
```
aws cloudformation get-stack-policy --stack-name <stack-name>
```

#### Set Stack Policy
```
aws cloudformation set-stack-policy --stack-name <stack-name> --stack-policy-body <file://policy.json>
```

#### List Stack Sets
```
aws cloudformation list-stack-sets
```

#### Describe Stack Set
```
aws cloudformation describe-stack-set --stack-set-name <stack-set-name>
```

#### Create Stack Set
```
aws cloudformation create-stack-set --stack-set-name <stack-set-name> --template-body <file://template-file.json>
```

#### Delete Stack Set
```
aws cloudformation delete-stack-set --stack-set-name <stack-set-name>
```

#### Update Stack Set
```
aws cloudformation update-stack-set --stack-set-name <stack-set-name> --template-body <file://template-file.json>
```

#### List Change Sets
```
aws cloudformation list-change-sets --stack-name <stack-name>
```

#### Create a Change Set
```
aws cloudformation create-change-set --stack-name <stack-name> --change-set-name <change-set-name> --template-body <file://template-file.json>
```

#### Delete a Change Set
```
aws cloudformation delete-change-set --change-set-name <change-set-name> --stack-name <stack-name>
```

#### Describe a Change Set
```
aws cloudformation describe-change-set --change-set-name <change-set-name> --stack-name <stack-name>
```

#### Execute a Change Set
```
aws cloudformation execute-change-set --change-set-name <change-set-name> --stack-name <stack-name>
```

#### List Exports
```
aws cloudformation list-exports
```

#### List Imports
```
aws cloudformation list-imports --export-name <export-name>
```

#### Detect Stack Drift
```
aws cloudformation detect-stack-drift --stack-name <stack-name>
```

#### Describe Stack Drift Detection Status
```
aws cloudformation describe-stack-drift-detection-status --stack-drift-detection-id <drift-detection-id>
```

#### Describe Stack Resource Drift
```
aws cloudformation describe-stack-resource-drifts --stack-name <stack-name>
```

#### List Stack Instances
```
aws cloudformation list-stack-instances --stack-set-name <stack-set-name>
```

#### Describe Stack Instance
```
aws cloudformation describe-stack-instance --stack-set-name <stack-set-name> --stack-instance-account <account-id> --stack-instance-region <region>
```

# <span style="color:red">S3</span>
#### List Buckets
```
aws s3 ls
```

#### Create a Bucket
```
aws s3 mb s3://<bucket-name>
```

#### Delete a Bucket
```
aws s3 rb s3://<bucket-name>
```

#### List Objects in a Bucket
```
aws s3 ls s3://<bucket-name>
```

#### Upload a File to a Bucket
```
aws s3 cp <file-path> s3://<bucket-name>/<key>
```

#### Download a File from a Bucket
```
aws s3 cp s3://<bucket-name>/<key> <local-file-path>
```

#### Delete an Object from a Bucket
```
aws s3 rm s3://<bucket-name>/<key>
```

#### Sync Local Directory to a Bucket
```
aws s3 sync <local-directory-path> s3://<bucket-name>
```

#### Sync Bucket to Local Directory
```
aws s3 sync s3://<bucket-name> <local-directory-path>
```

#### Enable Versioning on a Bucket
```
aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled
```

#### Suspend Versioning on a Bucket
```
aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Suspended
```

#### List Object Versions in a Bucket
```
aws s3api list-object-versions --bucket <bucket-name>
```

#### Enable Server-Side Encryption on a Bucket
```
aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

#### Get Bucket Encryption Status
```
aws s3api get-bucket-encryption --bucket <bucket-name>
```

#### Remove Bucket Encryption
```
aws s3api delete-bucket-encryption --bucket <bucket-name>
```

#### Set Bucket Policy
```
aws s3api put-bucket-policy --bucket <bucket-name> --policy <file://policy.json>
```

#### Get Bucket Policy
```
aws s3api get-bucket-policy --bucket <bucket-name>
```

#### Delete Bucket Policy
```
aws s3api delete-bucket-policy --bucket <bucket-name>
```

#### Set CORS Configuration on a Bucket
```
aws s3api put-bucket-cors --bucket <bucket-name> --cors-configuration <file://cors.json>
```

#### Get CORS Configuration of a Bucket
```
aws s3api get-bucket-cors --bucket <bucket-name>
```

#### Delete CORS Configuration of a Bucket
```
aws s3api delete-bucket-cors --bucket <bucket-name>
```

#### Enable Logging on a Bucket
```
aws s3api put-bucket-logging --bucket <bucket-name> --bucket-logging-status file://logging.json
```

#### Get Logging Status of a Bucket
```
aws s3api get-bucket-logging --bucket <bucket-name>
```

#### Enable Lifecycle Configuration on a Bucket
```
aws s3api put-bucket-lifecycle-configuration --bucket <bucket-name> --lifecycle-configuration <file://lifecycle.json>
```

#### Get Lifecycle Configuration of a Bucket
```
aws s3api get-bucket-lifecycle-configuration --bucket <bucket-name>
```

#### Delete Lifecycle Configuration of a Bucket
```
aws s3api delete-bucket-lifecycle --bucket <bucket-name>
```

#### Enable Public Access Block on a Bucket
```
aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

#### Get Public Access Block Status of a Bucket
```
aws s3api get-public-access-block --bucket <bucket-name>
```

#### Delete Public Access Block Configuration of a Bucket
```
aws s3api delete-public-access-block --bucket <bucket-name>
```

#### Copy an Object Between Buckets
```
aws s3 cp s3://<source-bucket>/<source-key> s3://<destination-bucket>/<destination-key>
```

# <span style="color:red">EC2</span>
#### Describe EC2 Instances
```
aws ec2 describe-instances
```

#### Start an EC2 Instance
```
aws ec2 start-instances --instance-ids <instance-id>
```

#### Stop an EC2 Instance
```
aws ec2 stop-instances --instance-ids <instance-id>
```

#### Reboot an EC2 Instance
```
aws ec2 reboot-instances --instance-ids <instance-id>
```

#### Terminate an EC2 Instance
```
aws ec2 terminate-instances --instance-ids <instance-id>
```

#### Describe EC2 Instance Status
```
aws ec2 describe-instance-status --instance-ids <instance-id>
```

#### Create a New EC2 Key Pair
```
aws ec2 create-key-pair --key-name <key-name>
```

#### Delete an EC2 Key Pair
```
aws ec2 delete-key-pair --key-name <key-name>
```

#### Create a Security Group
```
aws ec2 create-security-group --group-name <group-name> --description <description> --vpc-id <vpc-id>
```

#### Describe Security Groups
```
aws ec2 describe-security-groups
```

#### Authorize Inbound Traffic for a Security Group
```
aws ec2 authorize-security-group-ingress --group-id <security-group-id> --protocol <tcp|udp> --port <port> --cidr <cidr-block>
```

#### Revoke Inbound Traffic for a Security Group
```
aws ec2 revoke-security-group-ingress --group-id <security-group-id> --protocol <tcp|udp> --port <port> --cidr <cidr-block>
```

#### Create an EC2 Instance
```
aws ec2 run-instances --image-id <ami-id> --count <number-of-instances> --instance-type <instance-type> --key-name <key-name> --security-group-ids <security-group-id>
```

#### Describe EC2 AMIs
```
aws ec2 describe-images --owners <self|amazon|aws-marketplace>
```

#### Deregister an AMI
```
aws ec2 deregister-image --image-id <ami-id>
```

#### Create an EBS Volume
```
aws ec2 create-volume --availability-zone <az> --size <size-in-gb>
```

#### Describe EBS Volumes
```
aws ec2 describe-volumes
```

#### Attach an EBS Volume to an EC2 Instance
```
aws ec2 attach-volume --volume-id <volume-id> --instance-id <instance-id> --device <device-name>
```

#### Detach an EBS Volume from an EC2 Instance
```
aws ec2 detach-volume --volume-id <volume-id>
```

#### Delete an EBS Volume
```
aws ec2 delete-volume --volume-id <volume-id>
```

#### Create a Snapshot of an EBS Volume
```
aws ec2 create-snapshot --volume-id <volume-id> --description <description>
```

#### Describe EBS Snapshots
```
aws ec2 describe-snapshots --owner-ids <self|aws-account-id>
```

#### Delete an EBS Snapshot
```
aws ec2 delete-snapshot --snapshot-id <snapshot-id>
```

#### Create an AMI from an EC2 Instance
```
aws ec2 create-image --instance-id <instance-id> --name <ami-name>
```

#### Create a New Elastic IP Address
```
aws ec2 allocate-address
```

#### Associate an Elastic IP with an EC2 Instance
```
aws ec2 associate-address --instance-id <instance-id> --allocation-id <allocation-id>
```

#### Disassociate an Elastic IP from an EC2 Instance
```
aws ec2 disassociate-address --association-id <association-id>
```

#### Release an Elastic IP Address
```
aws ec2 release-address --allocation-id <allocation-id>
```

#### Create a VPC
```
aws ec2 create-vpc --cidr-block <cidr-block>
```

#### Describe VPCs
```
aws ec2 describe-vpcs
```

#### Delete a VPC
```
aws ec2 delete-vpc --vpc-id <vpc-id>
```

#### Create a Subnet in a VPC
```
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block <cidr-block>
```

#### Describe Subnets
```
aws ec2 describe-subnets
```

#### Delete a Subnet
```
aws ec2 delete-subnet --subnet-id <subnet-id>
```

#### Create an Internet Gateway
```
aws ec2 create-internet-gateway
```

#### Attach an Internet Gateway to a VPC
```
aws ec2 attach-internet-gateway --vpc-id <vpc-id> --internet-gateway-id <igw-id>
```

#### Describe Internet Gateways
```
aws ec2 describe-internet-gateways
```

#### Delete an Internet Gateway
```
aws ec2 delete-internet-gateway --internet-gateway-id <igw-id>
```

#### Create a Route Table for a VPC
```
aws ec2 create-route-table --vpc-id <vpc-id>
```

#### Describe Route Tables
```
aws ec2 describe-route-tables
```

#### Create a Route in a Route Table
```
aws ec2 create-route --route-table-id <route-table-id> --destination-cidr-block <cidr-block> --gateway-id <igw-id>
```

#### Associate a Route Table with a Subnet
```
aws ec2 associate-route-table --route-table-id <route-table-id> --subnet-id <subnet-id>
```

#### Disassociate a Route Table from a Subnet
```
aws ec2 disassociate-route-table --association-id <association-id>
```

#### Delete a Route Table
```
aws ec2 delete-route-table --route-table-id <route-table-id>
```

#### Delete a Route in a Route Table
```
aws ec2 delete-route --route-table-id <route-table-id> --destination-cidr-block <cidr-block>
```

# <span style="color:red">CloudTrail</span>

#### Create a New CloudTrail
```
aws cloudtrail create-trail --name <trail-name> --s3-bucket-name <s3-bucket-name>
```

#### Start Logging for a CloudTrail
```
aws cloudtrail start-logging --name <trail-name>
```

#### Stop Logging for a CloudTrail
```
aws cloudtrail stop-logging --name <trail-name>
```

#### Delete a CloudTrail
```
aws cloudtrail delete-trail --name <trail-name>
```

#### Describe a CloudTrail
```
aws cloudtrail describe-trails --trail-name-list <trail-name>
```

#### List all CloudTrails
```
aws cloudtrail list-trails
```

#### Get CloudTrail Status
```
aws cloudtrail get-trail-status --name <trail-name>
```

#### Lookup CloudTrail Events
```
aws cloudtrail lookup-events --lookup-attributes AttributeKey=<key>,AttributeValue=<value>
```

#### Update CloudTrail
```
aws cloudtrail update-trail --name <trail-name> --s3-bucket-name <new-s3-bucket-name>
```

#### Add Tags to CloudTrail
```
aws cloudtrail add-tags --resource-id <trail-arn> --tags-list Key=<key>,Value=<value>
```

#### Remove Tags from CloudTrail
```
aws cloudtrail remove-tags --resource-id <trail-arn> --tags-list Key=<key>
```

#### Create CloudTrail Insight
```
aws cloudtrail start-insight-selector --trail-name <trail-name> --insight-selectors '[{"InsightType": "ApiCallRateInsight"}]'
```

#### Stop CloudTrail Insight
```
aws cloudtrail stop-insight-selector --trail-name <trail-name> --insight-selectors '[{"InsightType": "ApiCallRateInsight"}]'
```

#### Get Insight Results
```
aws cloudtrail get-insight-results --insight-selector-arn <insight-arn>
```

# <span style="color:red">Lambda  </span>

#### Create a Lambda Function
```
aws lambda create-function --function-name <function-name> --runtime <runtime> --role <role-arn> --handler <handler> --zip-file fileb://<path-to-zip>
```

#### List Lambda Functions
```
aws lambda list-functions
```

#### Invoke a Lambda Function
```
aws lambda invoke --function-name <function-name> <output-file>
```

#### Update Lambda Function Code
```
aws lambda update-function-code --function-name <function-name> --zip-file fileb://<path-to-zip>
```

#### Update Lambda Function Configuration
```
aws lambda update-function-configuration --function-name <function-name> --handler <handler> --memory-size <size> --timeout <timeout>
```

#### Delete a Lambda Function
```
aws lambda delete-function --function-name <function-name>
```

#### Get Lambda Function Details
```
aws lambda get-function --function-name <function-name>
```

#### List Versions of a Lambda Function
```
aws lambda list-versions-by-function --function-name <function-name>
```

#### Publish a Lambda Version
```
aws lambda publish-version --function-name <function-name>
```

#### List Lambda Function Aliases
```
aws lambda list-aliases --function-name <function-name>
```

#### Create a Lambda Alias
```
aws lambda create-alias --function-name <function-name> --name <alias-name> --function-version <version>
```

#### Update a Lambda Alias
```
aws lambda update-alias --function-name <function-name> --name <alias-name> --function-version <version>
```

#### Delete a Lambda Alias
```
aws lambda delete-alias --function-name <function-name> --name <alias-name>
```

#### List Event Source Mappings
```
aws lambda list-event-source-mappings
```

#### Create Event Source Mapping
```
aws lambda create-event-source-mapping --function-name <function-name> --event-source-arn <arn> --batch-size <batch-size> --starting-position <position>
```

#### Update Event Source Mapping
```
aws lambda update-event-source-mapping --uuid <mapping-uuid> --function-name <function-name>
```

#### Delete Event Source Mapping
```
aws lambda delete-event-source-mapping --uuid <mapping-uuid>
```

#### Add Permission to Lambda Function
```
aws lambda add-permission --function-name <function-name> --statement-id <statement-id> --action <action> --principal <service>
```

#### Remove Permission from Lambda Function
```
aws lambda remove-permission --function-name <function-name> --statement-id <statement-id>
```

#### Get Lambda Function Policy
```
aws lambda get-policy --function-name <function-name>
```

#### List Layer Versions
```
aws lambda list-layer-versions --layer-name <layer-name>
```

#### Publish a Lambda Layer
```
aws lambda publish-layer-version --layer-name <layer-name> --zip-file fileb://<path-to-zip>
```

#### Delete a Lambda Layer Version
```
aws lambda delete-layer-version --layer-name <layer-name> --version-number <version-number>
```

#### Get Lambda Layer Details
```
aws lambda get-layer-version --layer-name <layer-name> --version-number <version-number>
```

#### Create Lambda Function URL Config
```
aws lambda create-function-url-config --function-name <function-name> --auth-type <auth-type>
```

#### Get Lambda Function URL Config
```
aws lambda get-function-url-config --function-name <function-name>
```

#### Update Lambda Function URL Config
```
aws lambda update-function-url-config --function-name <function-name> --auth-type <auth-type>
```

#### Delete Lambda Function URL Config
```
aws lambda delete-function-url-config --function-name <function-name>
```
