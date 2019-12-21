# aws_security_tester
A script to provide an analysis of public ip space with open ports/protocols


## Services tested

**by Specification:**
- EC2
- ELB
- ELBv2
- RDS

**by Research: **
- CloudFront / incomplete
- CodeBuild  / incomplete
- DynamoDB  / incomplete
- S3  / incomplete
- ElasticSearch  / incomplete

------------


## Services with public IP Space
=================================
- API_GATEWAY
- CLOUDFRONT
- CODEBUILD
- DYNAMODB
- EC2
- S3
- ELB (Classic ELB)
- ELBv2 (ALB/NLB)
- Lightsail
- Redshift
- EC2_INSTANCE_CONNECT

<span style="color:red">
#### Not Checked
- WORKSPACES_GATEWAYS
- ROUTE53_HEALTHCHECKS 
- ROUTE53
- GLOBALACCELERATOR
- CLOUD9
- AMAZON_CONNECT
</span>



## Instructions for Use

Not all options are active.

Sending log messages to console, syslog or file is active
Use of aws options are fully functional. If no options are passed, the program will 
attempt to use the aws default profile. (please use aws configure to setup prior to 
running this program)

Passing (keys and tokens works)
Passing (profile works)

Limitations were based on my access to an AWS development environment. 

## Example usages


### Use AWS Keys and w or w/o token
`./security_tester  --access-key AWS_ACCESS_KEY --secret-access-key SECRET_ACCESS_KEY [optional] --aws-session-token AWS_TOKEN -log file`

### Use AWS Profile
`./security_tester -profile AWS_PROFILE -log file`

### Use AWS default profile
`./security_tester -log file`


## Usage Help
```
usage: security_tester.py [-h] [--version] [-o {txt,csv,xls}] [-v] [-dr]
                          [-ll {DEBUG,INFO,NOTICE,CRITICAL,ERROR}] [-l LINES]
                          [-f OUT_FILE] [-d] [-log {none,console,syslog,file}]
                          [-lf LOG_FILE] [-sf LOG_FACILITY]
                          [-profile AWS_PROFILE]
                          [-r {us-east-1,us-east-2,us-west-1,us-west-2,ap-east-1,ap-south-1,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ca-central-1,cn-north-1,cn-northwest-1,eu-central-1,eu-west-1,eu-west-2,eu-west-3,eu-north-1,me-south-1,sa-east-1}]
                          [-key AWS_ACCESS_KEY] [-secret SECRET_ACCESS_KEY]
                          [-token AWS_TOKEN]

Description of the program

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -o {txt,csv,xls}, --output {txt,csv,xls}
                        Format for output { txt, csv, xls}
  -v, --verbose         Turn on verbose output
  -dr, --dryrun         Dryrun enabled no changes will occur
  -ll {DEBUG,INFO,NOTICE,CRITICAL,ERROR}, --log-level {DEBUG,INFO,NOTICE,CRITICAL,ERROR}
                        Set Loglevel ['DEBUG', 'INFO', 'NOTICE', 'CRITICAL',
                        'ERROR']
  -l LINES, --lines LINES
                        Restrict output to number of lines
  -f OUT_FILE, --file OUT_FILE
                        Output file
  -d, --debug           Turn on Debugging Mode
  -log {none,console,syslog,file}, --log-location {none,console,syslog,file}
                        Send logs to a location ['console', 'syslog', 'file']
  -lf LOG_FILE, --log-file LOG_FILE
                        Send logs to a logfile
  -sf LOG_FACILITY, --syslog-facility LOG_FACILITY
                        Help for this function
  -profile AWS_PROFILE, --profile AWS_PROFILE
                        AWS Profile to use
  -r {us-east-1,us-east-2,us-west-1,us-west-2,ap-east-1,ap-south-1,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ca-central-1,cn-north-1,cn-northwest-1,eu-central-1,eu-west-1,eu-west-2,eu-west-3,eu-north-1,me-south-1,sa-east-1}, --region {us-east-1,us-east-2,us-west-1,us-west-2,ap-east-1,ap-south-1,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,ca-central-1,cn-north-1,cn-northwest-1,eu-central-1,eu-west-1,eu-west-2,eu-west-3,eu-north-1,me-south-1,sa-east-1}
                        AWS region to use
  -key AWS_ACCESS_KEY, --access-key AWS_ACCESS_KEY
                        AWS access key
  -secret SECRET_ACCESS_KEY, --secret-access-key SECRET_ACCESS_KEY
                        AWS access key
  -token AWS_TOKEN, --aws-session-token AWS_TOKEN
                        AWS access session token
```
## Comments about the program

<span style="color:blue">
The edge cases and work left to do is related to testing and verifying all places where a public IP address might be used. I looked at a few methods to determine this with Security Groups and some other methods. 

The program provides two sets of data. One by the service and a summary and analysis at the end. Ideally, I would add comments and tags from the VPCs. 

There is a need for using some Cloud Vendors to provide an automated IP address report 
and tags. Given the time constraints and lack of development environment, these options 
are not included



### Examples

EC2 with Security Group:

```shell
================================================================================
Instance Name       : Lutra
Instance Private IP : 172.31.39.42
Instance Private DNS: ip-172-31-39-42.us-west-2.compute.internal
Instance Public IP  : 34.220.77.158
Instance Public DNS : ec2-34-220-77-158.us-west-2.compute.amazonaws.com
Instance Type       : t2.nano
Instance State      : running
Instance Launch Time: 2018-05-31 16:32:38+00:00
Instance Region     : us-west-2
================================================================================
Security Group ID: sg-068df045157b84a91 /  name: Pyrrhula
Group Description: Pyrrhula
================================================================================
Ingress Rules
|-----------|-----------|-----------|---------|---------|---------|-----------|
|Security Gr|ports      |IPv4 CIDR  |IPv4 Type|IPv6 CIDR|IPv6 Type|Security An|
|p          |           |           |         |         |         |alysis     |
|=============================================================================|
|sg-068df045|80:80:tcp  |172.32.4.50|PUBLIC   |[]       |-        |Open to pub|
|157b84a91  |           |/32        |         |         |         |lic space :|
|           |           |           |         |         |         | -:-       |
|-----------|-----------|-----------|---------|---------|---------|-----------|
|sg-068df045|5432:5432:t|172.32.4.50|PUBLIC   |[]       |-        |Open to pub|
|157b84a91  |cp         |/32        |         |         |         |lic space :|
|           |           |           |         |         |         | -:-       |
|-----------|-----------|-----------|---------|---------|---------|-----------|
|sg-068df045|22:22:tcp  |172.32.4.50|PUBLIC   |[]       |-        |Open to pub|
|157b84a91  |           |/32        |         |         |         |lic space :|
|           |           |           |         |         |         | -:-       |
> ================================================================================
Instance Name       : Lutra
Instance Private IP : 172.31.39.42
Instance Private DNS: ip-172-31-39-42.us-west-2.compute.internal
Instance Public IP  : 34.220.77.158
Instance Public DNS : ec2-34-220-77-158.us-west-2.compute.amazonaws.com
Instance Type       : t2.nano
Instance State      : running
Instance Launch Time: 2018-05-31 16:32:38+00:00
Instance Region     : us-west-2
================================================================================
Security Group ID: sg-068df045157b84a91 /  name: Pyrrhula
Group Description: Pyrrhula
================================================================================
Ingress Rules
|-----------|-----------|-----------|---------|---------|---------|-----------|
|Security Gr|ports      |IPv4 CIDR  |IPv4 Type|IPv6 CIDR|IPv6 Type|Security An|
|p          |           |           |         |         |         |alysis     |
|=============================================================================|
|sg-068df045|80:80:tcp  |172.32.4.50|PUBLIC   |[]       |-        |Open to pub|
|157b84a91  |           |/32        |         |         |         |lic space :|
|           |           |           |         |         |         | -:-       |
|-----------|-----------|-----------|---------|---------|---------|-----------|
|sg-068df045|5432:5432:t|172.32.4.50|PUBLIC   |[]       |-        |Open to pub|
|157b84a91  |cp         |/32        |         |         |         |lic space :|
|           |           |           |         |         |         | -:-       |
|-----------|-----------|-----------|---------|---------|---------|-----------|
|sg-068df045|22:22:tcp  |172.32.4.50|PUBLIC   |[]       |-        |Open to pub|
|157b84a91  |           |/32        |         |         |         |lic space :|
|           |           |           |         |         |         | -:-       |
|-----------|-----------|-----------|---------|---------|---------|-----------|
|-----------|-----------|-----------|---------|---------|---------|-----------|
```

### Example 2

```
IP Summary of Report
|-------|-------|-------|-------|-------|-------|-------|-------|-------|
|Service|IP Addr|DNS Nam|Service|Securit|Ports O|IPv4 CI|IPv6 CI|Securit|
|       |ess    |e      | Port  |y Group|pen    |DR     |DR     |y Check|
|=======================================================================|
|ec2    |34.220.|ec2-34-|*      |sg-068d|80:80:t|172.32.|[]     |Open to|
|       |77.158 |220-77-|       |f045157|cp     |4.50/32|       | public|
|       |       |158.us-|       |b84a91 |       |       |       | space |
|       |       |west-2.|       |       |       |       |       |: -:-  |
|       |       |compute|       |       |       |       |       |       |
|       |       |.amazon|       |       |       |       |       |       |
|-------|-------|-------|-------|-------|-------|-------|-------|-------|
|ec2    |34.220.|ec2-34-|*      |sg-068d|5432:54|172.32.|[]     |Open to|
|       |77.158 |220-77-|       |f045157|32:tcp |4.50/32|       | public|
|       |       |158.us-|       |b84a91 |       |       |       | space |
|       |       |west-2.|       |       |       |       |       |: -:-  |
|       |       |compute|       |       |       |       |       |       |
|       |       |.amazon|       |       |       |       |       |       |
|-------|-------|-------|-------|-------|-------|-------|-------|-------|
|ec2    |34.220.|ec2-34-|*      |sg-068d|22:22:t|172.32.|[]     |Open to|
|       |77.158 |220-77-|       |f045157|cp     |4.50/32|       | public|
|       |       |158.us-|       |b84a91 |       |       |       | space |
|       |       |west-2.|       |       |       |       |       |: -:-  |
|       |       |compute|       |       |       |       |       |       |
|       |       |.amazon|       |       |       |       |       |       |
|-------|-------|-------|-------|-------|-------|-------|-------|-------|
```


</span>