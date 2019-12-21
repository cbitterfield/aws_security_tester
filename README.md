# aws_security_tester
A script to provide an analysis of public ip space with open ports/protocols


## Services tested

by Specification: EC2, ELB and RDS

by Research: 

	SERVICES with public IP Space
	=================================
	-AMAZON_CONNECT - Not
	-API_GATEWAY
	-CLOUD9
	-CLOUDFRONT
	-CODEBUILD
	-DYNAMODB
	-EC2
	-EC2_INSTANCE_CONNECT - Not checking
	-GLOBALACCELERATOR - Not checking
	-ROUTE53 -- Won't Check
	-ROUTE53_HEALTHCHECKS -- Won't Check
	-S3 
	-WORKSPACES_GATEWAYS
	-ELB (Classic ELB)
	-ELBv2 (ALB/NLB)
	-Lightsail
	-Redshift
	
	### Services Checked:
	================================================================================
	-Service Counts
	-EC2 counts 4
	-ELB counts 1
	-ELBv2 counts 0
	-RDS counts 1
	-CloudFront counts 0
	-CodeBuild counts 0
	-DynamoDB counts 0
	-S3 counts 0
	-ElasticSearch counts 0
	================================================================================

## Instructions for Use

Not all options are active.

Sending log messages to console, syslog or file is active
Use of aws options are fully functional. If no options are passed, the program will 
attempt to use the aws default profile. (please use aws configure to setup prior to 
running this program)

Passing (keys and tokens works)
Passing (profile works)

Limitations were based on my access to an AWS development environment. 



-profile default -log file










## Usage Help
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

Comments about the program