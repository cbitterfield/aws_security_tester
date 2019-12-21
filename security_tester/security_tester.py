#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Program to get all public IPs and list them with appropriate tags

@author: colin bitterfield


SERVICES with public IP Space
=================================
AMAZON_CONNECT
API_GATEWAY
CLOUD9
CLOUDFRONT
CODEBUILD
DYNAMODB
EC2
EC2_INSTANCE_CONNECT - Not checking
GLOBALACCELERATOR - Not checking
ROUTE53 -- Won't Check
ROUTE53_HEALTHCHECKS -- Won't Check
S3 
WORKSPACES_GATEWAYS

    •    APIGateway
    •    CloudFront
    •    EC2 (and as a result: ECS, EKS, Beanstalk, Fargate, Batch, & NAT Instances)
    •    ElasticSearch
    •    ELB (Classic ELB)
    •    ELBv2 (ALB/NLB)
    •    Lightsail
    •    RDS
    •    Redshift



'''
### Library Imports  

# Required
import os
import sys
import shutil
import argparse
import time
from datetime import datetime



# Program Specific library imports
import boto3
from collections import defaultdict
from columnar import columnar
import shutil
import socket
from IPy import IP


# Program Description Variables
__author__ = "Colin Bitterfield"
__copyright__ = "Copyright 2019, " + __author__
__credits__ = ["Colin Bitterfield"]
__license__ = "GPL3"
__version__ = "0.2.0"
__maintainer__ = "colin_bitterfield"
__status__ = "Alpha"
__created___ = "10/19/2019"
__updated___ = ""
__prog_name__ = os.path.basename(__file__)
__short_name__ = os.path.splitext(__prog_name__)[0]
__console_size_ = shutil.get_terminal_size((80, 20))[0]
__timestamp__ = time.time() 
__run_datetime__ = datetime.fromtimestamp(__timestamp__) # Today's Date
__log_name__ = 'prog' # Use this to label the syslog output as a decorator

### Global Variables for Testing
#Test and Debugging Variables
# These are applied to all functions and classes
# These settings override the command line if set to TRUE
# Set to NONE to have no effect
# If set to True or False, it will override the CLI

DEBUG=False
DRYRUN=None
VERBOSE=None
LOG=None

####Global Variables # set defaults here.
AWS_REGION_CHOICES = [
    'us-east-1',
    'us-east-2',
    'us-west-1',
    'us-west-2',
    'ap-east-1',
    'ap-south-1',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-northeast-3',
    'ap-southeast-1',
    'ap-southeast-2',
    'ca-central-1',
    'cn-north-1',
    'cn-northwest-1',
    'eu-central-1',
    'eu-west-1',
    'eu-west-2',
    'eu-west-3',
    'eu-north-1',
    'me-south-1',
    'sa-east-1'
]
AWS_DEFAULT_REGION='us-east-1'
LOG_LEVEL_CHOICES=['DEBUG','INFO','NOTICE','CRITICAL','ERROR']
LOGLEVEL='INFO' #Default loglevel
OUTPUT_CHOICES=['txt','csv','xls']
OUTPUT_DEFAULT='txt'
QUIET = False
LINES = 20
FILE  = "output"
LOG_LOCATION_CHOICES = ['console','syslog','file']
LOG_DEFAULT = 'console'
LOG_FACILITY = None
LOG_FACILITY_DEFAULT='local0'
AWS_CREDENTIALS = {}
TTY_columns,TTY_lines = shutil.get_terminal_size((80, 20))
HR_LINE = "=" * TTY_columns

# This will be a list of DICT (Service,IP address, DNS Name, Ports, Security Group ID, Warning Message if world accessible
IP_DATA = list()




#### Setup Function for the application

def setup(configuration):
    global DEBUG
    global VERBOSE
    global DRYRUN
    global LOGLEVEL
    global LOGFILE
    global LOG_FACILITY
    global logger
    global AWS_CREDENTIALS
    global AWS_DEFAULT_REGION
    

    
    
    
    if DEBUG == None:
        DEBUG=getattr(configuration,'debug')
    
    if VERBOSE == None:
        VERBOSE = True
         
    if DRYRUN == None:
        DRYRUN = getattr(configuration,'dryrun')
        
    if LOGLEVEL == None:
        LOGLEVEL = getattr(configuration,'log_level')
        
    if getattr(configuration,'log_file'):
        LOGFILE = getattr(configuration,'log_file')
        
    if LOG_FACILITY == None:
        LOG_FACILITY = getattr(configuration,'log_facility')
        
    if getattr(configuration,'log') != None:
        import logging
        import logging.config
        import logging.handlers
        
        # Set Formatting
        LOG_FORMAT = '%(asctime)s:%(name)s:%(funcName)s:%(levelname)s:%(message)s'
        LOG_DATE = '%m/%d/%Y %I:%M:%S %p'
        LOG_STYLE = style='%'
        LEVEL = getattr(configuration,'loglevel')
        
        
        if not 'Linux' in os.uname()[0]:
            LOG_SOCKET = '/var/run/syslog'
        else:
            LOG_SOCKET = '/dev/log'

        
        # create logger
        # set name as desired if not in a module
        logger = logging.getLogger(__log_name__ + ":" + __name__)
        logger.setLevel(LEVEL)
        
        # create handlers for Console and set level
        CONSOLE = logging.StreamHandler()
        CONSOLE.setLevel(logging.DEBUG)
        
        #create handlers for Syslog and set level
        SYSLOG = logging.handlers.SysLogHandler(address=LOG_SOCKET, facility=LOG_FACILITY)
        SYSLOG.setLevel(logging.INFO)

        #create handler for FILENAME and set level
        LOG_FILE = logging.FileHandler(LOGFILE,mode='a', encoding=None, delay=False)
        LOG_FILE.setLevel(logging.INFO)
        # create formatter
        formatter = logging.Formatter(LOG_FORMAT)

        # add formatter(s) to handlers
        CONSOLE.setFormatter(formatter)
        SYSLOG.setFormatter(formatter)
        LOG_FILE.setFormatter(formatter)
        
        # add handlers to logger
        if getattr(configuration,'log') == 'console':
            logger.addHandler(CONSOLE)
            
        if getattr(configuration,'log') == 'syslog':
            logger.addHandler(SYSLOG)    
            
        if getattr(configuration,'log') == 'file':
            logger.addHandler(LOG_FILE)
            
        logger.info('{0} started  {1} Logging Enabled'.format(__prog_name__,getattr(configuration,'log')))
        logger.debug('CLI Parameters {0}'.format(configuration))    
        
        # Setup the AWS Credential Logic
        
        # Check for Profile, then keys, then env variables. If nothing use the default profile 
        # Boto3 checks environment variables for missing credential information
        # We have to set credentials if we receive them via CLI
        #
        
        aws_access_key     = configuration.aws_access_key
        aws_secret_key     = configuration.secret_access_key
        aws_profile        = configuration.aws_profile
        aws_token          = configuration.aws_token
        
        
        
        
        AWS_CREDENTIALS = {
            'aws_access_key_id'     : aws_access_key,
            'aws_secret_access_key' : aws_secret_key,
            'profile_name'          : aws_profile,
            'aws_session_token'     : aws_token
            }
 
         
        logger.debug(AWS_CREDENTIALS)
        
    return 
            
    ### Program Functions and Classes
    #
    # Apply the following to all when possible
    # 
    # def function(**kwargs)
def ip_check(ip_address):
    '''Determine if the IP is a known type
    
    PARAMS:
    -------
        ip_address
        
    RETURN
        ip type
    
    '''
    
    ip = IP(ip_address)
    result = ip.iptype()
    if 'public' in result.lower():
        isPublic = True 
    else:
        isPublic = False 
    
    return isPublic
def sg_check(ip_address):
    '''Determine if the IP is a known type
    
    PARAMS:
    -------
        ip_address
        
    RETURN
        ip type
    
    '''
    messageSecurity="-"
    
    ip = IP(ip_address)
    isPublic=False
    
    
    
    result = ip.iptype()
    
    if ip_address == "0.0.0.0/0" or ip_address == "::/0": 
        messageSecurity = "CRITICAL / Open to all IPs"
        result = "PUBLIC"
        isPublic=True
    else:
        count=0
        for x in ip:
            count += 1
            
        if 'public' in result.lower():
            isPublic=True
        

        if count > 32: 
            messageSecurity =  "CRITICAL / Open to {x} ip addresses or more".format(x=count)
        elif count > 16:
            messageSecurity = messageSecurity + "Warning / Open to {x} ip addresses".format(x=count)
        elif count > 1:
            messageSecurity = messageSecurity + "Open to {x} ip addresses".format(x=count)
        else:
            pass
        
    
    
    return isPublic, messageSecurity, result
def process_sg(sg_list,service_info,ec2):
    """
    Process a security group list.
    Produce a table for display and return a list for a summary

    PARAMS:
    --------
        sg_list = a service group list
        service_info = Service Info for the table and the return list.

    RETURN:
        SUCCESS or FAILURE
        Update Global Variables

    GLOBAL 
    -------
        IP_DATA

    """
    # Enumerate over the list of security group IDs
    # We will use sg_list so that this block of code is reusable
    # Create a table for all of the permissions for this object
    # This code will have two lists for input. 
    # server_info (information about the service object to be prepended to each line)
    # sg_list (a list of security group IDs to interate over)
    
    #GLOBAL Declarations
    global IP_DATA
    
    #Local Declarations
    ipv4_type = ""
    ipv6_type = ""
    ipV6_sg_public = False 
    ipV4_sg_public = False 
    securityMessage = ""
    V4_securityMessage = ""
    V6_securityMessage = ""
    service_isPublic = ip_check(service_info[1]) 
    ip_temp = list()
    ipv4Cidr = list()
    ipv6Cidr = list()
    
    
    
    sg_header = ['Security Grp','ports','IPv4 CIDR', 'IPv4 Type' , 'IPv6 CIDR', 'IPv6 Type', 'Security Analysis']

    for sg in sg_list:
        # List for summary report for public IPs
        summary_info = list()
        # List for security report for all lines
        ingress_list = list()
        # List for columnar reporting
        sg_data = list()

        security_group = ec2.SecurityGroup(sg)

        # Assign security group header information to local variables
        grp_id = security_group.group_id
        grp_name = security_group.group_name
        grp_desc = security_group.description

        # Output the security group report information header
        print('Security Group ID: {gid} /  name: {gname}'.format(gid=grp_id, gname=grp_name))
        print('Group Description: {desc}'.format(desc=grp_desc))
        print(HR_LINE)
        print("Ingress Rules")

        #Build a table of information for the group and summary reports
        for ingress_rule in security_group.ip_permissions:
            ipv4_type = "-"
            ipv6_type = "-"
            ipV6_public = False 
            ipV4_public = False 
            securityMessage = "-"
            V4_securityMessage = "-"
            V6_securityMessage = "-"
            # Start this section by clearing line variables
            ingress_list=list()
            summary_info=list()
            # Group Report & Group Report
            ingress_list.append(grp_id)
            summary_info.append(grp_id)

            # Create a consolidated entry for ports
            FromPort = str(ingress_rule.get('FromPort',''))
            ToPort   = str(ingress_rule.get('ToPort',''))
            protocol = "both" if ingress_rule.get('IpProtocol','') == '-1' else ingress_rule.get('IpProtocol','')
            ports = ":".join([FromPort,ToPort,protocol])
            # Add to reports
            ingress_list.append(ports)
            summary_info.append(ports)

            #Create a consolidated entry for IPv4 CIDRs
            for ip_range in ingress_rule.get('IpRanges',''):
                ipv4Cidr = list()
                ipv4Cidr.append(ip_range.get('CidrIp',''))
                ipv4Cidr = ','.join(ipv4Cidr)
                ipV4_public, V4_securityMessage ,ipv4_type = sg_check(ipv4Cidr)

            ipv4Cidr = '-' if ipv4Cidr == None else ipv4Cidr
            # Add to reports 
            ingress_list.append(ipv4Cidr)
            ingress_list.append(ipv4_type)
            summary_info.append(ipv4Cidr)



            # Create an entry for IPv6
            for ip_range in ingress_rule.get('Ipv6Ranges',''):
                ipv6Cidr = list()
                ipv6Cidr.append( ip_range.get('CidrIpv6','') )
                ipv6Cidr = ','.join(ipv6Cidr)
                ipV6_public, V6_securityMessage,ipv6_type = sg_check(ipv6Cidr)
            ipv6Cidr = '-' if ipv6Cidr == None else ipv6Cidr

            # Add to reports
            ingress_list.append(ipv6Cidr)
            ingress_list.append(ipv6_type)
            summary_info.append(ipv6Cidr)

            # Add security warning messages to each line if necessary
            # elif
            # If acessible by more than one host issue a warning
            if service_isPublic and (ipV4_public or ipV6_public):
                securityMessage = "Open to public space : " +  V4_securityMessage + ":" + V6_securityMessage
            else:
                securityMessage = V4_securityMessage + ":" + V6_securityMessage
            
            ingress_list.append(securityMessage)
            summary_info.append(securityMessage)
            

            # Use Temp space to extend and add lines to each report
            ip_temp.extend(service_info)
            ip_temp.extend(summary_info)
            # Only add the line for the summary report if it is public IP space
            if service_isPublic and (ipV4_public or ipV6_public):
                IP_DATA.append(ip_temp)
            else:
                ingress_list.append("-")
                summary_info.append("-")
            ip_temp = list()
            ip_temp.extend(ingress_list)
            sg_data.append(ip_temp)

            #Clear Temp Space
            ip_temp = list()



        for i in range(len(sg_data)):
            if DEBUG: print('{i} {sg_data}'.format(i=i,sg_data=sg_data[i]))
        table = columnar(sg_data, sg_header, no_borders=False)
        print(table)
    
    
    
    
    return True
def getRegions(**kwargs):
    """ Protects a field while still giving some usable information.

        If the required arguements are not passed the function dies with a return failure and an exception.

        Settings:
        ---------
        REQUIRED:
            AWS_CREDENTIALS type dict
            
        MAX_PARAMS = 2
        

        Parameters:
        ----------
            AWS_REGION
            AWS_CREDENTIALS type dict

        Raises:
        ------
        Exception
            If required parameters are not passed or too many parameters are passed
            
        Returns:
        --------
            SUCCESS FLAG
            LIST of REGIONS that are in use for EC2s
            
        
             
    """

    logger.debug('starting with paramters {0}'.format(kwargs))
    
    
    REQUIRED = list(['AWS_CREDENTIALS'])
    MAX_PARAMS = 2
    SUCCESS = True
    
    # Check for requirement parameters
    if DEBUG: print(REQUIRED,len(REQUIRED))
    if DEBUG: print(kwargs,len(kwargs))
    if len(kwargs) >= len(REQUIRED) and len(kwargs) <= MAX_PARAMS:
        for required in REQUIRED:
            if required not in kwargs:
                SUCCESS = False
                raise Exception("The parameter {0} is required".format(required))
                
    else:
        SUCCESS = False
        raise Exception('parameters required {0} parameters received {1}'.format(len(REQUIRED),len(kwargs)))
        
    if DEBUG: print('Success Flag, {0}, arguments {1}'.format(SUCCESS,kwargs))
    ## Code to execute here
    if SUCCESS: 
        REGION_LIST =[] 
        DEFAULT_REGION = kwargs.get('AWS_REGION',AWS_DEFAULT_REGION)
        
                          
        session = boto3.Session(
            **kwargs['AWS_CREDENTIALS'],
            region_name = DEFAULT_REGION
        )
        ec2 = session.client('ec2')
        response = ec2.describe_regions()
        for region in response['Regions']:
            REGION_LIST.append(region['RegionName'])
    
        
    
    
        return SUCCESS,REGION_LIST
    
    else:
        logger.error('Error in parameters')
        SUCCESS=False
        return SUCCESS
    
    
    ### End Program Functions and Classes

def getCLIparams(cli_args):
    if DEBUG: print('CLI Params {0}'.format(cli_args))
    parser = argparse.ArgumentParser(None)
    parser.prog = __prog_name__
    parser.description = "Description of the program"
    parser.epilog = "Comments about the program"
    
    
# Defaults for all programs
    parser.add_argument('--version', 
                        action='version', 
                        version='%(prog)s ' + __version__)
    
    # For different kinds of output, provide a choice
    
    parser.add_argument('-o','--output',
                    help = 'Format for output { txt, csv, xls}',
                    action = 'store',
                    required = False,
                    dest='format', 
                    choices=OUTPUT_CHOICES,
                    default=OUTPUT_DEFAULT
                    )

    parser.add_argument('-v', '--verbose', 
                    help = 'Turn on verbose output',
                    action = 'store_true',
                    required = False,
                    dest='verbose', 
                    default=VERBOSE
                    )
    
    parser.add_argument('-dr', '--dryrun', 
                    help = 'Dryrun enabled no changes will occur',
                    action = 'store_true',
                    required = False,
                    dest='dryrun', 
                    default=False
                    )

    parser.add_argument('-ll', '--log-level', 
                    help = 'Set Loglevel ' + str(LOG_LEVEL_CHOICES),
                    type = str,
                    action = 'store',
                    choices = LOG_LEVEL_CHOICES,
                    required = False,
                    dest='loglevel', 
                    default=LOGLEVEL
                    )
    
    parser.add_argument('-l','--lines',
                    help = 'Restrict output to number of lines',
                    action = 'store',
                    type = int,
                    required = False,
                    dest='lines', 
                    default=LINES
                    )

    parser.add_argument('-f','--file',
                    help = 'Output file',
                    type=str,
                    action = 'store',
                    required = False,
                    dest='out_file', 
                    default=FILE
                    )

    parser.add_argument('-d','--debug',
                        help = 'Turn on Debugging Mode',
                        action = 'store_true',
                        required = False,
                        dest='debug', 
                        default=DEBUG
                        )

    parser.add_argument('-log','--log-location',
                        help = 'Send logs to a location ' + str(LOG_LOCATION_CHOICES),
                        type=str,
                        action = 'store',
                        required = False,
                        dest='log', 
                        choices=['none'] + LOG_LOCATION_CHOICES,
                        default=LOG_DEFAULT
                        )

    parser.add_argument('-lf','--log-file',
                        help = 'Send logs to a logfile',
                        type=str,
                        action = 'store',
                        required = False,
                        dest='log_file', 
                        default=__short_name__ + '.log'
                        )
    
    parser.add_argument('-sf','--syslog-facility',
                        help = 'Help for this function',
                        type=str,
                        action = 'store',
                        required = False,
                        dest='log_facility', 
                        default=LOG_FACILITY_DEFAULT
                        )
        
    parser.add_argument('-profile', '--profile', type=str, help='AWS Profile to use',
                        action='store',
                        required=False,
                        dest='aws_profile',
                        default=None)
    parser.add_argument('-r', '--region', type=str, help='AWS region to use',
                        action='store',
                        required=False,
                        choices=AWS_REGION_CHOICES,
                        dest='aws_region',
                        default='us-east-1')
    parser.add_argument('-key', '--access-key', type=str, help='AWS access key',
                        action='store',
                        required=False,
                        dest='aws_access_key',
                        default=None)
    parser.add_argument('-secret', '--secret-access-key', type=str, help='AWS access key',
                        action='store',
                        required=False,
                        dest='secret_access_key',
                        default=None)
    parser.add_argument('-token', '--aws-session-token', type=str, help='AWS access session token',
                        action='store',
                        required=False,
                        dest='aws_token',
                        default=None)
    
    parse_out = parser.parse_args(cli_args)
    

    return parse_out


def main():
    CONFIG = getCLIparams(None)
    setup(CONFIG)
    logger.info('AWS Security Tester')
    logger.debug('AWS Credentials {}'.format(AWS_CREDENTIALS))
    
    # Get a set of regions that can support EC2s
    print('Evaluating regions to see which ones we can access')
    STATUS, AWS_REGIONS_IN_USE = getRegions(AWS_REGIONS=AWS_REGION_CHOICES, AWS_CREDENTIALS=AWS_CREDENTIALS)
    if STATUS:
        logger.info('AWS_REGIONS: {}'.format(AWS_REGIONS_IN_USE))
    else:
        raise Exception('No Available Regions')
        sys.exit(1)
        
    print('Regions we can access for testing')
    print('Region List: {}'.format(AWS_REGIONS_IN_USE))
    
    
    print('Checking All Supported Regions for EC2 Instances')

    # Setup Variables for this section
    count_ec2 = 0
    
    
    for AWS_REGION in AWS_REGIONS_IN_USE:
    
        session = boto3.Session(
            **AWS_CREDENTIALS,
            region_name = AWS_REGION
        )
        
        
        ec2 = session.resource('ec2')
        # Get information for all running instances
        running_instances = ec2.instances.filter(Filters=[
            {
            'Name': 'instance-state-name',
            'Values': ['running']
            }
        ])
        if len(list(running_instances)) > 0:
            print('Getting EC2 information for region {}'.format(AWS_REGION))
            for instance in running_instances:
                count_ec2 += 1
                for tag in instance.tags:
                    if 'Name'in tag['Key']:
                        name = tag['Value']
                # Output EC2s and their information
                print(HR_LINE)
                print('Instance Name       : {}'.format(name))
                print('Instance Private IP : {}'.format(instance.private_ip_address))
                print('Instance Private DNS: {}'.format(instance.private_dns_name))
                print('Instance Public IP  : {}'.format(instance.public_ip_address))
                print('Instance Public DNS : {}'.format(instance.public_dns_name))
                print('Instance Type       : {}'.format(instance.instance_type))
                print('Instance State      : {}'.format(instance.state['Name']))
                print('Instance Launch Time: {}'.format(instance.launch_time))
                print('Instance Region     : {}'.format(AWS_REGION))
                print(HR_LINE)
        
                # Set Summary line for instance
                if instance.public_ip_address:
                    service_info = ['ec2',instance.public_ip_address, instance.public_dns_name,"*" ]
                else:
                    service_info = ['ec2',instance.private_ip_address, instance.private_dns_name,"*" ]
        
                # Output the security group table for each instance
                # Clear Variables between EC2 Instances
                sg_data = list()
                ipv4Cidr = list()
                ipv6Cidr = list()
                
                #
        
                # Create a list of security groups for the standard function to process
                sg_list = list()
                for security_grp in instance.security_groups:
                    sg_list.append(security_grp['GroupId'])
                
                
                ## Call Process SG here:
                status_message = process_sg(sg_list,service_info,ec2)
                logger.debug('SG Processing return {}'.format(status_message))
        
                print(HR_LINE)
        
            # Send Count message             
            if count_ec2 == 0:
                print('No EC2 Instances found')
            else:
                print('Numnber of EC2 Instances Found {}'.format(count_ec2))
    
    print(HR_LINE) 
    print('Checking ELB LoadBalancers')
    count_elb = 0
    
    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )
        elb = session.client('elb')
        ec2 = session.resource('ec2')
        response = elb.describe_load_balancers()
        
        if response['LoadBalancerDescriptions']:
            count_elb += 1
            for load_balancer in response['LoadBalancerDescriptions']:
                print(HR_LINE)
                logger.debug(load_balancer)
                lb_ip_address = socket.gethostbyname(load_balancer['DNSName'])
                print('Load Balancer Name : {}'.format(load_balancer['LoadBalancerName']))
                print('Load Balancer DNS  : {}'.format(load_balancer['DNSName']))  
                print('Load Balancer IP   : {}'.format(lb_ip_address)  )
                service_info = ['elb',lb_ip_address, load_balancer['DNSName'],"*" ]
                
                
         
            # Create a list of security groups for the standard function to process
                sg_list = list()
                for sg in load_balancer['SecurityGroups']:
                    sg_list.append(sg)
                    
                status_message = process_sg(sg_list,service_info,ec2)
                logger.debug('SG Processing return {}'.format(status_message))
    
    if count_elb == 0:
        print('No ELB Instances found')
    else:
        print('Numnber of ELB Instances Found {}'.format(count_elb))            
                    
    print(HR_LINE)      
                    
        
    print(HR_LINE)                
    print('Checking ELBv2 LoadBalancers')
    
    count_elbv2 = 0
    
    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )
        elb2 = session.client('elbv2')
        ec2 = session.resource('ec2')
        response = elb2.describe_load_balancers()
        
        if response['LoadBalancers']:
            
            for load_balancer in response['LoadBalancers']:
                count_elbv2 += 1
                print(HR_LINE)
                print('Load Balancer Name : {}'.format(load_balancer['LoadBalancerName']))
                print('Load Balancer DNS : {}'.format(load_balancer['DNSName']))
                service_info = ['elb',socket.gethostbyname(load_balancer['DNSName']), load_balancer['DNSName'],"*" ]

            # Create a list of security groups for the standard function to process
                sg_list = list()
                for sg in load_balancer['SecurityGroups']:
                    sg_list.append(sg)
                    
                ## Call Process SG here:
                status_message = process_sg(sg_list,service_info,ec2)
                logger.debug('SG Processing return {}'.format(status_message))
    
    if count_elbv2 == 0:
        print('No ELBv2 LoadBalancers Found')
    else:    
        print('Number of ELBv2 LoadBalancers Found {}'.format(count_elbv2))
    
    print(HR_LINE)                 
        
        
    print(HR_LINE)                
    print('Checking RDS Instances')
    count_rds = 0
    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )
        rds = session.client('rds')
        ec2 = session.resource('ec2')
        db_instances = rds.describe_db_instances()
    
        count_rds = 0
        
        service_info = list()
        if db_instances:
    
            for db_instance in db_instances['DBInstances']:
                
                count_rds += 1
                print(HR_LINE)
                logger.debug(db_instance)
                print('RDS Instance Name   : {}'.format(db_instance['DBName']))
                print('RDS Instance DNS    : {}'.format(db_instance['Endpoint']['Address']))
                print('RDS Instance DNS    : {}'.format(socket.gethostbyname(db_instance['Endpoint']['Address'])))
                print('RDS Instance PORT   : {}'.format(db_instance['Endpoint']['Port']))
                print('RDS Instance Engine : {}'.format(db_instance['Engine']))
                print('RDS Instance Class  : {}'.format(db_instance['DBInstanceClass']))
                service_info = ['rds',socket.gethostbyname(db_instance['Endpoint']['Address']), db_instance['Endpoint']['Address'],db_instance['Endpoint']['Port'] ]
                print(HR_LINE)
                
                sg_list = list()
                
                for sg in db_instance['VpcSecurityGroups']:
                    sg_list.append(sg['VpcSecurityGroupId'])
                    print(sg_list)
                
                    status_message = process_sg(sg_list,service_info,ec2)
                    logger.debug('SG Processing return {}'.format(status_message))
   
    print(HR_LINE)                
    
    print('Checking All Supported Regions for API Resources')
    
    # Setup Variables for this section
    count_api = 0
    
    
    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )
    
        ec2 = session.resource('ec2')
        apigateway = boto3.client('apigateway')
        
        try:
            response = apigateway.get_resources()
            count_api += 1
        
        except:
            response='No restapis found'
            
        print('  -Region {0} Response {1}'.format(AWS_REGION,response))
        
    if count_api == 0:
        print('No API gateways found')
        print('Due to lack of test environment no further code written')
    print(HR_LINE)  
    
    print('Checking All Supported Regions for CloudFront Resources')

    # Setup Variables for this section
    count_cf = 0


    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )
    
        ec2 = session.resource('ec2')
        cloudfront = boto3.client('cloudfront')
    
        try:
            response = cloudfront.get_distribution()
            count_cf += 1
    
        except:
            response='No CloudFront found'
    
        print('  -Region {0} Response{1}'.format(AWS_REGION,response))
    
    if count_cf == 0:
        print('No CloudFront gateways found')
        print('Due to lack of test environment no further code written')
    print(HR_LINE)  
                    
    print('Checking All Supported Regions for CodeBuild Resources')

    # Setup Variables for this section
    count_cb = 0


    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )

        ec2 = session.resource('ec2')
        codebuild = boto3.client('codebuild')

        try:
            response = codebuild.list_builds()
            count_cb += 1

        except:
            response='No CodeBuild found'

        print('  -Region {0} Response {1}'.format(AWS_REGION,response))

    if count_api == 0:
        print('No CodeBuild Resources found')
        print('Due to lack of test environment no further code written')
    print(HR_LINE)  

    print('Checking All Supported Regions for DynamoDB  Resources')

    # Setup Variables for this section
    count_ddb = 0


    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )

        ec2 = session.resource('ec2')
        client = boto3.client('dynamodb')

        try:
            response = client.list_tables()
            count_ddb += 1

        except:
            response='No DynamoDB  found'

        print('  -Region {0} Response {1}'.format(AWS_REGION,response))

    if count_ddb == 0:
        print('No DynamoDB  Resources found')
        print('Due to lack of test environment no further code written')
    print(HR_LINE)                          
     
     
     
     
    print('Checking All Supported Regions for S3 Buckets  Resources')

    # Setup Variables for this section
    count_s3 = 0


    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )

        ec2 = session.resource('ec2')
        client = boto3.client('s3')

        try:
            response = client.list_buckets()
            print(response)
            count_s3 += 1

        except:
            response='No S3 Buckets found'

        print('  -Region {0} Response {1}'.format(AWS_REGION,response))

    if count_s3 == 0:
        print('No S3 Buckets found')
        print('Due to lack of test environment no further code written')
    print(HR_LINE)  

    print('Checking All Supported Regions for ElasticSearch Resources')

    # Setup Variables for this section
    count_es = 0


    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )

        ec2 = session.resource('ec2')
        client = boto3.client('es')

        try:
            response = client.list_domain_names()
            print(response)
            count_es += 1

        except:
            response='No ElasticSearch Resources found'

        print('  -Region {0} Response {1}'.format(AWS_REGION,response))

    if count_es == 0:
        print('No ElasticSearch Resources')
        print('Due to lack of test environment no further code written')
    print(HR_LINE)                      
                

    print('Checking All Supported Regions for Redshift Resources')

    # Setup Variables for this section
    count_rs = 0


    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )

        ec2 = session.resource('ec2')
        client = boto3.client('redshift')

        try:
            response = client.describe_clusters()
            print(response)
            count_rs += 1

        except:
            response='No Redshift Resources found'

        print('  -Region {0} Response {1}'.format(AWS_REGION,response))

    if count_rs == 0:
        print('No Redshift Resources')
        print('Due to lack of test environment no further code written')
    print(HR_LINE)  


               
    print(HR_LINE)
    print('IP Summary of Report')
    header = ['Service','IP Address','DNS Name','Service Port','Security Group','Ports Open','IPv4 CIDR','IPv6 CIDR','Security Check']
    data = list()
    for IP in IP_DATA:
        data.append(IP)
        logger.debug(len(IP),IP)
    table = columnar(data, header, no_borders=False)
    print(table)
   


    print(HR_LINE)
    print("Service Counts")
    print("EC2 counts {ec2}".format(ec2=count_ec2))
    print("ELB counts {elb}".format(elb=count_elb))
    print("ELBv2 counts {elbv2}".format(elbv2=count_elbv2))
    print("RDS counts {rds}".format(rds=count_rds))
    print("CloudFront counts {cf}".format(cf=count_cf))
    print("CodeBuild counts {cb}".format(cb=count_cb))
    print("DynamoDB counts {ddb}".format(ddb=count_ddb))
    print("S3 counts {s3}".format(s3=count_s3))
    print("ElasticSearch counts {es}".format(es=count_es))
    print(HR_LINE)

    print('End of Program')
    return 0

if __name__ == "__main__":
    
   
    main()
