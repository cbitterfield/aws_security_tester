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
EC2_INSTANCE_CONNECT
GLOBALACCELERATOR
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
    

    
    print('Conf {}'.format(configuration))
    
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
        
        if getattr(configuration,'aws_access_key') and getattr(configuration,'secret_access_key'):
            AWS_CREDENTIALS = {
                    'aws_access_key_id'     :  getattr(configuration,'aws_access_key'),
                    'aws_secret_access_key' :  getattr(configuration,'secret_access_key'),
  
                }
            if getattr(configuration,'aws_region'): AWS_DEFAULT_REGION=getattr(configuration,'aws_region')
        else:
            raise Exception ('You must pass AWS Keys, using the default profile is not enabled at this time')
            sys.exit(1)
            
        
    return 
            
    ### Program Functions and Classes
    #
    # Apply the following to all when possible
    # 
    # def function(**kwargs)
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
        
    parser.add_argument('-p', '--profile', type=str, help='AWS Profile to use',
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
    logger.debug(AWS_CREDENTIALS)
    
    # Get a set of regions that can support EC2s
    STATUS, AWS_REGIONS_IN_USE = getRegions(AWS_REGIONS=AWS_REGION_CHOICES, AWS_CREDENTIALS=AWS_CREDENTIALS)
    if STATUS:
        logger.info('AWS_REGIONS: {}'.format(AWS_REGIONS_IN_USE))
    else:
        raise Exception('No Available Regions')
        sys.exit(1)
    
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
        for tag in instance.tags:
            if 'Name'in tag['Key']:
                name = tag['Value']
        # Output EC2s and their information
        print("======================================================")
        print('Instance Name       : {}'.format(name))
        print('Instance Public IP  : {}'.format(instance.public_ip_address))
        print('Instance Public DNS : {}'.format(instance.public_dns_name))
        print('Instance Type       : {}'.format(instance.instance_type))
        print('Instance State      : {}'.format(instance.state['Name']))
        print('Instance Launch Time: {}'.format(instance.launch_time))
        print("======================================================")
        

        # Output the security group table for each instance
        sg_header = ['FromPort','ToPort','Protocol','IPv4','IPv6']
        sg_data = []
        ipv4Cidr = []
        ipv6Cidr = []
        
        for sg in instance.security_groups:
            security_group = ec2.SecurityGroup(sg['GroupId'])
            print('Security Group: {sg} Name {sg_name}'.format(sg=sg['GroupId'],sg_name=sg['GroupName']))
            for permission in security_group.ip_permissions:
                data = []
                data = [ permission.get('FromPort',''), permission.get('ToPort',''),permission.get('IpProtocol','')]
                for ip_range in permission.get('IpRanges',''):
                    ipv4Cidr = []
                    ipv4Cidr.append( ip_range.get('CidrIp','') )
                data.append(ipv4Cidr)
                print()
                for ip_range in permission.get('Ipv6Ranges',''):
                    ipv6Cidr = []
                    ipv6Cidr.append(ip_range.get('CidrIpv6',''))
                data.append(ipv6Cidr)   
            sg_data.append(data)   
                            
            table = columnar(sg_data, sg_header, no_borders=True)
            print(table)
            print("======================================================")
    
    
    
    ######################################################################################
    # Get Information about ELB
    
    for AWS_REGION in AWS_REGIONS_IN_USE:
        session = boto3.Session(
                    **AWS_CREDENTIALS,
                    region_name=AWS_REGION
                )
        elb = session.client('elb')
        ec2 = session.resource('ec2')
        response = elb.describe_load_balancers()
        if response['LoadBalancerDescriptions']:
            
            for load_balancer in response['LoadBalancerDescriptions']:
                print("======================================================")
                print('Load Balancer Name : {}'.format(load_balancer['LoadBalancerName']))
                print('Load Balancer DNS : {}'.format(load_balancer['DNSName']))
               
                
                
                # Output the security group table for each instance
                sg_header = ['FromPort','ToPort','Protocol','IPv4','IPv6']
                sg_data = []
                ipv4Cidr = []
                ipv6Cidr = []
    
                for sg in load_balancer['SecurityGroups']:
                    security_group = ec2.SecurityGroup(sg)
                    print('ELB Security GrpID  : {}'.format(security_group.group_id))
                    print('ELB Security GrpName: {}'.format(security_group.group_name))
                    print('ELB Security GrpDesc: {}'.format(security_group.description))
                    for permission in security_group.ip_permissions:
                        data = []
                        data = [ permission.get('FromPort',''), permission.get('ToPort',''),permission.get('IpProtocol','')]
                        for ip_range in permission.get('IpRanges',''):
                            ipv4Cidr = []
                            ipv4Cidr.append( ip_range.get('CidrIp','') )
                        data.append(ipv4Cidr)
    
                        for ip_range in permission.get('Ipv6Ranges',''):
                            ipv6Cidr = []
                            ipv6Cidr.append(ip_range.get('CidrIpv6',''))
                        data.append(ipv6Cidr)   
                        sg_data.append(data)   
                    table = columnar(sg_data, sg_header, no_borders=True)
                    print(table)
                    print("======================================================")
    
    print('End of Program')
    return 0

if __name__ == "__main__":
    
   
    main()
