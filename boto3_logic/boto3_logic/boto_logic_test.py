#!/usr/bin/env python3
'''
Boto3 Credential Logic Check
'''

# Required
import os
import sys
import shutil
import argparse
import time
from datetime import datetime


# Program Specific library imports
import boto3



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
DEBUG=False

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
    
    
def main():
    CONFIG = getCLIparams(None)
    setup(CONFIG)
    
    print(CONFIG)
    
    session = boto3.Session()
        
        
    ec2 = session.resource('ec2')
    # Get information for all running instances
    running_instances = ec2.instances.filter(Filters=[
        {
        'Name': 'instance-state-name',
        'Values': ['running']
        }
        ])
    for instance in running_instances:
        print(instance)
    
    return 


if __name__ == "__main__":
    
   
    main()