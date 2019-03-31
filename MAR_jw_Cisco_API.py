#!/usr/bin/env python3

##################
#Assumptions:
#   1. This program parses a inventory report csv file to find unique software versions.  If one isn't supplied via sys.argv, then the default from last month (NPL_Feb_Inventory.csv)
#   
#   2. For the bearer token for the Cisco API, a Client id/secret is needed.  This can be a file in the local directory (`credentials.json`) with the following format: { "CLIENT_ID": "<CLIENT-ID>", "CLIENT_SECRET": "<CLIENT-ID>"}.  Else, it will prompt for credentials.
# 
#   3. Warning, running this program against dozens of software versions can take a long time (about 18 minutes for 72 versions).
##################

#Rry to import pandas module, if this fails it probably isn't installed and therefore a warning message to install is displayed and programed in terminated.
try:
    import pandas
except:
    print('You need to install `Pandas` package to run this program. Run `pip install pandas` and try again, please!')
    exit()
#Sys is needed to input what file to parse.
import sys
#Pprint is a good tool for printing dictionaries
import pprint
#Requests needed for API call
import requests
#Json needed for getting API repsonse info
import json
#Getpass used as backup to enter API username/secret
import getpass
#Os used to read local password file
import os

#Function to convert csv to pandas datagram
def csv_to_pandas():
    #If there is a sys aruguement assign to variable.
    if len(sys.argv) > 1:
        vf_str_filename = sys.argv[1]
    #imports to pandas dataframe from csv, header=1 to skip first row.  Only need to include certain columns.
    #try to import csv from sys arguement filename.
    try:
        vf_pand_main = pandas.read_csv(vm_str_filename,header=1,usecols=['Device Name','Vendor','Model','Operating System','Device End-of-Service'])
    #if this fails, print error and then try default file ('NPL_Feb_Inventory.csv').
    except:
        print('Inputed file not found, trying default file')
        print('')
        try:
           vf_pand_main = pandas.read_csv('NPL_Feb_Inventory.csv',header=1,usecols=['Device Name','Vendor','Model','Operating System','Device End-of-Service'])
        #If that fails, print error and exit program.
        except:
            print('Inputted and default files not found, please run program again and select correct file/directory!')
            exit()
    #if successful, return dataframe back to main.
    return(vf_pand_main)

#Function to find unique vendor/model/OS combinations within the entire csv. These are then stored as list of dictionaries and passed back to main.
def extract_data(vf_pand_main):
    #extract unique OS versions from panda dataframe and convert to to list and then dictionary.
    vf_list_uniq_OS = vf_pand_main['Operating System'].unique()
    vf_dict_uniq_OS = {}
    for item in vf_list_uniq_OS:
        vf_dict_uniq_OS.update({item:[]})
    #Check is `XE` or `IOS` are in OS verion name, else mark as `N/A` - to be used later.
    for item in vf_dict_uniq_OS.keys():
        if 'XE' in item:
            vf_dict_uniq_OS[item]='XE'
        elif 'IOS' in item:
            vf_dict_uniq_OS[item]='IOS'
        else:
            vf_dict_uniq_OS[item]='N/A'
    return(vf_dict_uniq_OS)

#Function to Get API bearer token from Cisco.
def API_token():
    #Check is a `credentials.json` exists in local directory for the Client id/secret needed to get the bearer token.
    if os.path.isfile('./credentials.json'):
        with open('credentials.json', 'r') as vf_file_creds:
            vf_json_creds = json.load(vf_file_creds)
        try:
            vf_str_username = vf_json_creds['CLIENT_ID']
            vf_str_password = vf_json_creds['CLIENT_SECRET']
        except:
            print('Credentials file found but not in correct format.  Falling back to manual entry')
    #If there is no local credentials file, it prompts you.  FYI, getpass doesn't seem to work well in Windows.
    else:
        vf_str_username = input('client: ')
        vf_str_password = getpass.getpass(prompt='secret: ')

    #Put together parts of API call.
    vf_str_URL = 'https://cloudsso.cisco.com/as/token.oauth2'
    vf_str_payload = 'client_id=' + vf_str_username + '&client_secret=' + vf_str_password + '&grant_type=client_credentials'
    vf_str_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        }

    #Try API call, if it doesn't work, the program quits.
    try:
        vf_json_response = requests.request('POST', vf_str_URL, data=vf_str_payload, headers=vf_str_headers)
    except:
        print('something went wrong, check internet connection or credentials')
        exit()

    #Retrieve access token from API response and format.  Return formatted Bearer token to main.
    vf_json_data = json.loads(vf_json_response.text)
    vf_str_bearerkey = vf_json_data['access_token']
    vf_str_bearer_formatted = 'Bearer ' + vf_str_bearerkey
    return(vf_str_bearer_formatted)

#Function to make API calls to Cisco PSIRT openVuln API.
def get_advisories(vf_str_token,vf_dict_softver):
    print('WARNING, THIS PROCESS CAN TAKE SEVERAL MINUTES.')
    print('I HAVE IT PRINT A `!` AFTER EACH UNIQUE OS VERSION IS PROCESSED')
    #Set url for IOS compared to XE, anything else we just skip. Format to remove prefix info.
    for vf_str_item in vf_dict_softver.keys():
        print('!')
        if vf_dict_softver[vf_str_item] == 'XE':
            vf_str_URL = 'https://api.cisco.com/security/advisories/iosxe'
            vf_str_format = vf_str_item[7:]
        elif vf_dict_softver[vf_str_item] == 'IOS':
            vf_str_URL = 'https://api.cisco.com/security/advisories/ios'
            vf_str_format = vf_str_item[4:]
        else:
            continue

        #Other API parameters.
        vf_str_querystring = {'version':vf_str_format}
        vf_str_headers = {
            'Accept': 'application/json',
            'Authorization': vf_str_token,
            }
        #Try API call, else mark 'failed' in results dictionary.
        try:
            vf_json_response = requests.request('GET', vf_str_URL, headers=vf_str_headers, params=vf_str_querystring)
            vf_json_data = json.loads(vf_json_response.text)
            vf_list_advisories = vf_json_data['advisories']
            vf_dict_results = {}
            for vf_str_item2 in vf_list_advisories:
                vf_dict_results[vf_str_item2['advisoryId']]={'CVEs':vf_str_item2['cves'][0],'bugIDs':vf_str_item2['bugIDs'][0],'advisoryTitle':vf_str_item2['advisoryTitle'],'cvssBaseScore':vf_str_item2['cvssBaseScore'],'cwe':vf_str_item2['cwe'][0],'firstFixed':vf_str_item2['firstFixed'],'firstPublished':vf_str_item2['firstPublished'],'lastUpdated':vf_str_item2['lastUpdated']}
            vf_dict_softver[vf_str_item] = vf_dict_results
        except:
            vf_dict_softver[vf_str_item] = 'failed'
    #Return results dictionary to main.        
    return(vf_dict_softver)

#Function to list devices that either failed API, weren't applicable (Nexus or other), or list the number of vulernabilites.      
def list_no_API (vf_dict_softver):
    vf_list_API_fail = []
    vf_list_NA = []
    vf_dict_num_adv = {}
    #If 'failed' is the key value, add to failed list, else if 'N/A' is value add to NA list, else count advisories and add to dictionary.
    for vf_str_item in vf_dict_softver.keys():
        if vf_dict_softver[vf_str_item] == 'failed':
            vf_list_API_fail.append(vf_str_item)
        elif vf_dict_softver[vf_str_item] == 'N/A':
            vf_list_NA.append(vf_str_item)
        else:
            vf_int_count = len(vf_dict_softver[vf_str_item].keys())
            vf_dict_num_adv[vf_str_item] = vf_int_count
    #Add separate lists/dictionary to master list and return to main.
    vf_list_master = [vf_list_API_fail,vf_list_NA,vf_dict_num_adv]
    return(vf_list_master)

#Print all the things!
def print_stuff(vf_dict_final,vf_list_master):
    print('Devices where API call failed')
    print('-----------------------------')      
    for vf_str_item in vf_list_master[0]:
        print(vf_str_item)
    print('')
    print('Devices where software version was N/A')
    print('--------------------------------------')      
    for vf_str_item in vf_list_master[1]:
        print(vf_str_item)
    print('')
    print('Software/# of Advisories')
    print('------------------------')      
    for vf_str_item in vf_list_master[2]:
        print(vf_str_item,':',vf_list_master[2][vf_str_item])
    print('')
    input('THIS WILL BE A GIANT LIST OF INFO.  Press ENTER to Continue...')
    print('')
    print('Giant List of Software and Advisory Information')
    print('-----------------------------------------------')
    print('{:<14} {:<24} {:<16} {:<16} {:<8} {:<12} {:<12}'.format('OS Version','Advisory','CVE','bugIDs','Score','cwe','firstFixed'))
    for item in vf_dict_final:
        if vf_dict_final[item] != 'failed' and vf_dict_final[item] != 'N/A':
            for item2 in vf_dict_final[item]:
                print('{:<14} {:<24} {:<16} {:<16} {:<8} {:<12} {:<12}'.format(item[4:],item2[9:],vf_dict_final[item][item2]['CVEs'],vf_dict_final[item][item2]['bugIDs'],vf_dict_final[item][item2]['cvssBaseScore'],vf_dict_final[item][item2]['cwe'],vf_dict_final[item][item2]['firstFixed'][0]))    

#Main program.       
if __name__ == '__main__':
    #First import csv to pandas dataframe.
    vm_pand_main = csv_to_pandas()
    #Next organize material to print in list of dictionaries.
    vm_dict_softver = extract_data(vm_pand_main)
    #Get bearer token to be used for all API Calls.
    vm_str_token = API_token()
    #Get advisory information from Cisco PSIRT openVuln API.
    vm_dict_final = get_advisories(vm_str_token,vm_dict_softver)
    #Sort information.
    vm_list_master = list_no_API(vm_dict_final)
    #Print all the things!
    print_stuff(vm_dict_final,vm_list_master)
