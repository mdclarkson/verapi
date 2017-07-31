__author__ = "Clyde Fondop"
#!/usr/local/bin/python
# title           : Lambda env vars
# description     : VeraCode API Upload Files and submission
#                   AWS Lambda Role Name:
#                   AWS Lambda Arn:
#
# author          : clyde
# date            :
# version         : 0.1
# usage           : python nw-verapi.py
# notes           :
# python_version  : 2.7
# ==============================================================================
#
#
#
# Import the modules needed to run the script.

import click
from clint.textui.progress import Bar as ProgressBar
import requests, ast
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
import logging
from os.path import expanduser
import os, boto3, base64, botocore, json, re, datetime
import xml.etree.ElementTree as ET
from base64 import b64decode
from botocore.exceptions import ClientError
from datetime import datetime
from dateutil import tz


s3r = boto3.resource('s3')
s3 = boto3.client('s3')
kms = boto3.client('kms')
lamb = boto3.client('lambda', region_name='us-east-1')

VERACODE_API_URL = 'https://analysiscenter.veracode.com/api/5.0/'


# Manage all functions
class ManageLambdaFunction:
    def __init__(self):
        self.message = {}
        self.lambda_file_path = "/tmp/{}"

        # Response Object
        self.response = {}
        self.response["body"] = {}
        self.response['headers'] = {'Access-Control-Allow-Origin': '*'}
        self.response['statusCode'] = 200
        self.bad_http_requests = "Error requests wrong format"
        self.tab_files = []

        # AWS / Veracode Informations
        self.bucket_name = ""
        self.sandboxID = ""
        self.prefix_bucket = ""
        self.environment = ""
        self.appID = ""


    # Return Response event for API gateway
    def get_response(self):
        return self.response

    # Get last modified file
    def get_last_modified(self, obj):
        objName = fullName = ""
        from_zone = tz.gettz('UTC')
        utc = datetime.strptime('2000-01-21 02:37:21', '%Y-%m-%d %H:%M:%S') # make sure that the datetime is old enough
        utc = utc.replace(tzinfo=from_zone)
        my_bucket = s3r.Bucket(self.bucket_name)

        lastmodified = utc
        try:
            for key in my_bucket.objects.filter(Prefix="{}/{}/{}".format(self.prefix_bucket, obj["directory"], self.environment)):
                if lastmodified < key.last_modified and obj["filename"] in key.key:
                    lastmodified = key.last_modified
                    objName = obj["filename"]
                    fullName = key.key
                    self.tab_files.append(obj["filename"])
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                self.response["body"] = "The object does not exist {}".format(obj["directory"]+obj["filename"])
                self.response["statusCode"] = 403
            elif e.response['Error']['Code'] == "403":
                self.response["body"] = "You do not have the permission to get the object {}".format(obj["directory"]+obj["filename"])
                self.response["statusCode"] = 403
            elif e.response['Error']['Code'] in ['ParamValidationError','NoSuchBucket']:
                self.response["body"] = "The object does not exist {}".format(self.bucket_name)
                self.response["statusCode"] = 403
            else:
                raise

        return objName, fullName

    # Download file from s3 bucket to Lambda
    def download_s3_files(self):
        result_folder = s3.list_objects(Bucket=self.bucket_name, Prefix="{}/".format(self.prefix_bucket), Delimiter='/')

        data = []
        for o in result_folder.get('CommonPrefixes'):

            obj = {
                "directory":o.get('Prefix').split("/")[1],
                "filename":"{}.zip".format(o.get('Prefix').split("/")[1])
            }
            data.append(obj)
            obj = {}

        for obj_info in data:
            objName, fullName = self.get_last_modified(obj_info)
            localFilename = self.lambda_file_path.format(os.path.basename(objName))

            if objName:
                s3.download_file(Bucket=self.bucket_name, Key=fullName, Filename=localFilename)

        return self.response["statusCode"]

# Manage all functions
class veracodeAPI:
    def __init__(self):
        self.message = {}
        self.credential = {}
        self.credential["username"] = self.decrypt_kms_keys(os.environ.get("USERNAME"))
        self.credential["password"] = self.decrypt_kms_keys(os.environ.get("PASSWORD"))
        # self.credential["username"] = os.environ.get("USERNAME")
        # self.credential["password"] = os.environ.get("PASSWORD")


    # Begin the scan with Veracode
    def begin_scan(self, credential, payload):
        """Begins a scan."""
        api_endpoint = 'beginscan.do'
        if payload['modules']:
            payload['modules'] = ', '.join(payload['modules'])
        return self.api_submit(api_endpoint, credential, payload)

    # Begin the pre scan then call scan API
    def begin_prescan(self, payload):
        """
        Begins the prescan.
        """
        api_endpoint = "beginprescan.do"
        return self.api_submit(api_endpoint, payload)

    # Function d upload file for Veracode
    def upload_file(self, app_id, filename, save_as, sandbox_id):
        sandbox_id= ""
        """Uploads a file"""
        fields = {'app_id': app_id}
        if sandbox_id:
            fields['sandbox_id'] = sandbox_id
        if save_as:
            fields['save_as'] = save_as
        fields['file'] = (filename, open(filename, 'rb'), 'application/binary')
        encoder = MultipartEncoder(fields=fields)
        callback = self.create_callback(encoder)
        monitor = MultipartEncoderMonitor(encoder, callback)

        api_endpoint = "uploadfile.do"
        r = requests.post(VERACODE_API_URL + api_endpoint, data=monitor, headers={'Content-Type': encoder.content_type},
                          auth=(self.credential["username"], self.credential["password"]))
        return r

    # Encode request for Veracode
    def create_callback(self, encoder):
        bar = ProgressBar(expected_size=encoder.len, filled_char='=', hide=False)

        def callback(monitor):
            bar.show(monitor.bytes_read)
        return callback

    # Get scans results
    def get_prescan_results(self, payload):
        """Gets the results of a prescan."""
        api_endpoint = "getprescanresults.do"
        return self.api_submit(api_endpoint, payload)

    # Submit information to Veracode
    def api_submit(self, api_endpoint, payload=None, files=None):
        r = requests.post(VERACODE_API_URL + api_endpoint, params=payload, files=files,
                          auth=(self.credential["username"], self.credential["password"]))
        return r


    # Decrypt environment variable
    def decrypt_kms_keys(self, object):
        decrypted = boto3.client('kms').decrypt(CiphertextBlob=b64decode(object))['Plaintext']

        return decrypted


# Open XML and Match XML text
def match_string_text(string, root):
    return re.match(string, root.text)

# Open XML and Match XML tag
def match_string_tag(string, root):
    return re.match(string, root.tag)

# Function which will call Veracode API
def lambda_function_postfiles(event, context):
    MyMLF = ManageLambdaFunction()
    MyVAPI = veracodeAPI()
    filesData = {}
    http_param = ""

    try:
        http_param = ast.literal_eval(event["body"])
    except KeyError:
        MyMLF.response["body"] = "You should specify a body"


    if http_param:
        try:
            filesData = http_param

            MyMLF.appID = filesData["veracode_appid"]
            MyMLF.bucket_name = filesData["bucket_name"]
            MyMLF.prefix_bucket = filesData["prefix_bucket"]
            MyMLF.environment = filesData["environment"]
            MyMLF.sandboxID = filesData["veracode_sandboxid"]
        except TypeError:
            MyMLF.response["body"] = "Wrong format HTTP request Please check your content type"
            MyMLF.response["statusCode"] = 404
        except KeyError:
            MyMLF.response["body"] = "Wrong key, check your input json"
            MyMLF.response["statusCode"] = 404

    if filesData:

        #  Call Upload API to Veracode with credential, filename and application information
        MyMLF.download_s3_files()

        if MyMLF.response["statusCode"] == 200:

            # Unique table of file
            uniq_tab_files = sorted(set(MyMLF.tab_files))

            for file in uniq_tab_files:

                # Upload files to Veracode
                file_in_fs = MyMLF.lambda_file_path.format(file)

                try:
                    r = MyVAPI.upload_file(app_id='{}'.format(MyMLF.appID), filename='{}'.format(file_in_fs), save_as="", sandbox_id=MyMLF.sandboxID)
                except IOError:
                    MyMLF.response["statusCode"] = 404
                    MyMLF.response["body"] = "No such file or directory: {}".format(file_in_fs)

            print("\n")
            if MyMLF.response["statusCode"] == 200:
                # Call Function which will start the scan
                # Call the pre scan function to check the modules before scanning: autoscan: true => this will scan all the modules when the prescan finishes

                # try:
                r = MyVAPI.begin_prescan({'scan_all_nonfatal_top_level_modules': True, 'autoscan': True,  'app_id': u'{}'.format(MyMLF.appID), 'sandbox_id':MyMLF.sandboxID})
                try:
                    root = ET.fromstring(r.text)
                    if match_string_text("A scan request has already been submitted for this build.", root):
                        MyMLF.response["body"] = "A scan request has already been submitted for this build."
                        MyMLF.response["statusCode"] = 200
                    if match_string_text("Access denied.", root):
                        MyMLF.response["body"] = "Access Denied to submit the upload: check sandboxID/appID"
                        MyMLF.response["statusCode"] = 403
                    if match_string_tag("buildinfo", root):
                        MyMLF.response["body"] = "scan properly submitted {}".format(datetime.now().isoformat())
                        MyMLF.response["statusCode"] = 200
                except TypeError:
                    MyMLF.response["body"] = "scan properly submitted {}".format(datetime.now().isoformat())
                    MyMLF.response["statusCode"] = 200

    response = MyMLF.get_response()
    print("{} {}".format(datetime.now().isoformat(),response))

    return response

# Call Veracode Function which will get results
def lambda_function_getresults(event, context):
    MyMLF = ManageLambdaFunction()
    MyVAPI = veracodeAPI()
    scan_results = []
    veracode_attributs = {}
    http_param = {}

    # check http response
    try:
        http_param = event["path"]
    except KeyError:
        MyMLF.response["body"] = "You should specify an appid in the path parameter"

    # Check appid
    if http_param:
        appid = ast.literal_eval(http_param['appid'])

        # Call function to check the results
        results = MyVAPI.get_prescan_results({'app_id':"{}".format(appid)})

        #### Check results #####
        root = ET.fromstring(results.text)
        for child in root:
            if  "status" in child.attrib:

                veracode_attributs = {
                    "name": child.attrib["name"],
                    "platform": child.attrib["platform"],
                    "status": child.attrib["status"]
                }

                scan_results.append(veracode_attributs)
        MyMLF.response["body"] = scan_results
    response = MyMLF.get_response()

    print("{} {}".format(datetime.now().isoformat(),response))

    return response


# Test case
if __name__ == "__main__":
    context = event = {}
    lambda_function_getresults(event, context)

