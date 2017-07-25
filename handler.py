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
import requests
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
import logging
from os.path import expanduser
import os, boto3, base64, botocore, json, re, datetime
import xml.etree.ElementTree as ET


s3r = boto3.resource('s3')
s3 = boto3.client('s3')
kms = boto3.client('kms')

VERACODE_API_URL = 'https://analysiscenter.veracode.com/api/5.0/'


# Manage all functions
class ManageLambdaFunction:
    def __init__(self):
        self.message = {}
        self.lambda_file_path = "/tmp/{}"

        # Response Object
        self.response = {}
        self.response['headers'] = {'Access-Control-Allow-Origin': '*'}
        self.response['statusCode'] = 200
        self.bad_http_requests = "Error requests wrong format"

        self.bucket_name = ""
        self.sandboxID = ""
        self.appID = ""


    # check http response code
    def check_http_response(self, event):

        get_json = {}

        f = open("resources/upload_files.json", "r")

        try:
            get_json = json.loads(f.read())
            checkJson = True
        except KeyError:
            self.response["body"] = self.bad_http_requests
            self.response['statusCode'] = 404
        except TypeError:
            self.response["body"] = self.bad_http_requests
            self.response['statusCode'] = 404

        return get_json

    # Download file from s3 bucket to Lambda
    def download_s3_files(self, file_to_download, filename):

        localFilename = self.lambda_file_path.format(os.path.basename(filename))
        try:
            s3.download_file(Bucket=self.bucket_name, Key=file_to_download, Filename=localFilename)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                self.response["body"] = "The object does not exist {}".format(filename)
                self.response["statusCode"] = 403
            elif e.response['Error']['Code'] == "403":
                self.response["body"] = "You do not have the permnission to get the object {}".format(filename)
                self.response["statusCode"] = 403
            else:
                raise


    # Multi Upload files
    def multi_upload_files(self, files):

        for obj in files:

            # Save files in Lambda /tmp then get filenames
            try:
                my_bucket = s3r.Bucket(self.bucket_name)
                for obj in my_bucket.objects.filter(Prefix=file["directory"]):
                    if file["filename"] in obj.key:
                        lastmodified_filename = obj.key
            except:
                self.response["body"] = "The object does not exist {}".format(my_bucket.name)
                self.response["statusCode"] = 404

            if self.response["statusCode"] == 200:
                self.download_s3_files(lastmodified_filename, file["filename"])

        return self.response["statusCode"]


    # Return Response event for API gateway
    def get_response(self):
        return self.response

# Manage all functions
class veracodeAPI:
    def __init__(self):
        self.message = {}
        self.credential = {}
        self.credential["username"] = self.decrypt_kms_keys("username")
        self.credential["password"] = self.decrypt_kms_keys("password")


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
    def upload_file(self, app_id, filename, sandbox_id, save_as):
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
        # print(r.text)
        return r

    # Encode request for Veracode
    def create_callback(self, encoder):
        bar = ProgressBar(expected_size=encoder.len, filled_char='=', hide=False)

        def callback(monitor):
            bar.show(monitor.bytes_read)
        return callback

    # Submit information to Veracode
    def api_submit(self, api_endpoint, payload=None, files=None):
        r = requests.post(VERACODE_API_URL + api_endpoint, params=payload, files=files,
                          auth=(self.credential["username"], self.credential["password"]))
        return r


    # Decrypt environment variable
    def decrypt_kms_keys(self, encrypted_string):
        plaintext = ""

        meta = kms.decrypt(CiphertextBlob=encrypted_string)
        plaintext = meta[u'Plaintext']

        return plaintext


# Open XML and Match XML text
def match_string_text(string, root):
    return re.match(string, root.text)

# Open XML and Match XML tag
def match_string_tag(string, root):
    return re.match(string, root.tag)

# Function which will call Veracode API
def lambda_function(context, event):
    MyMLF = ManageLambdaFunction()
    MyVAPI = veracodeAPI()

    # check http response
    func_lambda_variables = MyMLF.check_http_response(event)

    filesData = func_lambda_variables["filesData"]

    MyMLF.sandboxID = filesData["veracode_sandboxid"]
    MyMLF.appID = filesData["veracode_appid"]
    MyMLF.bucket_name = filesData["bucket_name"]

    if func_lambda_variables:

        #  Call Upload API to Veracode with credential, filename and application information
        statusCode = MyMLF.multi_upload_files(filesData["data"])

        if statusCode == 200:

            for file in filesData["data"]:
                # Upload files to Veracode
                file_in_fs = MyMLF.lambda_file_path.format(file["filename"])
                r = MyVAPI.upload_file(app_id='{}'.format(MyMLF.appID), filename='{}'.format(file_in_fs), sandbox_id='{}'.format(MyMLF.sandboxID), save_as="")

            print("\n")
            # Call Function which will start the scan
            # Call the pre scan function to check the modules before scanning: autoscan: true => this will scan all the modules when the prescan finishes
            r = MyVAPI.begin_prescan({'scan_all_nonfatal_top_level_modules': False, 'autoscan': True, 'sandbox_id': u'{}'.format(MyMLF.sandboxID), 'app_id': u'{}'.format(MyMLF.appID)})
            root = ET.fromstring(r.text)
            if match_string_text("A scan request has already been submitted for this build.", root):
                MyMLF.response["body"] = "A scan request has already been submitted for this build."
            if match_string_text("Access Denied", root):
                MyMLF.response["body"] = "Access Denied to submit the upload: check sandboxID/appID"
            if match_string_tag("buildinfo", root):
                MyMLF.response["body"] = "scan properly submitted {}".format(datetime.datetime.now().isoformat())

    response = MyMLF.get_response()

    return response

if __name__ == "__main__":
    context = event = {}
    lambda_function(context, event)

