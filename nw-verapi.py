__author__ = "Clyde Fondop"
#!/usr/local/bin/python3 -u
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
import os, boto3, base64, botocore, json, re

s3r = boto3.resource('s3')
s3 = boto3.client('s3')
kms = boto3.client('kms')

VERACODE_API_URL = 'https://analysiscenter.veracode.com/api/5.0/'

# Begin the scan with Veracode
def begin_scan(credential, payload):
    """Begins a scan."""
    api_endpoint = 'beginscan.do'
    if payload['modules']:
        payload['modules'] = ', '.join(payload['modules'])
    return api_submit(api_endpoint, credential, payload)

# Begin the pre scan then call scan API
def begin_prescan(credential, payload):
    """
    Begins the prescan.
    """
    api_endpoint = "beginprescan.do"
    return api_submit(api_endpoint, credential, payload)


def upload_file(credential, app_id, filename, sandbox_id, save_as):
    """Uploads a file"""
    fields = {'app_id': app_id}
    if sandbox_id:
        fields['sandbox_id'] = sandbox_id
    if save_as:
        fields['save_as'] = save_as
    fields['file'] = (filename, open(filename, 'rb'), 'application/binary')
    encoder = MultipartEncoder(fields=fields)
    callback = create_callback(encoder)
    monitor = MultipartEncoderMonitor(encoder, callback)

    api_endpoint = "uploadfile.do"
    r = requests.post(VERACODE_API_URL + api_endpoint, data=monitor, headers={'Content-Type': encoder.content_type},
                      auth=(credential["username"], credential["password"]))
    # print(r.text)
    return r


def create_callback(encoder):
    bar = ProgressBar(expected_size=encoder.len, filled_char='=', hide=False)

    def callback(monitor):
        bar.show(monitor.bytes_read)
    return callback

# Submit information to Veracode
def api_submit(api_endpoint, credential, payload=None, files=None):
    r = requests.post(VERACODE_API_URL + api_endpoint, params=payload, files=files,
                      auth=(credential["username"], credential["password"]))
    print(r.text)
    return r


# Decrypt environment variable
def decrypt_kms_keys(kms_keyid, encrypted_string):
    plaintext = ""

    meta = kms.decrypt(CiphertextBlob=encrypted_string)
    plaintext = meta[u'Plaintext']

    return plaintext

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

        self.credential = {}
        self.credential["username"] = os.environ.get("VERACODE_USERNAME")
        self.credential["password"] = os.environ.get("VERACODE_PASSWORD")


# check http response code
    def check_http_response(self, event):

        get_json = {}

        try:
            get_json = event
            checkJson = True
        except KeyError:
            self.response["body"] = self.bad_http_requests
            self.response['statusCode'] = 404
        except TypeError:
            self.response["body"] = self.bad_http_requests
            self.response['statusCode'] = 404

        return self.response, get_json


    # Download file from s3 bucket to Lambda
    def download_s3_files(self, file_to_download, filename):

        localFilename = self.lambda_file_path.format(os.path.basename(filename))
        try:
             s3.download_file(Bucket=self.bucket_name, Key=file_to_download, Filename=localFilename)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                print("The object does not exist.")
            elif e.response['Error']['Code'] == "403":
                print("You do not have the permnission to get the object {}".format(filename))
            else:
                raise

    # this function saves the files into lambda filesystem
    def save_lambda_fs(self, file):

        my_bucket = s3r.Bucket(self.bucket_name)
        for obj in my_bucket.objects.filter(Prefix=file["directory"]):
            if file["filename"] in obj.key:
                lastmodified_filename = obj.key


        self.download_s3_files(lastmodified_filename, file["filename"])

        return self.lambda_file_path.format(file["filename"]) # return filenname to send to Veracode


    # Multi Upload files
    def multi_upload_files(self, files):

        for obj in files:

            # Save files in Lambda /tmp then get filenames
             self.save_lambda_fs(obj)

        for file in files:

            # Upload files to Veracode
            file_in_fs = self.lambda_file_path.format(file["filename"])
            upload_file(self.credential, app_id='{}'.format(self.appID), filename='{}'.format(file_in_fs), sandbox_id='{}'.format(self.sandboxID), save_as="")

# Function which will call Veracode API
def lambda_function(context, event):
    MyMLF = ManageLambdaFunction()

    # check http response
    # response, func_lambda_variables = MyMLF.check_http_response(event)
    f = open("resources/upload_files.json", "r")
    func_lambda_variables = json.loads(f.read())

    filesData = func_lambda_variables["filesData"]

    MyMLF.sandboxID = filesData["veracode_sandboxid"]
    MyMLF.appID = filesData["veracode_appid"]
    MyMLF.bucket_name = filesData["bucket_name"]

    if func_lambda_variables:

        #  Call Upload API to Veracode with credential, filename and application information
        MyMLF.multi_upload_files(filesData["data"])
        print("Upload finished")

        # Call Function which will start the scan
        # Call the pre scan function to check the modules before scanning: autoscan: true => this will scan all the modules when the prescan finishes
        begin_prescan(MyMLF.credential,{'scan_all_nonfatal_top_level_modules': False, 'autoscan': True, 'sandbox_id': u'{}'.format(MyMLF.sandboxID), 'app_id': u'{}'.format(MyMLF.appID)})
        print("Scan submission finished")

if __name__ == "__main__":
    context = event = {}
    lambda_function(context, event)

