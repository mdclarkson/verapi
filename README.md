# verapi

This Lambda function is using the latest version of the Veracode API available [here](http://www.rubydoc.info/gems/veracode-api)

In order to use this you will need:
- Generate AWS Access/Keys and create a AWS profile.
- You will need to get a veracode service user available in this link [here](https://analysiscenter.veracode.com)

This is only AWS on AWS NW AWS QA environment.

### How it works

Go to veracode console and create and APP, create a sandbox into this app.
Get the information (ID) about your APP and your sandbox.
You need to post a JSON by using AWS signing v4 available [here](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- Specify the bucket where are located your files to scan.
- Specify the veracode_appid & veracode_sandboxid.
- Specify each file within the bucket.

KMS encrypted for API [here](https://github.com/marcy-terui/serverless-crypt)

### USAGE

You need to specify IAM Auth in your requests
- AccessKey [your-access-key]
- SecretKey: [your-secret-access-key]
- AWS Region: us-east-1
- Service Name: execute-api

To post files to scan you need to perform this command:
PS: Because of API Gateway 30 seconds limitation, POST operations are not available for a build which requires important file size.

```
curl --header "Content-Type: application/json" -X POST https://qytqx7orfl.execute-api.us-east-1.amazonaws.com/qa/api/nwVerapi/sendFiles -d @resources/test_upload.json
```

To get the results you have to perform this command:

```
curl --header "Content-Type: application/json" -X GET ttps://qytqx7orfl.execute-api.us-east-1.amazonaws.com/qa/api/nwVerapi/getResults/{appid}
```


### POST API to Veracode
```
{
  "filesData": {
    "bucket_name": "nw-sls-deploy-941794040565-qa",
    "veracode_appid": 326812,
    "prefix_bucket": "serverless",
    "environment": "qa"
    }
}
```

## GET results from Veracode
```
{
   "body":[
      {
         "status":"OK",
         "platform":"JAVASCRIPT / JavaScript / JAVASCRIPT_5_1",
         "name":"JS files within nw-iam-master.zip"
      },
      {
         "status":"OK",
         "platform":"JVM / Java J2SE 6 / JAVAC_5",
         "name":"gradle-wrapper.jar"
      }
   ],
   "headers":{
      "Access-Control-Allow-Origin":"*"
   },
   "statusCode":200
}
```