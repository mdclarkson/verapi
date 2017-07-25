# verapi

This Lambda function is using the latest version of the Veracode API available [here](http://www.rubydoc.info/gems/veracode-api)

In order to use this you will need:
- Generate AWS Access/Keys and create a AWS profile.
- You will need to get a veracode service user available in this link [here](https://analysiscenter.veracode.com)

### How it works

Go to veracode console and create and APP, create a sandbox into this app.
Get the information (ID) about your APP and your sandbox.
You need to post a JSON by using AWS signing v4 available [here](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- Specify the bucket where are located your files to scan.
- Specify the veracode_appid & veracode_sandboxid.
- Specify each file within the bucket.

KMS encrypted for API [here](https://github.com/marcy-terui/serverless-crypt)

### USAGE

To post files to scan you need to perform this command:

```
curl --header "Content-Type: application/json" -X POST  -d @resources/test_upload.json
```

To get the results you have to perform this command:

```
curl --header "Content-Type: application/json" -X GET
```


### POST API to Veracode

    {
      "filesData": {
        "bucket_name": "S3nw-sls-deploy-668385047392-prod",
        "veracode_appid": 325008,
        "veracode_sandboxid": 385022
        "data": [
          {
            "directory": "serverless/nwApiGateway/prod/",
            "filename": "nwApiGateway.zip"
          },
          {
            "directory":"serverless/nwClassicIntStreams/prod/",
            "filename": "nwClassicIntStreams.zip"
          },
          {
            "directory":"serverless/nwClassicIntegration/prod/",
            "filename": "nwClassicIntegration.zip"
          },
          {
            "directory":"serverless/nwIAM/prod/",
            "filename": "nwIAM.zip"
          },
          {
            "directory":"serverless/nwInfra/prod/",
            "filename": "nwInfra.zip"
          },
          {
            "directory":"serverless/nwVault/prod/",
            "filename": "nwVault.zip"
          },
          {
            "directory":"serverless/nwWatchlist/prod/",
            "filename": "nwWatchlist.zip"
          },
          {
            "directory":"serverless/nwWatchlistStreams/prod/",
            "filename": "nwWatchlistStreams.zip"
          }
        ]
      }
    }

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