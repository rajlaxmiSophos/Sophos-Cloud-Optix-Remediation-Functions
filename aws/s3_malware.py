
"""
Copyright 2022 Sophos Ltd. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing permissions and limitations
#under the License.
"""

import logging
import boto3
from botocore.exceptions import ClientError

bucket_name = "sophos-optix-s3-malware-remediation"

def create_bucket(bucket_name, region=None):
    """Create an S3 bucket in a specified region in which all the files which needs attention will be transferred

    If a region is not specified, the bucket is created in the S3 default
    region (us-east-1).

    :param bucket_name: Bucket to create
    :param region: String region to create bucket in, e.g., 'us-west-2'
    :return: True if bucket created, else False
    """

    # Create bucket
    try:
        if region is None:
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client = boto3.client('s3', region_name=region)
            location = {'LocationConstraint': region}
            s3_client.create_bucket(Bucket=bucket_name,
                                    CreateBucketConfiguration=location)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def move_file_to_remediation_bucket(src_bucket_name, dest_bucket_name, old_key_name):
    """ This function moves the malware files from the buckets to the remediation bucket
    """

    client = boto3.client('s3')
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(dest_bucket_name)
    if(version is None):
        copy_source = {
            'Bucket': src_bucket_name,
            'Key': old_key_name
        }
        obj = bucket.Object(old_key_name)
    else:
        copy_source = {
            'Bucket': src_bucket_name,
            'Key': old_key_name,
            'VersionId': version
        }
        obj = bucket.Object(version+'-'+old_key_name)

    obj.copy(copy_source)

    if(version is None):
        response = client.delete_object(
            Bucket=src_bucket_name,
            Key=old_key_name
        )
    else:
        response = client.delete_object(
            Bucket=src_bucket_name,
            Key=old_key_name,
            VersionId=version
        )


def lambda_handler(event, context):
    """ Starting function to s3 malware remediation for malware files present in the s3 buckets.
        Check if this function can remediate the event.
        If no, returns
        If yes, Move every malware file to the common remediation s3 bucket

        Args:
            event (dict):
                This is the payload with is sent via Optix, whenever an alert is generated.
            context (dict):
                This is the AWS lambda context.
            ec2_regions (list):
                List of all available regions

        Returns:
            str: Always returns "Remediation successful". Everything else is logged.
    """
    if event['eventType'] == 'ALERT' and event['payloadData']['alertType'] == 'S3 Malware':
        create_bucket(bucket_name)
        payload_data = event['payloadData']
        affected_resources = payload_data['affectedResources']
        for affected_resource in affected_resources:
            if affected_resource['state'] == "OPEN":
                try:
                    bucket = affected_resource['resourceInfo']
                    affectedResourceJSON = affected_resource['affectedResourceJSON']
                    affectedResourceJSONObject = eval(affectedResourceJSON)
                    affectedFiles = affectedResourceJSONObject['affectedFiles']
                    for file in affectedFiles:
                        version=None
                        if('version' in file):
                            version=file['version']
                        move_file_to_remediation_bucket(bucket, bucket_name, file['objectKey'] , version)
                except Exception as e:
                    print(e)

        return "Remediation successful"