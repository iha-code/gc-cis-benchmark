from google.cloud import storage
from google.api_core.exceptions import GoogleAPICallError
from google.api_core.exceptions import BadRequest

def req51(credentials, project_id):
    requirement = '5.1 Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible'
    status = ''
    description = ''
    public_bucket_list = []
    nonpublic_bucket_list = []
    try:
        storage_client = storage.Client()
        buckets = storage_client.list_buckets()
        try:
            for bucketitm in buckets:
                bucket = storage_client.get_bucket(bucketitm.name)
                iam_configuration = bucket.iam_configuration
                if bucket.iam_configuration.public_access_prevention == 'enforced':
                    nonpublic_bucket_list.append(bucket.name)
                else:
                    public_bucket_list.append(bucket.name)
            if len(public_bucket_list) and len(nonpublic_bucket_list) >= 0:
                status = 'Failed'
                description = f'The followings buckets {public_bucket_list} has not public access prevention'
            if len(nonpublic_bucket_list) > 0:
                status = 'Passed'
                description = f'The followings buckets {nonpublic_bucket_list} has public access prevention'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Buckets does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description

def req52(credentials, project_id):
    requirement = '5.2 Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled'
    status = ''
    description = ''
    uniform_bucket_list = []
    nonuniform_bucket_list = []
    try:
        storage_client = storage.Client()
        buckets = storage_client.list_buckets()
        try:
            for bucketitm in buckets:
                bucket = storage_client.get_bucket(bucketitm.name)
                iam_configuration = bucket.iam_configuration
                if bucket.iam_configuration.uniform_bucket_level_access_enabled == True:
                    uniform_bucket_list.append(bucket.name)
                else:
                    nonuniform_bucket_list.append(bucket.name)
            if len(nonuniform_bucket_list) and len(uniform_bucket_list) >= 0:
                status = 'Failed'
                description = f'For the followings buckets {nonuniform_bucket_list} are not enabled uniform bucket level access'
            if len(uniform_bucket_list) > 0:
                status = 'Passed'
                description = f'For the followings buckets {uniform_bucket_list} are enabled uniform bucket level access'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Buckets does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description