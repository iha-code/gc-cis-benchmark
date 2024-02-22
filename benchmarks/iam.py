import datetime
import re
import json
from datetime import datetime, timedelta
from google.api_core.exceptions import GoogleAPICallError
from googleapiclient.errors import HttpError
from google.api_core.exceptions import BadRequest
from google.cloud import api_keys_v2
from google.cloud import dataproc_v1
from google.cloud import essential_contacts_v1
from google.cloud import functions_v1
from google.cloud import kms_v1
import googleapiclient.discovery
from googleapiclient.discovery import build
from google.oauth2 import service_account


def req1(credentials, project_id):
    requirement = '1.1 Ensure that Corporate Login Credentials are Used'
    status = ''
    description = ''
    try:
        service = googleapiclient.discovery.build('iam', 'v1', credentials=credentials)
        service_accounts = service.projects().serviceAccounts().list(name='projects/' + project_id).execute()
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for account in service_accounts['accounts']:
                keys = service.projects().serviceAccounts().keys().list(
                    name='projects/-/serviceAccounts/' + account['email']).execute()
                for key in keys:
                    keyList = json.dumps(list(map(lambda x: x[0], keys.values()))[0])
                    jsonKeyList = json.loads(keyList)
                    if jsonKeyList["keyOrigin"] != 'GOOGLE_PROVIDED':
                        account_list = list(account['email'])
                        status = 'Failed'
                        description = f'Email: {account_list} has a non-GCP-managed key'
                    else:
                        account_list = list(account['email'])
                        status = 'Passed'
                        description = f'Emails:  {account_list} has a GCP-managed key'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Account does not exist'
    except HttpError as e:
        if str(e.resp.status) == '403':
            status = 'Disabled'
            description = f'{e.reason}'
        else:
            status = 'Denied'
            description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req2():
    requirement = '1.2 Ensure that Multi-Factor Authentication is Enabled for All Non-Service Accounts'
    status = 'Unknown'
    description = 'This requirement require manuel checking'
    return requirement, status, description


def req3(credentials, project_id):
    requirement = '1.3 Ensure that Security Key Enforcement is Enabled for All Admin Accounts'
    status = ''
    description = ''
    try:
        service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for binding in policy['bindings']:
                roles = [re.match("(.+?)[aA]dmin|(.+?)owner", binding['role'])]
                members = [binding['members']]
                if roles != [None]:
                    for role in roles:
                        i = 0
                        for member in members:
                            if member[i].startswith("user:"):
                                for member[i] in member:
                                    status = 'Failed'
                                    description = f'For the following user {member[i]}  with the role {role.group()} perform Manual Security Key Enforcement'
                                    i = i + 1
                                    if i == len(member):
                                        break
                            else:
                                status = 'Passed'
                                description = f'For the following user {member[i]}  with the role {role.group()} is enabled Security Key Enforcement'
        except HttpError as e:
            if str(e.resp.status) == '403' and str(e.resp.reason) == 'Forbidden':
                status = 'Denied'
                description = f'{e.reason}'
            elif str(e.resp.status) == '403':
                status = 'Disabled'
                description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req4(credentials, project_id):
    requirement = '1.4 Ensure That There Are Only GCP-Managed Service Account Keys for Each Service Account'
    status = ''
    description = ''
    system_key_list = []
    google_key_list = []
    try:
        service = googleapiclient.discovery.build('iam', 'v1', credentials=credentials)
        resource = f'projects/{project_id}/serviceAccounts/{service_account}'
        service_accounts = service.projects().serviceAccounts().list(name='projects/' + project_id).execute()
        try:
            for account in service_accounts['accounts']:
                account_email = account['name']
                keys = service.projects().serviceAccounts().keys().list(
                    name='projects/-/serviceAccounts/' + account['email']).execute()
                for key in keys['keys']:
                    if key['keyType'] != "SYSTEM_MANAGED":
                        google_key_list.append(key.keys)
                    else:
                        system_key_list.append(key.keys)
                if len(system_key_list) > 0:
                    status = 'Failed'
                    description = f'For the following service accounts {system_key_list} found Non-GCP-managed keys!'
                else:
                    status = 'Passed'
                    description = f'For the following service accounts {google_key_list} found are GCP-managed keys!'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Keys does not exist'
    except HttpError as e:
        if str(e.resp.status) == '403':
            status = 'Disabled'
            description = f'{e.reason}'
        else:
            status = 'Denied'
            description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req5(credentials, project_id):
    requirement = '1.5 Ensure That Service Account Has No Admin Privileges'
    status = ''
    description = ''
    res = {}
    role_list = []
    member_list = []
    try:
        service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for binding in policy['bindings']:
                role = binding['role']
                x = re.match("(.+?)[Aa]dmin|(.+?)oles/owner|(.+?)oles/editor", role)
                if x != None:
                    for member in binding['members']:
                        if member.startswith('serviceAccount:') and binding['role'] == x.group():
                            role_list.append(role)
                            member_list.append(member)
            for key in role_list:
                for value in member_list:
                    res[key] = value
            if len(str(res)) > 0:
                status = 'Failed'
                description = f"For the followings service account {str(res)} remove listed role"
            else:
                status = 'Passed'
                description = f'The followings service account has not admin privileges'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Roles does not exist'
        except HttpError as e:
            if str(e.resp.status) == '403':
                status = 'Disabled'
                description = f'{e.reason}'
            else:
                status = 'Denied'
                description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req6(credentials, project_id):
    requirement = '1.6 Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level'
    status = ''
    description = ''
    res = {}
    role_list = []
    member_list = []
    try:
        service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for binding in policy['bindings']:
                if binding['role'] == 'roles/iam.serviceAccountUser' or binding[
                    'role'] == 'roles/iam.serviceAccountTokenCreator':
                    for member in binding['members']:
                        if member.startswith('user:'):
                            role = binding['role']
                            role_list.append(role)
                            member_list.append(member)
            for key in role_list:
                for value in member_list:
                    res[key] = value
            if len(str(res)) > 0:
                status = 'Failed'
                description = f'The following user {str(res)} has the  role at the project level'
            else:
                status = 'Passed'
                description = f'Does not exist users are not assigned the service account user or service account token creator roles at project level'
        except HttpError as e:
            if str(e.resp.status) == '403':
                status = 'Disabled'
                description = f'{e.reason}'
            else:
                status = 'Denied'
                description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req7(credentials, project_id):
    requirement = '1.7 Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days or Fewer'
    status = ''
    description = ''
    rotated_keys = []
    nonrotated_keys = []
    now = datetime.now()
    ninety_days_ago = now - timedelta(days=90)
    try:
        service = googleapiclient.discovery.build('iam', 'v1', credentials=credentials)
        service_accounts = service.projects().serviceAccounts().list(name='projects/' + project_id).execute()
        try:
            for account in service_accounts['accounts']:
                keys = service.projects().serviceAccounts().keys().list(
                    name='projects/-/serviceAccounts/' + account['email']).execute()
                if keys:
                    for key in keys['keys']:
                        if key['keyType'] == 'USER_MANAGED' or key['keyType'] == 'KEY_TYPE_UNSPECIFIED':
                            key_rotation_time = datetime.strptime(key['validAfterTime'], '%Y-%m-%dT%H:%M:%SZ')
                            if key_rotation_time < ninety_days_ago:
                                rotated_keys.append(key["name"])
                            else:
                                nonrotated_keys.append(key["name"])
                else:
                    status = 'Unknown'
                    description = f'Keys does not exist'
            if len(rotated_keys) > 0:
                status = 'Passed'
                description = f'User-Managed or External Keys {rotated_keys} for Service Accounts are rotated every 90 days'
            if len(nonrotated_keys) > 0 and len(rotated_keys) >= 0:
                status = 'Failed'
                description = f'Keys: {nonrotated_keys} has not been rotated in the last 90 days'
            if len(nonrotated_keys) == 0 and len(rotated_keys) == 0:
                status = 'Unknown'
                description = f'Keys does not exist'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Keys does not exist'
    except HttpError as e:
        if str(e.resp.status) == '403':
            status = 'Disabled'
            description = f'{e.reason}'
        else:
            status = 'Denied'
            description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req8(credentials, project_id):
    requirement = '1.8 Ensure That Separation of Duties Is Enforced While Assigning Service Account Related Roles to Users'
    status = ''
    description = ''
    separated_roles = []
    nonseparated_roles = []
    try:
        service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for binding in policy['bindings']:
                if binding['role'] == 'roles/iam.serviceAccountUser' and binding[
                    'role'] == 'roles/iam.serviceAccountAdmin':
                    for member in binding['members']:
                        if member.startswith('user:'):
                            role = binding['role']
                            nonseparated_roles.append(role)
                        else:
                            separated_roles.append(role)
                else:
                    status = 'Unknown'
                    description = f'Required roles does not exist'
            if len(nonseparated_roles) > 0 and len(separated_roles) >= 0:
                status = 'Failed'
                description = f'For the following users: {nonseparated_roles} separate of duties at the project level'
            if len(separated_roles) > 0:
                status = 'Passed'
                description = f'For the following users: {separated_roles} are separated duties at the project level'
            if len(nonseparated_roles) == 0 and len(separated_roles) == 0:
                status = 'Unknown'
                description = f'Roles does not exist at the project level'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Policy does not exist'
        except HttpError as e:
            if str(e.resp.status) == '403':
                status = 'Disabled'
                description = f'{e.reason}'
            else:
                status = 'Denied'
                description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req9(credentials, project_id):
    requirement = '1.9 Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible'
    status = ''
    description = ''
    protected_keys = []
    nonprotected_keys = []
    try:
        # Create KMS client object
        kms_client = kms_v1.KeyManagementServiceClient(credentials=credentials)
        # Create IAM API client object
        iam_service = build('iam', 'v1', credentials=credentials)
        # Get list of CryptoKeys in project
        parent = f'projects/{project_id}/locations/global/keyRings'
        keylistrings = kms_client.list_key_rings(request={'parent': parent})
        for key_ring in keylistrings:
            if key_ring:
                key_ring_name = key_ring.name
                for crypto_key in kms_client.list_crypto_keys(key_ring_name):
                    crypto_key_name = crypto_key.name.split('/')[-1]
                    policy = iam_service.projects().locations().keyRings().cryptoKeys().getIamPolicy(
                        resource=crypto_key_name).execute()
                    for binding in policy['bindings']:
                        if binding['role'] == 'roles/cloudkms.cryptoKeyEncrypterDecrypter' or binding[
                            'role'] == 'roles/cloudkms.cryptoKeyEncrypter' or binding[
                            'role'] == 'roles/cloudkms.cryptoKeyDecrypter' or binding[
                            'role'] == 'roles/cloudkms.admin':
                            if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                                nonprotected_keys.append(crypto_key_name)
                            else:
                                protected_keys.append(crypto_key_name)
            else:
                status = 'Unknown'
                description = f"Key ring does not exist"
        if len(nonprotected_keys) > 0 and len(protected_keys) >= 0:
            status = 'Failed'
            description = f'Error: CryptoKey {nonprotected_keys} has permissions for allUsers or allAuthenticatedUsers'
        if len(protected_keys) > 0:
            status = 'Passed'
            description = f'CryptoKey {protected_keys} does not have permissions for allUsers or allAuthenticatedUsers'
        if len(nonprotected_keys) == 0 and len(protected_keys) == 0:
            status = 'Unknown'
            description = f"Keys does not exist"
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req10(credentials, project_id):
    requirement = '1.10 Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days'
    status = ''
    rotated_keys = []
    nonrotated_keys = []
    location_id = 'global'
    parent = f'projects/{project_id}/locations/{location_id}/keyRings'
    try:
        # Create client object
        client = kms_v1.KeyManagementServiceClient(credentials=credentials)
        # Set rotation period
        rotation_period = timedelta(days=90)
        keyringlist = client.list_key_rings(request={'parent': parent})
        for key_ring in keyringlist:
            if key_ring:
                key_ring_name = key_ring.name
                parent_value = f'projects/{project_id}/locations/{location_id}/keyRings/{key_ring_name}'
                crypto_keys_request = kms_v1.ListCryptoKeysRequest(parent=parent_value)
                for crypto_key in client.list_crypto_keys(request=crypto_keys_request):
                    crypto_key_name = client.crypto_key_path(project_id, location_id, key_ring_name,
                                                             crypto_key.name)
                    parent_key_value = f'projects/{project_id}/locations/{location_id}/keyRings/{key_ring_name}/cryptoKeys/{crypto_key_name}'
                    crypto_key_request = kms_v1.ListCryptoKeyVersionsRequest(parent=parent_key_value)
                    crypto_key_version = client.list_crypto_key_versions(crypto_key_request)
                    # Get the latest key version
                    try:
                        latest_key_version = max(crypto_key_version, crypto_key=lambda x: x.create_time)
                    except ValueError as e:
                        print('ValueError :', e)
                        # Calculate the time difference between now and the creation time of the latest key version
                        time_difference = datetime.utcnow() - latest_key_version.create_time
                        # Check if the time difference is greater than the rotation period
                        if time_difference > rotation_period:
                            nonrotated_keys.append(crypto_key.name)
                        elif time_difference < rotation_period:
                            rotated_keys.append(crypto_key.name)
            else:
                status = 'Unknown'
                description = f"Key ring does not exist"
        if len(nonrotated_keys) > 0 and len(rotated_keys) >= 0:
            status = 'Failed'
            description = f'Keys {nonrotated_keys} are not rotated within the rotation period of 90 days'
        if len(rotated_keys) > 0:
            status = 'Passed'
            description = f'KMS Encryption keys {rotated_keys} are rotated within a period of 90 days'
        if len(nonrotated_keys) == 0 and len(rotated_keys) == 0:
            status = 'Unknown'
            description = f'Keys does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req11(credentials, project_id):
    requirement = '1.11 Ensure That Separation of Duties Is Enforced While Assigning KMS Related Roles to Users'
    status = ''
    description = ''
    multipleroles = []
    nonmultipleroles = []
    kmsadmin = []
    try:
        service = build('cloudresourcemanager', 'v1', credentials=credentials)
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for binding in policy['bindings']:
                for member in binding['members']:
                    if binding['role'] == 'roles/cloudkms.admin':
                        kmsadmin.append(member)
            for binding in policy['bindings']:
                for kmsmember in binding['members']:
                    for kms in kmsadmin:
                        if kms == kmsmember:
                            if binding['role'] == 'roles/cloudkms.cryptoKeyEncrypterDecrypter' or binding[
                                'role'] == 'roles/cloudkms.cryptoKeyEncrypter' or binding[
                                'role'] == 'roles/cloudkms.cryptoKeyDecrypter':
                                multipleroles.append(binding['role'])
                            if binding['role'] != 'roles/cloudkms.cryptoKeyEncrypterDecrypter' or binding[
                                'role'] != 'roles/cloudkms.cryptoKeyEncrypter' or binding[
                                'role'] != 'roles/cloudkms.cryptoKeyDecrypter':
                                nonmultipleroles.append(binding['role'])
            if len(multipleroles) > 0:
                status = 'Failed'
                description = f'There are members with multiple roles {multipleroles}'
            if len(nonmultipleroles) > 0:
                status = 'Passed'
                description = f'There are not members with multiple roles'
            if len(multipleroles) == 0 and len(nonmultipleroles) == 0:
                status = 'Disabled'
                description = f'Cloud KMS service is disabled'
        except HttpError as e:
            if str(e.resp.status) == '403' and str(e.resp.reason) == 'Forbidden':
                status = 'Denied'
                description = f'{e.reason}'
            elif str(e.resp.status) == '403':
                status = 'Disabled'
                description = f'{e.reason}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req12(credentials, project_id):
    requirement = '1.12 Ensure API Keys Are Not Created for a Project'
    status = ''
    description = ''
    api_key_list = []
    try:
        client = api_keys_v2.ApiKeysClient(credentials=credentials)
        parent_value = f"projects/{project_id}/locations/global"
        request = api_keys_v2.ListKeysRequest(parent=parent_value)
        api_keys = client.list_keys(request=request)
        for response in api_keys:
            if "restrictions" not in response:
                api_key_list.append(response.display_name)
            elif "restrictions" in response:
                status = 'Passed'
                description = f'The API keys there are not in project {project_id}'
        if len(api_key_list) > 0:
            status = 'Failed'
            description = f'The following API key {api_key_list} remove from project {project_id}'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req13(credentials, project_id):
    requirement = '1.13 Ensure API Keys Are Restricted To Use by Only Specified Hosts and Apps'
    status = ''
    description = ''
    api_key_list1 = []
    api_key_list2 = []
    api_key_list3 = []
    try:
        client = api_keys_v2.ApiKeysClient(credentials=credentials)
        parent_value = f"projects/{project_id}/locations/global"
        request = api_keys_v2.ListKeysRequest(parent=parent_value)
        api_keys = client.list_keys(request=request)
        for response in api_keys:
            if "restrictions" not in response:
                api_key_list1.append(response.display_name)
            elif "restrictions" in response and "api_targets" not in response.restrictions:
                api_key_list2.append(response.display_name)
            elif "restrictions" in response and "api_targets" in response.restrictions:
                api_key_list3.append(response.display_name)
        if len(api_key_list1) >= 0 and len(api_key_list2) > 0 and len(api_key_list3) == 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list1} need set and configure application restriction {(str(response.restrictions)[0:25])}'
        if len(api_key_list1) > 0 and len(api_key_list2) >= 0 and len(api_key_list3) == 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list1} need set and configure application restriction {(str(response.restrictions)[0:25])}'
        if len(api_key_list1) >= 0 and len(api_key_list2) > 0 and len(api_key_list3) > 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list1} need set and configure application restriction {(str(response.restrictions)[0:25])}'
        if len(api_key_list1) > 0 and len(api_key_list2) >= 0 and len(api_key_list3) > 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list1} need set and configure application restriction {(str(response.restrictions)[0:25])}'
        if len(api_key_list3) > 0 and len(api_key_list1) == 0 and len(api_key_list2) == 0:
            status = 'Passed'
            description = f'For the following API key {api_key_list3} has API restriction to use specified target'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req14(credentials, project_id):
    requirement = '1.14 Ensure API Keys Are Restricted to Only APIs That Application Needs Access'
    status = ''
    description = ''
    api_key_list1 = []
    api_key_list2 = []
    api_key_list3 = []
    try:
        client = api_keys_v2.ApiKeysClient(credentials=credentials)
        parent_value = f"projects/{project_id}/locations/global"
        request = api_keys_v2.ListKeysRequest(parent=parent_value)
        api_keys = client.list_keys(request=request)
        if api_keys:
            for response in api_keys:
                if "restrictions" in response and "api_targets" not in response.restrictions:
                    api_key_list1.append(response.display_name)
                elif "restrictions" not in response and "api_targets" not in response.restrictions:
                    api_key_list2.append(response.display_name)
                elif "restrictions" in response and "api_targets" in response.restrictions:
                    api_key_list3.append(response.display_name)
        if len(api_key_list1) > 0 and len(api_key_list2) >= 0 and len(api_key_list3) == 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list2} need set API restriction (Restrict key => API Keys API) inside {(str(response.restrictions)[0:25])} restriction'
        if len(api_key_list1) >= 0 and len(api_key_list2) > 0 and len(api_key_list3) == 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list2} need set API restriction (Restrict key => API Keys API) inside {(str(response.restrictions)[0:25])} restriction'
        if len(api_key_list1) > 0 and len(api_key_list2) >= 0 and len(api_key_list3) > 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list2} need set API restriction (Restrict key => API Keys API) inside {(str(response.restrictions)[0:25])} restriction'
        if len(api_key_list1) >= 0 and len(api_key_list2) > 0 and len(api_key_list3) > 0:
            status = 'Failed'
            description = f'For the following API keys {api_key_list1},{api_key_list2} need set API restriction (Restrict key => API Keys API) inside {(str(response.restrictions)[0:25])} restriction'
        if len(api_key_list3) > 0 and len(api_key_list1) == 0 and len(api_key_list2) == 0:
            status = 'Passed'
            description = f'For the following API key {api_key_list3} has API restriction and configured API targets'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req15(credentials, project_id):
    requirement = '1.15 Ensure API Keys Are Rotated Every 90 Days.'
    status = ''
    description = ''
    api_key_list1 = []
    api_key_list2 = []
    try:
        client = api_keys_v2.ApiKeysClient(credentials=credentials)
        parent_value = f"projects/{project_id}/locations/global"
        rotation_period = timedelta(days=90)
        request = api_keys_v2.ListKeysRequest(parent=parent_value)
        api_keys = client.list_keys(request=request)
        for response in api_keys:
            time_difference = datetime.now() - datetime.fromtimestamp(
                response.create_time.timestamp())
            # Check if the time difference is greater than the rotation period
            if time_difference > rotation_period:
                api_key_list1.append(response.display_name)
            else:
                api_key_list2.append(response.display_name)
        if len(api_key_list1) > 0 and len(api_key_list2) >= 0:
            status = 'Failed'
            description = f'API keys {api_key_list1} are not rotated within the rotation period of 90 days'
        if len(api_key_list2) > 0 and len(api_key_list1) == 0:
            status = 'Passed'
            description = f'API keys {api_key_list2} are rotated within the rotation period of 90 days'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req16(credentials, project_id):
    requirement = '1.16 Ensure Essential Contacts is Configured for Organization.'
    status = ''
    contacts_list = []
    try:
        client = essential_contacts_v1.EssentialContactsServiceClient(credentials=credentials)
        parent = f"projects/{project_id}"
        request = essential_contacts_v1.ListContactsRequest(parent=parent)
        page_result = client.list_contacts(request=request)
        if page_result:
            for response in page_result:
                contacts_list.append(response.contacts)
            if len(contacts_list) > 0:
                status = 'Passed'
                description = f'Configured essential contacts {contacts_list}'
        else:
            status = 'Failed'
            description = 'Essential contacts are not configured'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req17(credentials, project_id, region):
    requirement = '1.17 Ensure that Dataproc Cluster is encrypted using Customer-Managed Encryption Key'
    status = ''
    description = ''
    encrypted_dc = []
    nonencrypted_dc = []
    try:
        client = dataproc_v1.ClusterControllerClient(
            client_options={"api_endpoint": f"{region}-dataproc.googleapis.com:443"})
        request = dataproc_v1.ListClustersRequest(project_id=project_id, region=region)
        clusters = client.list_clusters(request=request)
        if clusters:
            for cluster in clusters:
                cluster_name = cluster.cluster_name
                cluster_desc = dataproc_client.get_cluster(project_id, region, cluster_name)
                disk_encryption_config = cluster_desc.config.encryption_config.gce_pd_kms_key_name
                if disk_encryption_config is None:
                    nonencrypted_dc.append(cluster_name)
                else:
                    encrypted_dc.append(cluster_name)
            if len(nonencrypted_dc) > 0 and len(encrypted_dc) >= 0:
                status = 'Failed'
                description = f'Clusters {nonencrypted_dc} are not encrypted'
            if len(encrypted_dc) > 0:
                status = 'Passed'
                description = f'Clusters {encrypted_dc} are encrypted'
        else:
            description = f'Did not created cluster for project {project_id}'
            status = 'Unknown'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req18(credentials, project_id):
    requirement = '1.18 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager'
    status = ''
    description = ''
    parent = f"projects/{project_id}/locations/global"
    function_secret_list = []
    function_list = []
    try:
        client = functions_v1.CloudFunctionsServiceClient()
        request = functions_v1.ListFunctionsRequest(parent=parent)
        page_result = client.list_functions(request=request)
        if page_result:
            for response in page_result:
                if response.secretEnvironmentVariables.secret:
                    function_secret_list.append(response.name)
                else:
                    function_list.append(response.name)
            if len(function_secret_list) > 0 and len(function_list) >= 0:
                status = 'Failed'
                description = f'In the followings cloud functions {function_secret_list} is stored in variable secret using secret manager'
            if len(function_list) > 0:
                status = 'Passed'
                description = f'In the followings cloud functions {function_secret_list} is not stored in variable secret using secret manager'
        status = 'Unknown'
        description = f'Cloud functions does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description
