import google.oauth2.credentials
import googleapiclient.discovery
from google.oauth2.service_account import Credentials
from google.api_core.exceptions import GoogleAPICallError
from googleapiclient.errors import HttpError
from modules.arguments import parser
import configparser
import json

def get_credentials(oauth2):
    args = parser.parse_args()
    if args.config_file:
        config = configparser.ConfigParser()
        config.read(args.config_file)
        config.sections()
    if oauth2 == 'uscred':
        client_id = config.get("USER_CREDENTIALS", "client_id")
        client_secret = config.get("USER_CREDENTIALS", "client_secret")
        refresh_token = config.get("USER_CREDENTIALS", "refresh_token")
        token_uri = config.get("USER_CREDENTIALS", "token_uri")
        token = config.get("USER_CREDENTIALS", "token")
        project_id = config.get("PROJECT_INFO", "project_id")
        try:
            creds = google.oauth2.credentials.Credentials(token=token, refresh_token=refresh_token, token_uri=token_uri,
                                                      client_id=client_id, client_secret=client_secret,
                                                      quota_project_id=project_id)
            scopes = ["https://www.googleapis.com/auth/cloud-platform",
                      "https://www.googleapis.com/auth/cloud-platform.read-only",
                      "https://www.googleapis.com/auth/admin.directory.user.readonly",
                      "https://www.googleapis.com/auth/logging.read",
                      "https://www.googleapis.com/auth/logging.admin"
                      ]
            role_status = rolestatus(project_id, creds)
            if role_status == 'None':
                print('Minimal recommended role for authenticated service account is roles/owner')
        except GoogleAPICallError as e:
            print(f"Error uscred : {str(e)}")
    if oauth2 == 'sacred':
        sa_file = config.get("SERVICE_ACCOUNT_CREDENTIALS", "sa_file")
        project_id = config.get("PROJECT_INFO", "project_id")
        try:
            creds = Credentials.from_service_account_file(sa_file)
            role_status = rolestatus(project_id, creds)
            if role_status == 'None':
                print('Minimal recommended role for authenticated service account is roles/owner')
        except GoogleAPICallError as e:
            print(f"Error sacred: {str(e)}")
        return creds


def rolestatus(project_id, credentials):
    args = parser.parse_args()
    if args.config_file:
        config = configparser.ConfigParser()
        config.read(args.config_file)
        config.sections()
        credentials = credentials
        sa_file = config.get("SERVICE_ACCOUNT_CREDENTIALS", "sa_file")
        service_account_info = json.load(open(sa_file))
        role_status =''
        sa_list = []
        nonsa_list = []
        for k,v in service_account_info.items():
            if k == 'client_email':
                sa = v
        try:
            service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
            response = service.projects().getIamPolicy(resource=project_id, body={}).execute()
        except HttpError as e:
            if str(e.resp.status) == '403':
                role_status = 'None'
        if role_status != 'None':
            for binding in response['bindings']:
                if binding['role'] == 'roles/owner':
                    for sad in binding['members']:
                        if sad.startswith(f'serviceAccount:{sa}'):
                            sa_list.append(sad)
                        else:
                            nonsa_list.append(sad)
            if len(nonsa_list) > 0 and len(sa_list) == 0:
                role_status = 'None'
    return role_status