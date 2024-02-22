from google.cloud import api_keys_v2
import googleapiclient.discovery
from googleapiclient import discovery
from google.api_core.exceptions import GoogleAPICallError
from google.api_core.exceptions import BadRequest
from google.cloud import storage
from googleapiclient.errors import HttpError
import google.cloud.logging
from google.cloud import monitoring_v3
from google.cloud import logging_v2
from google.cloud import service_usage_v1
from google.cloud import billing_v1
from google.cloud.logging_v2.services.logging_service_v2 import LoggingServiceV2Client
from google.cloud import accessapproval_v1
import re


def req21(credentials, project_id):
    requirement = '2.1 Ensure That Cloud Audit Logging Is Configured Properly Across All Services and All Users From a Project'
    status = ''
    description = ''
    list_auditlogconfigs = []
    try:
        service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
        try:
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            if "auditConfigs" in policy:
                for auditconfigs in policy['auditConfigs']:
                    for auditlogconfigs in auditconfigs['auditLogConfigs']:
                        list_auditlogconfigs.append(auditlogconfigs['service'])
                        if auditlogconfigs['logType'] == 'ADMIN_READ':
                            status = 'Failed'
                            description = f'For the followings service  {list_auditlogconfigs} need remove logType ADMIN_READ'
                        elif auditlogconfigs['logType'] == 'DATA_WRITE' and auditlogconfigs['logType'] == 'DATA_READ':
                            status = 'Passed'
                        else:
                            status = 'Failed'
                            description = f'For all services set logType DATA_WRITE and DATA_READ'
            else:
                status = 'Failed'
                description = f'auditConfigs is not setted'
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


def req22(credentials, project_id):
    requirement = '2.2 Ensure That Sinks Are Configured for All Log Entries'
    status = ''
    description = ''
    created_sinks_list = []
    parent = f'projects/{project_id}'
    try:
        client = google.cloud.logging.Client(project=project_id, credentials=credentials)
        sinks = client.list_sinks(parent=parent)
        try:
            for sink in sinks:
                created_sinks_list.append(sink.name)
            if len(created_sinks_list) > 0:
                status = 'Passed'
                description = f'Created sinks: {created_sinks_list}'
            else:
                status = 'Failed'
                description = f'Sinks are not configured for log entries'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Sinks does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req23(credentials, project_id):
    requirement = '2.3 Ensure That Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock'
    status = ''
    description = ''
    locked_bucket_list = []
    unlocked_bucket_list = []
    try:
        storage_client = storage.Client(credentials=credentials)
        buckets = list(storage_client.list_buckets(project=project_id))
        try:
            for bucket in buckets:
                bucket.reload()
                if bucket.retention_policy_locked and bucket.retention_policy_effective_time:
                    locked_bucket_list.append(bucket.name)
                else:
                    unlocked_bucket_list.append(bucket.name)
            if len(locked_bucket_list) > 0:
                status = 'Passed'
                description = f'Locked buckets: {locked_bucket_list}'
            else:
                status = 'Failed'
                description = f'Unlocked buckets: {unlocked_bucket_list}'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Bucket does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req24(credentials, project_id):
    requirement = '2.4 Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in '(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")  OR (protoPayload.serviceData.policyDelta.bindingDeltas.action ="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list.append(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list.append(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'Log-based Metrics without alert policy: {ap_log_metric_listprint}'
                                    else:
                                        status = 'Passed'
                                        description = f'Log-based Metrics with alert policy: {ap_log_metric_listprint}'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req25(credentials, project_id):
    requirement = '2.5 Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list.append(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list.append(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'For the followings Log-based Metrics : {ap_log_metric_listprint} are not setted audit logging'
                                    else:
                                        status = 'Passed'
                                        description = f'For the followings Log-based Metrics :  {ap_log_metric_listprint} are setted audit logging'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req26(credentials, project_id):
    requirement = '2.6 Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in 'resource.type="iam_role" AND protoPayload.methodName = "google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list.append(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list.append(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'For the followings Log-based Metrics : {ap_log_metric_listprint} are not setted custom role changes'
                                    else:
                                        status = 'Passed'
                                        description = f'For the followings Log-based Metrics :  {ap_log_metric_listprint} are setted custom role changes'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req27(credentials, project_id):
    requirement = '2.7 Ensure That the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in 'resource.type="gce_firewall_rule" AND protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete"':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list.append(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list.append(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'For the followings Log-based Metrics : {ap_log_metric_listprint} are not setted for VPC network firewall rule changes'
                                    else:
                                        status = 'Passed'
                                        description = f'For the followings Log-based Metrics :  {ap_log_metric_listprint} are setted for VPC network firewall rule changes'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req28(credentials, project_id):
    requirement = '2.8 Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in 'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert"':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list.append(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list.append(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'For the followings Log-based Metrics : {ap_log_metric_listprint} are not setted for VPC network route rule changes'
                                    else:
                                        status = 'Passed'
                                        description = f'For the followings Log-based Metrics :  {ap_log_metric_listprint} are setted for VPC network route rule changes'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req29(credentials, project_id):
    requirement = '2.9 Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in 'resource.type=gce_network AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list.append(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list.append(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'For the followings Log-based Metrics : {ap_log_metric_listprint} are not setted for VPC network changes'
                                    else:
                                        status = 'Passed'
                                        description = f'For the followings Log-based Metrics :  {ap_log_metric_listprint} are setted for VPC network changes'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req210(credentials, project_id):
    requirement = '2.10 Ensure That the Log Metric Filter and Alerts Exist for Cloud Storage IAM Permission Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in 'resource.type=gcs_bucket AND protoPayload.methodName="storage.setIamPermissions"':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list.append(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list.append(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'For the followings Log-based Metrics : {ap_log_metric_listprint} are not setted for Cloud Storage IAM Permission Changes'
                                    else:
                                        status = 'Passed'
                                        description = f'For the followings Log-based Metrics :  {ap_log_metric_listprint} are setted for Cloud Storage IAM Permission Changes'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req211(credentials, project_id):
    requirement = '2.11 Ensure That the Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes'
    status = ''
    description = ''
    ap_log_metric_list = []
    log_metric_list = []
    try:
        project_name = f"projects/{project_id}"
        client = logging_v2.Client(credentials=credentials, project=project_name)
        apsclient = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        request = monitoring_v3.ListAlertPoliciesRequest(name=project_name)
        alert_policies = apsclient.list_alert_policies(request=request)
        try:
            for logmetrics in client.list_metrics():
                if logmetrics:
                    if logmetrics.metricDescriptor.type.startswith(
                            'logging.googleapis.com/user/') and logmetrics.filter in 'protoPayload.methodName="cloudsql.instances.update"':
                        for policy in alert_policies:
                            conditions = policy.conditions
                            if policy.enabled:
                                for condition in conditions:
                                    if conditionThreshold.filter in 'metric.type = {logmetrics.metricDescriptor.type}' and condition.conditionThreshold.aggregations.perSeriesAligner in 'ALIGN_COUNT':
                                        ap_log_metric_list_print.list(logmetrics.metricDescriptor.type)
                                    else:
                                        log_metric_list_print.list(logmetrics.metricDescriptor.type)
                                    if len(log_metric_listprint) > 0:
                                        status = 'Failed'
                                        description = f'For the followings Log-based Metrics : {ap_log_metric_listprint} are not setted for SQL Instance Configuration Changes'
                                    else:
                                        status = 'Passed'
                                        description = f'For the followings Log-based Metrics :  {ap_log_metric_listprint} are setted for SQL Instance Configuration Changes'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Log-based Metrics does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req212(credentials, project_id):
    requirement = '2.12 Ensure That Cloud DNS Logging Is Enabled for All VPC Networks'
    status = ''
    description = ''
    vpc_logged_list = []
    vpc_unlogged_list = []
    try:
        service = discovery.build('dns', 'v1', credentials=credentials)
        try:
            request = service.policies().list(project=project_id)
            while request is not None:
                response = request.execute()
                for policy in response['policies']:
                    if policy.networks:
                        if policy.enableLogging in 'true':
                            vpc_logged_list.append(policy.kind)
                            if length(vpc_logged_list) > 0:
                                status = 'Passed'
                                description = f'For the followings VPN network {vpc_logged_list} is enabled cloud DNS logging'
                        else:
                            vpc_unlogged_list.append(policy.kind)
                            if length(vpc_unlogged_list) > 0:
                                status = 'Failed'
                                description = f'For the followings VPN network {vpc_unlogged_list} is disabled cloud DNS logging'
                    else:
                        status = 'Unknown'
                        description = f'VPC networks does not exist'
        except HttpError as e:
            if str(e.resp.status) == '403':
                status = 'Disabled'
                description = f'{e.reason}'
            else:
                status = 'Denied'
                description = f'{e.reason}'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Policy does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req213(credentials, project_id):
    requirement = '2.13 Ensure Cloud Asset Inventory Is Enabled'
    status = ''
    description = ''
    assets_list = []
    try:
        client = service_usage_v1.ServiceUsageClient(credentials=credentials)
        request = service_usage_v1.ListServicesRequest(parent="projects/teoinhouse", filter="state:ENABLED")
        page_result = client.list_services(request=request)
        try:
            for response in page_result:
                if response.config.name == 'cloudasset.googleapis.com':
                    assets_list.append(response.config.name)
                    if len(assets_list) > 0:
                        status = 'Passed'
                        description = f'Cloud Asset Inventory is enabled: {assets_list}'
                    else:
                        status = 'Failed'
                        description = f'Cloud Asset Inventory is not enabled'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Cloud Asset Inventory not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req214(credentials, project_id):
    requirement = f'2.14 Ensure Access Transparency is Enabled'
    status = ''
    description = ''
    role_list = []
    try:
        client_billing = billing_v1.CloudBillingClient(credentials=credentials)
        client_logging = LoggingServiceV2Client(credentials=credentials)
        service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
        filter_str = f'jsonPayload.@type:"type.googleapis.com/google.cloud.audit.TransparencyLog"'
        request = billing_v1.GetProjectBillingInfoRequest(name="projects/{project_id}")
        response = client_billing.get_project_billing_info(request=request)
        try:
            if response.billingEnabled in 'true':
                try:
                    policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
                    for binding in policy['bindings']:
                        if binding['role'] == 'roles/axt.admin':
                            role_list.append(binding['role'])
                    if len(role_list) > 0:
                        entries = list(client_logging.list_log_entries(
                            {"resource_names": [f"projects/{project_id}"], "filter": filter_str}))
                        if entries:
                            status = 'Passed'
                            description = f'Access Transparency is enabled for project {project_id}'
                        else:
                            status = 'Failed'
                            description = f'Access Transparency is not enabled for project {project_id} but is associated with a billing account'
                    else:
                        status = 'Failed'
                        description = f'The project {project_id} is associated with a billing account but missing role axt.admin'
                except HttpError as e:
                    status = 'Unknown'
                    description = f'{e.resp.status} : {e.reason}'
            else:
                status = 'Failed'
                description = f'The project {project_id} is not associated with a billing account'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Billing account does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description


def req215(credentials, project_id):
    requirement = f'2.14 Ensure Access Approval is Enabled'
    status = ''
    description = ''
    notification_emails_list = []
    try:
        client = accessapproval_v1.AccessApprovalClient(credentials=credentials)
        request = accessapproval_v1.GetAccessApprovalSettingsMessage(name="projects/{project_id}")
        settings = client.get_access_approval_settings(request=request)
        try:
            for setting in settings['notification_emails']:
                if setting.notification_emails:
                    notification_emails_list.append(setting.notification_emails)
            if len(notification_emails_list) > 0:
                status = 'Passed'
                description = f'Access Approval is enabled for project {project_id}'
            else:
                status = 'Failed'
                description = f'Access Approval is not enabled for project {project_id}'
        except BadRequest as e:
            status = 'Unknown'
            description = f'Billing account does not exist'
    except GoogleAPICallError as e:
        if str(e.reason) == 'SERVICE_DISABLED':
            status = 'Disabled'
            description = f'{str(e.message)}'
        elif str(e.reason) == 'None' or re.match(r"(.+?)PERMISSION_DENIED", str(e.reason))  and re.match(r"(.+?)FORBIDDEN", str(e.code)):
            status = 'Denied'
            description = f'{str(e.message)}'
    return requirement, status, description
