from argparse import ArgumentParser, RawTextHelpFormatter

parser = ArgumentParser(prog='main.py', description='Tool to benchmark your GC environment against CIS',
                        usage='python3 %(prog)s [optional arguments]', formatter_class=RawTextHelpFormatter)
parser.add_argument("-c", "--config_file", type=str,  required=True, help='PROJECT_NAME.conf config file')
parser.add_argument("--oauth2", type=str,  required=True, choices=['sacred', 'uscred'],
                    help='''credentials based on OAuth 2.0 access
sacred - OAuth 2.0 Service Accounts Credentials 
uscred - User OAuth 2.0 credentials that authorize access to a user’s data
                     ''')
parser.add_argument('-b', '--benchmark', type=str,
                    required=True, help='''Choose one or more Google Cloud services for benchmark,
iam -       Benchmark  for Identity and Access Management
logmon -    Benchmark  for Logging and Monitoring
net -       Benchmark  for Networking
vm -        Benchmark  for Virtual Machines
storage -   Benchmark  for Storage
mysql -     Benchmark  for MySQL Database
postgres -  Benchmark  for PostgreSQL Database
mssql -     Benchmark  for SQL Server
bq -        Benchmark  for BigQuery
                     ''')
parser.add_argument("-f", type=str,  required=True, choices=['txt', 'html'], help='Format output type txt or html')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0', help='Display version of the tool')