import os
import time
import html
from benchmarks.iam import *
from benchmarks.storage import *
from benchmarks.logmon import *
from modules.auth import get_credentials
from modules.arguments import parser
from jinja2 import Environment, FileSystemLoader
from tabulate import tabulate
from bs4 import BeautifulSoup
import shutil
# from benchmarks import iam, logmon, net, vm, storage, mysql,postgres, msssql, bq
import configparser


args = parser.parse_args()
if args.config_file:
    config = configparser.ConfigParser()
    config.read(args.config_file)
    config.sections()
    project_id = config.get("PROJECT_INFO", "project_id")
    region = config.get("PROJECT_INFO", "region")
    parent = f"projects/{project_id}"
try:
    d = vars(parser.parse_args())
except argparse.ArgumentError:
    print('An error occurred while during parsing argument values')
if "oauth2" in d.keys():
    d["oauth2"] = [str(s.strip()) for s in d["oauth2"].split(",")]
for p in d["oauth2"]:
    if p == 'uscred':
        try:
            credentials = get_credentials('uscred')
        except GoogleAPICallError as e:
            print(f"Error uscred: {str(e)}")
    else:
        try:
            credentials = get_credentials('sacred')
        except GoogleAPICallError as e:
            print(f"Error sacred: {str(e)}")


def iam(format):
    iamList = [req1(credentials, project_id), req2(), req3(credentials, project_id), req4(credentials, project_id),
               req5(credentials, project_id), req6(credentials, project_id), req7(credentials, project_id),
               req8(credentials, project_id), req9(credentials, project_id), req10(credentials, project_id),
               req11(credentials, project_id), req12(credentials, project_id), req13(credentials, project_id),
               req14(credentials, project_id), req15(credentials, project_id), req16(credentials, project_id),
               req17(credentials, project_id, region), req18(credentials, project_id)]
    control = 'Identity and Access Management'
    print(f'... scanning {control} services')
    arg = 'iam'
    if format == 'txt':
        txt(control, iamList)
    elif format == 'html':
        html(control, iamList)
        crtchartjs(iamList, arg, control)


def logmon(format):
    logmonList = [req21(credentials, project_id), req22(credentials, project_id), req23(credentials, project_id),
                  req24(credentials, project_id), req25(credentials, project_id), req26(credentials, project_id),
                  req27(credentials, project_id), req28(credentials, project_id), req29(credentials, project_id),
                  req210(credentials, project_id), req211(credentials, project_id), req212(credentials, project_id),
                  req213(credentials, project_id), req214(credentials, project_id), req215(credentials, project_id)]
    control = 'Logging and Monitoring'
    print(f'... scanning {control} services')
    arg = 'logmon'
    if format == 'txt':
        txt(control, logmonList)
    elif format == 'html':
        html(control, logmonList)
        crtchartjs(logmonList, arg, control)
    else:
        print("This format does not exist")

def storage(format):
    storageList = [req51(credentials, project_id), req52(credentials, project_id)]
    control = 'Storage'
    print(f'... scanning {control} services')
    arg = 'storage'
    if format == 'txt':
        txt(control, storageList)
    elif format == 'html':
        html(control, storageList)
        crtchartjs(storageList, arg, control)
    else:
        print("This format does not exist")

def rpthtm():
    lttuple = time.localtime()
    creation_time = time.strftime("%Y-%m-%d, %H:%M:%S", lttuple)
    rpt_time = time.strftime("%Y-%m-%d_%H_%M_%S", lttuple)
    environment = Environment(loader=FileSystemLoader("reports/templates"))
    results_filename = f"reports/templates/GC_CIS_REPORT_{rpt_time}.html"
    results_template = environment.get_template("gc_report.html.tmpl")
    context = {
        "project_id": project_id,
        "region": region,
        "creation_time": creation_time,
    }
    with open(results_filename, mode="w", encoding="utf-8") as results:
        results.write(results_template.render(context))
    try:
        os.replace(f'reports/templates/GC_CIS_REPORT_{rpt_time}.html', f'reports/GC_CIS_REPORT_{rpt_time}.html')
        print(f"Created report reports/GC_CIS_REPORT_{rpt_time}.html")
    except PermissionError:
        print("Operation not permitted.")
    except OSError as err:
        print("Operation system error:", err)
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")

def html(control, lists):
    headers = ["Control", "Status", "Description"]
    resultList = []
    for item in lists:
        control_dict = dict(zip(headers, item))
        tmpList = list(control_dict.items())
        resultList.append(tmpList)
    environment = Environment(loader=FileSystemLoader("reports/templates"))
    results_filename = "reports/templates/GC_SERVICES.html"
    results_template = environment.get_template("report.html.tmpl")
    context = {
        "resultList": resultList,
        "control": control,
    }
    with open(results_filename, mode="a", encoding="utf-8") as results:
        results.write(results_template.render(context))

def rpttxt():
    lttuple = time.localtime()
    creation_time = time.strftime("%Y-%m-%d, %H:%M:%S", lttuple)
    rpt_time = time.strftime("%Y-%m-%d_%H_%M_%S", lttuple)
    environment = Environment(loader=FileSystemLoader("reports/templates"))
    results_filename = f"reports/GC_CIS_REPORT_{rpt_time}.txt"
    results_template = environment.get_template("gc_report.txt.tmpl")
    context = {
        "project_id": project_id,
        "region": region,
        "creation_time": creation_time,
    }
    with open(results_filename, mode="w", encoding="utf-8") as results:
        results.write(results_template.render(context))
    try:
        os.replace(f'reports/templates/GC_CIS_REPORT_{rpt_time}.txt', f'reports/GC_CIS_REPORT_{rpt_time}.txt')
        print(f"Created report reports/GC_CIS_REPORT_{rpt_time}.txt")
    except PermissionError:
        print("Operation not permitted.")
    except OSError as err:
        print("Operation system error:", err)
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")

def txt(control, cont):
    headers = ["Control", "Status", "Description"]
    content = tabulate(cont, headers=headers, tablefmt="grid", numalign="center")
    pos = "*"
    L = ["\n", pos.center(420, '*'), "\n", control.center(220), "\n", pos.center(420, '*'), "\n", "\n"]
    with open('reports/templates/GC_SERVICES.txt', 'a') as outputfile:
        outputfile.writelines(L)
        outputfile.write(content)
        outputfile.close()

def clearhtm():
    if os.path.exists("reports/templates/GC_SERVICES.html"):
        try:
            os.remove("reports/templates/GC_SERVICES.html")
        except PermissionError:
            print("Operation not permitted.")
        except OSError as err:
            print("Operation system error:", err)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
    else:
        print(f'The file GC_SERVICES.html does not exist')
    if os.path.exists("reports/templates/pie.html"):
        try:
            os.remove("reports/templates/pie.html")
        except PermissionError:
            print("Operation not permitted.")
        except OSError as err:
            print("Operation system error:", err)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
    else:
        print(f'The file pie.html does not exist')

def cleartxt():
    if os.path.exists("reports/templates/GC_SERVICES.txt"):
        try:
            os.remove("reports/templates/GC_SERVICES.txt")
        except PermissionError:
            print("Operation not permitted.")
        except OSError as err:
            print("Operation system error:", err)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
    else:
        print(f'The file GC_SERVICES.txt does not exist')

def crtchartjs(list,arg,control):
    denied = 0
    passed = 0
    unknown = 0
    failed = 0
    disabled = 0
    for itm in list:
        if itm[1] == 'Denied':
            denied += 1
        elif itm[1] == 'Passed':
            passed += 1
        elif itm[1] == 'Unknown':
            unknown += 1
        elif itm[1] == 'Failed':
            failed += 1
        elif itm[1] == 'Disabled':
            disabled += 1
    nestedList = [['Status', 'Numbers'], ['Denied',denied],['Passed',passed],['Unknown',unknown],['Failed',failed],['Disabled',disabled]]
    environment = Environment(loader=FileSystemLoader("reports/templates"))
    results_filename = f'reports/templates/{arg}.js'
    results_template = environment.get_template("js.html.tmpl")
    context = {
        "nestedList": nestedList,
        "arg": arg,
        "control": control,
    }
    with open(results_filename, mode="w", encoding="utf-8") as results:
        results.write(results_template.render(context))

def crtpiehtm():
    benchList = []
    benchstr = ''
    str1 = '''<script type="text/javascript">{% include '''
    str2 = ''' %}</script>\n'''
    if "benchmark" in d.keys():
        d["benchmark"] = [str(s.strip()) for s in d["benchmark"].split(",")]
        nargs = len(d["benchmark"])
        for bench in d["benchmark"]:
            if bench == 'iam' or bench == 'logmon' or bench == 'storage':
                benchList.append(str1+f'"{bench}' + '.js'+'"'+str2)
        for bench in benchList:
            benchstr += bench
        try:
            shutil.copy2('reports/templates/pie.html.tmpl', 'reports/templates/pie.html.tmpl.tmp')
        except PermissionError:
            print("Operation not permitted.")
        except OSError as err:
            print("Operation system error:", err)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
        with open("reports/templates/pie.html.tmpl", encoding="utf-8") as f:
            soup = BeautifulSoup(f, "html.parser")
            f.close()
        head = soup.find('head')
        head.insert(2, benchstr)
        with open("reports/templates/pie.html.tmpl", "w+") as f_output:
            f_output.write(str(soup.prettify(formatter=None)))
            f_output.close()
        environment = Environment(loader=FileSystemLoader("reports/templates"))
        results_filename = "reports/templates/pie.html"
        results_template = environment.get_template("pie.html.tmpl")
        context = {
            "nargs": nargs,
            "benchmarks": d["benchmark"],
        }
        with open(results_filename, mode="w", encoding="utf-8") as results:
            results.write(results_template.render(context))
        try:
            shutil.copy2('reports/templates/pie.html.tmpl.tmp', 'reports/templates/pie.html.tmpl')
            os.remove('reports/templates/pie.html.tmpl.tmp')
        except PermissionError:
            print("Operation not permitted.")
        except OSError as err:
            print("Operation system error:", err)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")








