from modules.gcservices import *

def main():
    try:
        d = vars(parser.parse_args())
    except argparse.ArgumentError:
        print('An error occurred while during parsing argument values')
    if "benchmark" in d.keys():
        d["benchmark"] = [str(s.strip()) for s in d["benchmark"].split(",")]
    choices = ['iam', 'logmon', 'net', 'vm', 'storage', 'mysql', 'postgres', 'mssql', 'bq']
    if "f" in d.keys():
        d["f"] = [str(s.strip()) for s in d["f"].split(",")]
    for p in d["f"]:
        if p == 'txt':
            format = 'txt'
            cleartxt()
        elif p == 'html':
            format = 'html'
            clearhtm()
    for p in d["benchmark"]:
        if p in choices:
            if p == 'iam':
                iam(format)
            elif p == 'logmon':
                logmon(format)
            elif p == 'storage':
                storage(format)
        else:
            print("not exist")

def rpt():
    try:
        d = vars(parser.parse_args())
    except argparse.ArgumentError:
        print('An error occurred while during parsing argument values')
    if "f" in d.keys():
        d["f"] = [str(s.strip()) for s in d["f"].split(",")]
    for p in d["f"]:
        if p == 'txt':
            rpttxt()
        elif p == 'html':
            crtpiehtm()
            rpthtm()

if __name__ == '__main__':
    main()
    rpt()

