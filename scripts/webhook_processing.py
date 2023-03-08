from pathlib import Path
import csv
import datetime


now = datetime.date.today()
# current week format is YYYY-W## (e.g., week of jan 1 1999 is 1999-W01). change format if you hate it.
current_week = now.strftime("%Y-W%V")


current_file_path = Path(__file__).resolve().parents[1]
path = Path(current_file_path, 'output')


def check_and_init_output_file(fields, alert_type):
    if not Path.is_dir(path):
        Path.mkdir(path, mode=0o750)

    filename = Path(path, f"{current_week}_{alert_type}.csv")
    if Path.is_file(filename):
        with open(filename) as check:
            written_to = check.read(1)
    else:
        written_to = 0
    if not written_to:
        with open(filename, 'a') as outfile:
            csvwriter = csv.writer(outfile)
            csvwriter.writerow(fields)
    return filename


def process_request_not_db(req):
    ip = req['ip_str']
    port = req['port']
    try:
        vulns = list(req['vulns'].keys())
    except:
        vulns = ["None Listed in Shodan"]
    module = req['_shodan']['module']
    if module == "http" or module == "https":
        webapp_scan = "yes"
    else:
        webapp_scan = "no"
    product = req['product']

    fields = ['IP', 'Port', 'Product', 'Module', 'Run Webapp Scan?', 'Shodan Vulnerabilities']
    out_file = check_and_init_output_file(fields, "assets_to_scan")

    output_to_write = [ip, port, product, module, webapp_scan, vulns]

    with open(out_file, 'r') as current_data:
        items = csv.reader(current_data)
        next(items)
        asset_in_file = False
        for line in items:
            if [ip, port] == [line[0], int(line[1])]:
                asset_in_file = True
                break

        if not asset_in_file:
            with open(out_file, 'a') as output:
                csvwriter = csv.writer(output)
                csvwriter.writerow(output_to_write)



def process_open_db(req):
    ip = req['ip_str']
    port = req['port']
    module = req['module']
    product = req['product']
    fields = ['IP', 'Port', 'Product', 'Module']
    lines_to_write = [ip, port, product, module]
    out_file = check_and_init_output_file(fields, "open_dbs")

    with open(out_file, 'a') as output:
        csvwriter = csv.writer(output)
        csvwriter.writerow(lines_to_write)
