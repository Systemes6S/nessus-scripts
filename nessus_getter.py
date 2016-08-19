#!/usr/bin/python

import os
import sys
import time
import requests
import argparse
from requests import Session, Request
import json
import ConfigParser
import warnings
import logging

FORMAT = '%(asctime)s %(levelname)s  - %(message)s'
try:
    logging.basicConfig(filename='/var/log/nessus_getter.log', format=FORMAT)
except IOError:
    logging.basicConfig(
        filename=os.getcwd() +
        '/nessus_getter.log',
        format=FORMAT)
logger = logging.getLogger('nessus_getter')
logger.setLevel(logging.INFO)

class restend():
    """ super-minimal rest endpoint for use in nessus_getter """

    def __init__(self, host, port, **kwargs):
        self.host = "https://%s:%s" % (host, port)
        self.custom_headers = {}
        if 'session' in kwargs.keys():
            self.session = kwargs['session']
        else:
            self.session = Session()
        if 'verify' in kwargs.keys():
            self.verify = kwargs['verify']
        else:
            self.verify = True
        if 'headers' in kwargs.keys():
            for k, v in kwargs['headers']:
                self.custom_headers[k] = v

    def set_header(self, headers):
        for k, v in headers.iteritems():
            self.custom_headers[k] = v

    def rest(self, endpoint, method, data=None, **kwargs):
        url = "%s/%s" % (self.host, endpoint)
        req = self.session.prepare_request(
            Request(
                method,
                url,
                json=data,
                headers=self.custom_headers))
        try:
            response = self.session.send(req, verify=self.verify)
        except requests.exceptions.SSLError as e:
            errorquit(
                "\nError with SSL connection for %s: %s.\nBailing out.\n" %
                (self.host, str(e)))
        return response

    def get_request(self, endpoint, args=None, data=None):
        if args:
            argbit = '/'.join([str(x) for x in args])
            get_endpoint = "%s/%s" % (endpoint, argbit)
        else:
            get_endpoint = endpoint
        if data:
            data_text = ''
            for k, v in data.iteritems():
                data_text = data_text + '&%s=%s' % (k, v)
            data_text = data_text.lstrip('&')
            get_endpoint = "%s?%s" % (get_endpoint, data_text)
        return self.rest(get_endpoint, 'GET')

    def post_request(self, endpoint, args=None, data=None):
        if args:
            argbit = '/'.join([str(x) for x in args])
            post_endpoint = "%s/%s" % (endpoint, argbit)
        else:
            post_endpoint = endpoint
        return self.rest(post_endpoint, 'POST', data)


class nessus():

    def __init__(self, host, port, user, password, **kwargs):
        if 'logdir' in kwargs:
            self.logdir = kwargs['logdir']
        else:
            self.logdir = os.getcwd()
        if 'data_format' in kwargs:
            self.data_format = kwargs['data_format']
        else:
            self.data_format = 'nessus'
        if 'api' in kwargs:
            self.api = kwargs['api']
        else:
            self.api = False
        self.restend = restend(host, port, **kwargs)
        self.user = user
        self.password = password
        self.host = "https://%s:%s" % (host, port)
        self.token = self.establish_session()
        self.policies = {}
        self.get_policies()

    def get(self, endpoint, args=None, data=None):
        return self.restend.get_request(endpoint, args, data)

    def post(self, endpoint, args=None, data=None):
        return self.restend.post_request(endpoint, args, data)

    def establish_session(self):
        """ log in to nessus and get the token we'll be using """
        if self.api:
            self.restend.set_header(
                {'X-ApiKeys': 'accessKey=%s; secretKey=%s' %
                    (self.user, self.password)})
        else:
            data = {'username': self.user, 'password': self.password}
            try:
                r = self.post('session', data=data)
            except requests.exceptions.ConnectionError as e:
                log("Unable to connect to server %s" %
                    self.host, logging.ERROR)
                errorquit(str(e))
            if r.status_code == requests.codes.ok:
                js = json.loads(r._content)
                self.restend.set_header(
                    {'X-Cookie': 'token=%s;' % js['token']})
                return js['token']
            else:
                errorquit(
                    "\nError establishing session - server says: %s" %
                    r.text)

    def get_policies(self):
        """retrieve policies available to this user"""
        pols = self.jsonget('policies')
        # print pols
        if pols is None:
            return None
        for policy in pols.get('policies',{}):
            self.policies[
                policy['id']] = {
                'name': policy['name'],
                'uuid': policy['template_uuid']}
        return self.policies

    def name2slug(self, name):
        """ take a name and replace characters you might not want in a
        filename with something else. Let's say _ """
        return "".join(self.safe_or_score(x) for x in name)

    def safe_or_score(self, char):
        if char.isalnum() or char in '-_':
            return char
        return '_'

    def get_all_reports(self):
        reportjs = self.jsonget('folders')
        data = {'format': self.data_format}
        file_list = []
        for folder in reportjs['folders']:
            if folder['default_tag'] == 1:
                scanjs = self.jsonget(
                    'scans', data={
                        'folder_id': folder['id']})
                for scan in scanjs['scans']:
                    uuid = scan['uuid']
                    scanid = str(scan['id'])
                    """scanname = self.host + '-' + scan['name']"""
		    scanname = scan['name']
                    scanslug = self.name2slug(scanname)
                    if scan['status'] not in ['completed', 'canceled']:
                        continue
                    try:
                        f = open(self.logdir + scanid + '.' + scanslug + '.timestamp')
                        timestamp = int(f.readline().strip())
                    except:
                        timestamp = None
                    if timestamp:
                        if timestamp >= scan['last_modification_date']:
                            continue
                    log("Getting most recent scan for %s" % scanname)
                    rjs = self.jsonpost('scans/%s/export' % scanid, data=data)
                    fileid = rjs['file']
                    r = self.try_download(scanid, fileid, scanslug)
                    if r.startswith('OK'):
                        file_list.append(r[5:])
                    log(r)
        return file_list


    def get_report(self, scanid, name, count=0):
        data = {'format': self.data_format}
        scanslug = self.name2slug(name)
        rjs = self.jsonpost('scans/%s/export' % scanid, data=data)
        if isinstance(rjs, type({})):
            fileid = rjs['file']
            r = self.try_download(scanid, fileid, scanslug)
            log(r)
        else:
            log(rjs.text, logging.ERROR)
            count += 1
            if count == 4:
                log("something went wrong trying to get scan %s (%s)" %
                    (scanid, name), logging.ERROR)
                return
            self.get_report(scanid, name, count)

    def try_download(self, scanid, fileid, scanslug=None):

        scanid = str(scanid)
        if scanslug is None:
            scanslug = str(fileid)
        status_args = [scanid, 'export', fileid, 'status']
        download_args = [scanid, 'export', fileid, 'download']
        data = {'token': self.token}
        response_js = self.jsonget('scans', status_args)
        waitcount = 0
        sleeper = 1
        json.dumps(response_js)
        while response_js['status'] != 'ready':
            waitcount += 1
            if waitcount % 5 == 0:
                sleeper += 30
            if waitcount < 15:
                time.sleep(sleeper)
                response_js = self.jsonget('scans', status_args)
            else:
                return "giving up on %s %s (%s)" % (scanid, fileid, scanslug)
        if self.api:
            response = self.get('scans', download_args)
        else:
            response = self.get('scans', download_args, data=data)
        timestamp = int(time.time())
        if response.status_code == requests.codes.ok:
            filename = self.logdir + scanid + "." + scanslug + "." + \
                time.strftime("%Y-%m-%d") + "." + self.data_format
            with open(filename, 'w') as f:
                f.write(response.content)
            """with open(self.logdir + scanid + '.' + scanslug + '.timestamp', 'w') as f:
                f.write("%s" % timestamp)"""
            return "OK - %s" % filename
        else:
            return "got an error downloading file:\n%s" % response.content

    def present(self, dictlist):
        """ take a list of dicts (from data, for instance) and present them
        to choose from. req: name/id fields """

        for d in dictlist:
            try:
                displaystring = "%s\t%s" % (d['id'], d['name'])
            except KeyError:
                continue  # git faakd
            try:
                displaystring += '\tStatus: %s' % d['status']
            except KeyError:
                pass
            try:
                if d['default_tag'] == 1:
                    displaystring += "\tDefault Folder"
            except:
                pass
            print displaystring

    def check_quit(self, x):

        if x.lower() in ['q', 'quit', 'exit', 'ohshit', 'x']:
            print "bye!"
            sys.exit(0)
        else:
            return x

    def interactive(self):
        """pretend you're a command-line interface to nessus"""
        print """1. Download scan results
2. Start or stop scans
3. Create new scan
4. Quit"""
        x = raw_input('Choose an option or quit: ')
        x = self.check_quit(x)
        if x == '1':
            return self.download_scans()
        if x == '2':
            return self.manage_scans()
        if x == '3':
            return self.create_scan()
        if x == '4':
            print "bye!"
            sys.exit(0)
        else:
            print "I didn't understand that, sorry."
            return self.interactive()

    def create_scan(self, name=None, description=None,
                    policy=None, targets=None):

        if name is None:
            name = raw_input("Please enter a name for this scan: ").strip()
            name = self.check_quit(name)
        if description is None:
            description = raw_input("Please enter a description: ").strip()
            description = self.check_quit(description)
        if policy is None:
            pols = self.jsonget('policies')['policies']
            polids = []
            for pol in pols:
                polids.append(pol['id'])
            self.present(pols)
            x = raw_input('Choose a policy for this scan: ').strip()
            x = self.check_quit(x)
            if int(x) in polids:
                policy = int(x)
            else:
                print "I'm not sure what you meant there - let's try again"
                return self.create_scan(name, description)
        if targets is None:
            targets = raw_input('Enter scan targets(IP, cidr range, '
                                'hostnames in a comma - separated list): '
                                ).strip()
            targets = self.check_quit(targets)

        results = self.createscan(name, description, targets, policy)
        if isinstance(results, type({})):
            log("created scan id %s" % results['scan']['id'])
            print "Created scan, id: %s" % results['scan']['id']
        else:
            log("failed to create scan: %s" % results.content)
            print "Failed to create scan: %s" % results.content

        time.sleep(1)
        return self.interactive()

    def toggle_scan(self, scanid, status):
        if status.lower() != 'running':
            bit = 'launch'
        else:
            bit = 'stop'
        r = self.jsonpost('scans', args=[scanid, bit])
        return r

    def manage_scans(self):
        """semi-stub"""
        scans = self.jsonget("scans")['scans']
        scanid2status = {}
        for scanid in scans:
            scanid2status[scanid['id']] = scanid['status'].lower()
        self.present(scans)

        x = raw_input(
            "0\tto return to previous menu\nselect scan to start/stop: ")
        x = self.check_quit(x)
        x = int(x)
        if x == 0:
            return self.interactive()
        if x in scanid2status.keys():
            r = self.toggle_scan(x, scanid2status[x])
            if isinstance(r, type({})):
                if 'scan_uuid' in r.keys():
                    print "Started scan %s" % x
                else:
                    print "stopped scan %s, probably?" % x
            else:
                print "Starting/stopping scan %s produced an error:\n%s" % (
                    x, r.text)
        time.sleep(1)
        return self.manage_scans()

    def download_scans(self):
        """ present a list of available scans to download """
        scans = self.jsonget('scans')['scans']
        scanids = []
        scanid2name = {}
        for scan in scans:
            scanids.append(str(scan['id']))
            scanid2name[str(scan['id'])] = scan['name']
        print "Scan ID\tScan Name"
        self.present(scans)
        print
        x = raw_input(
            'Choose a scan to download or 0 for all (quit to exit): ')
        x = self.check_quit(x)
        if x in scanids:
            self.get_report(x, scanid2name[x])
            return 1
        elif x == '0':
            for scanid in scanids:
                self.get_report(scanid, scanid2name[scanid])
            return 1
        else:
            print "Sorry, I didn't understand that."
            time.sleep(1)
            return self.interactive()
        return 0

    def jsonget(self, endpoint, args=None, data=None):
        """ wrapper for self.get which just returns the data object """

        response = self.get(endpoint, args, data)
        if response.status_code == requests.codes.ok:
            js = json.loads(response.text)
        else:
            js = response  # consider returning the response object instead.
        return js

    def jsonpost(self, endpoint, args=None, data=None):
        """ wrapper for self.post which just returns the data object """

        response = self.post(endpoint, args, data)
        if response.status_code == requests.codes.ok:
            js = json.loads(response.text)
        else:
            js = response
        return js

    def createscan(self, name, description, targets, pid=None, email=None):
        """create a new scan object on the server. Run it. If pid (policy id)
        is none or incorrect, use the most recently created policy.
        Dangerous games! But like, don't use the wrong policy id. """

        if not isinstance(pid, type(1)) and pid:
            pid = int(pid)

        if pid is None or pid not in self.policies.keys():
            pids = sorted(self.policies.keys())
            pid = pids[-1]
        # targets should be a comma-separated list of cidr ranges, host names,
        # ips.
        if email is None:
            email = ''

        policy_uuid = self.policies.get(pid).get('uuid')

        data = {'uuid': policy_uuid,
                'settings': {
                    'name': name,
                    'description': description,
                    'text_targets': targets,
                    'policy_id': pid,
                    'file_targets': '',
                    'launch': 'ONDEMAND',
                    'launch_now': True,
                    'emails': email,

                }
                }
        results = self.jsonpost('scans', data=data)
        return results


def log(s, crit=None):
    if crit is None:
        crit = logging.INFO
    if crit == logging.ERROR:
        print s
    logger.log(crit, s)


def errorquit(s):
    log(s, logging.ERROR)
    sys.exit(1)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--get-all-new",
        help="Get all reports updated since last run, otherwise interactive",
        action="store_true")
    parser.add_argument("-u", "--username", help="username for nessus")
    parser.add_argument("-p", "--password", help="password for nessus")
    parser.add_argument(
        "-U",
        "--url",
        help="Full URL for nessus, i.e. https://nessus.local:8443")
    parser.add_argument(
        "-n",
        "--no-verify-ssl",
        help="Use this if your nessus instance's certificate is not "
        "valid in this context",
        action="store_false")
    parser.add_argument(
        "-c",
        "--config-file",
        help="Path to config file",
        type=argparse.FileType('r'))
    parser.add_argument("-o", "--out-dir", help="Path to save nessus reports")
    parser.add_argument(
        "-f",
        "--format",
        choices=[
            'nessus',
            'pdf',
            'html',
            'csv'],
        help="Nessus export format - defaults to nessus",
        default='nessus')
    parser.add_argument(
        "-i",
        "--interactive",
        help="interactive/debug mode",
        action="store_true")
    parser.add_argument(
        "-s",
        "--scan",
        help="add a scan. Use json, indicate at least {name:string, "
        "targets:string, policy_id:int} and possibly description:string, "
        "emails:string.")
    args = parser.parse_args()

    host = None
    port = None
    username = None
    password = None
    logdir = None
    verify = None
    data_format = None
    api = False

    if args.config_file:
        config = ConfigParser.SafeConfigParser()
        config.readfp(args.config_file)
        try:
            host = config.get("nessus", "host")
        except:
            pass
        try:
            port = config.get("nessus", "port")
        except:
            pass
        try:
            username = config.get("nessus", "username")
        except:
            pass
        try:
            password = config.get("nessus", "password")
        except:
            pass
        try:
            username = config.get("nessus", "accesskey")
            api = True
        except:
            pass
        try:
            password = config.get("nessus", "secretkey")
        except:
            pass
        try:
            verify = config.getboolean("nessus", "verify")
        except:
            pass
        try:
            logdir = config.get("nessus", "logdir")
        except:
            pass
        try:
            data_format = config.get("nessus", "format")
        except:
            pass

    if args.url:
        try:
            x, host, port = args.url.split(':')
            host = host.lstrip('/')
        except:
            errorquit("invalid url %s" % args.url)

    if args.username:
        username = args.username
    if args.password:
        password = args.password
    if verify is None:
        verify = args.no_verify_ssl
    if args.out_dir:
        logdir = args.out_dir
    if args.format:
        data_format = args.format

    if username is None or password is None or host is None or port is None:
        errorquit("We need all of: host, port, username and password. "
                  "\nPlease either use the command line options or a "
                  "config file")

    if logdir and not os.path.isdir(logdir):
        log("%s doesn't exist, trying to create %s:" % (logdir, logdir))
        try:
            os.makedirs(logdir)
        except:
            errorquit(
                "Could not create %s - bailing out. Please use a real path." %
                logdir)

    ness = nessus(
        host,
        port,
        username,
        password,
        verify=verify,
        logdir=logdir,
        data_format=data_format,
        api=api)

    if args.interactive:
        return ness
    if args.scan:
        try:
            scan = json.loads(args.scan)
        except:
            errorquit("can't parse this json, sorry")
        try:
            name = scan['name']
        except:
            errorquit("Need valid name for scan")
        try:
            targets = scan['targets']
        except:
            errorquit("Need targets for scan")
        try:
            policyid = scan['policy_id']
        except:
            errorquit("Need a policy ID")
        try:
            description = scan['description']
        except:
            description = ''
        try:
            emails = scan['emails']
        except:
            emails = ''
        j = ness.createscan(name, description, targets, policyid, emails)
        if isinstance(j, type({})):
            logging.info("Scan created:\nID:%s Name: %s Targets: %s",
                         (j['scan']['id'], j['scan']['name'],
                          j['scan']['custom_targets']))
            print "Scan created:\nID:%s Name: %s Targets: %s" % (
                j['scan']['id'], j['scan']['name'],
                j['scan']['custom_targets'])
        else:
            log("something went wrong with creating scan: %s" %
                j.text, logging.ERROR)
        return ness

    if args.get_all_new:
        ness.get_all_reports()
    else:
        x = ness.interactive()

    return ness

if __name__ == '__main__':

    ness = main()
