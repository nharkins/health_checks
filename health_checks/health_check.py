#!/usr/bin/python -u
import os
import re
import sys
import time
import copy
import pprint
import socket
import signal
import subprocess
import threading
import traceback
import logging
import decimal
import optparse
import urllib
import urllib2
import base64
import json

import yaml

PP = pprint.PrettyPrinter(indent=1, width=1)
def pretty(obj):
    return PP.pformat(obj)

logging.basicConfig(format='%(asctime)s %(levelname)s %(name)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream = sys.stderr)

EXECUTION_INTERVAL = 20 
# defined in stats-collector.d
# so setting at 10 here to alert us when getting close
# but note that stats-collector prevents "stacking" up multiple

OLD_STATE_DIR = '/var/service-stage/stats-collector'
STATE_DIR = '/var/lib/stats-collector-state'

NSCA_BINARY_PATH = '/usr/sbin/send_nsca' # sudo yum install nsca-client
NSCA_CONFIG_PATH = '/etc/nagios/send_nsca.cfg' # fcm to push these out?
CRIT = 'CRIT'
WARN = 'WARN'
OK = 'OK'
NAG_CODE = {OK:0, WARN:1, CRIT:2}
DEFAULT_CRIT_PCT = 95
DEFAULT_WARN_PCT = 85
DEFAULT_NAGIOS_SERVER = 'system-nagios-internal'

class HTTPGetException(Exception):
    pass

def http_get(url, args = None, debug = False, timeout = 60):
    if type(args) is str:
        query_string = urllib.urlencode({'a':args})[2:]
        # that is lame, surely there's a non-dict/str urlencode
    elif type(args) is dict:
        query_string = urllib.urlencode(args)
    elif args == None:
        query_string = ''
    else:
        raise AssertionError()
    url = url + '?' + query_string.replace('%28','(') \
                                  .replace('%29',')') \
                                  .replace('%2C',',')
    req = urllib2.Request(url)
    if debug:
        print url
    try:
        # basically, i don't trust the timeout within urlopen,
        # so we put another timeout above it, with a few more seconds
        handle = exec_timeout(urllib2.urlopen, timeout + 5,
                              req, timeout = timeout)
    except Exception, X:
        raise HTTPGetException('%s: %s' % (str(X), url))
    buf = handle.read()
    return buf

def range_get(range_expression, range_server = 'range.vip', timeout = 10):
    # we time it out (two places), and let it exit w/stacktrace
    # stats-collector will restart the health check
    tmp =  http_get('http://%s/range/list' % range_server,
                    range_expression,
                    timeout = timeout).split('\n')
    res = filter(None, tmp)
    return res

def perlre_extract(pattern, input, tests = None, debug = False):
    """
       on a pattern match which extracts via (), return [$1,$2,]
       on a pattern match which does not extract, return [None]
       on a pattern which does NOT match, return []
       if the first char of a pattern is !, eat the !, then do negative match
    """
    if type(input) not in (str, unicode):
        raise AssertionError("'input' argument is type '%s': '%s'"
                             % (type(input).__name__, repr(input)))
    if debug:
        result = perlre_debug(pattern, input)
    else:
        negation = False
        if pattern.startswith('!'):
            negation = True
            pattern = pattern[1:]
        result = []
        input = "%s" % input
        # if it wasn't a string, it will be now
        m = re.search(pattern, input)
        if m:
            if negation:
                result = []
            else:
                tmp = m.groups()
                if tmp:
                    # detuple-ize, just in case
                    for i in range(0,len(tmp)):
                        result.append(tmp[i])
                else:
                    result = [''] # i.e. positive, but no captures
        elif negation:
            result = ['']
    for i in range(len(result)):
        if result[i] == None:
            result[i] = ''
    if result and tests:
        if len(result) != len(tests):
            raise AssertionError('# tests must == # captures')
        for i in range(len(result)):
            if not tests[i]:
                continue
            test = tests[i] % tuple([result[i],] * tests[i].count('%s'))
            if not eval(test):
                if debug:
                    raise AssertionError('test #%i failed: %s' % (i, test))
                return []
    return result

def perlre_debug(pattern, input):
    """
       display where the potentially long pattern went wrong
    """
    fullpat_m = perlre_extract(pattern, input, debug = False) # avoid recursion
    if fullpat_m:
        return fullpat_m
    last = pattern
    matched = False
    for i in range(len(pattern),0,-1):
        # range stops before the 2nd arg,
        # so we'll always have at least one char in the pattern
        try:
            m = perlre_extract(pattern[0:i], input)
        except sre_constants.error:
            # took off an end marker, thus now invalid regex
            # keep going, eventually we'll take off the front marker
            continue
        if not m:
            last = pattern[0:i]
            continue
        if m:
            matched = True
            print "FAIL BEGINS AT LAST TOKEN SHOWN: %s <-- HERE" % last
            break
    if not matched:
        print "FAIL EVEN AT VERY FIRST TOKEN: %s" % pattern
    return fullpat_m

class TimeoutException(Exception):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return self.message
    def __repr__(self):
        return self.message

def exec_timeout(*args, **kwargs):
    """
       suppose you need this call to timeout after 5 seconds:
           foo(1, 2, bar = 3)
       just rewrtie it as:
           try:
               exec_timeout(foo, 5, 1, 2, bar = 3)
           except TimeoutException:
               print "timeout!"
    """
    target = args[0]
    timeout = int(args[1])
    args = args[2:]
    result = None
    def inner():
        # the reason for using the function.variable notation
        # is because multiple threads could easily use the
        # same proc instance at the same time, therefore
        # a global won't work. also, a simple "result ="
        # won't work because it's local to the function.
        # this is safe because the function is instantiated
        # per calling instance of the function.
        try:
            inner.result = target(*args, **kwargs)
        except Exception, X:
            print traceback.format_exc()
            inner.result = X
    myname = 'exec_timeout-%s' % time.time()
    t = threading.Thread(target = inner, name = myname)
    t.setDaemon(True) # so the parent can exit, killing hung threads,
                      # else it would just wait indefinitely for this thread
    t.start()
    t.join(timeout)
    if t.isAlive():
        # i.e. the thread will still be running. no way to kill it. :(
        raise TimeoutException('HIT TIMEOUT of %is on still-runnning '
                               '%s(args=*%s, kwargs=**%s)'
                               % (timeout, target.__name__,
                                  repr(args), repr(kwargs)))
    if issubclass(type(inner.result), Exception):
        raise inner.result
    return inner.result

class HealthCheck(object):
    def __init__(self, state_filename=None, debug=False):
        os.nice(10)
        if not hasattr(self, 'name'):
            raise AssertionError('subclass must define .name')
        if self.name:
            self.default_service = self.name + '_health'
        else:
            # general_health defines name as ''
            # to populate multiple subtrees of the node,
            # while mysql and postgres are all under that
            self.default_service = 'general_health'
        self.nag_router = {self.default_service:'.+'} 
        # NOTE: that matches all, for now, later might be first match only
        self.log = logging.getLogger(self.name + '_healthcheck')
        self.debug = debug
        if debug:
            self.log.setLevel(logging.DEBUG)
        if os.getcwd() not in (OLD_STATE_DIR, STATE_DIR):
            self.log.warn("cwd is '%s', should be '%s' (or '%s')"
                          % (os.getcwd(), STATE_DIR, OLD_STATE_DIR))
            if os.path.isdir(STATE_DIR) and os.access(STATE_DIR, os.W_OK):
                os.chdir(STATE_DIR)
            elif (os.path.isdir(OLD_STATE_DIR) and 
                  os.access(OLD_STATE_DIR, os.W_OK)):
                os.chdir(OLD_STATE_DIR)
            else:
                self.log.error('need to be able write state '
                               'to a stats-collector state dir')
                os._exit(1)
        self.state_dir = os.getcwd()
        if state_filename:
            self.filename = state_filename
        else:
            self.filename = self.name + '.yaml'
        # internal absolute metrics used for deltas
        self.state_last = {}
        self.state_current = {}
        self.state_last_time = None
        self.state_current_time = None
        # exposed metrics, e.g. deltas from absolute states
        self.params = {}
        self.nag = {} # contains thresholds for metric.name=float
        self.nag_msg = {'CRIT':[], 'WARN':[], 'OK':[]} # just strings
        self.host = socket.gethostname()
        self.num_cores = self.cpu_info()['cpu_cores']

        # XXX TODO: check version of __main__.__file__?

    def oomkiller_protect(self, pid):
        # NOTE: this requires root access,
        # despite the permissions on the "file"
        # being owned by the process owner
        oom_score_adj_file = "/proc/%s/oom_score_adj" % pid
        try:
            with open(oom_score_adj_file, 'w') as f:
                f.write("-1000\r\n")
        except Exception, X:
            self.log.error('%s: %s' % (oom_score_adj_file, str(X)))

    def cmdline(self, cmd, env = None):
        envdict = copy.deepcopy(os.environ)
        if env:
            for key in env.keys():
                envdict[key] = env[key]
        p = subprocess.Popen(cmd, shell=True, env=envdict,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             close_fds=True,
                             preexec_fn=lambda:
                                 signal.signal(signal.SIGPIPE, signal.SIG_DFL))
                         # https://blog.nelhage.com/2010/02/a-very-subtle-bug/
        self.log.debug('executing: %s' % cmd)
        stdout = ''
        # http://stackoverflow.com/questions/1410849
        # http://hg.python.org/cpython/rev/03a056c3b88e
        tmp_buf = ' ' # to get into the loop
        while p.returncode == None or tmp_buf:
            tmp_buf = p.stdout.read(1)
            stdout += tmp_buf
            p.poll()
        return (p.returncode, stdout)

    def cpu_info(self):
        mydict = {}
        rc, blob = self.cmdline('cat /proc/cpuinfo')
        total_processors = 0
        cpu_cores = None
        siblings = None
        models = {} # set()?
        for line in blob.split('\n'):
            line = line.strip()
            if not line or not ':' in line:
                continue
            k,v = [x.strip() for x in line.split(':',1)]
            if k == 'model name':
                v = ' '.join(v.split()) # collapse multiple spaces into single
                models[v] = 1
            if not cpu_cores and k == 'cpu cores':
                cpu_cores = int(v)
                continue
            if not siblings and k == 'siblings':
                siblings = int(v)
                continue
            if k == 'processor':
                total_processors += 1
                continue
        # If siblings doesn't match cpu_cores, we have HT:
        has_hyperthreading = siblings != cpu_cores
        if has_hyperthreading:
            cores = total_processors / 2
        else:
            cores = total_processors
        mydict['cpu_model'] = ','.join(models)
        mydict['cpu_cores'] = cores
        mydict['cpu_hyperthreading'] = has_hyperthreading
        return mydict

    def processes(self, substr=None):
        """
           returns a list of dictionaries parsed from "ps aux"
        """
        result = []
        cmd = 'ps aux | grep -v grep'
        if not substr and hasattr(self, 'name'):
            substr = self.name
        if substr:
            if "'" in substr:
                raise AssertionError('singlequotes invalid in substr')
            cmd += " | grep -F '%s' " % substr
        rc, out = self.cmdline(cmd)
        for line in out.split('\n'):
            if not line:
                continue
            fields = line.split()
            p = {}
            try:
                p['user'], p['pid'], p['%cpu'], p['%mem'], \
                    p['vsz'], p['rss'], p['tty'], p['stat'], \
                    p['start'], p['time'] = fields[:10]
            except ValueError:
                self.log.error("ERROR: incomplete 'ps aux' output line: %s"
                               % repr(fields))
                raise
            p['cmd'] = ' '.join(fields[10:])
            if substr and (substr in p['user'] or substr in p['cmd']):
                result.append(p)
        return result

    def query_return_columns_tuples(self, query, timeout = 5):
        return exec_timeout(self._query_return_columns_tuples,
                            timeout, query)

    def _query_return_columns_tuples(self, query):
        """
           executes a query using subclass self.cur
           which conforms to python db api spec 2.0
        """
        if self.debug:
            print query
        try:
            self.cur.execute(query)
        except:
            print query
            raise
        column_names = []
        if not self.cur.description:
            return ((), ())
        for col_meta_list in self.cur.description:
            column_names.append(col_meta_list[0])
        res = self.cur.fetchall()
        if self.debug:
            print res
        return (column_names, res)

    def query_return_dict_result(self, query):
        """
           executes a query using subclass self.cur
           which conforms to python db api spec 2.0
        """
        column_names, res = self.query_return_columns_tuples(query)
        result = []
        for row in res:
            dictrow = {}
            for i in range(len(column_names)):
                dictrow[column_names[i]] = row[i]
            result.append(dictrow)
        return result

    def load_state(self, filename=None):
        """
           returns tuple of (mtime, struct)
        """
        if self.state_last_time and self.state_last:
            self.log.debug('using already loaded state from %s/%s'
                          % (self.state_dir, self.filename))
            return (self.state_last_time, self.state_last)
        t0 = time.time()
        self.log.debug('loading state from %s/%s' 
                       % (self.state_dir, self.filename))
        if not os.path.isfile(self.filename):
            # want to throw exception if it's not readable
            #or not os.access(self.filename, os.R_OK)):
            self.state_last_time = 0
            return (0, {})
        self.state_last_time = int(os.stat(self.filename).st_mtime)
        # ^ should use os.path.getmtime() instead?
        with open(self.filename, 'r') as f:
            try:
                self.state_last = yaml.safe_load(f)
            except Exception, X:
                self.log.error('could not parse yaml from %s/%s: %s'
                               % (self.state_dir, self.filename, X))
                return (0, {})
        self.log.debug('load_state of %s keys took %ss' \
                       % (len(self.state_last), time.time() - t0))
        return (self.state_last_time, self.state_last)

    def save_state(self, obj=None, filename=None):
        t0 = time.time()
        if not hasattr(self, 'state_current'):
            self.state_current = obj
        if not obj and hasattr(self, 'state_current'):
            obj = self.state_current
        with open(self.filename, 'w') as f:
            yaml.dump(obj, stream=f)
        self.log.debug('save_state of %s keys took %ss' \
                       % (len(self.state_current), time.time() - t0))

    def output_stats_collector(self):
        if not self.params and not self.nag_msg['CRIT']:
            self.params = self.gather()
        buf = []
        for key in sorted(self.params.keys()):
            name = ''
            if self.name:
                name = '.' + self.name
            metric_name = 'nodes.%s%s.%s' \
                          % (self.host.replace('.','_'),
                             name, key)
            if (self.params[key] == None 
                or (type(self.params[key]) in (str, unicode) and
                    self.params[key].strip() == '')):
                self.log.warn("%s='%s'\n" 
                              % (metric_name, self.params[key]))
                continue
            try:
                line = '%s %.04f ts=%s' \
                       % (metric_name,
                          float(self.params[key]),
                          self.state_current_time)
            except Exception, X:
                self.log.warn('%s -> float(%s): %s' 
                              % (metric_name, self.params[key], str(X)))
                continue
            buf.append(line)
        return '\n'.join(buf)

    def nagios_check(self):
        nag_results = {}
        if not self.params and not self.nag_msg['CRIT']:
            self.params = self.gather()
        for service in self.nag_router.keys():
            regex = self.nag_router[service]
            pairs_by_level = { CRIT:{}, WARN:{}, OK:{} }
            for key in self.params.keys():
                m = perlre_extract(regex, key)
                if not m:
                    continue
                if key in self.nag:
                    if CRIT in self.nag[key]:
                        try:
                            expr = '%s %s' % (self.params[key], 
                                              self.nag[key][CRIT])
                            if eval(expr):
                                pairs_by_level[CRIT][key] = self.params[key]
                        except (SyntaxError, TypeError):
                            self.log.error("invalid expression "
                                           "for %s CRIT: '%s'"
                                           % (key, self.nag[key][CRIT]))
                    if (key not in pairs_by_level[CRIT] and
                        WARN in self.nag[key]):
                        try:
                            expr = '%s %s' % (self.params[key], 
                                              self.nag[key][WARN])
                            if eval(expr):
                                pairs_by_level[WARN][key] = self.params[key]
                        except (SyntaxError, TypeError):
                            self.log.error("invalid expression "
                                           "for %s WARN: '%s'"
                                           % (key, self.nag[key][WARN]))
                    if (key not in pairs_by_level[CRIT] and 
                        key not in pairs_by_level[WARN]):
                        pairs_by_level[OK][key] = self.params[key]
                elif key.endswith('_pct'):
                    if self.params[key] >= DEFAULT_CRIT_PCT:
                        pairs_by_level[CRIT][key] = self.params[key]
                    elif self.params[key] >= DEFAULT_WARN_PCT:
                        pairs_by_level[WARN][key] = self.params[key]
                    else:
                        pairs_by_level[OK][key] = self.params[key]
                else:
                    self.log.debug('no threshold for %s=%s'
                                   % (key, self.params[key]))
            # we tailor our message to provide only the most important details
            if (len(pairs_by_level[CRIT]) or
                service == self.default_service and len(self.nag_msg['CRIT'])):
                lvl = CRIT
                res = pairs_by_level[CRIT]
            elif (len(pairs_by_level[WARN]) or
                service == self.default_service and len(self.nag_msg['WARN'])):
                lvl = WARN
                res = pairs_by_level[WARN]
            else:
                lvl = OK
                res = pairs_by_level[OK]
            msg = ' '.join(map(lambda x: '%s=%0.2f' % (x, float(res[x])), 
                               sorted(res.keys())))
            # XXX TODO: rework self.nag_msg to use self.params,
            # but string/unicode type instead of int/float type
            if service == self.default_service and self.nag_msg[lvl]:
                if msg:
                    msg +=  ', '
                msg += ', '.join(self.nag_msg[lvl])
            nag_results[service] = [lvl, msg]
        for service in nag_results.keys():
            lvl, msg = nag_results[service] 
            if lvl != OK:
                self.log.warn('%s: %s %s' % (service, lvl, msg))
            else:
                self.log.info('%s: %s %s' % (service, lvl, msg))
        return nag_results

    def send_nagios_passive(self, server):
        nag_results = self.nagios_check()
        for service in nag_results.keys():
            state_code, message = nag_results[service]
            state_code = NAG_CODE[state_code]
            fields = (self.host, service, state_code, message)
            info = '\t'.join(map(str, fields))
            try:
                #tmpfile = '/tmp/ncsa_%' % time.time()
                #with open(tmpfile, w) as f:
                #    f.write(info + '\n')
                #cmd = '%s %s -c %s < %s' % (NSCA_BINARY_PATH,
                #                            server,
                #                            NSCA_CONFIG_PATH,
                #                            tmpfile))
                cmd = 'printf "%s\\n" | %s %s -c %s' % (info.replace('%','%%'), 
                                            # /usr/bin/printf converts % to 0.00000
                                            NSCA_BINARY_PATH,
                                            server,
                                            NSCA_CONFIG_PATH)
                rc, out = self.cmdline(cmd)
                # test result code, print to stderr on failure
                if rc:
                    self.log.error("'%s' errored with:\n%s" % (cmd, out))
                else:
                    self.log.debug("'%s' stdout:\n%s" % (cmd, out))
            except Exception, X:
                self.log.error("'%s' errored with:\n%s" % (cmd, X))
            #os.unlink(tmpfile)

    def gather(self):
        t0 = time.time()
        self.params = {} # external parameters, e.g. deltas
        self.load_state()
        if int(time.time()) == int(self.state_last_time):
            self.log.warn('sleeping for 1s to avoid zero-division in deltas')
            time.sleep(1)
        self.state_current_time = int(time.time())
        if hasattr(self, 'get_version'):
            self.get_version() # first because it can toggle behavior in others
        early_exit = False
        for name in dir(self):
            if name == 'get_version':
                continue
            method = eval('self.' + name)
            if (type(method).__name__ == 'instancemethod' and
                name.startswith('get_')):
                self.log.debug('EXECUTING %s()' % name)
                try:
                    method() # i.e. execute it
                except TimeoutException, X:
                    early_exit = True
                    self.nag_msg['CRIT'].append('QUERY TIMEOUT in %s()' % name)
                    print X
                    # don't execute any more collectors, 
                    # they'd probably block also
                    break 
                self.log.debug('FINISHED %s()' % name)
        if not early_exit:
            self.save_state()
        if (time.time() - self.state_current_time) > (EXECUTION_INTERVAL * .9):
            msg = 'data collection taking %ss' \
                  % (time.time() - self.state_current_time,)
            self.log.warn(msg)
            self.nag_msg['WARN'].append(msg)
        # NOTE: we grab load average here, so subclasses can alert on it
        rc, out = self.cmdline('uptime')
        lav1, lav5, lav15 = out.split()[-3:]
        self.params['loadavg.1min'] = float(lav1.strip(','))
        self.params['loadavg.5min'] = float(lav5.strip(','))
        self.params['loadavg.15min'] = float(lav15.strip(','))
        return self.params

    def calc_rate(self, key, current_value):
        """
           XXX: is there concern of wraparound here?
           <jat> suggests sending the absolute values,
           then configuring the individual graphs to be deltas,
           in graphite or whatever's next
        """
        key = str(key) # convert from unicode
        stamp = key + '_stamp'
        self.state_current[key] = current_value
        self.state_current[stamp] = time.time()
        if not (key in self.state_last and stamp in self.state_last):
            return None
        return abs((self.state_current[key] - self.state_last[key]) \
                 / (self.state_current[stamp] - self.state_last[stamp]))

class GeneralHealth(HealthCheck):
    def __init__(self, debug=False):
        self.name = '' # each get_...() must use a prefix!
        super(GeneralHealth, self).__init__(debug=debug, 
                             state_filename = 'general_health.yaml')
        self.load_state()

    def get_tmp(self):
        # i found some @mysql machines with /tmp -> /data/tmp
        # and owned by mysql, not root, so "ssh .. sudo" was failing.
        # ideally, this should be done by config/state management system,
        # but puppet is deprecated, and FCM is file-based, not for ad-hoc cmds,
        # and hoist only runs on deploys, so it wouldn't fix this.
        # so we don't currently have anything to do this kind of ensurance
        # so i'm doing it here. 
        TMP = '/tmp'
        s = os.lstat(TMP)
        tmp_mode = "%o" % (s.st_mode & 07777)
        if tmp_mode != '1777':
            self.log.error('%s mode was %s, changing to 01777' 
                           % (TMP, tmp_mode))
            os.chmod(TMP, 01777)
        if s.st_uid != 0 or s.st_gid != 0:
            self.log.error('%s uid/gid was %s/%s, changing to root'
                           % (TMP, s.st_uid, s.st_gid))
            os.chown(TMP, 0, 0)

    def get_sips(self):
        rc, out = self.cmdline('/sbin/ip addr')
        for line in out.split('\n'):
            # sip can look like either:
            #inet 10.1.68.8/32 scope global bond0
            #inet 10.1.68.8/32 scope global secondary bond0
            m = perlre_extract('^\s+inet ([0-9\.]+)\/\d+ scope global ', line)
            if m:
                sip_hostname = socket.gethostbyaddr(m[0])[0].replace('.','_')
                self.params['sip.%s' % sip_hostname] = 1

    def get_khugepaged_proc_info(self):
        self.params['khugepaged.num_processes'] = 0
        for proc in self.processes('[khugepaged]'):
            if '[khugepaged]' in proc['cmd']:
                self.params['khugepaged.num_processes'] += 1
                self.params['khugepaged.cpu_pct'] = float(proc['%cpu'])
                self.params['khugepaged.mem_pct'] = float(proc['%mem'])
                self.params['khugepaged.mem_vsz'] = float(proc['vsz'])
                self.params['khugepaged.mem_rss'] = float(proc['rss'])

    def get_conntrack(self):
        # requires root access to execute: 
        cmd = 'wc -l /proc/net/nf_conntrack'
        rc, out = self.cmdline(cmd)
        # 603 /proc/net/nf_conntrack
        try:
            current = float(out.split()[0])
        except ValueError:
            self.log.error("need to run as root? '%s' output '%s'" 
                           % (cmd, out))
            return
        rc, out = self.cmdline('sysctl net.nf_conntrack_max')
        # net.nf_conntrack_max = 262144
        max = float(out.split()[2])
        self.params['conntrack_used_pct'] = (current / max) * 100

    def get_tcp_state_counts(self):
        rc, out = self.cmdline("/usr/sbin/ss -an")
        state_counts = {}
#ESTAB      0      0               127.0.0.1:57482            127.0.0.1:28309
        for line in out.split('\n'):
            m = perlre_extract('^(\S+)\s+\d+\s+\d+\s+(\d+\.\d+\.\d+\.\d+):\d+',
                               line)
            if not m:
                continue
            state, src_ip = m
            state = state.replace('-', '_')
            src_ip = src_ip.replace('.', '_')
            if src_ip not in state_counts:
                state_counts[src_ip] = {}
            if state not in state_counts[src_ip]:
                state_counts[src_ip][state] = 0
            state_counts[src_ip][state] += 1
        for src_ip in state_counts:
            for state in state_counts[src_ip]:
                self.params['tcp.%s.%s' % (src_ip, state)] = float(state_counts[src_ip][state])
                self.nag['tcp.%s.%s' % (src_ip, state)] = {WARN:'>= 20000', CRIT:'>= 28000'}

    def get_vmstat(self, cmd = "vmstat 1 5"):
        rc, out = self.cmdline(cmd)
        """
procs -----------memory---------- ---swap-- -----io---- --system-- -----cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 1  0 513908 788584  35048 285252288    0    0    34   202    0    0  3  1 97  0  0	
 1  0 513908 785428  35048 285254400    0    0     0  1120 4426 2365  4  1 95  0  0	
 1  0 513908 789736  35048 285254336    0    0     0  1336 5271 3308  4  2 95  0  0	
"""
        f = out.split('\n')[-2].split()
        self.params['vmstat.proc_wait_run'] = f.pop(0)
        self.params['vmstat.proc_unintr_sleep'] = f.pop(0)
        self.params['vmstat.mem_virt_used'] = f.pop(0)
        self.params['vmstat.mem_free'] = f.pop(0)
        if ' -a ' in cmd:
            self.params['vmstat.mem_buffers'] = f.pop(0)
            self.params['vmstat.mem_cache'] = f.pop(0)
        else:
            self.params['vmstat.mem_inact'] = f.pop(0)
            self.params['vmstat.mem_active'] = f.pop(0)
        self.params['vmstat.mem_swap_bi'] = f.pop(0)
        self.params['vmstat.mem_swap_bo'] = f.pop(0)
        self.params['vmstat.dev_blocks_in'] = f.pop(0)
        self.params['vmstat.dev_blocks_out'] = f.pop(0)
        self.params['vmstat.sys_interrupts'] = f.pop(0)
        self.params['vmstat.sys_context_switches'] = f.pop(0)
        self.params['vmstat.cpu_user_time'] = f.pop(0)
        self.params['vmstat.cpu_kern_time'] = f.pop(0)
        self.params['vmstat.cpu_idle_time'] = f.pop(0)
        self.params['vmstat.cpu_iowait'] = f.pop(0)
        self.params['vmstat.cpu_steal_time'] = f.pop(0)
        # weird: vmstat bi/bo apparently are ~5x snmpd "swapIn"/"swapOut"
        # these limits are still too noisy
        #self.nag['vmstat.mem_swap_bi'] = {WARN:'>= 1000', CRIT:'>= 5000'}
        #self.nag['vmstat.mem_swap_bo'] = {WARN:'>= 1000', CRIT:'>= 5000'}
        # load avg should be sufficient coverage on cpu, so commenting for now
        #self.nag['vmstat.cpu_idle_time'] = {WARN:'<= 5', CRIT:'<= 1'}

    def get_numa(self):
        rc, out = self.cmdline("numactl --hardware")
        struct = {}
        for line in out.split('\n'):
            m = perlre_extract('node (\d+) (\S+): (\d+) MB', line)
            if m:
                nodeid, param, value = m
                if nodeid not in struct:
                    struct[nodeid] = {}
                struct[nodeid][param] = float(value)
                self.params['numa.bank%s.%s_MB' % (nodeid, param)] \
                                                       = float(value)
        avail_pcts = []
        for nodeid in struct:
            avail_pct = struct[nodeid]['free'] / struct[nodeid]['size']
            avail_pcts.append(avail_pct)
            self.params['numa.bank%s.avail_pct' % (nodeid,)] = avail_pct
        if len(avail_pcts) < 2:
            return
        self.params['numa.imbalance'] = max(avail_pcts) - min(avail_pcts)
        self.nag['numa.imbalance'] = {WARN:'>= 20'} # XXX TODO: tune threshold

    def get_fio_status(self):
        # according to fio support, this misconfiguration causes 
        # the off-peak 99th percentile latency spikes beemo saw
        # when space used on the fio is > 80% full
        rc, out = self.cmdline("fio-status -fj -U")
        try:
            fio = json.loads(out)
            epo = fio['adapter'][0]['external_power_override']
            if epo == '0':
                self.nag_msg['WARN'].append("fusionio external_power_override "
                                            "should not be set to 0")
        except:
            return

if __name__ == '__main__':
    p = optparse.OptionParser(usage = 'USAGE: %s' % '%prog')
    p.add_option('--debug', action='store_true', default = False)
    p.add_option('--output', type='string', default='stats-collector',
                 help="DEFAULT='stats-collector'")
    p.add_option('--nagios-server', type='str', default='',
                 help="DEFAULT is '', but you probably want '%s'" 
                      % DEFAULT_NAGIOS_SERVER)
    (opts, args) = p.parse_args()
    try:
        gh = GeneralHealth(debug=opts.debug)
        gh.gather()
    except Exception, X:
        msg = X.__class__.__name__ + ': ' + str(X)
        gh.log.error(msg)
        gh.nag_msg['CRIT'].append(msg)
        pass # so it goes to nagios
    output_handler = 'output_' + opts.output.replace('-','_')
    if not hasattr(gh, output_handler):
        raise AssertionError('unknown output handler: %s' % output_handler)
    exec('print gh.%s()' % output_handler)
    if opts.nagios_server:
        gh.send_nagios_passive(opts.nagios_server)
    os._exit(0) # to kill any hung exec_timeout threads


