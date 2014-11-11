#!/usr/bin/python -u
import os
import re
import sys
import time
import socket
import optparse
from ConfigParser import ConfigParser

# 3rd-party RPMs:
import mysql.connector

# other code from this package:
import health_check

DEFAULT_MYSQL_USER = 'root'
CRIT = 'CRIT'
WARN = 'WARN'
OK = 'OK'

SIP_RW_HOST = 'SIP_RW_HOST'
SIP_RO_HOST = 'SIP_RO_HOST'
BACKUP = 'MYSQL_BACKUP_HOSTS'

AUTO_DEBUG_RETENTION_MINS = 20

class MysqlHealthCheck(health_check.HealthCheck):
    def __init__(self, mysql_user = DEFAULT_MYSQL_USER, 
                 debug=False):
        self.creds = {'root': '/root/.my.cnf',
                      'nrpe': '/etc/my_nrpe.cnf'}
        self.name = 'mysql'
        self.mysql_user = mysql_user
        super(MysqlHealthCheck, self).__init__(debug=debug)

    def bootstrap(self):
        # here we route subsets of metrics to different alerts:
        self.nag_router['mysql.slave'] = '^slave.+$'
        self.nag_router['mysql.sessions'] = '^(conn_max_pct|sess.+|loadavg.+)$'
        self.nag_router['mysql.long'] = '^(active_long_run_queries|oldest_query_s|innodb_history_link_list)$'
        dsn = {'user':self.mysql_user, 'db':'information_schema'}
        socket_file = '/var/lib/mysql/mysql.sock'
        if os.path.exists(socket_file):
            dsn['unix_socket'] = socket_file
        try:
            self.conn = mysql.connector.connect(**dsn)
        except: # mysql.connector.errors.ProgrammingError
            if 'password' in dsn:
                raise
            if self.mysql_user not in self.creds:
                msg = "no known my.cnf for user '%s'" % self.mysql_user
                raise AssertionError(msg)
            ini_file = self.creds[self.mysql_user]
            if not os.path.exists(ini_file):
                msg = "'%s' does not exist" % ini_file
                raise AssertionError(msg)
            if not os.access(ini_file, os.R_OK):
                msg = "'%s' is not readable" % ini_file
                raise AssertionError(msg)
            try:
                ini = ConfigParser()
                ini.read(ini_file)
                password = ini.get('client', 'password')
                dsn['password'] = password
            except Exception, X:
                msg = 'looking for pw in %s: %s' % (ini_file, X)
                raise AssertionError(msg)
            self.conn = mysql.connector.connect(**dsn)
        self.cur = self.conn.cursor()
        self.query_return_columns_tuples("SET autocommit = 1;") # just in case
        self.load_state()
        # get any globals used by other routines here:
        sql = "SELECT @@GLOBAL.read_only;"
        cols, res = self.query_return_columns_tuples(sql)
        self.read_only = int(res[0][0])
        self.params['read_only'] = self.read_only

        sql = "SHOW GLOBAL VARIABLES LIKE 'innodb_log_file_size';"
        cols, res = self.query_return_columns_tuples(sql)
        self.innodb_log_file_size = float(res[0][1]) # in bytes

        # we capture innodb status and processlist if WARN or CRIT,
        # and they might contain PII, therefore we would like to 
        # keep the captures on the same disk as the data, if possible.
        self.debug_dir = '/data/mysql_health_captures'
        for flash in ('flash', 'virident', 'fusionio'):
            # fusionio and virident shouldn't both exist,
            # but if so, virident wins. plus moving to /data/flash instead
            if os.path.isdir('/data/%s' % flash):
                realdir = '/data/%s/mysql_health_captures' % flash
                if os.path.isdir(realdir):
                    self.debug_dir = realdir
                    break
                symlink = self.debug_dir
                if not os.path.isdir(symlink):
                    os.system('ln -s %s %s' % (realdir, symlink))
                    self.debug_dir = realdir
                    break 
        os.system('mkdir -p %s' % self.debug_dir) # make sure it exists
        self.debugfile_timestamp = time.strftime('%Y%m%d_%H%M%S')
        self.innodb_status = '' # cache for debug
        self.processlist = '' # cache for debug

        # NOTE: we do this here, as load is less significant on non-DBs
        self.nag['loadavg.5min'] = {CRIT:'>= %s' % (self.num_cores * 1.50),
                                    WARN:'>= %s' % (self.num_cores * 1.25)}
        # cache info from range, to reduce load
        self.cluster = ''
        use_cached_range = False
        if ('roles_stamp' in self.state_last and
            self.state_last['roles_stamp'] > (time.time() - 300) and
            not self.debug):
            use_cached_range = True
        if use_cached_range:
            self.roles = self.state_last['roles']
            for role in (SIP_RW_HOST, SIP_RO_HOST, BACKUP):
                if role not in self.roles:
                    self.roles[role] = []
            self.state_current['cluster'] = self.state_last['cluster']
            self.cluster = self.state_last['cluster']
            self.state_current['roles'] = self.state_last['roles']
            # important: keep the original stamp, so it expires:
            self.state_current['roles_stamp'] = self.state_last['roles_stamp']
        else:
            # get role expectations from range
            t0 = time.time()
            self.log.debug('querying range for roles')
            my_clusters = health_check.range_get(
                             "clusters(%s) &/-mysql-/" % self.host)
            # XXX: that could potentially timeout
            # if we expect range to remain crappy, i.e. not recover within 120s
            # then this code should change to at least check other metrics
            # without bailing...
            if my_clusters and len(my_clusters) > 1:
                for cluster in my_clusters:
                    if 'hoist' not in cluster:
                        self.cluster = cluster
                        break
            elif my_clusters:
                # XXX: need to be able to handle multiple clusters?
                self.cluster = my_clusters[0]
            self.state_current['cluster'] = self.cluster
            self.roles = {}
            for role in (SIP_RW_HOST, SIP_RO_HOST, BACKUP):
                self.roles[role] = []
                if self.cluster:
                    self.roles[role] = health_check.range_get("%%%s:%s" 
                                                 % (self.cluster, role))
            self.state_current['roles'] = self.roles
            self.state_current['roles_stamp'] = time.time()
            range_query_duration = time.time() - t0
            msg = 'querying range took %ss' % range_query_duration
            if range_query_duration > 5:
                self.log.warn(msg)
            else:
                self.log.debug(msg)
        self.cluster_ips = {} # using as a Set
        for role in self.roles.keys():
            if type(role) is not list:
                continue # old style in cache
            for host in filter(None, self.roles[role]):
                self.cluster_ips[socket.gethostbyname(host)] = 1

    def get_version(self):
        cols, res = self.query_return_columns_tuples("SELECT VERSION();")
        # looks like: 
        # '5.5.28-29.1' or '5.5.25a-27.1-log'
        version = res[0][0].replace('-','.')
        version = filter( lambda x: x in '0123456789.', version) # strip chars
        version_components = map(int, filter(None, version.split('.')))
        ver = version_components[0]
        for i in range(1, len(version_components)):
            ver += version_components[i] * (.01 ** i)
        self.params['version'] = ver
        self.nag['version'] = {OK:'or True'} # just informational

    def get_global_status(self):
        cols, res = self.query_return_columns_tuples("SHOW GLOBAL STATUS;")
        for row in res:
            name, value = row
            name = name.lower()
            if name in ('threads_running',
                        'threads_connected',
                        'uptime',
                        'innodb_row_lock_current_waits',
                        'innodb_current_row_locks',
                        'innodb_row_lock_time_avg',
                        'innodb_row_lock_time_max'):
                self.params[name] = float(value)
                self.nag['innodb_row_lock_current_waits'] = {}
            elif name == 'queries':
                # special case
                tps = self.calc_rate(name, float(value))
                if tps:
                    self.params['TPS'] = tps
                    self.nag['TPS'] = {OK:'or True'} # just informational
            elif name in ('innodb_log_os_waits',
                          'com_select',
                          # DDL
                          'com_create_table',
                          'com_alter_table',
                          'com_drop_table',
                          # TRX
                          'com_begin',
                          'com_commit',
                          'com_rollback',
                          # DML
                          'com_insert',
                          'com_insert_select',
                          'com_update',
                          'com_update_multi',
                          'com_delete',
                          'com_delete_multi',
                          'com_replace',
                          'com_replace_select',
                          # other increasing counters which need rates
                          'binlog_cache_use',
                          'binlog_cache_disk_use',
                          'sort_merge_passes',
                          'created_tmp_disk_tables',
                          'created_tmp_files',
                          'created_tmp_tables'):
                new_name = name + '_per_s'
                new_value = self.calc_rate(new_name, float(value))
                if new_value > 0:
                    self.params[new_name] = new_value
        # this was a litmus for the frisky sort merge query stacking up:
        self.nag['innodb_row_lock_current_waits'] = {CRIT:'>= 20', WARN:'>= 5'}

    def get_backups(self):
        # XXX TODO: combine process check with get_main_process_info() 
        # for only one pass through process table
        backup_procs = 0
        for proc in self.processes():
            if 'grep' in proc['cmd']:
                continue
            executable = proc['cmd'].split()[0]
            if ('innobackupex' in executable
                or 'mysqldump' in executable
                or 'mydumper' in executable):
                backup_procs += 1
        self.params['backups_running'] = backup_procs
        # check age of last backup
        if self.host not in self.roles[BACKUP] or not self.read_only:
            # must be both
            return
        rc, out = self.cmdline("ls -l /data/backups/")
        backup_file_timestamps = []
        for line in out.split("\n"):
            if not line.strip():
                continue
            fname = line.split()[-1]
            m = health_check.perlre_extract('(\d\d\d\d)[\-_](\d\d)[\-_](\d\d)[\-_ ](\d\d)[\-_:](\d\d)[\-_:](\d\d)', fname)
            if m:
                tm_isdst = time.localtime(time.time())[-1]
                # XXX: off by 1 hr when straddling dst changes
                m += [0, 0, tm_isdst]
                utime = time.mktime(map(int, m))
                backup_file_timestamps.append(utime)
        if len(backup_file_timestamps) == 0:
            self.nag_msg['WARN'].append('No backups whatsoever')
            return
        recent_backup = sorted(backup_file_timestamps)[-1]
        oldest_backup = sorted(backup_file_timestamps)[0]
        if recent_backup < (time.time() - (60 * 60 * 24)):
            # XXX TODO: need to verify that the backup is COMPLETE/GOOD
            self.nag_msg['WARN'].append('No backup in past 24 hours')
        elif oldest_backup < (time.time() - (60 * 60 * 24 * 7)):
            self.nag_msg['WARN'].append(
                                     'Backups older than 1 week need purging')
        else:
            self.nag_msg['OK'].append('Backups good')

    def get_writeability(self):
        if self.host in self.roles[SIP_RW_HOST]:
            if self.read_only:
                self.nag_msg['WARN'].append('@@GLOBAL.READ_ONLY should be OFF on RW SIP')

    def get_security(self):
        sql = """
SELECT GROUP_CONCAT(CONCAT(user, '@', host) SEPARATOR ', ') 
  FROM mysql.user WHERE password  = '' AND ssl_type = '';
"""
        cols, res = self.query_return_columns_tuples(sql)
        # aggregate result will be NULL if no rows
        if res[0][0]:
            self.nag_msg['WARN'].append('FOUND USERS WITHOUT PW OR SSL: %s'
                                        % res[0][0])
        vip_flipper_clause = ''
        if self.cluster_ips:
            vip_flipper_clause = """
   AND NOT (user = 'flipper' AND
            host IN (%s))
""" % ','.join(map(lambda x: "'" + x + "'", self.cluster_ips.keys()))
        sql = """
SELECT GROUP_CONCAT(CONCAT(user, '@', host) SEPARATOR ', ') 
  FROM mysql.user 
 WHERE super_priv = 'Y' 
%s
   AND NOT (user IN ('root','xtrabackup') AND 
            host IN ('localhost','127.0.0.1','::1')) 
""" % vip_flipper_clause
        # NOTE: ideally we can fix unity to not need SUPER.
        # NOTE: later on this code may run as something other than root,
        # but might need SUPER exception for SHOW ENGINE INNODB STATUS
        cols, res = self.query_return_columns_tuples(sql)
        if res[0][0]:
            # XXX TODO: only OK until we can address them, so as not to alert,
            # OR we move this alert to a different check:
            self.nag_msg['WARN'].append('FOUND USERS WITH SUPER PRIVS: %s'
                                        % res[0][0])

    def get_sessions(self):
        sql = """
SELECT @@GLOBAL.max_connections;
"""
        cols, res = self.query_return_columns_tuples(sql)
        sess_max = float(res[0][0])
        # we order the rows to assist someone debugging while "in the shit"
        sql = """
SELECT IF(command LIKE 'Sleep',1,0) + 
       IF(state LIKE '%master%' OR state LIKE '%slave%',1,0) AS sort_col, 
       processlist.* 
  FROM information_schema.processlist  
 ORDER BY 1, time DESC;
"""
        res = self.query_return_dict_result(sql)
        self.processlist = res # save for later dumping, if WARN/CRIT
        total = len(res)
        self.params['sess_cur_total'] = total 
        self.params['conn_max'] = sess_max
        self.params['conn_max_pct'] = (total / sess_max) * 100
        # pmp-check-mysql-processlist captures these:
        self.params['sessions.unauthenticated'] = 0
        self.params['sessions.table_lock_wait'] = 0
        self.params['sessions.locked'] = 0
        self.params['sessions.global_read_lock_wait'] = 0
        self.params['sessions.copy_to_table'] = 0
        self.params['sessions.statistics'] = 0
        active = 0.0 # float for division below
        for row in res:
            if row['COMMAND'] not in ('Sleep','Connect','Binlog Dump'):
                active += 1
            if health_check.perlre_extract('unauthenticated', row['USER']):
                self.params['sessions.unauthenticated'] += 1
            elif row['STATE'] == None:
                self.log.debug('WTF? ' + repr(row))
                continue
            elif health_check.perlre_extract('Locked', row['STATE']):
                self.params['sessions.locked'] += 1
            elif health_check.perlre_extract('Table lock', row['STATE']):
                self.params['sessions.table_lock_wait'] += 1
            elif health_check.perlre_extract('Waiting for global read lock', 
                                             row['STATE']):
                self.params['sessions.global_read_lock_wait'] += 1
            elif health_check.perlre_extract('opy.*table', row['STATE']):
                self.params['sessions.copy_to_table'] += 1
            elif health_check.perlre_extract('statistics', row['STATE']):
                self.params['sessions.statistics'] += 1
        self.params['sess_busy_pct'] = (active / total) * 100
        self.nag['sess_busy_pct'] = {OK:'or True'}
        self.nag['active_long_run_queries'] = {CRIT:'>= 50', WARN:'>= 30'}
        self.nag['sessions.unauthenticated'] = {CRIT:'>300', WARN:'>200'}
        self.nag['sessions.locked'] = {CRIT:'>= 32', WARN:'>= 16'}
        self.nag['sessions.table_lock_wait'] = {CRIT:'>= 32', WARN:'>= 16'}
        self.nag['sessions.global_read_lock_wait'] = {CRIT:'>= 32', WARN:'> 1'}
        if self.host in self.roles[SIP_RW_HOST]:
            # very sensitive to global read lock on RW/master
            self.nag['sessions.global_read_lock_wait']['WARN'] = '>= 1'
        self.nag['sessions.copy_to_table'] = {CRIT:'>= 32', WARN:'>= 16'}
        self.nag['sessions.statistics'] = {CRIT:'>= 32', WARN:'>= 16'}

    def get_blocking_queries(self):
        # this one query covers all 3 queries in 
        # /usr/lib64/nagios/plugins/contrib/pmp-check-mysql-innodb
        # and it provides more information to aid in debugging
        # NOTE: the main clause is the OLDEST waiter and what's blocking it,
        # the correlated subquery is counting all the OTHER waiters 
        # on the same blocking trx
        sql = """
SELECT 
       UNIX_TIMESTAMP() - UNIX_TIMESTAMP(blocking_trx.trx_started) 
         AS blocker_age, 
       blocking_sess.command AS blocker_cmd,
       blocking_sess.db AS blocker_db, 
       SUBSTR(blocking_trx.trx_query, 1, 80) AS blocker_query_truncated,
       blocking_sess.user AS blocker_user, 
       blocking_sess.host AS blocker_host, 
       UNIX_TIMESTAMP() - UNIX_TIMESTAMP(waiting_trx.trx_started) 
         AS waiter_age, 
       waiting_sess.command AS waiter_cmd,
       SUBSTR(waiting_trx.trx_query, 1, 80) AS waiter_query_truncated,
       (SELECT COUNT(DISTINCT requesting_trx_id) 
          FROM INFORMATION_SCHEMA.INNODB_LOCK_WAITS 
         WHERE blocking_trx_id = blocking_trx.trx_id) AS other_waiters_count
  FROM INFORMATION_SCHEMA.INNODB_LOCK_WAITS  AS w
 INNER JOIN INFORMATION_SCHEMA.INNODB_TRX    AS blocking_trx
         ON  w.blocking_trx_id = blocking_trx.trx_id
 INNER JOIN INFORMATION_SCHEMA.INNODB_TRX    AS waiting_trx
         ON  w.requesting_trx_id = waiting_trx.trx_id
  LEFT JOIN INFORMATION_SCHEMA.PROCESSLIST   AS waiting_sess
         ON  waiting_trx.trx_mysql_thread_id = waiting_sess.id
  LEFT JOIN INFORMATION_SCHEMA.PROCESSLIST   AS blocking_sess
         ON  blocking_trx.trx_mysql_thread_id = blocking_sess.id
 ORDER BY 1 DESC 
 LIMIT 1;
"""
        res = self.query_return_dict_result(sql)
        if res:
            row = res[0]
            self.params['blocking_query_s'] = row['blocker_age']
            # thresholds from pmp-check-mysql-innodb
            if row['blocker_age'] > 600:
                self.nag_msg['CRIT'].append(repr(row)) # give all the info
            elif row['blocker_age'] > 60:
                self.nag_msg['WARN'].append(repr(row)) # give all the info
            row = res[0]
            # XXX TODO: determine what if any metrics we want from this, e.g.
            #self.params['other_waiters'] = row['other_waiters']
            self.nag_msg['WARN'].append(repr(row))
        
    def get_oldest(self):
        """
           note that a long running query will also be a long running trx,
           but comparing them can tell us if someone has an explicit trx
           open but idle for a while, 
           which isn't good unless you know what you're doing.
        """
        sql = """
SELECT time FROM information_schema.processlist
 WHERE command NOT IN ('Sleep','Connect','Binlog Dump')
 ORDER BY time DESC LIMIT 1;
"""
        cols, res = self.query_return_columns_tuples(sql)
        self.params['oldest_query_s'] = int(res[0][0] or 0)
        # XXX: this can be VERY wrong
        # i.e. small race where it's uninitialized memory
        # TODO: capture queries seen in state_last, 
        # and validate query duration increased 
        # by the interval on which this check executes
        # TODO: also suggest combining
        # this to use the one query in get_sessions()
        self.nag['oldest_query_s'] = {CRIT:'>= 7200', WARN:'>= 600'}
        if 'unity' in self.cluster:
            self.nag['oldest_query_s'] = {CRIT:'>= 14400', WARN:'>= 7200'}


    def get_user_active_stmt_type(self, threshold_s = 30):
        sql = """
SELECT USER,
       SUBSTRING_INDEX(
           TRIM(
               IF(
                   info like '%*/%',
                   SUBSTR(info, 
                       LOCATE('*/',info)+2, 
                       LOCATE('*/',info)+10),
                   info)
               ),
           ' ',
           1
       ) AS stmt_first_token, 
       COUNT(*) FROM information_schema.processlist
 WHERE info IS NOT NULL 
   AND info NOT LIKE '%SUBSTRING_INDEX(TRIM(IF(info%' 
   AND state != ''  
   AND command != 'Sleep' 
 GROUP BY 1,2;
"""
        cols, res = self.query_return_columns_tuples(sql)
        for row in res:
            # XXX: which order? user.cmd? or cmd.user?
            user, stmt_first_token, count = row
            user = user.replace(' ','_')
            self.params['user_active_stmt_type.%s.%s' 
                        % (user, stmt_first_token.lower())] = int(count)

    def get_num_long_run_queries(self, threshold_s = 30):
        # threshold should be dropped to 10s, after query analysis is happening
        sql = """
SELECT * FROM information_schema.processlist 
 WHERE command NOT IN ('Sleep','Connect','Binlog Dump')
   AND time > %s;
""" % threshold_s
        found_sql = self.query_return_dict_result(sql)
        self.params['active_long_run_queries'] = len(found_sql)
        self.nag['active_long_run_queries'] = {CRIT:'>= 50', WARN:'>= 30'}

    def get_main_process_info(self):
        for proc in self.processes():
            if 'mysqld --basedir' in proc['cmd']:
                self.oomkiller_protect(proc['pid'])
                self.params['cpu_pct'] = float(proc['%cpu'])
                # cpu_pct is since boot time
                self.nag['cpu_pct'] = {OK:'or True'}
                self.params['mem_pct'] = float(proc['%mem'])
                self.params['mem_vsz'] = float(proc['vsz'])
                self.params['mem_rss'] = float(proc['rss'])

    def get_myisam_count(self):
        cols, res = self.query_return_columns_tuples("""
SELECT table_schema AS db, COUNT(*) as myisam_tbls 
  FROM information_schema.tables 
 WHERE engine = 'MyISAM'
   AND table_schema NOT IN ('performance_schema','mysql','information_schema')
   AND table_schema NOT LIKE 'mysql_bak%'
   AND table_name NOT IN ('checksums')
 GROUP BY 1 
 ORDER BY 2 DESC;
""")
        for row in res:
            self.nag_msg['WARN'].append("%s db has %s myisam tbls" % row)

    def get_binlog_stats(self):
        cols, res = self.query_return_columns_tuples("SHOW MASTER STATUS;")
# | File             | Position  | Binlog_Do_DB | Binlog_Ignore_DB |
# +------------------+-----------+--------------+------------------+
# | mysql-bin.005507 | 488101111 |              |                  |
        res = self.query_return_dict_result("SHOW MASTER STATUS;")
        if not len(res):
            return
        row = res[0]
        binlog_seqfile = int(row['File'].split('.')[1])
        self.state_current['binlog_seqfile'] = binlog_seqfile
        binlog_position = int(row['Position'])
        write_Bps = self.calc_rate('binlog_position', binlog_position)
        if not write_Bps:
            return
        if ('binlog_seqfile' in self.state_last and
            self.state_last['binlog_seqfile'] 
            != self.state_current['binlog_seqfile']):
            # straddled a rotate binlog, very rare
            # keep new state, but can't calculate a metric
            return
        self.params['write_Bps'] = write_Bps

    def get_slave_stats(self):
        if self.host in self.roles[BACKUP]:
            sql = """
SELECT COUNT(*) 
  FROM information_schema.processlist 
 WHERE user LIKE '%backup%';
"""
            cols, res = self.query_return_columns_tuples(sql)
            # XXX replication will be blocked during backups
            if res[0][0] > 0:
                self.params['slave_seconds_behind_master'] = -1
                self.nag['slave_seconds_behind_master'] = {OK:'or True'}
                self.nag_msg['OK'].append('Not checking slave during backup')
                return
        slave_long_trx_threshold = 900
        sql = """
SELECT time
  FROM information_schema.processlist
 WHERE user = 'system user'
  AND state = 'Reading event from the relay log';
"""
        #cols, res = self.query_return_columns_tuples(sql)
        # XXX: that query needs work
        #if len(res):
        #    self.params['slave_time_executing_s'] = res[0][0]
        res = self.query_return_dict_result("SHOW SLAVE STATUS;")
        if not len(res):
            self.nag_msg['CRIT'].append('Slave is not configured')
            return
        row = res[0]
        self.params['slave_seconds_behind_master'] = row['Seconds_Behind_Master']
        if self.params['slave_seconds_behind_master'] == None:
            msg = row['Last_IO_Error'] + ' ' + row['Last_SQL_Error']
            if not msg.strip():
                msg = 'Slave is NOT running'
            self.nag_msg['CRIT'].append(msg)
            self.params['slave_seconds_behind_master'] = -1
            self.nag['slave_seconds_behind_master'] = {CRIT:'< 0'}
        elif self.host in self.roles[BACKUP]:
            self.nag['slave_seconds_behind_master'] = {CRIT:'>= 3600', 
                                                       WARN:'>= 1800'}
        else:
            self.nag['slave_seconds_behind_master'] = {CRIT:'>= 600', 
                                                       WARN:'>= 300'}
        slave_seqfile = int(row['Relay_Master_Log_File'].split('.')[1])
        self.state_current['slave_seqfile'] = slave_seqfile
        self.params['slave_seqfile'] = slave_seqfile
        slave_position = int(row['Exec_Master_Log_Pos'])
        self.params['slave_position'] = slave_position
        if ('slave_seqfile' in self.state_last and
            self.state_last['slave_seqfile'] 
            != self.state_current['slave_seqfile']):
            # straddled a rotate binlog, fairly rare.
            # we can't calculate a metric, 
            # but keep new state for next time
            return
        self.params['slave_commit_Bps'] = self.calc_rate('slave_position', 
                                                         slave_position)

    def get_query_response_times(self):
        try: 
            cols, res = self.query_return_columns_tuples("""
SELECT time, count FROM INFORMATION_SCHEMA.QUERY_RESPONSE_TIME;
""")
        except Exception, X:
            self.log.error(str(X))
            return
        for row in res:
            bucket, count = row
            if count < 1:
                continue
            metric = 'query_response_secs.%s' \
                     % bucket.strip().strip('0').replace('.','_')
            self.params[metric] = self.calc_rate(metric, float(count))

    def get_table_statistics(self):
        res = self.query_return_dict_result("""
SELECT table_schema AS db, table_name AS tbl, 
       rows_read, rows_changed, rows_changed_x_indexes  
  FROM INFORMATION_SCHEMA.TABLE_STATISTICS
 WHERE rows_read > 0;
""")
        # because we cut off after 1000, try to sort it by something
        # although it's not perfect. we'd need rate, not counter.
        tmp_dict = {}
        for row in res:
            for col in ('rows_read', 'rows_changed', 'rows_changed_x_indexes'):
                # need to catch tmp tables which appear as "#sql-12e4_296" 
                row['tbl'] = row['tbl'].replace('#','_')
                metric = 'tbl_stats.%s.%s.%s' \
                         % (row['db'], row['tbl'], col)
                rate = self.calc_rate(metric, row[col])
                if rate > 1000:
                    # try to reduce impact to opentsdb,
                    # only capture tables getting a lot of changes
                    tmp_dict[metric + '_per_s'] = rate
        if len(tmp_dict) > 5000:
            self.nag_msg['WARN'].append('more than 5000 tbl_stats')
        self.params.update(tmp_dict)

    def get_stacked_queries(self):
        # detect application bugs which result in multiple instances
        # of the same query "stacking up"/executing at the same time
        sql = """
SELECT COUNT(*) AS identical_queries_stacked, 
       MAX(time) AS max_age, 
       GROUP_CONCAT(id SEPARATOR ' ') AS thread_ids, 
       info AS query
  FROM information_schema.processlist 
 WHERE user != 'system user' 
   AND user NOT LIKE 'repl%' 
   AND info IS NOT NULL 
 GROUP BY 4 
HAVING COUNT(*) > 1 
   AND MAX(time) > 300 
 ORDER BY 2 DESC;
"""
        res = self.query_return_dict_result(sql)
        if len(res):
            self.params['identical_queries_stacked'] = \
                 res[0]['identical_queries_stacked']
            self.params['identical_queries_max_age'] = \
                 res[0]['max_age']
        self.nag['identical_queries_stacked'] = {WARN:'> 1', CRIT:'> 5'}

    def get_sizes(self):
        # PER-DATABASE ROLLUPS
        cols, res = self.query_return_columns_tuples("SELECT @@GLOBAL.innodb_stats_on_metadata;")
        if res[0][0] == 1:
            self.nag_msg['WARN'].append('Not capturing db/tbl sizes '
                          'because @@GLOBAL.innodb_stats_on_metadata = 1')
            return
        # that should be disabled in my.cnf, needed so this query is fast:
        sql = """
SELECT table_schema AS db,
       SUM( data_length + index_length ) AS db_size_bytes
  FROM information_schema.TABLES
 WHERE table_schema NOT IN ('performance_schema', 'information_schema', 'mysql')
 GROUP BY 1;
"""
        cols, res = self.query_return_columns_tuples(sql, timeout = 60)
        for row in res:
            db, db_size_bytes = row
            if db_size_bytes < (50 * 1024 * 1024):
                continue # too small, let's not waste the space in graphite
            self.params['db_size_bytes.%s' % db] = int(db_size_bytes)

        # PER-TABLE SIZES
        sql = """
SELECT table_schema AS db, table_name AS tbl,
       data_length + index_length AS tbl_size_bytes
  FROM information_schema.TABLES
 WHERE table_schema NOT IN ('performance_schema', 'information_schema', 'mysql');
"""
        cols, res = self.query_return_columns_tuples(sql, timeout = 60)
        for row in res:
            db, tbl, tbl_size_bytes = row
            if tbl_size_bytes < (50 * 1024 * 1024):
                continue # too small, let's not waste the space in graphite
            self.params['table_size_bytes.%s.%s' % (db, tbl)] \
                                          = float(tbl_size_bytes)
        # BINLOGS TOTAL SIZE
        try:
            cols, res = self.query_return_columns_tuples("SHOW MASTER LOGS;")
        except Exception, X:
            if 'You are not using binary logging' not in str(X):
                raise
            self.nag_msg['WARN'].append('binlogging not enabled')
            return
        first_binlog = "/data/mysql/%s" % res[0][0]
        if not os.path.exists(first_binlog):
            self.nag_msg['WARN'].append('binlog index has nonexistent files')
        else: 
            rc, out = self.cmdline("/usr/bin/mysqlbinlog --stop-position=5 %s"
                                   % first_binlog)
            for line in out.split('\n'):
                m = health_check.perlre_extract(
                      '#(\d\d)(\d\d)(\d\d) (\d\d):(\d\d):(\d\d) server id \d+', 
                      line)
                if m:
                    m = map(int, m)
                    m[0] += 2000
                    tm_isdst = time.localtime(time.time())[-1]
                    # XXX: off by 1 hr when straddling dst changes
                    m += [0, 0, tm_isdst]
                    self.params['binlog_oldest_event_age'] \
                           = int(time.time() - time.mktime(m))
                    self.nag['binlog_oldest_event_age'] = {WARN:'< 172800', 
                                                           CRIT:'< 86400'}
                    break
        binlog_count = len(res)
        binlogs_total_size = 0
        for row in res:
            binlog_seq_file, size_bytes = row
            binlog_count += 1
            binlogs_total_size += size_bytes
        self.params['binlog_files'] = binlog_count
        self.params['db_size_bytes._binlogs'] = binlogs_total_size
        # i.e. warn @ >600 Gigs
        self.nag['db_size_bytes._binlogs'] = {WARN:'> 600000000000'}

    def get_innodb_bufferpool_mutex_waits(self):
        frequency_limit_seconds = 20 # i.e. collect no more than once per...
        # NOTE: '_per_s' gets appended to metric after rate calculation below
        mapping = {'&buf_pool->LRU_list_mutex':
                        'innodb_bufpool_lru_mutex_os_wait',
                   '&buf_pool->zip_mutex':
                        'innodb_bufpool_zip_mutex_os_wait'}
        # NOTE SQL below can be expensive, thus less frequent than usual 20s
        for metric in mapping.values():
            stamp_key = metric + '_stamp'
            if (stamp_key in self.state_last and
                self.state_last[stamp_key] 
                > (time.time() - frequency_limit_seconds)):
                # NOTE: have to manually copy stuff not updating every time:
                self.state_current[metric] = self.state_last[metric]
                self.state_current[stamp_key] = self.state_last[stamp_key]
                return
        cols, res = self.query_return_columns_tuples(
                           "SHOW ENGINE INNODB MUTEX;")
        for row in res:
            type, name, status = row
            for key in mapping:
                metric = mapping[key]
                if name == key:
                    if not status.startswith('os_waits='):
                        self.log.error("mutex status did not contain "
                                       "'os_waits'"
                                       % repr(row))
                        continue
                    os_waits = float(status[9:])
                    self.params[metric + '_per_s'] \
                             = self.calc_rate(metric, os_waits)

    def get_autodebug_size(self):
        rc, out = self.cmdline("du -sk %s" % self.debug_dir)
        try:
            self.params['auto_debug_dir_size'] = int(out.split()[0]) * 1024
        except:
            pass
        # base estimates on heaviest db:
        sqweb_avg_innodb_status = 250000
        sqweb_avg_processlist = 525000
        # 3 = 60 seconds/min / 20 second execution interval
        threshold = (sqweb_avg_innodb_status + sqweb_avg_processlist) \
                    * 3 * 1.75 * AUTO_DEBUG_RETENTION_MINS
        self.nag['auto_debug_dir_size'] = {WARN:'> %s' % threshold}

    def nagios_check(self):
        # here we wrap the superclass' .nagios_check() method
        # in order to capture debugging if WARN/CRIT
        nag_results = super(MysqlHealthCheck, self).nagios_check()
        if not hasattr(self, 'debug_dir'):
            return nag_results
        highest_seen = OK
        for service in nag_results.keys():
            state_code, message = nag_results[service]
            if state_code == CRIT:
                highest_seen = CRIT
            elif highest_seen != CRIT and state_code == WARN:
                highest_seen = WARN
        if highest_seen in (WARN, CRIT):
            # we are NOT ok, so let's dump out innodb status and processlist
            innodb_status_file = '%s/%s.innodb_statusdump' \
                                 % (self.debug_dir, self.debugfile_timestamp)
            with open(innodb_status_file, 'w') as f:
                f.write(self.innodb_status)
            processlist_file = '%s/%s.processlist_dump' \
                               % (self.debug_dir, self.debugfile_timestamp)
            with open(processlist_file, 'w') as f:
                f.write(health_check.pretty(self.processlist))
        # Now, purge any debug files older than 90 minutes
        # so, if ever "in the shit", just touch files you want to keep
        # to prevent their reaping for another 90 minutes
        # XXX: let's start lower (10 mins), then increase it later
        os.system('find %s/ -type f -name \*dump -mmin +%i -exec /bin/rm {} \;' 
                  % (self.debug_dir, AUTO_DEBUG_RETENTION_MINS))
        return nag_results

    def get_innodb_status(self):
        try:
            cols, res = self.query_return_columns_tuples(
                           "SHOW ENGINE INNODB STATUS")
            self.innodb_status = res[0][2]
        except Exception, X:
            if 'Failed converting row to Python types' not in str(X):
                raise
            self.log.error(str(X))
            self.innodb_status = str(X) 
            # so we see the error in the file
            # instead of 0-length
        # save it, if we WARN/CRIT, write out to a file
        struct = innodb_status().parse(self.innodb_status)
        if 'FILE IO' in struct:
            if 'avg_bytes_per_read' in struct['FILE IO']:
                self.params['avg_bytes_per_read'] = struct['FILE IO']['avg_bytes_per_read']
            if 'fsyncs_per_s' in struct['FILE IO']:
                self.params['fsyncs_per_s'] = struct['FILE IO']['fsyncs_per_s']
        if ('BUFFER POOL AND MEMORY' in struct and
            'buffer_pool_hit_rate' in struct['BUFFER POOL AND MEMORY']):
            self.params['cache_hit_pct'] = struct['BUFFER POOL AND MEMORY']['buffer_pool_hit_rate'] * 100
            self.nag['cache_hit_pct'] = {CRIT:'<= 5', WARN:'<= 50'} # note: inverse
        if 'LOG' in struct:
            for key in struct['LOG']:
                if key == 'raw':
                    continue
                self.params['innodb_' + key] = struct['LOG'][key]
        # LSNs are bytes:
        # http://www.mysqlperformanceblog.com/2013/09/11/how-to-move-the-innodb-log-sequence-number-lsn-forward/
        # http://www.mysqlperformanceblog.com/2006/07/17/show-innodb-status-walk-through/
        if 'innodb_log_sequence_number' in self.params:
            lsn_s = self.calc_rate('innodb_log_sequence_number',
                                   self.params['innodb_log_sequence_number'])
            if lsn_s == None:
                return
            self.params['innodb_lsn_Bps'] = lsn_s
            self.nag['innodb_lsn_Bps'] = {OK:'or True'}
            # OK just include the number in a nagios OK
            # we should identify sane thresholds for that,
            # but in the meantime, the rule of thumb is 
            # to be able to hold an hour's worth of writes 
            self.params['innodb_log_write_ratio'] = (lsn_s * 3600) \
                                                  / self.innodb_log_file_size
            # XXX TODO: change this to WARN once the log size has been increased
            self.nag['innodb_log_write_ratio'] = {OK:'> 0.9'} 
        if 'TRANSACTIONS' in struct:
            self.params['innodb_trxes_not_started'] = struct['TRANSACTIONS']['trxes_not_started']
            self.params['innodb_undo'] = struct['TRANSACTIONS']['undo']
            self.nag['innodb_undo'] = {WARN:'>100000', CRIT:'>1000000'}
            self.params['innodb_undo_per_s'] = self.calc_rate('innodb_undo',
                                                  self.params['innodb_undo'])
            if 'history_list_length' in struct['TRANSACTIONS']:
                self.params['innodb_history_link_list'] \
                           = struct['TRANSACTIONS']['history_list_length']
                self.nag['innodb_history_link_list'] = {WARN:'>20000', 
                                                        CRIT:'>100000'}

class innodb_status:
    def parse(self, blob):
        struct = {}
        chunks = re.split('\n[\-\=]{3,80}\n', blob)
        i = 0
        while i < len(chunks):
            m = re.search('([/ A-Z]+)\s*$', chunks[i])
            if m:
                key = m.groups()[0].strip()
                key = key.replace('/', '') # I/O -> IO
                struct[key] = {}
                raw = chunks[i+1].split('\n')
                struct[key]['raw'] = raw
                method = 'parse_' + key.lower().replace(' ', '_')
                if hasattr(self, method):
                    exec("tmp = self.%s(raw)" % method)
                    struct[key].update(tmp)
                i += 1
            i += 1
        return struct

    def parse_file_io(self, lines):
        struct = {}
        for line in lines:
            if ',' in line:
                for element in line.split(', '):
                    m = re.search("^(\d+(\.\d+)?) ([A-Za-z/ ]+)\s*$", element)
                    if m:
                        m = m.groups()
                        key = m[2].replace(' ','_').replace('/','_per_')
                        struct[key] = float(m[0])
        return struct

    def parse_log(self, lines):
        struct = {}
        for line in lines:
            m = re.search("^(.+?)\s+(\d+)\s*$", line)
            if m:
                m = m.groups()
                key = m[0].lower().replace(' ','_')
                struct[key] = float(m[1])
                continue
            m = re.search("^(\d+) pending log writes, (\d+) pending chkp writes\s*$", line)
            if m:
                m = m.groups()
                struct['pending_log_writes'] = float(m[0])
                struct['pending_chkp_writes'] = float(m[1])
                continue
            m = re.search(", (\d+\.\d+) log i/o's/second", line)
            if m:
                struct['log_io_per_s'] = float(m.groups()[0])
                continue
        return struct

    def parse_buffer_pool_and_memory(self, lines):
        struct = {}
        for line in lines:
            m = re.search('([A-Za-z ]+) (\d+)( / (\d+))?,', line)
            if m:
                tmp = m.groups()
                key = tmp[0].strip().lower().replace(' ','_')
                if tmp[3]:
                    value = float(tmp[1]) / float(tmp[3])
                else:
                    value = float(tmp[1])
                struct[key] = value
        return struct

    def parse_transactions(self, lines):
        struct = {}
        trxes_not_started = 0
        undo = 0
        for line in lines:
            m = re.search("^(.+?)\s+(\d+)\s*$", line)
            if m:
                m = m.groups()
                key = m[0].lower().replace(' ','_')
                struct[key] = float(m[1])
            m = re.search("^---TRANSACTION (\S+), not started\s*$", line)
            if m:
                trxes_not_started += 1
            m = re.search("^ROLLING BACK \d+ lock struct\(s\), heap size \d+, \d+ row lock\(s\), undo log entries (\d+)\s*$", line)
            if m:
                m = m.groups()
                # if multiple long-running rollbacks, use the biggest one
                if m[0] > undo:
                    undo = m[0]
        struct['trxes_not_started'] = float(trxes_not_started)
        struct['undo'] = float(undo)
        return struct

if __name__ == '__main__':
    p = optparse.OptionParser(usage = 'USAGE: %s' % '%prog')
    p.add_option('--debug', action='store_true', default = False)
    p.add_option('--mysql_user', type='string', default=DEFAULT_MYSQL_USER,
                 help="DEFAULT='%s'" % DEFAULT_MYSQL_USER)
    p.add_option('--output', type='string', default='stats-collector',
                 help="DEFAULT='stats-collector'")
    p.add_option('--nagios-server', type='str', default='',
                 help="DEFAULT=''(i.e. disabled), eventually 'mon-vip'?")
    (opts, args) = p.parse_args()
    try: 
        my = MysqlHealthCheck(debug=opts.debug, mysql_user = opts.mysql_user)
        my.bootstrap()
        my.gather()
    except Exception, X:
        msg = X.__class__.__name__ + ': ' + str(X)
        my.log.error(msg)
        lvl = 'CRIT'
        if 'HTTPGetException' in msg:
            # these are range requests, so if the server breaks,
            # a lot of machines are going to hit this codepath in parallel
            # so let's WARN instead of CRIT->pagerduty alert
            # note: confirmed for cmg that pws don't wind up in nagios :)
            lvl = 'WARN'
        my.nag_msg[lvl].append(msg)
        pass # so it goes to nagios
    output_handler = 'output_' + opts.output.replace('-','_')
    if not hasattr(my, output_handler):
        raise AssertionError('unknown output handler: %s' % output_handler)
    exec('print my.%s()' % output_handler)
    if opts.nagios_server:
        my.send_nagios_passive(opts.nagios_server)
    else:
        my.nagios_check() # log it to stderr
    os._exit(0) # to kill any hung exec_timeout threads

