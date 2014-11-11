#!/usr/bin/python -u
import os
import sys
import time
import copy
import string
import socket
import optparse

# 3rd-party RPMs:
import psycopg2

# other code from this package:
import health_check

# TODO: also look at 
# http://bucardo.org/check_postgres/check_postgres.pl.html

CRIT = 'CRIT'
WARN = 'WARN'
OK = 'OK'

SIP_RW_HOST = 'SIP_RW_HOST'
SIP_RO_HOST = 'SIP_RO_HOST'
BACKUP = 'BACKUP'

class PostgresHealthCheck(health_check.HealthCheck):
    def __init__(self, dsn={'dbname':'postgres', 'user':'postgres'},
                 debug=False):
        self.name = 'postgres'
        super(PostgresHealthCheck, self).__init__(debug=debug)
        self.dsn = dsn

    def bootstrap(self):
        psycopg2_dsn = ' '.join(map(lambda x: '%s=%s' % (x, repr(self.dsn[x])),
                                    self.dsn.keys()))
        self.conn = psycopg2.connect(psycopg2_dsn)
        self.cur = self.conn.cursor()
        self.query_return_columns_tuples("SET autocommit = 1;") # just in case
        self.load_state()
        self.pid_col = 'procpid'
        self.query_col = 'current_query'
        # here we route all slave related stuff to a different check:
        self.nag_router['postgres.slave'] = '^slave.+$'
        self.nag_router['postgres.sessions'] = '^(conn_max_pct|sess.+|loadavg.+)$'
        self.nag_router['postgres.long'] = '^(active_long_run_queries|oldest_trx_s|oldest_query_s)$'

        # NOTE: we do this here, as load is less significant on non-DBs
        self.nag['loadavg.5min'] = {CRIT:'>= %s' % (self.num_cores * 1.50),
                                    WARN:'>= %s' % (self.num_cores * 1.25)}

        self.PGDATA = '/data/pgsql' # our default, but some exceptions exist
        sysconfig_pgsql = '/etc/sysconfig/pgsql'
        if os.path.exists(sysconfig_pgsql):
            sysconfig_pgsql += '/' + os.listdir(sysconfig_pgsql)[0]
        with open(sysconfig_pgsql, 'r') as f:
            for line in f:
                if 'PGDATA' in line:
                    self.PGDATA = map(string.strip, line.split('='))[1]

        # cache info from range, to reduce load
        use_cached_range = False
        self.cluster = ''
        if ('roles_stamp' in self.state_last and
            self.state_last['roles_stamp'] > (time.time() - 300) and
            not self.debug):
            use_cached_range = True
        if use_cached_range:
            self.roles = self.state_last['roles']
            for role in (SIP_RW_HOST, SIP_RO_HOST, BACKUP):
                if role not in self.roles:
                    self.roles[role] = []
            self.state_current['roles'] = self.state_last['roles']
            # important: keep the original stamp, so it expires:
            self.state_current['roles_stamp'] = self.state_last['roles_stamp']
            if 'cluster' in self.state_last:
                self.state_current['cluster'] = self.state_last['cluster']
                self.cluster = self.state_last['cluster']
        else:
            # get role expectations from range
            t0 = time.time()
            self.log.debug('querying range for roles')
            my_clusters = health_check.range_get(
                             "clusters(%s) &/-pg-/" % self.host)
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

    def get_uptime(self):
        sql = """
SELECT EXTRACT(epoch FROM now()) 
     - EXTRACT(epoch FROM pg_postmaster_start_time());
"""
        cols, res = self.query_return_columns_tuples(sql)
        if len(res):
            self.params['uptime'] = float(res[0][0])

    def get_version(self):
        cols, res = self.query_return_columns_tuples("SELECT VERSION();")
        # looks like:
        # 'PostgreSQL 9.1.5 on x86_64-unknown-linux-gnu...'
        version_components = map(int, res[0][0].split()[1].split('.'))
        ver = int(version_components[0]) 
        for i in range(1, len(version_components)):
            ver += version_components[i] * (.01 ** i)
        self.params['version'] = ver
        self.nag['version'] = {OK:'or True'} # just informational
        # toggle column name based on version
        if self.params['version'] >= 9.02:
            self.pid_col = 'pid'
            self.query_col = 'query'
            self.idle_col = 'state'
            self.idle_string = 'idle'
        else:
            self.pid_col = 'procpid'
            self.query_col = 'current_query'
            self.idle_col = self.query_col
            self.idle_string = '<IDLE>'
        if self.params['version'] in (9.0300, 9.0301, 9.0205, 9.0110, 9.0014):
            self.nag['version'] = {CRIT:'or True'}
            self.nag_msg['CRIT'].append('vulnerable to data loss')

    def get_tps(self):
        """
           XXX: this is only writes? what about reads??
        """
        if not self.state_current_time:
            self.state_current_time = int(time.time())
        sql = """
SELECT SUM(xact_commit + xact_rollback) FROM pg_stat_database;
"""
        cols, res = self.query_return_columns_tuples(sql)
        tps = self.calc_rate('xid', float(res[0][0]))
        if tps == None:
            return
        self.params['TPS'] = tps
        self.nag['TPS'] = {OK:'or True'} # just informational
        return tps

    def get_cache_info(self):
        sql = """
SELECT SUM(blks_read) AS block_reads_disk, SUM(blks_hit) AS block_reads_cache 
  FROM pg_stat_database;
"""
        cols, res = self.query_return_columns_tuples(sql)
        block_reads_disk, block_reads_cache = map(float, res[0])
        block_reads_disk = self.calc_rate('block_reads_disk', block_reads_disk)
        block_reads_cache = self.calc_rate('block_reads_cache', 
                                            block_reads_cache)
        if None in (block_reads_disk, block_reads_cache):
            return
        self.params['blocks_read_per_s'] = block_reads_disk
        self.params['cache_hits_per_s'] = block_reads_cache
        self.params['cache_hit_pct'] = (block_reads_cache \
                                     / (block_reads_cache + block_reads_disk)) \
                                     * 100
        if self.host in self.roles[SIP_RW_HOST]:
            self.nag['cache_hit_pct'] = {CRIT:'<= 5', WARN:'<= 50'} # note: inverse
        else:
            self.nag['cache_hit_pct'] = {OK:'or True'} # slaves are cold

    def get_commit_ratio(self):
        sql = """
SELECT AVG(ROUND((100.0*sd.xact_commit)/(sd.xact_commit+sd.xact_rollback), 2))
  FROM pg_stat_database sd
  JOIN pg_database d ON (d.oid=sd.datid)
  JOIN pg_user u ON (u.usesysid=d.datdba)
 WHERE sd.xact_commit+sd.xact_rollback != 0;
"""
        cols, res = self.query_return_columns_tuples(sql)
        self.params['commit_pct'] = float(res[0][0])
        # XXX TODO: find out why so many instances here are so low...
        self.nag['commit_pct'] = {CRIT:'<= 10', WARN:'<= 40'} # note: inverse

    def get_xid_freeze(self):
        sql = """
SELECT datname,
       AGE(datfrozenxid) / (SELECT setting 
                              FROM pg_settings
                             WHERE name = 'autovacuum_freeze_max_age'
                            )::float AS xid_wrap,
       PG_DATABASE_SIZE(datname) AS db_size_bytes
  FROM pg_database 
 WHERE datname != 'template0'
 ORDER BY 2 DESC;
"""
        # template0 is apparently special 
        # and doesn't allow connections,
        # thus can't be manually VACUUMed
        try:
            cols, res = self.query_return_columns_tuples(sql)
        except:
            # this query apparently can't be executed on a slave/RO:
            # "ERROR:  cannot assign TransactionIds during recovery"
            return
        self.params['xid_freeze_age_pct'] = res[0][1] * 100
        self.nag['xid_freeze_age_pct'] = {CRIT:'>= 95', WARN:'>= 90'}

    def get_wal_keep_segments(self):
        sql = """
SELECT setting FROM pg_settings WHERE name = 'wal_keep_segments';
"""
        cols, res = self.query_return_columns_tuples(sql)
        self.params['wal_keep_segments'] = float(res[0][0])
        self.nag['wal_keep_segments'] = {CRIT:'< 512', WARN:'< 1024'}

    def get_sessions(self):
        sql = """
SELECT setting FROM pg_settings WHERE name = 'max_connections';
"""
        cols, res = self.query_return_columns_tuples(sql)
        sess_max = float(res[0][0])
        sql = """
SELECT (SELECT COUNT(*) FROM pg_stat_activity 
         WHERE %s = '%s') AS idle,
       (SELECT COUNT(*) FROM pg_stat_activity 
         WHERE %s != '%s') AS active;
""" % (self.idle_col, self.idle_string, self.idle_col, self.idle_string)
        res = self.query_return_dict_result(sql)[0]
        total = res['idle'] + res['active']
        self.params['sess_cur_total'] = total
        self.params['sess_busy_pct'] = (res['active'] / total) * 100
        self.nag['sess_busy_pct'] = {OK:'or True'}
        self.params['conn_max_pct'] = (total / sess_max) * 100
        
    def get_oldest(self):
        """
           note that a long running query will also be a long running trx,
           but comparing them can tell us if someone has an explicit trx
           open when they possibly shouldn't.
        """
        info = {
                'xact_start':'oldest_trx_s',
                'query_start':'oldest_query_s',
                #'backend_start':'oldest_sess',
                # it looks like connections hang out indefinitely.
                # arguably they should recycle every now and then,
                # but it's not a cause for alarm(s)
                }
        for col in info.keys():
            sql = """
SELECT EXTRACT(epoch FROM NOW()) - EXTRACT(epoch FROM %s) 
  FROM pg_stat_activity 
 WHERE %s != '%s'
   AND UPPER(%s) NOT LIKE '%%VACUUM%%'
 ORDER BY 1 DESC LIMIT 1;
""" % (col, self.idle_col, self.idle_string, self.query_col) 
            cols, res = self.query_return_columns_tuples(sql)
            self.params[info[col]] = int(res[0][0] or 0)
        self.nag['oldest_trx_s'] = {CRIT:'>= 3600', WARN:'>= 600'}
        self.nag['oldest_query_s'] = {CRIT:'>= 3600', WARN:'>= 600'}
        if ('batch' in self.cluster
            or 'pbs' in self.cluster
            or 'pbr' in self.cluster):
            self.nag['oldest_trx_s'] = {CRIT:'>= 7200', WARN:'>= 600'}
            self.nag['oldest_query_s'] = {CRIT:'>= 7200', WARN:'>= 600'}


    def get_num_long_run_queries(self, threshold_s = 30):
        # threshold should be dropped to 10s, after query analysis is happening
        sql = """
SELECT * FROM pg_stat_activity 
 WHERE EXTRACT(epoch FROM NOW()) - EXTRACT(epoch FROM query_start) > %s
   AND %s != '%s';
""" % (threshold_s, self.idle_col, self.idle_string)
        found_sql = self.query_return_dict_result(sql)
        self.params['active_long_run_queries'] = len(found_sql)
        self.nag['active_long_run_queries'] = {CRIT:'>= 40', WARN:'>= 30'}

    def get_locks(self):
        sql = """
SELECT bl.pid                 AS blocked_pid,
       a.usename              AS blocked_user,
       ka.%s       AS blocking_statement,
       NOW() - ka.query_start AS blocking_duration,
       kl.pid                 AS blocking_pid,
       ka.usename             AS blocking_user,
       a.%s        AS blocked_statement,
       NOW() - a.query_start  AS blocked_duration
  FROM pg_catalog.pg_locks bl
  JOIN pg_catalog.pg_stat_activity a
    ON a.%s = bl.pid
  JOIN pg_catalog.pg_locks kl 
    ON kl.transactionid = bl.transactionid AND kl.pid != bl.pid
  JOIN pg_catalog.pg_stat_activity ka ON ka.%s = kl.pid
 WHERE NOT bl.granted;
""" % (self.query_col, self.query_col, self.pid_col, self.pid_col)
        res = self.query_return_dict_result(sql)
        self.params['lock_waiters'] = len(res)
        sql = """
SELECT mode, COUNT(*) FROM pg_locks WHERE granted GROUP BY 1;
"""
        cols, res = self.query_return_columns_tuples(sql)
        for row in res:
            name, count = row
            name = name.lower()
            if name.endswith('lock'):
                name = 'lock_%s' % name[:-4]
            name += '_granted'
            self.params[name] = count
        # this caught stacking in help_center, i.e. ROLL-11788
        self.nag['lock_accessshare_granted'] = {CRIT:'>= 500', WARN:'>= 250'}

    def get_vacuums_in_progress(self):
        """
           XXX: TODO: need to validate this, i.e. look during autovacuums
        """
        sql = """
SELECT * FROM pg_stat_activity 
 WHERE UPPER(%s) LIKE '%%VACUUM%%';
""" % (self.query_col,)
        found_sql = self.query_return_dict_result(sql)
        auto = 0
        manual = 0
        # note ANALYZE isn't a significant difference:
        # 'autovacuum: VACUUM ANALYZE public.feed_cursors',
        # 'autovacuum: VACUUM public.payments',
        # BUT 'FREEZE' is potentially significant, 
        # perhaps we should track that separately?
        for row in found_sql:
            if 'datfrozenxid' in row[self.query_col]:
                continue
            #['autovacuum: ', 'VACUUM ', 'ANALYZE ', 'public.feed_cursors']
            m = health_check.perlre_extract('(?i)(\s*autovacuum:\s*)?(\s*VACUUM\s*)?(\s*ANALYZE\s*)?\s*(.+?)$', row[self.query_col])
            if m:
                if m[-1] == ';':
                    m.pop()
                if m[-1] == '':
                    m[-1] = '__all__'
                m = map(string.strip, m)
                m = map(string.lower, m)
                if m[0]:
                    m[0] = 'auto'
                tbl = m[-1]
                if '.' not in tbl:
                    # fully qualify any manual VACUUMs done relatively
                    tbl = row['datname'] + '.' + tbl
                key = 'maint.%s.%s' % (tbl, '_'.join(filter(None, m[:-1])))
                if key not in self.params:
                    self.params[key] = 0
                self.params[key] += 1
                # less-specific rollup counts:
                if row[self.query_col].startswith('autovacuum: '):
                    auto += 1
                else:
                    manual += 1
        self.params['vacuums_auto_running'] = auto
        self.params['vacuums_manual_running'] = manual
        # postgres could potentially start multiple,
        # but that could have an impact, so we want to know.
        self.nag['vacuums_auto_running'] = {CRIT:'>= 10', WARN:'>= 3'}
        # a human should ONLY EVER run one vacuum at a time
        self.nag['vacuums_manual_running'] = {CRIT:'>= 2'}

    def get_main_process_info(self):
        """
           the master daemon process is 'postmaster'
        """
        # could also look at /var/run/postmaster-9.1.pid
        # but that's version-dependent
        for proc in self.processes():
            if 'postmaster' in proc['cmd']:
                # note: oomkiller_protect doesn't work here currently 
                # because this runs as 'postgres' (via stats-collector.d)
                #self.oomkiller_protect(proc['pid'])
                self.params['cpu_pct'] = float(proc['%cpu']) 
                # cpu_pct is since boot time
                self.nag['cpu_pct'] = {OK:'or True'}
                self.params['mem_pct'] = float(proc['%mem'])
                self.params['mem_vsz'] = float(proc['vsz'])
                self.params['mem_rss'] = float(proc['rss'])

    def get_writeability(self):
        sql = "CREATE SCHEMA postgres_health;"
        try:
            cols, res = self.query_return_columns_tuples(sql)
        except Exception, X:
            if "read-only" in str(X):
                if self.host in self.roles[SIP_RW_HOST]:
                    msg = 'read-only set on %s:%s. update range? %s' \
                          % (self.cluster, SIP_RW_HOST, repr(self.roles))
                    self.log.error(msg)
                    self.nag_msg['CRIT'].append(msg)
                return # expected state
            elif not "already exists" in str(X):
                raise
            self.query_return_columns_tuples("ROLLBACK;")
        sql = """
CREATE TABLE IF NOT EXISTS postgres_health.postgres_health 
 (id INT PRIMARY KEY, stamp TIMESTAMP);
"""
        cols, res = self.query_return_columns_tuples(sql)
        sql = """
BEGIN;
DELETE FROM postgres_health.postgres_health;
INSERT INTO postgres_health.postgres_health VALUES (1, NOW());
COMMIT;
"""
        cols, res = self.query_return_columns_tuples(sql)
        # if we got to this point on a slave, that is BAD
        if (self.host not in self.roles[SIP_RW_HOST] and
            self.host in (self.roles[SIP_RO_HOST]
                        + self.roles[BACKUP])):
            self.nag_msg['CRIT'].append('slave is writeable, must not be')

    def get_seconds_behind_master(self):
        if self.host in self.roles[SIP_RW_HOST]:
            return
        recovery_conf_file = self.PGDATA + '/recovery.conf'
        recovery_done_file = self.PGDATA + '/recovery.done'
        sql = """
SELECT EXTRACT(epoch FROM NOW()) 
     - EXTRACT(epoch FROM pg_last_xact_replay_timestamp());
"""
        cols, res = self.query_return_columns_tuples(sql)
        # XXX TODO: have an self.nagios_errors list of messages
        # which are not metric=float to include in errors
        # how to convey a not-connected slave in SBM terms?
        # high is alert-worthy, but an arbitrarily high # seems lame, 
        # and -1 is less then thresholds... so, conditional below.
        if res[0][0] != None and res[0][0] < 0:
            self.log.warn("negative SBM, clock skew between master/slave?")
            # set it to 0 so people don't ask about the wacky graph.
            # hopefully there is a separate monitoring of clock skew!?
            self.params['slave_seconds_behind_master'] = 0
        else:
            self.params['slave_seconds_behind_master'] = res[0][0] or -1
        self.nag['slave_seconds_behind_master'] = {CRIT:'>=3600', WARN:'>=300'}
        if ('batch' in self.cluster
            or 'pbs' in self.cluster
            or 'pbr' in self.cluster):
            self.nag['slave_seconds_behind_master'] = {CRIT:'>= 5400',
                                                       WARN:'>= 300'}
        if (self.host in self.roles[SIP_RO_HOST]
            or self.host in self.roles[BACKUP]):
            # a slave should be running here
            slave_procs = self.processes('postgres: wal receiver process')
            if (res[0][0] == None 
                or len(slave_procs) != 1 
                or 'streaming' not in slave_procs[0]['cmd']):
                self.log.error("expected single slave in 'streaming' state, "
                               "but saw: %s" % repr(slave_procs))
                self.nag_msg['CRIT'].append("no slave process streaming")
            if not os.path.exists(recovery_conf_file):
                msg = "'%s' not found, accidental removal?" \
                      % recovery_conf_file
                self.log.error(msg)
                self.nag_msg['CRIT'].append(msg)
                self.params['slave_seconds_behind_master'] = -1
            if (os.path.exists(recovery_done_file) and
                not os.path.exists(recovery_conf_file)):
                msg = "'%s' found, was it promoted? update range?" \
                      % recovery_done_file
                self.log.error(msg)
                self.nag_msg['CRIT'].append(msg)
                self.params['slave_seconds_behind_master'] = -1

    def get_slave_delay_bytes(self):
        sql = """
SELECT pg_current_xlog_location(), write_location, client_hostname
  FROM pg_stat_replication;
"""
        cols, res = self.query_return_columns_tuples(sql)
        slaves_connected = []
        for row in res:
            slaves_connected.append(row[2])
        self.params['slaves_connected_to_me'] = len(res)
        if len(filter(None, self.roles.values())) < 2:
            msg = 'insufficient replication topology configured in range, ' \
                  'or range queries failing?'
            self.log.error(msg)
            self.nag_msg['WARN'].append(msg)
            self.nag['slaves_connected_to_me'] = {WARN:'or 1'}
        if self.host in self.roles[SIP_RW_HOST]:
            # we should have AT LEAST one slave connected
            self.nag['slaves_connected_to_me'] = {CRIT:'< 1'}
            def overlap(expect, actual, all = False):
                # XXX TODO: move up to health_check module
                matched = 0
                for e in expect:
                    if e in actual:
                        matched += 1
                if not all and matched:
                    # i.e. any
                    return True
                if all and matched == len(expect):
                    return True
                return False
            if not overlap(self.roles[SIP_RO_HOST], slaves_connected, all=True):
                msg = "%s slave(s) not in connected: %s" \
                      % (repr(self.roles[SIP_RO_HOST]),
                         repr(slaves_connected))
                self.log.error(msg)
                self.nag_msg['CRIT'].append(msg)
                self.nag['slaves_connected_to_me'] = {CRIT:'or 1'}
            if (self.roles[SIP_RO_HOST] and 
                self.roles[BACKUP] and 
                not overlap(self.roles[SIP_RO_HOST], self.roles[BACKUP])):
                # we should have 2 slaves connected
                self.nag['slaves_connected_to_me'] = {CRIT:'< 1', WARN:'< 2'}
                if (not overlap(self.roles[SIP_RO_HOST], slaves_connected, 1)
                    and not overlap(self.roles[BACKUP], slaves_connected, 1)):
                    msg = "%s and %s slave not in connected: %s" \
                          % (repr(self.roles[SIP_RO_HOST]), 
                             repr(self.roles[BACKUP]), 
                             repr(slaves_connected))
                    self.log.error(msg)
                    self.nag_msg['CRIT'].append(msg)
                    # self.nag['slaves_connected_to_me'] = {CRIT:'or 1'}
        if not len(res):
            return
        def hex_to_int(input):
            return int('0x' + input, 0)
        try:
            master_file, master_pos = map(hex_to_int, res[0][0].split('/'))
            slave_file, slave_pos = map(hex_to_int, res[0][1].split('/'))
        except AttributeError:
            # pg_basebackup will have None in write_location
            return
        segment_size = int('0xFFFFFFFF', 0)
        self.params['slave_bytes_behind_me'] = \
                ((master_file * segment_size) + master_pos) \
                - ((slave_file * segment_size) + slave_pos)

    def get_sizes(self):
        # binlogs
        cmd = "ls -l %s/pg_xlog/ | egrep -v 'archive_status|history'" \
              % self.PGDATA
        rc, out = self.cmdline(cmd)
        count = 0
        total = 0
        for line in out.split("\n"):
            cols = line.split()
            if len(cols) < 5:
                continue
            count += 1
            total += int(cols[4])
        self.params['binlog_files'] = count
        self.params['db_size_bytes._binlogs'] = total
        # per-database rollups
        sql = """
SELECT datname AS dbname, PG_DATABASE_SIZE(datname)
  FROM pg_database;
"""
        cols, res = self.query_return_columns_tuples(sql)
        dbs = []
        for row in res:
            if int(row[1]) < (50 * 1024 * 1024):
                continue # too small, let's not waste the space in graphite
            self.params['db_size_bytes.%s' % row[0]] = int(row[1])
            dbs.append(row[0])
        # per-table sizes
        for db in dbs:
            dsn = copy.deepcopy(self.dsn)
            dsn['dbname'] = db
            psycopg2_dsn = ' '.join(map(lambda x: '%s=%s' % (x, repr(dsn[x])),
                                        dsn.keys()))
            conn = psycopg2.connect(psycopg2_dsn)
            cur = conn.cursor()
            sql = """
SELECT nspname || '.' || relname AS "relation",
    PG_TOTAL_RELATION_SIZE(C.oid) AS "total_size"
  FROM pg_class C
  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
 WHERE nspname NOT IN ('pg_catalog', 'information_schema')
   AND C.relkind <> 'i'
   AND nspname !~ '^pg_toast'
 ORDER BY pg_total_relation_size(C.oid) DESC;
"""
            cur.execute(sql)
            for row in cur.fetchall():
                if int(row[1]) < (50 * 1024 * 1024):
                    continue # too small, let's not waste the space in graphite
                self.params['table_size_bytes.%s.%s' % (db, row[0])] \
                                = int(row[1])
            del cur
            del conn

    def get_backups(self):
        # XXX TODO: combine process check with get_main_process_info()
        # for only one pass through process table
        backup_procs = 0
        for proc in self.processes():
            if 'grep' in proc['cmd']:
                continue
            if 'pg_dump' in proc['cmd'].split()[0]:
                backup_procs += 1
        self.params['backups_running'] = backup_procs
        # check age of last backup
        if self.host not in self.roles[BACKUP]:
            return
        rc, out = self.cmdline("ls -l /backups/")
        backup_file_timestamps = []
        for line in out.split("\n"):
            if not line.strip():
                continue
            fname = line.split()[-1]
            m = health_check.perlre_extract(
                             '(\d\d\d\d)[\-_](\d\d)[\-_](\d\d).pg_dump',
                                            fname)
            if m:
                tm_isdst = time.localtime(time.time())[-1]
                # XXX: off by 1 hr when straddling dst changes
                m += [23, 0, 0, 0, 0, tm_isdst]
                utime = time.mktime(map(int, m))
                backup_file_timestamps.append(utime)
        if len(backup_file_timestamps) == 0:
            self.nag_msg['WARN'].append('No backups whatsoever')
            return
        recent_backup = sorted(backup_file_timestamps)[-1]
        oldest_backup = sorted(backup_file_timestamps)[0]
        if recent_backup < (time.time() - (60 * 60 * 24 * 2)):
            # XXX TODO: need to verify that the backup is COMPLETE/GOOD
            self.nag_msg['WARN'].append('No backup in past 48 hours')
        elif oldest_backup < (time.time() - (60 * 60 * 24 * 7)):
            self.nag_msg['WARN'].append(
                                     'Backups older than 1 week need purging')
        else:
            self.nag_msg['OK'].append('Backups good')

    def get_security(self):
        # VULN-350
        sql = """
SELECT usename FROM pg_shadow WHERE passwd IS NULL;
"""
        cols, res = self.query_return_columns_tuples(sql)
        if res:
            self.nag_msg['WARN'].append('FOUND USERS W/O PW: %s' % repr(res))

if __name__ == '__main__':
    p = optparse.OptionParser(usage = 'USAGE: %s' % '%prog')
    p.add_option('--debug', action='store_true', default = False)
    p.add_option('--output', type='string', default='stats-collector',
                 help="DEFAULT='stats-collector'")
    p.add_option('--nagios-server', type='str', default='',
                 help="DEFAULT=''(i.e. disabled), eventually 'mon-vip'?")
    (opts, args) = p.parse_args()
    try:
        pg = PostgresHealthCheck(debug=opts.debug)
        pg.bootstrap()
        pg.gather()
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
    if not hasattr(pg, output_handler):
        raise AssertionError('unknown output handler: %s' % output_handler)
    exec('print pg.%s()' % output_handler)
    if opts.nagios_server:
        pg.send_nagios_passive(opts.nagios_server)
    else:
        pg.nagios_check() # log it to stderr
    os._exit(0) # to kill any hung exec_timeout threads
