"""ODBC sqlcmd/psql command construction; no mutation entry points.

Adapted from the verified inspection client. Only query building and credential
redaction helpers are retained; no database creation code is included.
"""
import os
from pathlib import Path
import re
import shutil

def find_client(kind, override=None):
    name = 'psql' if kind == 'postgresql' else 'sqlcmd'
    path = shutil.which(override or name)
    if not path and (not override) and (name == 'sqlcmd'):
        candidate = Path('/opt/mssql-tools18/bin/sqlcmd')
        if candidate.is_file() and os.access(candidate, os.X_OK):
            path = str(candidate)
    return path

def base_environment(kind):
    return {k: v for (k, v) in os.environ.items() if not (k.startswith('PG') or k.startswith('SQLCMD') or k in ('PSQLRC', 'ODBCINI', 'ODBCSYSINI'))}

def command(endpoint, executable, password, query, max_rows, query_timeout):
    env = base_environment(endpoint['database_type'])
    if endpoint['database_type'] == 'postgresql':
        env.update(PGHOST=endpoint['host'], PGPORT=str(endpoint['port']), PGDATABASE=endpoint['database_name'], PGUSER=endpoint['username'], PGPASSWORD=password, PGSSLMODE=endpoint['sslmode'], PGCONNECT_TIMEOUT='15', PGAPPNAME='replication_inventory', PGCLIENTENCODING='UTF8', PGOPTIONS=f'-c default_transaction_read_only=on -c statement_timeout={query_timeout * 1000} -c lock_timeout=3000')
        if endpoint.get('ca_file'):
            env['PGSSLROOTCERT'] = endpoint['ca_file']
        sql = f"SELECT COALESCE(json_agg(inventory_row),'[]'::json) FROM ({query}\nLIMIT {max_rows + 1}) AS inventory_row;\n"
        argv = [executable, '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-P', 'pager=off', '-f', '-']
    else:
        env['SQLCMDPASSWORD'] = password
        argv = [executable, '-S', f"tcp:{endpoint['host']},{endpoint['port']}", '-d', endpoint['database_name'], '-U', endpoint['username'], '-N', '-b', '-r', '1', '-l', '15', '-t', str(query_timeout), '-y', '0', '-w', '65535', '-f', '65001', '-x', '-m', '11']
        if endpoint.get('trust_server_certificate', False):
            argv.append('-C')
        capped = re.sub('^SELECT\\s+', f'SELECT TOP ({max_rows + 1}) ', query, count=1, flags=re.I)
        sql = f"SET NOCOUNT ON;\nSET LOCK_TIMEOUT 3000;\nSELECT COALESCE(({capped}\nFOR JSON PATH, INCLUDE_NULL_VALUES),N'[]') AS inventory_json;\nGO\n"
    return (argv, env, sql)

def clean_error(raw, password):
    value = raw.replace(password, '[redacted]') if password else raw
    value = re.sub('(?i)(password|pwd)\\s*=\\s*[^;\\s]+', '\\1=[redacted]', value)
    return value.strip()[:1800] or 'Client failed without an error message.'

