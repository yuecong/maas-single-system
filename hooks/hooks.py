#!/usr/bin/python

# Copyright 2012-2014 Canonical Ltd.

import re
import sys
import time

from charmhelpers.core.hookenv import (
    config,
    Hooks,
    log as juju_log,
    UnregisteredHookError, )

from charmhelpers.fetch import (
    add_source,
    apt_install,
    apt_update,
    )

from charmhelpers.payload.execd import execd_preinstall


from subprocess import (
    check_call,
    check_output,
    )

hooks = Hooks()


def get_cluster_uuid():
    with open('/etc/maas/maas_cluster.conf') as maas_cluster:
        content = maas_cluster.read()

    cluster_uuid = re.search(r'CLUSTER_UUID.*', content, re.DOTALL).group()

    return cluster_uuid.split('"')[1]


def do_maas_login(username):
    cmd = ['maas-region-admin', 'apikey', '--username', '%s' % username]
    apikey = check_output(cmd).strip()
    check_call(['maas', 'login', username, 'http://localhost/MAAS', apikey])


def configure_cluster(cluster_uuid):
    conf = config()

    # do login
    do_maas_login(username=conf['username'])

    # wait a while before attempting to accept the cluster
    time.sleep(15)
    # accept cluster based on uuid
    check_call(['maas', conf['username'], 'node-groups', 'accept',
                'uuid=%s' % cluster_uuid])

    # configure cluster DNS/DHCP only if cluster_management has been set.
    if conf.get('cluster_management') is None:
        return

    # configure DNS zone
    check_call(['maas', conf['username'], 'node-group', 'update', cluster_uuid,
                'name=%s' % conf['cluster_dns_zone']])

    # configure_dns_dhcp
    check_call(['maas', conf['username'], 'node-group-interface', 'update',
                cluster_uuid,
                conf['cluster_nic'],
                'subnet_mask=%s' % conf['subnet_mask'],
                'ip_range_high=%s' % conf['ip_range_high'],
                'ip_range_low=%s' % conf['ip_range_low'],
                'management=%s' % conf['cluster_management'],
                'broadcast_ip=%s' % conf['broadcast_ip'],
                'router_ip=%s' % conf['router_ip']])


@hooks.hook('install')
def install_hook():
    juju_log('INFO', 'Begin install hook')
    execd_preinstall()
    conf = config()
    source_key_id = conf.get('source_key_id')
    if source_key_id is not None:
        cmd = [
            'apt-key', 'adv', '--keyserver', 'keyserver.ubuntu.com',
            '--recv-keys', '%s' % (source_key_id)]
        check_call(cmd)

    if conf.get('source') is not None:
        add_source(conf['source'])

    apt_update()
    apt_install(['maas', 'maas-dhcp', 'maas-dns'])

    # create super user
    check_call(['maas-region-admin', 'createadmin', '--username',
                conf['username'], '--password', conf['password'],
                '--email', conf['email']])

    cluster_uuid = get_cluster_uuid()
    configure_cluster(cluster_uuid)

    juju_log('INFO', 'End install hook')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
