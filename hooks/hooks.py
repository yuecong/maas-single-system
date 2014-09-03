#!/usr/bin/python

# Copyright 2012-2014 Canonical Ltd.

import re
import sys
import time
import json
from textwrap import dedent

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


def get_ifconfig_settings():
    contents = check_output(['ifconfig', 'eth0'])
    addr = re.findall(
        r'inet addr:([.0-9]+)', contents, re.MULTILINE)
    mask = re.findall(
        r'Mask:([.0-9]+)', contents, re.MULTILINE)

    return {
        'address': addr[0],
        'netmask': mask[0],
    }


def create_bridge_config():
    conf = config()
    ifconfig = get_ifconfig_settings()
    output = dedent('''\
    auto lo
    iface lo inet loopback

    auto eth0
    iface eth0 inet manual

    auto {0}
    iface {0} inet static
        address {1}
        broadcast {2}
        netmask {3}
        gateway {4}
        bridge_ports eth0
        bridge_stp off
        bridge_waitport 0
        bridge_fd 0
    '''.format(
        conf['cluster_nic'], ifconfig['address'], conf['broadcast_ip'],
        conf['subnet_mask'], conf['router_ip']))
    return output


def restart_networking():
    check_call(
        ['ifdown --exclude=lo -a && ifup --exclude=lo -a'],
        shell=True)
    check_call(['killall', '-9', 'dhclient'])


def write_config(config, path):
    with open(path, 'w') as out_file:
        out_file.write(config)


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


def configure_maas_server(conf):
    juju_log('Begin configure MAAS server')

    config_keys = [
        'commissioning_distro_series',
        'default_osystem',
        'check_compatability',
        'http_proxy',
        'windows_kms_host',
        'default_distro_series',
        'ntp_server',
        'enlistment_domain',
        'upstream_dns',
        'enable_third_party_drivers',
        'kernel_opts',
        'main_archive',
        'maas_name',
        'ports_archive',
    ]

    fields_to_set = {}

    juju_log('conf is %s' % conf)

    for key in config_keys:
        value = conf.get(key)
        if value is not None:
            fields_to_set[key] = value

    for key, value in fields_to_set.iteritems():
        juju_log('MAAS setting: %s=%s' % (key, value))
        check_call(
            ['maas', conf['username'], 'maas', 'set-config',
                'name=%s' % key, 'value=%s' % value])


def check_output_load(*args, **kwargs):
    output = check_output(*args, **kwargs)
    return json.loads(output)


def get_boot_resources():
    conf = config()
    return check_output_load([
        'maas', conf['username'], 'boot-resources', 'read'])


def is_boot_resource_complete(resource_id):
    conf = config()
    output = check_output_load([
        'maas', conf['username'], 'boot-resource', 'read', str(resource_id)])
    for _, resource_set in output['sets'].items():
        if resource_set['complete']:
            return True
    return False


def import_boot_resources():
    """Start the import boot resource process, and waits for it to finish."""
    conf = config()
    check_call(['maas', conf['username'], 'boot-resources', 'import'])
    juju_log('Started the boot image process.')

    import_started = False
    while True:
        time.sleep(10)
        resources = get_boot_resources()

        # import_stated is marked true once the resources have started to
        # appear in the list. This is so we don't leave the loop early when
        # importing hasn't even finished.
        if len(resources) > 0:
            juju_log('Waiting for all boot images to complete.')
            import_started = True

        # see if any resources are not complete
        incomplete = False
        for resource in resources:
            resource_id = resource['id']
            if not is_boot_resource_complete(resource_id):
                incomplete = True
                break

        # are we done?
        if incomplete:
            continue

        # if we made it this far, then all of the resources have been imported
        # unless the import process has not started.
        if import_started:
            break
    juju_log('Finished import boot images on region.')


def wait_for_boot_images(cluster_uuid):
    """Waits for the boot images to appear on the cluster."""
    # Load all of the images that need to go from the region, to the cluster.
    conf = config()
    resources = get_boot_resources()
    needed_images = set()
    for resource in resources:
        os, series = resource['name'].split('/')
        arch, subarch = resource['architecture'].split('/')
        image_name = '%s/%s/%s/%s' % (os, arch, subarch, series)
        needed_images.add(image_name)

    # Wait for those images to be reported by the cluster.
    juju_log('Waiting for all boot images to be reported by the cluster.')
    while True:
        images = check_output_load([
            'maas', conf['username'], 'boot-images', 'read', cluster_uuid])
        images = {
            '%s/%s/%s/%s' % (
                image['osystem'],
                image['architecture'],
                image['subarchitecture'],
                image['release'])
            for image in images
            }

        if set(needed_images).issubset(images):
            juju_log("Have Needed Images")
            break
        else:
            juju_log("Needed: %s" % needed_images)
            juju_log("Have: %s" % images)

        time.sleep(10)
    juju_log('Finished importing of boot images on the cluster.')


def import_boot_images(cluster_uuid):
    """Imports the boot images on the region and waits for them to appear on
    the cluster."""
    import_boot_resources()
    wait_for_boot_images(cluster_uuid)


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

    create_bridge_config()
    restart_networking()
    apt_update()
    apt_install(['maas', 'maas-dhcp', 'maas-dns'])

    # create super user
    check_call(['maas-region-admin', 'createadmin', '--username',
                conf['username'], '--password', conf['password'],
                '--email', conf['email']])

        # do login
    do_maas_login(username=conf['username'])

    # configure MAAS server settings
    configure_maas_server(conf)

    # configure the cluster
    cluster_uuid = get_cluster_uuid()
    configure_cluster(cluster_uuid)

    # import the boot images
    if conf['import_boot_images']:
        import_boot_images(cluster_uuid)

    juju_log('INFO', 'End install hook')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
