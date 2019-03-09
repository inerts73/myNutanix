#!/usr/bin/env python
#
# Copyright (c) 2012-2017 Nutanix Inc. All rights reserved.
#
# Author: cui@nutanix.com
#
# This scripts start/stop/create/destroy a cluster from vma for
# developer machine using a cluster.cfg file as input.

assert __name__ == "__main__", "This module should NOT be imported."

# This must be the first line!
try:
  import env

  import concurrent.futures
  import collections
  import gflags
  import getpass
  import json
  import os
  import re
  import shlex
  import shutil
  import simplejson
  import sys
  import time
  import traceback
  import uuid

  import cluster.consts # FLAGS.
  import cluster.genesis_utils as genesis_utils
  import cluster.upgrade_helper as upgrade_helper
  import cluster.cluster_upgrade as cluster_upgrade
  import cluster.host_upgrade_common as host_upgrade_common
  import cluster.host_upgrade_helper as host_upgrade_helper
  import cluster.sshkeys_helper as sshkeys_helper
  import cluster.utils.foundation_utils as foundation_utils
  import cluster.utils.genesis_rack_utils as genesis_rack_utils
  import cluster.utils.new_node_nos_upgrade as new_node_upgrade
  import cluster.foundation_upgrade_helper as foundation_upgrade_helper
  import cluster.genesis.convert_cluster.utils as conversion_utils
  import cluster.genesis.ns.backplane_utils as backplane_utils
  import cluster.genesis.ns.helper as ns_helper
  import prism_client.proto.prism_auth_pb2 as prism_auth_pb2
  import util.cluster.consts # For FLAGS: nutanix_log_dir.
  import util.ndb.misc.rack_utils as rack_utils

  from cluster.cluster_config import ClusterConfig
  from cluster.ipv4config import IPv4Config
  from cluster.firewall.consts import node_states
  from cluster.genesis.client import genesis_proxy as proxy
  from cluster.genesis.cluster_manager import ClusterManager
  from cluster.genesis.convert_cluster.cluster_conversion import \
      ClusterConversion
  from cluster.genesis.la_jolla.la_jolla_utils import *
  from cluster.genesis.node_manager import NodeManager
  from cluster.genesis.ns.network_segmentation import NetworkSegmentation
  from cluster.two_node.cluster_manager import TwoNodeClusterManager
  from ergon.ergon_types_pb2 import Task
  from util.base import log
  from util.base.command import timed_command
  from util.base.command_executor import CommandExecutor
  from util.base.sudo import read_file_as_root
  from util.net.rpc import RpcError
  from util.net.ssh_client import SSHClient
  from util.zeus import utils as zeus_utils
  from zeus.configuration import ConfigurationProto, Configuration
  from zeus.domain_fault_tolerance_state_pb2 import DomainFaultToleranceState
  from zeus.zookeeper_session import ZookeeperSession
except ImportError as err:
  sys.stderr.write(err.message)
  sys.stderr.write(traceback.format_exc())
  sys.stderr.write("Failed to import a package. Ensure the build version and "
      "architecture are compatible with the system.")
  sys.exit(1)

FLAGS = gflags.FLAGS

gflags.DEFINE_string("config", "",
                     "Path to the cluster configuration file.",
                     short_name="c")
gflags.DEFINE_string("cluster_name", "",
                     "Name of the cluster (use with create).")
gflags.DEFINE_list("cluster_function_list", ClusterManager.NDFS_FUNCTION,
                   "List of functions of the cluster (use with create). "
                   "Accepted functions are %s" %
                   ClusterManager.CLUSTER_FUNCTIONS_BITMAP.keys())
gflags.DEFINE_boolean("add_dependencies", False,
                      "Include Dependencies.", short_name="d")
gflags.DEFINE_boolean("wait", True, "Wait for action to complete.",
                      short_name="w")
gflags.DEFINE_string("migrate_from", "",
                     "The old zeus node IP address for Zeus migration.")
gflags.DEFINE_string("migrate_to", "",
                     "The new zeus node IP address for Zeus migration.")
gflags.DEFINE_integer("timeout", 180,
                      "Number of seconds each command to SVMs should take.",
                      short_name="t")
gflags.DEFINE_string("svm_login", "nutanix",
                     "User name for logging into SVM.")
gflags.DEFINE_string("installer_dir_path", "",
                     "Location of the Nutanix installer directory.",
                     short_name="i")
gflags.DEFINE_string("svm_ips", "",
                     "Comma separated list of IP addresses of one or more "
                     "SVMs in the target cluster. "
                     "Not required if cluster.cfg is being used.",
                     short_name="s")
gflags.DEFINE_string("cluster_external_ip", "",
                     "Cluster ip to manage the entire cluster.")
gflags.DEFINE_string("cluster_uuid", "",
                     "Cluster uuid for cluster in string format.")
gflags.DEFINE_boolean("clean_debug_data",
                      False,
                      "If 'clean_debug_data' is True, then when we destroy a "
                      "cluster we will also remove the logs, binary logs, "
                      "cached packages, and core dumps on each node.")
# This is so that we can use HA 2.0 when upgrading from 3.5 to future Genesis.
# Please remove this flag after the new HA is present.
gflags.DEFINE_boolean("force_install_genesis",
                      True,
                      "Installs the infrastructure package on all of the "
                      "nodes.")
gflags.DEFINE_string("ip_specification_json", "",
                     "JSON file with IP configuration.", short_name="j")
gflags.DEFINE_bool("lockdown_mode",
                   False,
                   "Flag for lockdown mode", short_name="l")
gflags.DEFINE_bool("password_lockdown_mode",
                   False,
                   "Flag for password lockdown mode")
gflags.DEFINE_string("key_file",
                     "/home/nutanix/ssh_keys/nutanix.pub",
                     "Nutanix default SSH public key.")
gflags.DEFINE_string("key_name",
                     "legacy_nos_compatibility",
                     "Identifier of the public ssh key in the cluster.")
gflags.DEFINE_string("python_proto_egg_path",
                     "lib/py/protobuf-2.6.1-py2.6-linux-x86_64.egg",
                     "Path of protobuf egg relative to the install dir.")
gflags.DEFINE_string("upgrade_node_ip", "",
                     "Ipv4 or IPv6 address of node to be upgraded.",
                     short_name="u")
gflags.DEFINE_integer("stand_alone_upgrade_timeout", 600,
                      "Timeout for stand-alone upgrade.")
gflags.DEFINE_string("shutdown_token_ip", "",
                     "IP address of intended shutdown token holder SVM.")
gflags.DEFINE_bool("manual_upgrade", False,
                   "Manual upgrade method.", short_name="m")
gflags.DEFINE_integer("redundancy_factor",
                      -1,
                      "Max redundancy factor supported by the cluster. "
                      "'redundancy_factor - 1' determines the number of node "
                      "failures that the cluster should be able to tolerate.")
gflags.DEFINE_string("verification_file", "",
                     "Metadata file for package integrity, upgrade info.",
                     short_name="v")
gflags.DEFINE_boolean("ignore_preupgrade_tests", False,
                      "Perform preupgrade tests",
                      short_name="p")
gflags.DEFINE_boolean("skip_upgrade", False, "Skip actual upgrade.")
gflags.DEFINE_boolean("skip_reconfig", False, "Skip CVM reconfig.")
gflags.DEFINE_boolean("no_verification", True,
                      "Skip verification for package integrity.",
                      short_name="n")
gflags.DEFINE_boolean("skip_discovery", False, "Skip discovery.")
# TODO: use one gflag for all workflow bundles.
gflags.DEFINE_string("bundle", "", "Bundle for upgrading host in cluster.")
gflags.DEFINE_string("version", "", "Version to which upgrade needs to be "
                     "performed.")
gflags.DEFINE_string("md5sum", "", "Md5sum of the bundle.")
gflags.DEFINE_string("hypervisor", "", "Hypervisor that needs to be upgraded. "
                     "Possible values: esx, kvm, hyperv.")
gflags.DEFINE_string("domain_username", "","Domain username of the hosts.")
gflags.DEFINE_string("domain_password", "", "Domain password of the hosts.")
gflags.DEFINE_string("hyperv_sku", "", "Hypervisor sku to which the HyperV "
                      "host is being upgraded.")
gflags.DEFINE_boolean("host_upgrade", False, "Operation specified will be "
                      "done in context of host_upgrade")
gflags.DEFINE_string("hardware_device_type", "",
                     "Type of hardware device. Please specify one of the "
                     "following: disk nic hba bios bmc. (Currently supported: "
                     "disk, bios, bmc.)",
                     short_name="h")
gflags.DEFINE_boolean("foundation_upgrade", False, "Operation specified will be"
                      " done in context of foundation upgrade")
gflags.DEFINE_boolean("seed_prism_password", True,
                      "Seed Prism admin password to be the same as the nutanix "
                      "user if nutanix user has non-default password.")
gflags.DEFINE_string("nutanix_default_password_salt",
                     "$6$Mkd8T74/$",
                     "Seed prism admin password only if the password hash "
                     "does not contain this salt.")
gflags.DEFINE_boolean("helpfull", False, "Show flags for all modules")
gflags.DEFINE_string("target_hypervisor", "", "Target hypervisor type for "
                     "cluster conversion. Valid types esx/kvm.")
gflags.DEFINE_boolean("ignore_vm_conversion_warnings", False,
                      "Ignore vm conversion errors during cluster conversion.")
gflags.DEFINE_boolean("remove_installer_dir", True, "Whether or not to "
                      "remove the installer directory automatically when "
                      "finished.", short_name="r")
gflags.DEFINE_boolean("backplane_network", False, "Backplane network config")
gflags.DEFINE_integer("backplane_vlan", -1, "Backplane VLAN id")
gflags.DEFINE_string("backplane_subnet", "", "Backplane subnet")
gflags.DEFINE_string("backplane_netmask", "", "Backplane netmask")
gflags.DEFINE_string("container_name", "",
                     "Name of the default container on the cluster.")
gflags.DEFINE_string("license_file_zknode",
                     "/appliance/logical/license/license_file",
                     "Path to the zookeeper node that contains the cluster "
                     "license information.")
gflags.DEFINE_string("dns_servers", "",
                     "Comma separated list of one or more DNS servers.")
gflags.DEFINE_string("ntp_servers", "",
                     "Comma separated list of one or more NTP servers.")
gflags.DEFINE_string("vcenter_json_file", "",
                     "File containing vcenter details for dial workflow. "
                     "The json has host, username and password keys.")
gflags.DEFINE_bool("enable_lite_upgrade", True,
                   "Set to False to disable lite upgrade before it is ready.")
gflags.DEFINE_bool("rack_aware", False,
                   "Set to True to enable rack awareness. This workflow is "
                   "unsupported, in favour of configuring rack awareness on a "
                   "created cluster")
gflags.DEFINE_bool("block_aware", False,
                   "Set to True to enable block awareness. This workflow is "
                   "unsupported, in favour of configuring block awareness on a "
                   "created cluster")
gflags.DEFINE_bool("vcenter_not_required", False,
                   "Set it to true if vcenter is not used to manage ESX "
                   "cluster.")
gflags.DEFINE_string("rack_config_json_path", "",
                     "Path to the json file containing svm_ips to rack name"
                     "mapping. Json file will contain svm_ips as the keys and "
                     "the name of the rack they belong to, as values")
gflags.DEFINE_bool("reset_gflags_on_destroy", False,
                   "When performing cluster destroy, remove all gflag files.")
gflags.DEFINE_string("provided_root_certificate", "", "File to be used as the "
                     "root certificate when creating or upgrading a cluster.")
gflags.DEFINE_string("provided_root_certificate_key", "", "File to be used as "
                     "the root CA private key.")
KERNEL_PACKAGE_RE = re.compile(r"linux-image-.*")
FUSION_IO_PACKAGE_RE = re.compile(r"(fio|libvsl|iomemory).*")
LINK_LOCAL_RE = re.compile(r'^fe80:')

SSH_ERROR_CODE_MAP = {
  255: "Timed out while trying to connect to host"
}


def get_default_ssh_key():
  """
  Get ssh default key.
  """
  return os.environ.get("SSH_KEY")

def block_as_long_as_file_exists(path, svm_ips):
  """
  This method blocks as long as a file exists at 'path' on svms specified in
  the 'svm_ips'.

  path: Name of the file to check for.

  svm_ips: List of svm ip addresses where path must disappear.

  Returns True if file has vanished on all svms. Returns False otherwise.
  """
  ssh_key = get_default_ssh_key()
  cmd = "test ! -f %s" % path
  ips = svm_ips[:]
  while ips:
    log.INFO("Checking for %s to disappear on ips %s" % (path, ips))
    with CommandExecutor(len(ips)) as ce:
      for ip in ips:
        ssh_client = SSHClient(ip, FLAGS.svm_login, private_key=ssh_key)
        ssh_client.execute(cmd, cmd_executor=ce)

      while ce.num_unfinished():
        ce.wait(2.0)

      done = set()
      for ii in ce.finished():
        if ce.result(ii)[0] == 0:
          done.add(ips[ii])

    ips = list(set(ips).difference(done))
    if ips:
      time.sleep(2.0)
  return True

def start_genesis(svm_ips):
  """
  Returns True if Genesis is started on all svms. Returns False otherwise.

  svm_ips: List of svm ip addresses for whom genesis should be restarted.

  username: Must be 'nutanix'.

  keypath: Path to the ssh key used to login into the svms.

  timeout_secs: Number of seconds this operation is expected to take.
  """
  result = True
  cmd_map = dict((ip, "%s start" % FLAGS.genesis_path) for ip in svm_ips)
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  for ip, (ret, out, err) in result_map.iteritems():
    if ret == 0:
      log.INFO("Started Genesis on %s." % ip)
      continue
    result = False
    if ret == -1:
      log.ERROR("Starting Genesis timed out on %s." % ip)
    else:
      log.ERROR("Starting Genesis failed on %s." % ip)
      log.DEBUG("out, err:\n%s\n%s" % (out, err))
  return result

def stop_genesis(svm_ips):
  """
  Returns True if Genesis is stopped on all svms. Returns False otherwise.

  svm_ips: List of svm ip addresses for whom genesis should be restarted.
  """
  return stop_service(svm_ips, "genesis")

def stop_service(svm_ips, service):
  """
  Returns True if 'service' is stopped on all svms. Returns False otherwise.

  svm_ips: List of svm ip addresses where 'service' should be stopped.
  service: The name of the service to stop.
  """
  result = True
  cmd_map = dict((ip, "%s stop %s" % (FLAGS.genesis_path, service))
                  for ip in svm_ips)
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  for ip, (ret, out, err) in result_map.iteritems():
    if ret == 0:
      log.INFO("Stopped %s on %s." % (service, ip))
      continue
    result = False
    if ret == -1:
      log.ERROR("Stopping %s timed out on %s." % (service, ip))
    else:
      log.ERROR("Stopping %s failed on %s." % (service, ip))
      log.DEBUG("out, err:\n%s\n%s" % (out, err))
  return result

def restart_genesis(svm_ips):
  """
  Returns True if Genesis is started on all svms. Returns False otherwise.

  svm_ips: List of svm ip addresses for whom genesis should be restarted.

  username: Must be 'nutanix'.

  keypath: Path to the ssh key used to login into the svms.

  timeout_secs: Number of seconds this operation is expected to take.
  """
  result = True
  cmd_map = dict((ip, "%s restart" % FLAGS.genesis_path) for ip in svm_ips)
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  for ip, (ret, out, err) in result_map.iteritems():
    if ret == 0:
      log.INFO("Restarted Genesis on %s." % ip)
      continue
    result = False
    if ret == -1:
      log.ERROR("Restarting Genesis timed out on %s." % ip)
    else:
      log.ERROR("Restarting Genesis failed on %s." % ip)
    log.ERROR("Stdout: %s\nStderr:%s" % (out, err))
  return result

def get_svm_ips(cc):
  """
  Returns the svm ips found the in cluster config.

  cc: ClusterConfig object.
  """
  svm_ips = []
  badconfig = False
  for esxhost in cc.esx_hosts():
    ip = cc[esxhost]["svm_ip"]
    if not ip:
      badconfig = True
      log.ERROR("Esxhost section %s has no svm_ip field" % esxhost)
    svm_ips.append(ip)

  if badconfig:
    return None
  else:
    return svm_ips

def format_node(node):
  node_ip = node.get("svm_ip", None) or node["ip"]
  out_str = "ip: %s\n\t" % node_ip
  display_keys = ("rackable_unit_serial", "node_position", "node_uuid")
  return out_str + "\n\t".join("%s: %s" % (k, node[k]) for k in display_keys)

def read_specification_file_json():
  """
  Opens and loads the json configuration file specified by
  'FLAGS.ip_specification_json' and returns the loaded value if the file
  loading is successful.
  Returns the loaded symbols if successfule else returns 'None'.
  """
  def check_for_duplicate_keys(ordered_pairs):
    # Check if file has duplicate keys.
    d = {}
    for k, v in ordered_pairs:
      if k in d:
        log.ERROR("Duplicate Entry %s:%s exists." % (k, d))
        raise Exception
      else:
        d[k] = v
    return d

  if not os.path.exists(FLAGS.ip_specification_json):
    log.ERROR("%s file not found" % FLAGS.ip_specification_json)
    return None

  try:
    with open(FLAGS.ip_specification_json) as jsonfile:
      ipspec = simplejson.load(jsonfile,
                               object_pairs_hook=check_for_duplicate_keys)
  except ValueError:
    log.ERROR("%s file is not a valid JSON file"
              % FLAGS.ip_specification_json)
    return None
  except IOError:
    log.ERROR("Error loading %s file" % FLAGS.ip_specification_json)
    return None
  except Exception:
    log.ERROR("Exception while reading %s file" % FLAGS.ip_specification_json)
    return None

  return ipspec

def get_svm_ips_json():

  ipspec = read_specification_file_json()
  if not ipspec:
    return None

  svm_ips = []
  for key, value in ipspec["IP Addresses"].items():
    svm_ips.append(value["Controller"])

  return svm_ips

def get_cluster_external_ip_json():
  """
  Returns the cluster-external_ip from the json specification file if
  successful otherwise returns None.
  """
  ipspec = read_specification_file_json()
  if not ipspec:
    return None

  return ipspec.get("Cluster External IP", "")

def do_backplane_ipconfig(svmips):
  """
  Applies backplane network config to each node of the cluster.
  The SVM external IPs (eth0) need to be pre-configured.
  Args:
    svmips: list of svm external IP addresses.
  The FLAGS relevant for this command:
    backplane_network - boolean (Needs to be set to True)
    backplane_vlan - vlan_id (Optional)
    backplane_subnet - backplane subnet (e.g. "10.10.10.0") Mandatory
    backplane_netmask - backplane netmask (e.g. "255.255.255.0") Mandatory
  CLI format:
  cluster -s <svmips> --backplane_network --backplane_vlan=<vlan-id>
    --backplane_subnet=<subnet> --backplane_netmask=<netmask> ipconfig
  OR
  cluster -s <svmips> --backplane_network --backplane_subnet=<subnet>
    --backplane_netmask=<netmask> ipconfig
  e.g. cluster -s "10.1.1.1,10.1.1.2,10.1.1.3" --backplane_network
       --backplane_subnet="172.16.0.0" --backplane_netmask="255.255.255.0"
       --backplane_vlan=100 ipconfig
  """
  ret, err = get_validate_backplane_conf(svmips, validate_only=True)
  if not ret:
    log.ERROR(err)
    return False
  bp_vlan = FLAGS.backplane_vlan

  bp_subnet = FLAGS.backplane_subnet
  bp_netmask = FLAGS.backplane_netmask
  if not bp_subnet or not bp_netmask:
    log.ERROR("backplane_subnet '%s' and backplane_netmask '%s' are "
              "mandatory params" % (bp_subnet, bp_netmask))
    return False

  if len(svmips) < 3:
    log.ERROR("Backplane IP supported for clusters with 3 or more nodes")
    return False

  if bp_vlan == -1:
    bp_vlan = None
  elif bp_vlan < 0 or bp_vlan > 4095:
    log.ERROR("Valid vlan id range is 0 - 4095")
    return False

  ret = ns_helper.allocate_cluster_backplane_ips(svmips, bp_subnet, bp_netmask)
  ret_status, ret_val = ret
  if not ret_status:
    log.ERROR("Could not allocate backplane IPs for cluster nodes: %s"
              % ret_val)
    return False

  ip_address_map = ret_val

  log.INFO("IP address allocated %s" % ip_address_map)

  failed = False
  for svm_ext_ip in svmips:
    ret = genesis_utils.call_genesis_method(
        [svm_ext_ip], NodeManager.configure_backplane_ip, (bp_netmask,
        ip_address_map[svm_ext_ip][0], ip_address_map[svm_ext_ip][1], bp_vlan))

    if isinstance(ret, RpcError):
      log.ERROR("Backplane IP config RPC failed on %s" % svm_ext_ip)
      failed = True
      break

    retval, errmsg = ret
    if not retval:
      log.ERROR("Failed to apply backplane IP config on %s error %s"
                % (svm_ext_ip, errmsg))
      failed = True
      break

  if failed:
    log.INFO("Backplane IP config failed for some nodes. Reverting config that"
             " is already applied")
    backplane_utils.unconfigure_all_backplane_ipconfig(svmips)
    return False

  log.INFO("Successfully applied backplane networking config to all nodes")
  return True

def admin_user_present_in_zk():
  """
  Check whether admin user authentication credentials are present in Zookeeper.
  This is required for Witness VM, as the authentication of 'admin' user wont
  be based on zookeeper stored credentials.
  """
  zk_path = "/appliance/physical/userrepository"
  zk_session = genesis_utils.get_zk_session(
      host_port_list=FLAGS.zookeeper_host_port_list)
  user_data = genesis_utils.get_znode_content(zk_session, zk_path)
  if user_data is None:
    return False
  user_proto = prism_auth_pb2.UserRepository()
  user_proto.ParseFromString(user_data)
  for user in user_proto.user:
    if user.username == "admin":
      return True
  return False

def do_ipconfig():
  """
  Configures IP addresses listed in Flags.ip_specification_json file.
  Returns True on success and False on error.

  Following is the format of JSON file.
  {
    "Cluster Name":"<Value in string>",
    "Cluster External IP":"IPv4 address",
    "DNS servers":"<Value in string>",
    "NTP servers":"<Value in string>",
    "Subnet Mask":{
      "Controller":"<Valid IPv4 address>",
      "Hypervisor":"<Valid IPv4 address>",
      "IPMI":"<Valid IPv4 address>"
    },
    "Default Gateway":{
      "Controller":"<value in string>",
      "Hypervisor":"<value in string>",
      "IPMI":"<value in string>"
    },
    "Discover Nodes": true,
    "IP Addresses":{
      "block_serial/node_position": {
        "Controller":"IPv4 address",
        "Hypervisor":"IPv4 address",
        "IPMI":"IPv4 address"
      },
      "08b7586c-ce7c-4901-92a9-fd742e346f51/C": {
        "Controller":"10.1.40.178",
        "Hypervisor":"10.1.40.111",
        "IPMI":"10.1.40.10"
      }
      ...
    }
    # OR
    "Discover Nodes": false,
    "IP Addresses":{
      "IPv6%Link": {
        "Controller":"IPv4 address",
        "Hypervisor":"IPv4 address",
        "IPMI":"IPv4 address"
      },
      "fe80::f816:3eff:fe48:f9ba%eth0": {
        "Controller":"10.1.40.178",
        "Hypervisor":"10.1.40.111",
        "IPMI":"10.1.40.10"
      }
      ...
    }
  }

  Cluster Name, DNS servers, NTP Servers are not used currently.
  Assigning empty string to Controller/ ESX/ IPMI in "IP Addresses" leave
  corresponding IPs unchanged.
  e.g. "Controller" = "" will not change Controller IP.
  """
  if FLAGS.svm_ips and FLAGS.backplane_network:
    # This is to apply configuration for backplane network.
    svmips = FLAGS.svm_ips.split(",")
    return (do_backplane_ipconfig(svmips))

  ipspec = read_specification_file_json()
  if not ipspec:
    return False

  # Input JSON file has object representing "IP Addresses".
  # "IP Addresses" contain IPs to be assigned to CVM, Hypervisor, IPMI.
  ip_addresses = ipspec["IP Addresses"]

  if ipspec.get("Discover Nodes", True):
    ip_addresses_by_name = ip_addresses
    ip_addresses = {}

    # Discover nodes using localhost.
    discovered_nodes = genesis_utils.call_genesis_method(
        ["localhost"], NodeManager.discover_unconfigured_nodes, ("IPv6",))

    if not discovered_nodes:
      log.ERROR("Could not discover unconfigured nodes")
      return False

    for discovered_node in discovered_nodes:
      key = "%(rackable_unit_serial)s/%(node_position)s" % discovered_node

      if key in ip_addresses_by_name:
        ipv6 = discovered_node["ip"]
        ip_addresses[ipv6] = ip_addresses_by_name[key]
        del ip_addresses_by_name[key]
        log.INFO("Node %s discovered at %s" % (key, ipv6))

    if ip_addresses_by_name:
      log.ERROR("Nodes %r could not be discovered" %
                ip_addresses_by_name.keys())
      return False

  for ipv6, ips in ip_addresses.items():
    def make_addr_dict(what):
      if not ips.get(what):
        return None
      try:
        return {"address": ips[what],
                "netmask": ipspec["Subnet Mask"][what],
                "gateway": ipspec["Default Gateway"][what]}
      except KeyError:
        log.FATAL("Error in IP specification JSON")

    def validate_ip(ip_dict):
      """
      This function validates the ip, subnet of host, CVM and IPMI.
      These Ips are passed as dictionary.
      """
      for key, value in ip_dict.iteritems():
        if key == "netmask":
          if not IPv4Config.is_valid_netmask(value):
            log.ERROR("Netmask %s is not valid." % value)
            return False
        elif key == "address" or key == "gateway":
          if not IPv4Config.is_valid_address(value):
            log.ERROR("Address %s is not valid." % value)
            return False
        else:
          log.ERROR("Unknown Entry %s:%v in json file." % (key, value))
          return False

      # Check if IP provided overlaps with reserved subnet.
      ip = ip_dict["address"]
      netmask = ip_dict["netmask"]
      subnetip = IPv4Config.calc_subnet(ip, netmask)
      res_subnet_mask = FLAGS.svm_internal_netif_netmask
      res_subnet_ip = IPv4Config.calc_subnet(FLAGS.hypervisor_internal_ip,
                                             res_subnet_mask)
      if (IPv4Config.calc_subnet(subnetip, res_subnet_mask) == res_subnet_ip or
          IPv4Config.calc_subnet(res_subnet_ip, netmask) == subnetip):
        log.ERROR("IP %s/%s has subnet that overlaps with reserved subnet "
                  "%s/%s." % (ip, netmask, res_subnet_ip, res_subnet_mask))
        return False
      return True

    ip_type = ["Controller", "Hypervisor", "IPMI"]
    ip_dict = map(make_addr_dict, ip_type)
    for ii in ip_dict:
      if ii and not validate_ip(ii):
        return False

    ret = genesis_utils.call_genesis_method([ipv6], NodeManager.configure_ip,
                                            (ip_dict[0],
                                             ip_dict[1],
                                             ip_dict[2]))

    if not ret:
      log.ERROR("IP configuration RPC failed on %s" % ipv6)
      return False

    status, message = ret
    if status != True:
      log.ERROR("IP configuration failed on %s: %s" % (ipv6, message))
      return False
    else:
      log.INFO("IP configuration succeeded on %s" % ipv6)

  return True

def get_validate_backplane_conf(svm_ips, validate_only=False):
  """
  Do validations to check if backplane can be enabled on this cluster.
  Optionally fetch and return the CVM backplane IPs as well
  Args:
    svm_ips: List of svm ips
    validate_only: If True, just perform validation checks and don't fetch
                   the IP addresses from the CVMs.
  Returns:
    (True, map of cvm external ip to cvm backplane ip) on success
    (False, error message) otherwise
  Note:
    FLAGS.backplane_network must be set as True for this function's logic to
    come in effect.
  """
  if not FLAGS.backplane_network:
    error = ("The gflag backplane_network must be set as True for "
             "backplane network to be created")
    return (False, error)
  if FLAGS.cluster_function_list[0].strip() != ClusterManager.NDFS_FUNCTION:
    error = "Backplane network can only be enabled on NDFS clusters"
    return (False, error)

  allowed_hyps = ns_helper.BackplaneNwInterface.ALLOWED_HYPS
  ret, error = ns_helper.verify_allowed_hypervisors(svm_ips, allowed_hyps)
  if not ret:
    return (False, error)

  # Validate DVS status.
  # Network Segmentation is not supported on DVS enabled cluster.
  ret, error = ns_helper.validate_dvs_enabled()
  if not ret:
    return (False, error)

  if validate_only:
    return (True, {})

  # Create a map of CVM external IP to backplane IP.
  backplane_cfgd = True
  cvm_bp_ip_map = {}
  error = ""
  for svm_ext_ip in svm_ips:
    addr = genesis_utils.call_genesis_method(
        [svm_ext_ip], NodeManager.get_backplane_cvm_ip)

    if isinstance(addr, RpcError):
      error = "RPC failed to get backplane IP on %s" % svm_ext_ip
      backplane_cfgd = False
      break
    if not addr:
      backplane_cfgd = False
      break
    cvm_bp_ip_map[svm_ext_ip] = addr
  else:
    return (backplane_cfgd, cvm_bp_ip_map)

  return (False, error)

def do_config(svm_ips, cluster_external_ip):
  # redundancy_factor=-1 indicates that no redundancy_factor flag was passed.
  # For single node clusters we default to rf1 and rf2 for multinode clusters.
  if FLAGS.redundancy_factor == -1:
    if len(svm_ips) == 1:
      FLAGS.redundancy_factor = 1
    else:
      FLAGS.redundancy_factor = 2

  if not genesis_utils.is_valid_redundancy_factor(svm_ips):
    log.FATAL("Invalid redundancy factor value: %d. Allowed values [2-3] for "
              "multi-node clusters" % FLAGS.redundancy_factor)
  fault_tolerance = FLAGS.redundancy_factor - 1
  num_zk_nodes = (
    zeus_utils.num_zk_nodes_required(fault_tolerance, len(svm_ips)))

  if len(svm_ips) < num_zk_nodes:
    log.FATAL("At least %d nodes required to support redundancy factor: %d" %
              (num_zk_nodes, FLAGS.redundancy_factor))

  if len(FLAGS.cluster_function_list) != 1:
    log.FATAL("Expect 1 function for cluster_function_list")

  if (FLAGS.cluster_function_list[0].strip() not in
      ClusterManager.CLUSTER_FUNCTIONS_BITMAP.keys()):
    log.FATAL("Valid arguments for cluster_function_list are %s" %
              ", ".join(ClusterManager.CLUSTER_FUNCTIONS_BITMAP.keys()))

  single_node_cluster_types = [
    ClusterManager.MULTICLUSTER_FUNCTION,
    ClusterManager.CLOUD_DATA_GATEWAY_FUNCTION,
    ClusterManager.WITNESS_VM_FUNCTION
  ]

  single_node_cluster = False
  for xx in single_node_cluster_types:
    if xx in FLAGS.cluster_function_list:
      single_node_cluster = True
      break

  two_node_cluster = False
  if ClusterManager.TWO_NODE_CLUSTER_FUNCTION in FLAGS.cluster_function_list:
    log.INFO("Creating a 2-node cluster with redundancy factor 2")
    two_node_cluster = True

  is_snb_cluster = genesis_utils.is_single_node_backup_cluster(
      svm_ips, FLAGS.redundancy_factor)
  if is_snb_cluster:
    FLAGS.cluster_function_list = [ClusterManager.ONE_NODE_CLUSTER_FUNCTION]

  if (single_node_cluster == False and not is_snb_cluster):
    # Single node clusters, other than single_node_backup clusters require
    # user confirmation.
    if two_node_cluster:
      log.CHECK_EQ(len(svm_ips), 2)

    elif len(svm_ips) < 3:
      prompt = ("Atleast 3 nodes are required for cluster creation!. %d "
                "IPs provided. Do you want to proceed? (Y/[N]): "
                % len(svm_ips))
      while True:
        confirmation = raw_input(prompt)
        if not confirmation or confirmation.upper() in ["N", "NO"]:
          # Default value is no.
          # Do not continue and exit.
          log.INFO("Cluster creation request cancelled by use")
          sys.exit(0)
        if confirmation.upper() in ["Y", "YES"]:
          break
        print "Please enter a valid input."

    if len(svm_ips) < num_zk_nodes:
      log.WARNING("At least %d nodes required to support redundancy factor %d"
                  % (num_zk_nodes, FLAGS.redundancy_factor))

  if len(svm_ips) != len(set(svm_ips)):
    log.FATAL("Provide unique IPs for cluster creation.")

  dns_servers = None
  if FLAGS.dns_servers:
    dns_servers = FLAGS.dns_servers.split(",")
    # Check if there are any invalid IPv4 addresses in the DNS IP list.
    invalid_dns_ips = [ip for ip in dns_servers if not
                       IPv4Config.is_valid_address(ip)]
    if invalid_dns_ips:
      log.FATAL("Invalid IPv4 addresses in list of dns_servers %s"
                % invalid_dns_ips)

  ntp_servers = None
  if FLAGS.ntp_servers:
    ntp_servers = FLAGS.ntp_servers.split(",")

  deadline = time.time() + FLAGS.timeout
  node_map = {}
  cluster_arch = None
  node_info_list=[]

  # TODO: Remove the force block completely.
  if FLAGS.skip_discovery:
    for svm_ip in svm_ips:
      node_manager = proxy.import_service(svm_ip, NodeManager)
      retry_count = 0
      while True:
        node_info = node_manager.get_published_info()
        if isinstance(node_info, RpcError):
          if retry_count < 10:
            log.WARNING("Node %s is not ready yet. Retrying." % svm_ip)
            retry_count = retry_count + 1
            time.sleep(3)
            continue
          else:
            log.FATAL("Node %s is not reachable. Aborting." % svm_ip)
        else:
          break
      # Copy over the actual model-string to rackable_unit_model.
      node_info["rackable_unit_model"] = node_info["model_string"]
      node_ip = node_info.get("svm_ip", None)
      if not node_ip:
        log.FATAL("Failed to force discover node %s" % svm_ip)
      node_map[node_ip] = node_info
      # use node["ip"] for the node-ip across both if and else cases.
      node_info["ip"] = node_ip
      node_info_list.append(node_info)

  else:
    # Discover only the required nodes based on ipv4 filters.
    discovered_nodes = genesis_utils.call_genesis_method(
        ["localhost", ], NodeManager.discover_unconfigured_nodes,
        ("IPv4", svm_ips))
    if isinstance(discovered_nodes, RpcError):
      log.FATAL("Failed to discover nodes. RPC failed")
    if len(discovered_nodes) != len(svm_ips):
      discovered_ips = [node["ip"] for node in discovered_nodes]
      failed_ips = set(svm_ips) - set(discovered_ips)
      log.FATAL("Could not discover all nodes specified. Please make sure that "
                "the SVMs from which you wish to create the cluster are not "
                "already part of another cluster. Undiscovered ips : %s" %
                ",".join(failed_ips))

    # Create node ip to node dictionary.
    for node in discovered_nodes:
      node_ip = node["ip"]
      if node_ip in svm_ips:
        log.INFO("Discovered node: \n%s\n" % format_node(node))
        node_map[node_ip] = node

    node_info_list = discovered_nodes

  for node_info in node_info_list:
    # Check if all nodes belong to the same arch.
    node_arch = node_info.get("arch", None)
    if node_arch:
      if cluster_arch and node_arch != cluster_arch:
        log.ERROR("Nodes on different archs, cluster cannot be created")
        return False
      if not cluster_arch:
        cluster_arch = node_arch
    else:
      log.ERROR("Cannot verify arch of svm %s" % node_info["ip"])
      return False

  log.INFO("Cluster is on arch %s" % cluster_arch)

  backplane_cfgd, cvm_bp_ip_map = get_validate_backplane_conf(svm_ips)
  if not backplane_cfgd:
    log.DEBUG(cvm_bp_ip_map)
    cvm_bp_ip_map = {}

  sx_nodes = []
  nx_nodes = []
  block_to_node_ips_map = {}

  # Create a map of rackable unit to list of ips of nodes which belong to this
  # rackable unit.
  for node_ip, node in node_map.items():
    block_id = node["rackable_unit_serial"]
    if block_id not in block_to_node_ips_map:
      block_to_node_ips_map[block_id] = [node["ip"]]
    else:
      block_to_node_ips_map[block_id].append(node["ip"])

    if node["attributes"] and node["attributes"].get("is_xpress_node", False):
      sx_nodes.append(node_ip)
    else:
      nx_nodes.append(node_ip)

  # SX and NX nodes cannot commingle. Test for cluster homogeneity.
  if len(sx_nodes) > 0 and len(nx_nodes) > 0:
    log.ERROR("Xpress nodes %s are incompatible with %s" % (sx_nodes, nx_nodes))
    return False

  # SX cluster size check.
  if (len(svm_ips) == len(sx_nodes) and len(sx_nodes) >
      cluster.consts.SX_MAX_NODES):
    log.ERROR("Number of Xpress nodes (%s) exceed the limit %s " %
              (len(svm_ips), cluster.consts.SX_MAX_NODES))
    return False

  # G4 and G5 nodes cannot commingle on the same block.
  for block_id, node_ip_list in block_to_node_ips_map.items():
    g4_nodes = []
    g5_nodes = []
    for node_ip in node_ip_list:
      if node_map[node_ip]["rackable_unit_model"].endswith("-G5"):
        g5_nodes.append(node_ip)
      else:
        g4_nodes.append(node_ip)

    if len(g4_nodes) > 0 and len(g5_nodes) > 0:
      log.ERROR("G4 nodes %s cannot commingle with G5 %s nodes in the "
                "same block: %s" % (g4_nodes, g5_nodes, block_id))
      return False

  # HyperV specific checks:
  # 1. Block mixed version cluster creation.
  # 2. Cluster name cannot have special characters.

  hyperv_version_list = []
  has_hyperv_node = False
  for node_info in node_info_list:
    # Make sure this picks only HyperV nodes for count.
    if (node_info.get("hypervisor") == 'hyperv'):
      has_hyperv_node = True
      version = node_info.get("hypervisor_version", None)
      if version:
        version = version.replace("_Standard", "").replace("_Datacenter", "")
      else:
        log.ERROR("Invalid hypervisor version")
      hyperv_version_list.append(version)

  version_count_list = collections.Counter(hyperv_version_list).values() or []
  if len(version_count_list) > 1:
    err = ("Cannot create mixed version HyperV cluster. Version list : %s" %(
           hyperv_version_list))
    log.ERROR(err)
    return False

  # HyperV cluster name cannot have special chars.
  if has_hyperv_node and not re.match("^[a-zA-Z0-9._-]*$", FLAGS.cluster_name):
    log.ERROR("Cluster name cannot have special characters")
    return False

  if FLAGS.rack_config_json_path:
    err_str="""
    The flag rack_config_json_path contains path to the json file, which has the
    map of svm_ips to the name of the rack, they belong to. This file has to
    contain all the svm_ips that are to be configured a part of this cluster.
    Any extra entries in JSON will be ignored.
    A typical such json file will look like:-
    {
        "10.1.1.1" : "Rack A",
        "10.1.1.4" : "Rack B",
        "10.1.1.2" : "Rack B",
        .
        .
        .
    }
    """
    rack_config = None
    try:
      with open(FLAGS.rack_config_json_path) as jsonfile:
        rack_config = json.load(jsonfile)
    except (OSError, IOError) as ee:
      log.ERROR(err_str + "Failed to load %s with %s. Please ensure "
                "appropriate READ permissions are granted for the file"
                % (FLAGS.rack_config_json_path, ee))
      return False
    except ValueError as ee:
      log.ERROR(err_str + "Failed to parse %s as JSON. Error: %s"
                % (FLAGS.rack_config_json_path, ee))
      return False
    for svm_ip in svm_ips:
      if svm_ip not in rack_config:
        log.ERROR("Complete rack configuration needs to be provided for rack "
                  "information to be consumed by cluster services. svm_ip %s "
                  "does not have a rack configuration" % svm_ip)
        return False
    for svm_ip in rack_config:
      if svm_ip not in svm_ips:
        del rack_config[svm_ip]
    if not genesis_rack_utils.update_rack_config(rack_config):
      log.ERROR("Failed to update all nodes, with the rack configuration "
                "provided. Please check if all nodes are reachable")
      return False

  svm_ips_to_rack_map = genesis_rack_utils.get_svm_ips_to_rack_map(svm_ips)

  # If rack is not configured on one or more nodes of the cluster, don't check
  # rack consistency.
  bad_rack_config_svms = []
  if svm_ips_to_rack_map:
    bad_rack_config_svms = rack_utils.check_rack_mapping_consistency(
        svm_ips_to_rack_map, block_to_node_ips_map)

  # Denotes the desired domain awareness state of the cluster. All the CDP
  # services would read this from zeus and try to drive the cluster towards this
  # 'domain' aware state. These domain levels are defined in
  # DomainFaultToleranceState.Domain.DomainType
  desired_domain_ft_level = None

  if FLAGS.rack_aware:
    if FLAGS.block_aware:
      log.ERROR("Rack awareness and Block awareness cannot be guaranteed at "
                "the same time. Only one option can be selected for creating "
                "the cluster")
      return False
    if FLAGS.redundancy_factor < 2:
      log.ERROR("For Rack awareness to be enabled, cluster should be created "
                "with redundancy factor >= 2")
      return False
    # Checking if rack is configured for each node and node distribution is
    # valid among the racks to allow rack awareness.
    if svm_ips_to_rack_map is None:
      log.ERROR("One or more nodes in the cluster do not have rack configured")
      return False
    if bad_rack_config_svms:
      log.ERROR("All nodes on one block should belong to the same rack. Rack "
                "awareness could not be enabled.")
      return False
    if rack_utils.meets_rack_awareness_criteria(svm_ips_to_rack_map)[0]:
      log.INFO("Rack awareness basic criteria met")
    else:
      log.ERROR("Cluster does not support basic criteria for Rack awareness")
      return False
    desired_domain_ft_level = DomainFaultToleranceState.Domain.kRack
  elif FLAGS.block_aware:
    if FLAGS.redundancy_factor < 2:
      log.ERROR("For Block awareness to be enabled, cluster should be created "
                "with redundancy factor >= 2")
      return False
    # Check for block awareness criteria if only rack awareness is not explicity
    # desired.
    svm_ips_to_rackable_unit_map = {}
    for _, node in node_map.items():
      svm_ips_to_rackable_unit_map[node["ip"]] = node["rackable_unit_serial"]
    if rack_utils.meets_block_awareness_criteria(svm_ips_to_rackable_unit_map,
                                                  FLAGS.redundancy_factor)[0]:
      log.INFO("Block awareness basic criteria met")
    else:
      log.ERROR("Cluster does not support basic criteria for Block awareness")
      return False
    desired_domain_ft_level = DomainFaultToleranceState.Domain.kRackableUnit
  if bad_rack_config_svms:
    log.WARNING("Rack Configuration is inconsistent for SVMs on one or more"
                "blocks. Deleting incorrect configuration")
    remove_bad_config = genesis_rack_utils.remove_rack_config(
        bad_rack_config_svms)
    if not remove_bad_config:
      log.ERROR("Could not remove bad rack configuration from "
                "auxiliary_config.json for some of svm_ips (%s)"
                % bad_rack_config_svms)
      return False

  num_zks = 1 if len(svm_ips) < num_zk_nodes else num_zk_nodes

  # Build the rack to blocks map from svm_ip to rack map.
  rack_to_blocks_map = dict()
  if svm_ips_to_rack_map and not bad_rack_config_svms:
    for svm_ip, rack_id in svm_ips_to_rack_map.iteritems():
      if rack_id not in rack_to_blocks_map:
        rack_to_blocks_map[rack_id] = set()
      rack_to_blocks_map[rack_id].add(node_map[svm_ip]["rackable_unit_serial"])

    for rack_id, block_set in rack_to_blocks_map.iteritems():
      rack_to_blocks_map[rack_id] = list(block_set)

  # rack_to_blocks_map and block_to_node_ips_map will be
  # modified within the function. If you need to use them below then make a
  # copy.
  zk_list = genesis_utils.select_nodes_best_effort_rack_aware(
    num_zks, rack_to_blocks_map, block_to_node_ips_map)

  log.CHECK_EQ(
    len(zk_list), num_zks,
    "Failed to map %d Zookeeper servers. current zk_list: %s,"
    " rack_to_blocks_map: %s," " block_to_node_ips_map: %s" %
    (num_zks, zk_list, rack_to_blocks_map, block_to_node_ips_map))

  if backplane_cfgd:
    zk_list = [cvm_bp_ip_map[node_ip] for node_ip in zk_list]

  # Need to spoof a zookeeper node in case of a two node cluster.
  if two_node_cluster:
    zk_list.append(NodeManager.INVALID_ZOOKEEPER_IP)

  backplane_svm_ips = svm_ips
  state_name = node_states.kBaseConfig
  # If backplane network is configured, need to apply the firewall rules before
  # we setup zeus mapping and set ip_list_for_rpcs to backplane ips.
  # Once iptables are applied, genesis RPCs will no longer be available on
  # the external interface - eth0.
  # TODO ENG-73555 : Close genesis port on management interface - eth0 once
  # all the scripts in cluster/bin are ported.
  if backplane_cfgd:
    log.INFO("Backplane network is configured and will be used")
    backplane_svm_ips = cvm_bp_ip_map.values()
    state_name = node_states.kBackplaneConfig
  if FLAGS.cluster_function_list[0].strip() == ClusterManager.NDFS_FUNCTION:
    for svm_ip in svm_ips:
      ret = genesis_utils.call_genesis_method(
          [svm_ip], NodeManager.apply_iptables_for_state, (state_name,))
      if isinstance(ret, RpcError):
        log.FATAL("RpcError (%s) for SVM %s" % (str(ret), svm_ip))
      else:
        ret, err = ret
        if not ret:
          log.FATAL("Failed to configure iptables on SVM "
                    "node %s, error: %s" % (svm_ip, err))
      log.INFO("iptables configured on SVM %s" % svm_ip)

  deadline = time.time() + FLAGS.timeout

  # Map from zookeeper node ip to the zookeeper id assigned to it.
  zk_map = {}
  for ii in range(0, len(zk_list)):
    zk_map[zk_list[ii]] = ii + 1

  for svm_ip in backplane_svm_ips:
    node = proxy.import_service(svm_ip, NodeManager)

    # Setting the cluster functions field in node manager. This will be used to
    # start Zookeeper with real time priority scheduling.
    log.INFO("Setting the cluster functions on SVM node %s" % svm_ip)
    ret = node.configure_cluster_functions(FLAGS.cluster_function_list)
    if isinstance(ret, RpcError):
      log.FATAL("RpcError (%s) for SVM %s" % (str(ret), svm_ip))

    # We need to store cluster_function in a temporary file until
    # cached proto is present on the CVM. The in memory variable in
    # NodeManager will be lost if it restarts during cluster create.
    # Firewall might fail to initialize in this case as seen in ENG-151844.
    with open(FLAGS.cluster_function_temp_file, "w") as fd:
      cluster_function = (
          ClusterManager.CLUSTER_FUNCTIONS_BITMAP[
              FLAGS.cluster_function_list[0].strip()])
      fd.write(str(cluster_function))

    log.INFO("Configuring Zeus mapping (%s) on SVM node %s" % (zk_map, svm_ip))
    while time.time() < deadline:
      ret = node.configured()
      if isinstance(ret, RpcError):
        time.sleep(2)
        continue
      elif ret:
        log.FATAL("SVM %s is already configured" % svm_ip)

      ret = node.configure_zookeeper_mapping(zk_map)
      break

    if not ret:
      log.FATAL("Failed to configure Zeus mapping on node %s: %s" %
                (svm_ip, ret))

  log.INFO("Creating cluster with SVMs: %s" % ",".join(svm_ips))
  node_list = [(node_map[ip]["node_uuid"], ip) for ip in svm_ips]

  # Lookup /etc/shadow for possible prism password seed.
  prism_password = None
  if FLAGS.seed_prism_password:
    for line in read_file_as_root("/etc/shadow").splitlines():
      user, pw, _ = line.split(":", 2)
      if (user == "nutanix" and
          pw and not pw.startswith(FLAGS.nutanix_default_password_salt)):
        prism_password = pw
        log.INFO("Will seed prism with password hash %s" % pw)
        break

  if FLAGS.container_name:
    container_name = FLAGS.container_name
  else:
    container_name = None
  cluster_uuid = FLAGS.cluster_uuid
  if cluster_uuid == "":
    cluster_uuid = None
  else:
    try:
      # Good idea to validate user input.
      cluster_uuid = str(uuid.UUID(cluster_uuid))
    except ValueError:
      log.ERROR("Invalid cluster_uuid specifified -- %s" % cluster_uuid)
      return False

  # Only create cluster certificates for PE and PC clusters.
  if (FLAGS.cluster_function_list[0].strip() in
      [ClusterManager.NDFS_FUNCTION, ClusterManager.MULTICLUSTER_FUNCTION]):
    if FLAGS.provided_root_certificate and FLAGS.provided_root_certificate_key:
      if (not os.path.exists(FLAGS.provided_root_certificate) or
          not os.path.exists(FLAGS.provided_root_certificate_key)):
        log.FATAL("Provided bad flags for root certificate information")
      ca_path = os.join(FLAGS.authn_certs_root_path, FLAGS.authn_root_ca)
      key_path = os.join(FLAGS.authn_certs_root_path, FLAGS.authn_root_ca_key)
      try:
        # Ensure the directory is there with the appropriate permissions.
        if not os.path.isdir(FLAGS.authn_certs_root_path):
          # We need to make the certs directory on all nodes and give it the
          # appropriate permissions.
          config_create_cmd = "sudo mkdir -p %s" % FLAGS.authn_certs_root_path
          permissions_cmd = ("sudo chown nutanix:nutanix %s"
                             % FLAGS.authn_certs_root_path)
          for cmd in [config_create_cmd, permissions_cmd]:
            ret, out, err = timed_command(cmd)
            if ret != 0:
              log.ERROR("Failed to create directory for certificates %s" % err)
              return False
        shutil.copyfile(FLAGS.proviced_root_certificate, ca_path)
        shutil.copyfile(FLAGS.proviced_root_certificate_key, key_path)
      except (OSError, IOError) as ex:
        log.ERROR("Got exception %s" % ex)
        return False
    elif (FLAGS.provided_root_certificate or
          FLAGS.provided_root_certificate_key):
      log.ERROR("Need to provide both root certificate and key flags")
      return False

  cluster_manager = proxy.import_service(backplane_svm_ips[0], ClusterManager)
  while True:
    ret = cluster_manager.cluster_init(
        FLAGS.cluster_name, node_list, cluster_external_ip,
        FLAGS.redundancy_factor, FLAGS.cluster_function_list, prism_password,
        cvm_backplane_ip_map=cvm_bp_ip_map, container_name=container_name,
        dns_servers=dns_servers, ntp_servers=ntp_servers,
        desired_domain_ft_level=desired_domain_ft_level,
        cluster_uuid=cluster_uuid,
        password_lockdown_mode=FLAGS.password_lockdown_mode)
    if ret is None:
      log.INFO("Zeus is not ready yet, trying again in 5 seconds")
      time.sleep(5.0)
      continue
    elif not ret:
      log.FATAL("Cluster initialization on %s failed with ret: %s" %
                (svm_ips[0], ret))
    else:
      break

  if FLAGS.lockdown_mode:
    log.INFO("Removing all external ssh keys on this cluster")
    result = do_remove_all_public_keys(backplane_svm_ips)
    if not result:
      log.ERROR("Failed to remove all external ssh keys")
      return False
    else:
      log.INFO("Successfully removed all external ssh keys on this cluster")

  if FLAGS.wait:
    log.INFO("Waiting for services to start")
    ret = __wait_until_error_or_done(backplane_svm_ips, "start")

  if ret:
    log.DEBUG("Starting La Jolla")
    status, error = genesis_utils.call_genesis_method(backplane_svm_ips,
        ClusterManager.start_la_jolla)
    if not status:
      log.DEBUG("La Jolla start failed:%s\n" % error)
    else:
      log.DEBUG("La Jolla start initiated\n")

  if util.cluster.consts.CE_ON:
    cmd = os.path.join(FLAGS.genesis_bin_dir, "ce_post_cluster_create")
    if os.path.exists(cmd):
      log.INFO("Running CE cluster post-create script")
      args = shlex.split(cmd.encode())
      ce = CommandExecutor()
      ce.execute(args[0], args, opts="TEMPFILES", detached=True)
      # don't wait for exit/result
    else:
      log.INFO("Cannot find CE cluster post-create script: %s" % cmd)

  # Update arithmos for features enabled during cluster create. To be used by
  # Pulse HD. For now it is only backplane network segmentation.
  if backplane_cfgd:
    event = ("Cluster created with network segmentation enabled for %s"
             % ns_helper.nw_types.kBackplane)
    ns_helper.record_ns_event_in_arithmos(event)
  return ret

def __unconfigure(svm_ips):
  '''
  This function distributes responsibility for unconfiguring CO nodes among all
  HCI nodes, and writes unconfigure marker WAL on all HCI nodes for node manager
  to pick up and unconfigure the nodes.
  '''
  # Force destroy option has been removed as it has danger of the command
  # being accidentally used leading to loss of customer data!
  state = genesis_utils.call_genesis_method(svm_ips, ClusterManager.state)
  if not state:
    log.ERROR("Failed to get the state of the cluster")
    return False
  if state == "start":
    log.ERROR("Cannot destroy a started cluster. "
              "Cluster needs to be stopped first.")
    return False

  cmd_map = {}
  proto = genesis_utils.get_cached_zeus_configuration()
  for i in xrange(0, len(svm_ips), 1):
    marker_cmd = "touch %s;" % FLAGS.node_unconfigure_marker
    # Assign every Compute node at len(svmips) gap, starting from ith index
    # to be unconfigured by ith svm.
    co_node_ips = ""
    for j in xrange(i, len(proto.compute_node_list), len(svm_ips)):
      co_node_ips = (co_node_ips +
                     (" %s" %
                      proto.compute_node_list[j].management_server_name))
    if co_node_ips:
      marker_cmd = (marker_cmd +
                    (' echo "%s" > %s' %
                     (co_node_ips, FLAGS.co_nodes_unconfigure_marker)))
    cmd_map[svm_ips[i]] = marker_cmd

  result = True
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  for ip, (ret, out, err) in result_map.iteritems():
    if ret == 0:
      continue
    result = False
    if ret == -1:
      log.ERROR("Destroy timed out on %s." % ip)
    else:
      log.ERROR("Destroy failed on %s." % ip)
      log.ERROR("ret, out, err:\n%s\n%s\n%s" % (ret, out, err))
      svm_ips.remove(ip)
  if not result:
    log.ERROR("Failed to create marker on all svms")
    restart_genesis(svm_ips)
    log.FATAL("Unable to completely unconfigure cluster")
  if restart_genesis(svm_ips):
    return True
  log.FATAL("Failed to restart genesis on all svms")

def __reconfig(svm_ips, marker_cmd):
  # Force destroy option has been removed as it has danger of the command
  # being accidentally used leading to loss of customer data!
  state = genesis_utils.call_genesis_method(svm_ips, ClusterManager.state)
  if not state:
    log.ERROR("Failed to get the state of the cluster")
    return False
  if state == "start":
    log.ERROR("Cannot reconfig a started cluster. "
              "Cluster needs to be stopped first.")
    return False

  cmd_map = dict((ip, marker_cmd) for ip in svm_ips)

  result = True
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  for ip, (ret, out, err) in result_map.iteritems():
    if ret == 0:
      continue
    result = False
    if ret == -1:
      log.ERROR("Reconfig timed out on %s." % ip)
    else:
      log.ERROR("Reconfig failed on %s." % ip)
      log.ERROR("ret, out, err:\n%s\n%s\n%s" % (ret, out, err))
      svm_ips.remove(ip)

  if not result:
    log.ERROR("Failed to create marker on all svms")
    restart_genesis(svm_ips)
    log.FATAL("Unable to completely reconfigure cluster")

  if restart_genesis(svm_ips):
    return True

  log.FATAL("Failed to restart genesis on all svms")

def __log_action(action):
  """
  Logs the msg to system, using /usr/bin/logger.
  """
  ssh_client = os.environ.get("SSH_CLIENT")
  if ssh_client:
    client_ip = ssh_client.split()[0]
    msg = "Cluster %s initiated by ssh client IP: %s" % (action, client_ip)
  else:
    msg = "Cluster %s initiated through console" % action
  log.INFO(msg)
  cmd = "/usr/bin/logger -p security.info -t cluster %s" % msg
  ret, out, err = timed_command(cmd)
  if ret:
    log.DEBUG("Failed to execute cmd: %s, ret: %s, stdout: %s, stderr: %s" %
              (cmd, ret, out, err))

def do_unconfig(svm_ips):
  # If CPS, prompt the user to call cps_cluster_destroy
  zk_session = ZookeeperSession(FLAGS.zookeeper_host_port_list)
  genesis_utils.ensure_zk_session(zk_session, new_session=True)
  if LaJollaUtils.is_cluster_la_jolla_capable(zk_session):
    log.INFO("This is a CPS cluster, "
             "please invoke cps_cluster_destroy")
    return False

  # Disallow cluster destroy for licensed clusters.
  license_file = zk_session.stat(FLAGS.license_file_zknode)
  if license_file is not None and genesis_utils.valid_license(zk_session):
    log.ERROR("We have detected that you are destroying a cluster that is "
              "in a licensed state. Please refer to "
              "https://portal.nutanix.com/kb/3716 to reclaim the licenses "
              "from this cluster before proceeding with `cluster destroy`.")
    return False

  # Destroying the cluster when disks are password protected will lock the
  # disks forever, so deny the destroy operation. Users should disable password
  # protection and retry.
  __log_action("destroy")
  passwd_state = genesis_utils.call_genesis_method(
    svm_ips, ClusterManager.password_state)
  if isinstance(passwd_state, RpcError):
    log.ERROR("Genesis RPC failure. Could not contact Genesis to discover if "
              "this cluster has configured passwords.")
    return False

  if passwd_state:
    log.ERROR("Cannot destroy the cluster when password protection is active. "
              "Please disable password protection and retry.")
    return False

  if FLAGS.clean_debug_data and not __clean_debug_data(svm_ips):
    return False

  # Need to pass management ips instead of backplane as backplane ips
  # are unconfigured during the destroy process.
  ext_ips = genesis_utils.get_svm_ips()
  ret = (__unconfigure(svm_ips) and
         block_as_long_as_file_exists(FLAGS.node_unconfigure_marker, ext_ips))

  # Best effort to remove gflags if flag is given.
  if ret and FLAGS.reset_gflags_on_destroy:
    log.INFO("Removing all gflag files")
    cmd = "find /home/nutanix/config/ -maxdepth 1 -mindepth 1 " \
          "-regex .*gflags.* -exec rm {} +"
    cmd_map = dict((ip, cmd) for ip in svm_ips)
    genesis_utils.run_command_on_svms(cmd_map)

  return ret


def save_logs(service_glob, svm_ips, dest_dir):
  src_glob = os.path.join(FLAGS.nutanix_log_dir, service_glob)
  cmd = "/bin/cp %s %s" % (src_glob, dest_dir)
  cmd_map = dict((ip, cmd) for ip in svm_ips)
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  log.INFO("Result of savelog operation %s" % str(result_map))
  ret_codes = [x[0] for x in result_map.values()]
  for ret_code in ret_codes:
    if ret_code != 0:
      return False
  return True


def save_genesis_hades_logs(svm_ips):
  dest_dir = "/home/nutanix/infra-logs/"
  cmd = "/bin/mkdir -p %s" % dest_dir
  cmd_map = dict((ip, cmd) for ip in svm_ips)
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  log.INFO("Result of mkdir operation %s" % str(result_map))
  ret_codes = [x[0] for x in result_map.values()]
  for ret_code in ret_codes:
    if ret_code != 0:
      return False

  service_globs = ("genesis.out*", "hades.out*")
  for service_glob in service_globs:
    result = save_logs(service_glob, svm_ips, dest_dir)
    if not result:
      return False
  return True

def __clean_debug_data(svm_ips):
  """
  Removes all of the logs, binary logs, and core dumps. Returns True on
  success.
  """
  log.INFO("Saving Hades & genesis logs for debugging")
  result = save_genesis_hades_logs(svm_ips)
  if not result:
    log.INFO("Could not save logs for debugging")
  # Delete data logs but leave hades log files since hades persists across
  # destroy operations and could be writing to the log file.
  # This deletes all files/dirs in ~/data/logs except hades.out*
  cmd = r"find %s -maxdepth 1 -mindepth 1  ! -name 'hades.out*'  -exec rm -rf {} + " % (
    FLAGS.nutanix_log_dir)
  cmd_map = dict((ip, cmd) for ip in svm_ips)
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  log.INFO("cmd %s result %s" % (cmd, str(result_map)))


  # Clean extra directories.
  clean_dir = r"rm -rf {0}; mkdir {0}"
  clean_cmd = "; ".join([clean_dir.format(FLAGS.nutanix_binary_log_dir),
                         clean_dir.format(FLAGS.nutanix_core_dir)])
  cmd_map = dict((ip, clean_cmd) for ip in svm_ips)
  result_map = genesis_utils.run_command_on_svms(cmd_map)
  log.INFO("Executed cmd %s result %s" % (cmd_map, str(result_map)))

  return True

def do_reconfig(svm_ips):
  # Do not start a reconfiguration if a zookeeper migration is in progress.
  if genesis_utils.is_zknode_present(FLAGS.zookeeper_migration_zknode):
    log.ERROR("Cannot start a reconfig as a zookeeper migration is in "
              "progress")
    return False

  cmd = "cp /etc/hosts %s" % FLAGS.node_reconfigure_marker
  return __reconfig(svm_ips, cmd)

def __print_status(status):
  """
  Prints the current status of the cluster services.
  """
  print "The state of the cluster: %s" % status.get("state", "Unknown")
  print "Lockdown mode: %s" % status.get("lockdown_mode", "Disabled")
  for svm in sorted(status["svms"].keys()):
    print "\n\tCVM: %s %s" % (svm, status["svms"][svm]["state"])
    for details in status["svms"][svm]["services"]:
      state = "DOWN"
      if details["pids"]:
        if details["last_error"]:
          state = "ERROR"
        else:
          state = "UP"
      print "\t\t%20s %4s\t%s\t%s" % (details["service"], state,
                                      details["pids"] or [],
                                      details["last_error"] or "")

def __wait_until_error_or_done(svm_ips, op):
  poll_again = True
  while poll_again:
    status = {}
    ret_val = do_status(svm_ips, result_dict=status)
    if not ret_val:
      log.WARNING("Could not reach a ClusterManager, retrying...")
      continue

    poll_again = status.get("retry", False)
    svm_ips = status["svms"].keys()
    for svm in sorted(svm_ips):
      if status["svms"][svm].get("state") == "Down":
        poll_again = True

      if (op == "start" and NodeManager.TWO_NODE_CLUSTER_SEPARATED_NODE in
          status["svms"][svm]["state"]):
        print ("Waiting on %s:  SEPARATED NODE, not starting services" % svm)
      else:
        print ("Waiting on %s (%s) to %s: " %
               (svm, status["svms"][svm]["state"], op)),
        for details in status["svms"][svm]["services"]:
          if details["last_error"]:
            __print_status(status)
            return False
          if (op == "start" and not details["pids"] or
              op == "stop" and details["pids"]):
            print details["service"],
        print
    print

  __print_status(status)
  return True

def do_start(svm_ips):
  """
  Starts the cluster. Returns True on success.

  svm_ips: One of more IP addresses of SVMs in the cluster.
  """
  if not genesis_utils.call_genesis_method(svm_ips, ClusterManager.start):
    log.ERROR("Failed to execute a cluster start")
    return False

  # If wait is True loop until status shows all processes are up.
  ret = True
  if FLAGS.wait:
    ret = __wait_until_error_or_done(svm_ips, "start")

  return ret

def do_stop(svm_ips):
  """
  Stops the cluster. Returns True on success.

  svm_ips: One of more IP addresses of SVMs in the cluster.
  """
  config = Configuration().initialize()
  num_vms = 0

  # Check if this cluster is managed by Acropolis. Note that the assumption
  # here is that we do not support clusters that are partially managed by
  # Acropolis, so I just check that there is an Acropolis management server
  # entry.
  managed_by_acropolis = False
  for mgmt_server in config.config_proto().management_server_list:
    if mgmt_server.management_server_type == mgmt_server.kAcropolis:
      managed_by_acropolis = True
      break

  if managed_by_acropolis:
    for node in config.config_proto().node_list:
      cmd = "acli -o json host.list_vms %s" % node.uuid
      try:
        ret, stdout, stderr = timed_command(cmd)
        if ret != 0:
          log.WARNING("Failed to check host %s for VMs" % node.uuid)
          log.DEBUG("Cmd %s failed with %s: (%s, %s)" %
                    (cmd, ret, stdout, stderr))
          continue
        cmd_data = json.loads(stdout)
        num_vms += len(cmd_data["data"])
      except ValueError as ex:
        log.DEBUG("Failed to decode output %s: %s" % (stdout, str(ex)))
        continue
      except Exception as ex:
        log.WARNING("Failed to run cmd to check host %s for VMs" % node.uuid)
        log.DEBUG("Cmd %s failed with error: %s" % (cmd, str(ex)))
        continue

    if num_vms > 0:
      log.ERROR("Found %s Acropolis VMs still running on hosts in the "
                "cluster" % num_vms)
      return False

  if not genesis_utils.call_genesis_method(svm_ips, ClusterManager.stop):
    log.ERROR("Failed to execute cluster stop")
    return False

  # Loop until status shows all processes are down.
  ret = True
  if FLAGS.wait:
    ret = __wait_until_error_or_done(svm_ips, "stop")

  return ret


def do_reset(svm_ips):
  """
  Reset the nodes in cluster to a KVM and NOS image, which could be the current
  NOS version if Foundation does not have NOS image.
  """
  if not foundation_utils.at_least_min_foundation():
    min_foundation = ".".join(map(str, cluster.consts.MIN_FOUNDATION_VERSION))
    log.ERROR(
        "Installed Foundation does not support cluster reset. Upgrade "
        "Foundation to version >= %s. See KB 3068 for details." %
        min_foundation)
    return False

  # Resetting the cluster when disks are password protected will lock the
  # disks forever, so deny the destroy operation. Users should disable password
  # protection and retry.
  __log_action("reset")
  passwd_state = genesis_utils.call_genesis_method(
    svm_ips, ClusterManager.password_state)
  if isinstance(passwd_state, RpcError):
    log.ERROR("Genesis RPC failure. Could not contact Genesis to discover if "
              "this cluster has configured passwords.")
    return False

  if passwd_state:
    log.ERROR("Cannot destroy the cluster when password protection is active. "
              "Please disable password protection and retry.")
    return False

  ret = genesis_utils.call_genesis_method(
            ["localhost"],
            ClusterManager.poc_reset)

  if isinstance(ret, RpcError):
    log.ERROR("Genesis RPC failure. Reset failed.")
    return False
  if not ret:
    log.ERROR("Failed to execute cluster reset.")
  else:
    log.INFO("PLEASE SAVE /tmp/reset_status OUTSIDE THIS NODE"
             " AND USE IT TO TRACK RESET STATUS.")
  return ret

def node_status(svm_ip):
  """
  Find node status by doing RPC to node with given address.
  """
  log.DEBUG("Finding node status for %s" % svm_ip)
  status = genesis_utils.call_genesis_method(
      [svm_ip], ClusterManager.node_status, valid=lambda x: True)
  if isinstance(status, RpcError):
    status = {"service_status": {"state": "Down", "services": []}}
  else:
    log.DEBUG("Got response for node status from %s" % svm_ip)
  return status

def do_status(svm_ips, result_dict=None):
  """
  Returns status of the services in the cluster.
  Args:
    svm_ips: One of more IP addresses of SVMs in the cluster.
    result_dict (dict): If dictionary is passed, then status is not printed.
                        Instead they are populated in the dictionary.
  """
  workers = len(svm_ips)
  num_retries = 12
  with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
    svm_res = {}
    for svm_ip in svm_ips:
      svm_res[executor.submit(node_status, svm_ip)] = svm_ip

    pending_svms = []
    for _ in xrange(num_retries):
      result = {}
      result["svms"] = {}
      result["retry"] = False
      done_list, pending_list = concurrent.futures.wait(svm_res, timeout=15)
      got_result = False
      for future in done_list:
        svm_ip = svm_res[future]
        # If status of svm has already printed, ignore them in next iteration.
        if pending_svms and svm_ip not in pending_svms:
          continue

        log.DEBUG("Got result for %s" % svm_ip)
        node_result = future.result()
        if node_result.get("state") is not None:
          result["state"] = node_result["state"]
        if node_result.get("lockdown_mode") is not None:
          result["lockdown_mode"] = node_result["lockdown_mode"]
        if node_result.get("service_status") is not None:
          result["svms"][svm_ip] = node_result["service_status"]
        if node_result.get("retry") is not None:
          result["retry"] = (result["retry"] | node_result["retry"])

        got_result = True

      if got_result:
        # If result dict is passed as dictionary, all the services list is
        # saved there.
        if result_dict is not None:
          result_dict.update(result)
        else:
          __print_status(result)

      if pending_list:
        pending_svms = [svm_res[future] for future in pending_list]
        log.INFO("Waiting for response from %s" % ", ".join(pending_svms))
      else:
        log.DEBUG("All nodes have responded")
        return True
    return False

def do_restart_genesis(svm_ips):
  return restart_genesis(svm_ips)

def __install_and_upgrade(svm_ips, manual_upgrade):
  """
  Upgrade packages on SVM.
  Following is sequence of things:
  1) Preupgrade checks are performed if ignore_preupgrade_tests flag is not set.
  2) If Verification file is provided with -v option then preupgrade checks
     test version compatibility etc.
  3) Upgrade method is set to manual or automatic based on manual_upgrade flag.
  4) Genesis is installed if force_install_genesis option is set.
  5) Initiates rolling upgrade if skip_upgrade is not set.
  Status can be viewed using progress monitor in UI or upgrade_status command.
  Returns True on success, False otherwise.
  """
  if not FLAGS.installer_dir_path:
    log.FATAL("Please provide an installer directory with the -i flag")
  if not os.path.isdir(FLAGS.installer_dir_path):
    log.FATAL("Installer directory %s does not exist" %
              FLAGS.installer_dir_path)

  if not FLAGS.no_verification and not FLAGS.verification_file:
    log.FATAL("Please provide path for verification file with -v flag. "
              "Use -n/--no_verification option if you want to skip upgrade "
              "compatibility checks.")

  if not FLAGS.no_verification and not os.path.exists(FLAGS.verification_file):
    log.FATAL("Verification file %s does not exist." % FLAGS.verification_file)

  nutanix_manifest = upgrade_helper.get_nutanix_manifest(
                        FLAGS.installer_dir_path)
  if not nutanix_manifest:
    log.FATAL("Failed to read manifest file in %s" % FLAGS.installer_dir_path)

  proto = genesis_utils.get_cached_zeus_configuration()
  if (proto and proto.cluster_functions & ConfigurationProto.kWitnessVM and
      admin_user_present_in_zk()):
    print("After upgrade is complete, credentials for this cluster will "
          "be changed to default. Please refer upgrade document for more "
          "details.")

  # Check if cluster script being used is from installer directory.
  cluster_script_path = os.path.abspath(__file__)
  installer_dir_path = os.path.abspath(FLAGS.installer_dir_path)
  if (os.path.commonprefix([cluster_script_path, installer_dir_path]) !=
      installer_dir_path):
    log.ERROR("Please run cluster script present in %s/bin" %
              installer_dir_path)
    return False

  # Perform upgrade tasks based on flags specified.
  if not cluster_upgrade.perform_cluster_upgrade(FLAGS.installer_dir_path,
                                                 FLAGS.no_verification,
                                                 FLAGS.verification_file,
                                                 FLAGS.manual_upgrade,
                                                 FLAGS.ignore_preupgrade_tests,
                                                 FLAGS.skip_upgrade,
                                                 FLAGS.force_install_genesis,
                                                 skip_reconfig=(
                                                  FLAGS.skip_reconfig)):
    log.ERROR("Failed to perform cluster upgrade")
    return False

  if FLAGS.remove_installer_dir and not FLAGS.skip_upgrade:
    current_dir = os.getcwd()
    full_installer_path = os.path.abspath(
      os.path.expanduser(FLAGS.installer_dir_path))
    if (os.path.islink(full_installer_path)):
      # The installer directory had been moved as part of upgrade.
      # Only a symlink might have remained. Removing that here.
      log.INFO("Removing %s from CVM" % full_installer_path)
      os.unlink(full_installer_path)

    if genesis_utils.is_subdir(child=current_dir, parent=full_installer_path):
      log.INFO("CWD is stale, please change CWD "
               "before executing any further commands on this shell.")
  return True

def do_convert_cluster():
  """
  Perform cluster conversion, by invoking RPC to cluster manager.
  Expected flag is target_hypervisor string.
  """
  valid_host_list = genesis_utils.call_genesis_method(
      ["127.0.0.1"], ClusterConversion.valid_hypervisors_for_conversion,
      rpc_timeout_secs=-1)
  if isinstance(valid_host_list, RpcError) or not valid_host_list:
    log.FATAL("Error doing RPC to local svm ip, Error: %s" % valid_host_list)

  if FLAGS.target_hypervisor not in valid_host_list:
    log.ERROR("Given target hypervisor %s is not valid, valid types %s" % (
              FLAGS.target_hypervisor, valid_host_list))
    return False

  svm_ids = []
  if FLAGS.svm_ips:
    proto = genesis_utils.get_cached_zeus_configuration()
    svm_ips = FLAGS.svm_ips.split(",")
    svm_ids = map(lambda x: genesis_utils.get_svm_id_from_svm_ip(
                  proto, x), svm_ips)
    svm_ids = map(str, filter(lambda x: x, svm_ids))
    if len(svm_ids) != len(svm_ips):
      log.ERROR("All the service vm ips cannot be mapped to service vm ids, "
                "svm_ips %r, svm_ids %r" % (svm_ips, svm_ids))
      return False

  if FLAGS.vcenter_json_file:
    try:
      # If Vcenter params are passed as json file, read from it.
      with open(FLAGS.vcenter_json_file) as fd:
        vcenter_details = simplejson.load(fd)
    except IOError as ee:
      log.FATAL("IO Exception seen during reading %s, err %s" %
                (FLAGS.vcenter_json_file, ee))
  else:
    ip, user, password = prompt_mgmt_server_details(
        host_type=ConfigurationProto.ManagementServer.kVMware)
    vcenter_details = {"host": ip, "username": user, "password": password}

  hyp_name = FLAGS.target_hypervisor
  ret = genesis_utils.call_genesis_method(
      ["127.0.0.1"], ClusterConversion.validate_cluster_conversion,
      (hyp_name, vcenter_details, svm_ids,),
      rpc_timeout_secs=-1)

  ret, warnings, errors = conversion_utils.check_convert_cluster_status(
      "validate_cluster_conversion", deadline=-1)
  log.CHECK(ret is not None)
  if ret == Task.kFailed:
    log.ERROR("Validate cluster conversion failed:\nWARNINGS:\n%s\n"
              "ERRORS:\n%s" % ("\n".join(warnings), "\n".join(errors)))
    return False
  log.INFO("Validate cluster conversion succeeded, warnings %s" % warnings)

  ret = genesis_utils.call_genesis_method(
      ["127.0.0.1"], ClusterConversion.start_cluster_conversion,
      (hyp_name, FLAGS.ignore_vm_conversion_warnings,), rpc_timeout_secs=-1)
  if isinstance(ret, RpcError):
    log.FATAL("Rpc to local genesis failed %s" % ret)
  ret, warnings, errors = conversion_utils.check_convert_cluster_status(
      "start_cluster_conversion", deadline=-1)
  log.CHECK(ret is not None)
  if ret == Task.kFailed:
    log.ERROR("Start cluster conversion failed:\nWARNINGS:\n%s\n"
              "ERRORS:\n%s" % ("\n".join(warnings), "\n".join(errors)))
    return False
  log.INFO("Cluster conversion started, warnings %s" % warnings)
  return ret

def do_host_upgrade():
  # Set the target host type to be current node host type.
  target_hypvsr_type = host_upgrade_common.get_host_type()
  target_hypvsr_name = host_upgrade_common.get_hypervisor_name_from_type(
                           target_hypvsr_type)

  # Check if bundle path exists.
  if not os.path.exists(FLAGS.bundle):
    log.ERROR("Bundle not found. Please ensure that %s location is correct"
              % FLAGS.bundle)
    return False

  if genesis_utils.is_mixed_hypervisor_cluster():
    if not FLAGS.hypervisor:
      prompt = ("Cluster has mixed hypervisor nodes. You can provide the "
                "--hypervisor flag to specify the hypervisor to upgrade. "
                "Since, the flag is not provided, hosts with hypervisor of"
                "current node's hypervisor type: %s will be upgraded. Do you "
                "want to proceed? (Y/[N]):" %
                target_hypvsr_name)
      while True:
        confirmation = raw_input(prompt)
        if not confirmation or confirmation.upper() in ["N", "NO"]:
          # Default value is no.
          log.INFO("Upgrade request cancelled by user")
          return False
        if confirmation.upper() in ["Y", "YES"]:
          break
        # If we reach here the input is invalid.
        print "Please enter a valid input"
    else:
      # Convert hypservisor string to enum.
      target_hypvsr_type = host_upgrade_common.get_hypervisor_type_from_name(
                               FLAGS.hypervisor)
      if target_hypvsr_type is None:
        log.ERROR("Please provide a valid hypervisor type. Provided: %s, "
                  "Allowed: %s" % (FLAGS.hypervisor, "esx, kvm or hyperv"))
        return False
      target_hypvsr_name = FLAGS.hypervisor

  if target_hypvsr_name == "esx":
    # In case of Esx, we require details of management entity like
    # Vcenter for HA/DRS.
    if not FLAGS.vcenter_not_required:
      set_mgmt_server_details(
          host_type=ConfigurationProto.ManagementServer.kVMware)
    confirm_md5sum()

  if target_hypvsr_name == "hyperv":
    set_post_upgrade_params()

  log.INFO("Performing Host upgrade with params: version %s bundle %s "
           "chksum %s preupgrade %s manual upgrade %s hypervisor %s"
            % (FLAGS.version, FLAGS.bundle, FLAGS.md5sum,
            not FLAGS.ignore_preupgrade_tests, FLAGS.manual_upgrade,
            target_hypvsr_name))

  svm_id = genesis_utils.get_svm_id()
  ret = host_upgrade_helper.translate_upgrade_info_to_params(
      FLAGS.bundle, FLAGS.version, FLAGS.md5sum, svm_id,
      not FLAGS.ignore_preupgrade_tests, FLAGS.manual_upgrade,
      FLAGS.skip_upgrade, target_hypvsr_type)
  log.DEBUG("Host upgrade params commit status: %s" % ret)
  return ret

def do_foundation_upgrade(svm_ips):
  """
  Upgrade foundation.
  Input : Foundation tar.gz file (-i flag)
  """
  # Upload foundation pacakge on cluster.
  filepath = FLAGS.installer_dir_path
  if not filepath:
    log.ERROR("Foundation upgrade needs package path, use -i and provide "
              "package path")
    return False

  if not os.path.isabs(filepath):
    filepath = os.path.abspath(filepath)

  if not foundation_upgrade_helper.update_package_zk(filepath):
    log.ERROR("Failed to upload package %s" % filepath)
    return False

  md5sum = genesis_utils.calculate_md5sum(filepath)
  if not md5sum:
    log.ERROR("Failed to calculate md5sum of %s" % filepath)
    return False

  # Trigger upgrade.
  ret = genesis_utils.call_genesis_method(svm_ips,
                                          ClusterManager.foundation_upgrade,
                                          (md5sum,
                                           FLAGS.ignore_preupgrade_tests,
                                           FLAGS.skip_upgrade))
  if isinstance(ret, RpcError):
    log.ERROR("Failed to start foundation upgrade on cluster")
    return False
  return True

def do_upgrade(svm_ips):
  # Check installer_dir_path, if given, to ensure correct architecture.
  if FLAGS.installer_dir_path:
    log.CHECK(genesis_utils.verify_installer_architecture(
              FLAGS.installer_dir_path),
              "Build architecture does not match system architecture.")
  return __install_and_upgrade(svm_ips, manual_upgrade=FLAGS.manual_upgrade)

def do_lite_upgrade(svm_ips):
  """Lite Upgrade entry point.

  Note: all commands are passed svm ips. Lite upgrade will not use them, so we
  ignore from the beginning

  1. Basic validation that we are running for correct (new) bits.
  2. Trigger lite upgrade in cluster_upgrade module
  3. If triggered successfully, clean up unused directories.

  Status can be viewed using progress monitor in UI or upgrade_status command.

  Returns:
    True on success, False otherwise.
  """
  # Ensure there is an installer dir and we are running from it
  if not FLAGS.installer_dir_path:
    log.ERROR("Please provide an installer directory with the -i flag")
    return False
  if not os.path.isdir(FLAGS.installer_dir_path):
    log.ERROR("Installer directory %s does not exist" %
              FLAGS.installer_dir_path)
    return False
  cluster_script_path = os.path.abspath(__file__)
  installer_dir_path = os.path.abspath(FLAGS.installer_dir_path)
  if (os.path.commonprefix([cluster_script_path, installer_dir_path]) !=
      installer_dir_path):
    log.ERROR("Please run cluster script present in %s/bin" %
              installer_dir_path)
    return False

  # Log that users will have to reset password.
  proto = genesis_utils.get_cached_zeus_configuration()
  if (proto and proto.cluster_functions & ConfigurationProto.kWitnessVM and
      admin_user_present_in_zk()):
    print("After upgrade is complete, credentials for this cluster will "
          "be changed to default. Please refer upgrade document for more "
          "details.")

  # Perform upgrade tasks based on flags specified.
  if not cluster_upgrade.perform_lite_upgrade(FLAGS.installer_dir_path,
                                              FLAGS.no_verification,
                                              FLAGS.verification_file,
                                              FLAGS.ignore_preupgrade_tests,
                                              FLAGS.skip_upgrade):
    log.ERROR("Failed to perform lite upgrade.")
    return False

  # Cleanup install directory on successful start.
  if FLAGS.remove_installer_dir and not FLAGS.skip_upgrade:
    current_dir = os.getcwd()
    full_installer_path = os.path.abspath(
      os.path.expanduser(FLAGS.installer_dir_path))
    log.INFO("Removing installer directory '%s' from CVM" % full_installer_path)
    shutil.rmtree(full_installer_path)
    if genesis_utils.is_subdir(child=current_dir, parent=full_installer_path):
      log.INFO("CWD is stale, please change CWD "
               "before executing any further commands on this shell.")
  return True

def do_pass_shutdown_token(svm_ips, node_ip):
  ret = genesis_utils.call_genesis_method(svm_ips, ClusterManager.svm_ips)
  if isinstance(ret, RpcError):
    log.FATAL("Failed to get IPs of nodes in cluster")
  if not ret:
    log.FATAL("Cluster is not configured")
  if node_ip not in ret:
    log.FATAL("Given IP is not part of cluster")

  workflow = "nos_upgrade"
  if FLAGS.host_upgrade:
    workflow = "host_upgrade"
  log.INFO("Passing shutdown token to node with ip %s for %s" % (node_ip,
                                                                 workflow))

  if not genesis_utils.call_genesis_method(
      svm_ips, ClusterManager.set_shutdown_token, (node_ip, workflow)):
    log.ERROR("Failed to pass shutdown token to node %s" % node_ip)
    return False
  return True

def get_disable_upgrade_marker_file_name():
  """
  Returns disable upgrade file name as per context.
  """
  if FLAGS.foundation_upgrade:
    return FLAGS.foundation_disable_auto_upgrade_marker
  else:
    return FLAGS.node_disable_auto_upgrade_marker

def do_disable_auto_install(svm_ips):
  # Write marker need to tell Genesis not to automatically
  # revert back to old version.

  if FLAGS.host_upgrade:
    ret = True
    svm_ids = genesis_utils.get_svm_ids()
    for id in svm_ids:
      if not host_upgrade_helper.disable_host_upgrade_on_node(id):
        log.ERROR("Unable to create disable marker on %s" % id)
        ret = False
    return ret

  filename = get_disable_upgrade_marker_file_name()

  cmd_map = dict((ip, "touch %s" % filename) for ip in svm_ips)

  for ip, (ret, out, err) in (
      genesis_utils.run_command_on_svms(cmd_map).iteritems()):
    if ret != 0:
      log.FATAL("Could not create %s on SVM %s." %
                (FLAGS.node_disable_auto_upgrade_marker, ip))
  return True

def do_enable_auto_install(svm_ips):
  # Write marker need to tell Genesis not to automatically
  # revert back to old version.
  if FLAGS.host_upgrade:
    ret = True
    svm_ids = genesis_utils.get_svm_ids()
    for id in svm_ids:
      if not host_upgrade_helper.enable_host_upgrade_on_node(id):
        log.ERROR("Unable to create disable marker on %s" % id)
        ret = False
    return ret

  filename = get_disable_upgrade_marker_file_name()

  cmd_map = dict((ip, "rm -f %s" % filename) for ip in svm_ips)
  for ip, (ret, out, err) in (
       genesis_utils.run_command_on_svms(cmd_map).iteritems()):
    if ret != 0:
      log.FATAL("Could not remove %s on SVM %s." %
                (FLAGS.node_disable_auto_upgrade_marker, ip))
  return True

def compute_zk_fault_tolerance(zknodelist):
  """
  Based on the current placement of Zookeeper servers on racks,
  computes the maximum number of rack failures the cluster can tolerate.
  """
  ru_to_zk_instances_map = dict()
  num_zk_instances_total = len(zknodelist)
  max_fault_tolerance_rack = 0
  for node in zknodelist:
    if node.HasField("rackable_unit_id"):
      ru_to_zk_instances_map[node.rackable_unit_id] = (
          ru_to_zk_instances_map.get(node.rackable_unit_id, 0) + 1)

  # Sort the zk instances per rackable unit in non increasing order.
  num_zk_instances_per_ru_list = ru_to_zk_instances_map.values()
  num_zk_instances_per_ru_list.sort(reverse=True)

  # Quorum requirement for Zookeeper is always n/2 + 1, where n is the
  # number of Zookeeper instances running on the cluster.
  min_zk_instances_for_quorum = (num_zk_instances_total / 2) + 1

  num_zk_failures = 0
  for num_zk_instances_per_ru in num_zk_instances_per_ru_list:
    num_zk_failures += num_zk_instances_per_ru
    if (num_zk_instances_total - num_zk_failures <
        min_zk_instances_for_quorum):
      break
    max_fault_tolerance_rack += 1

  return max_fault_tolerance_rack

def determine_migration_target(ru_to_zk_instances_map, ru_to_non_zk_nodes):
  """
  This method determines the target node where the zookeeper server can be
  migrated to without compromising block fault tolerance of cluster.
  """
  new_zk_node = None
  # Sort ru_to_zk_instances_map to get a list of tuples
  # (rack,num_zk_instances_on_the_rack). Then iterate the list to find
  # the ideal node which can be used as a migration target.
  sorted_ru_zk_instances_list = sorted(ru_to_zk_instances_map.iteritems(),
                                       key=lambda key_value: key_value[1])
  for i in range(0, len(sorted_ru_zk_instances_list)):
    min_rack_zk_instances_tuple = sorted_ru_zk_instances_list[i]
    next_rack_with_min_zk_instances = min_rack_zk_instances_tuple[0]

    # Now pick up a node from the rack which contains no zk instances.
    if next_rack_with_min_zk_instances in ru_to_non_zk_nodes.keys():
      non_zk_node_list = ru_to_non_zk_nodes[next_rack_with_min_zk_instances]
      # Pick the first node which does not have any zk instance.
      new_zk_node = non_zk_node_list[0]
      break

  return new_zk_node

def do_migrate_zookeeper(svm_ips):
  log.ERROR("Action not supported. Zookeeper only supports auto migration.")
  return False

def do_remove_all_public_keys(svm_ips):
  """
  Removes all external ssh keys effectively locks down cluster.
  Returns True on success, False otherwise.
  """
  result = False
  external_ssh_keyid_list = genesis_utils.call_genesis_method(
      svm_ips, ClusterManager.get_external_ssh_keyid_list)
  if external_ssh_keyid_list is None:
    log.ERROR("Failed to get the list of external ssh keys")
    return False
  else:
    result = genesis_utils.call_genesis_method(
        svm_ips, ClusterManager.remove_external_ssh_keys,
        (external_ssh_keyid_list,))
    if not result:
      log.ERROR("Failed to remove all ssh keys")
      return False
    log.INFO("Successfully removed all ssh keys")
    return True

def do_remove_public_key(svm_ips):
  """
  Removes an external ssh key.
  Returns True on success, False otherwise.
  """
  result = False
  key_list = []
  if not FLAGS.key_name:
    log.ERROR("Please provide a valid key name")
    return False

  key_list.append(FLAGS.key_name)
  result = genesis_utils.call_genesis_method(
      svm_ips, ClusterManager.remove_external_ssh_keys, (key_list,))
  if not result:
    log.ERROR("Failed to remove ssh key %s" % FLAGS.key_name)
    return False
  log.INFO("Successfully removed ssh key %s" % FLAGS.key_name)
  return True

def do_add_public_key(svm_ips):
  """
  Adds ssh key, effectively disables lock down.
  Returns True on success, False otherwise.
  """
  result = False
  if not (FLAGS.key_name and FLAGS.key_file):
    log.ERROR("Please provide valid key name and key file.")
    return False

  pub_ssh_key = sshkeys_helper.read_ssh_key(FLAGS.key_file)
  if not pub_ssh_key:
    log.ERROR("Failed to read key file %s" % FLAGS.key_file)
    return False

  ssl_cert = ""
  result = genesis_utils.call_genesis_method(
      svm_ips, ClusterManager.add_external_ssh_key,
      (FLAGS.key_name, pub_ssh_key, ssl_cert,))
  if not result:
    log.ERROR("Failed to add ssh key %s" % FLAGS.key_name)
    return False
  else:
    log.INFO("Successfully added ssh key %s" % FLAGS.key_name)
    return True

def do_upgrade_node(svm_ips):
  """
  Upgrade node with ip=FLAGS.upgrade_node_ip to cluster's current version.
  """
  if not FLAGS.upgrade_node_ip:
    log.ERROR("Please specify node's ip using --upgrade_node_ip/-u option")
    return False

  if LINK_LOCAL_RE.match(FLAGS.upgrade_node_ip):
    node_ip = FLAGS.upgrade_node_ip + "%eth0"
  elif IPv4Config.is_valid_address(FLAGS.upgrade_node_ip):
    node_ip = FLAGS.upgrade_node_ip
  else:
    log.ERROR("Invalid IP address provided")

  ret = genesis_utils.call_genesis_method(
      [FLAGS.upgrade_node_ip], NodeManager.configured)
  if isinstance(ret, RpcError):
    log.FATAL("Could not reach IP: %s" % FLAGS.upgrade_node_ip)
  if ret:
    log.FATAL("Node with ip=%s is already part of cluster." %
              FLAGS.upgrade_node_ip)

  ssh_key = FLAGS.nutanix_default_ssh_key

  ssh_client = SSHClient(node_ip, FLAGS.svm_login, private_key=ssh_key)
  if not ssh_client:
    log.ERROR("Failed to set up ssh connection with %s" % node_ip)
    return False

  result = genesis_utils.call_genesis_method(
      svm_ips, ClusterManager.software_versions)

  if not result or isinstance(result, RpcError):
    log.ERROR("Failed to get cluster software version")
    return False

  nutanix_release_version = result["nutanix_release_version"]

  ret, out, err = ssh_client.execute("sudo cat %s" % FLAGS.release_version_path)
  if ret != 0:
    log.ERROR("Failed to get software version from node %s with %s."
              % (node_ip, ret))
    return False

  if out.strip() == nutanix_release_version:
    log.INFO("Node has same software version as that of cluster,"
             " skipping upgrade ..")
    return True

  if not new_node_upgrade.transfer_package_to_node(ssh_client,
                                                   nutanix_release_version,
                                                   node_ip):
    log.ERROR("Failed to transfer package to %s" % node_ip)
    return False

  if not new_node_upgrade.install_genesis_on_standalone_node(node_ip,
                                                        nutanix_release_version,
                                                        ssh_client):
    log.ERROR("Failed to install new genesis to %s" % node_ip)
    return False

  if not new_node_upgrade.install_package_on_node(ssh_key,
                                                  nutanix_release_version,
                                                  node_ip):
    log.ERROR("Failed to install package on %s" % node_ip)
    return False

  if not new_node_upgrade.finish_install_package_on_node(
      ssh_client, nutanix_release_version, node_ip):
    log.ERROR("Failed to finish install package on %s" % node_ip)
    return False

  if not new_node_upgrade.reboot_node(ssh_client, node_ip):
    log.FATAL("Failed to reboot node %s" % node_ip)
  log.INFO("Node %s has been upgraded to %s" %
           (node_ip, nutanix_release_version))
  return True

def confirm_md5sum():
  """
  Confirm from user that md5sum provided for bundle is picked from VMware site.
  """
  ret = genesis_utils.call_genesis_method(["127.0.0.1"],
                                          ClusterManager.cluster_name)
  if isinstance(ret, RpcError):
    log.FATAL("Could not reach local svm ip, Error: %s" % ret)

  prompt_str = """
SUMMARY:
Upgrading Cluster {name} : VMware Host Hypervisor Upgrade
Upgrade Bundle: {bundle}
User Supplied md5sum: {checksum}

Note: This md5sum should come from VMware's download page and not be user
      generated. Using user generated md5sum of the upgrade file after
      downloading the upgrade file may introduce a corrupted file.

Press Y to acknowledge this is a VMware supplied md5sum: """.format(
    name=ret, bundle=FLAGS.bundle, checksum=FLAGS.md5sum)
  confirmation = raw_input(prompt_str)
  if not confirmation or confirmation.upper() not in ["Y", "YES"]:
    log.INFO("Not continuing with hypervisor upgrade")
    sys.exit(0)
  return

def get_backplane_svm_ips():
  """
  Get list of cluster backplane CVM IPs from zookeeper. If that fails, read
  from cached zeus config in genesis.
  """
  host_port_list = genesis_utils.get_zk_host_port_list()
  if not host_port_list:
    return None
  config_proto = None
  config = Configuration().initialize(host_port_list)
  if config:
    config_proto = config.config_proto()
  return genesis_utils.get_svm_ips(config_proto=config_proto, backplane=True)

def prompt_mgmt_server_details(host_type=None):
  """
  Prompt for details of managemenet server like Vcenter and return them.
  """
  def prompt_mgmt_server():
    """
    Prompt for mgmt server details.
    """
    prompt = "Please enter Vcenter details:\nIP address of Vcenter: "
    ip = raw_input(prompt)
    prompt = "Username: "
    user = raw_input(prompt)
    password = getpass.getpass()
    return (ip, user, password)

  mgmt_json = host_upgrade_common.get_zk_host_management_server(
      host_type=host_type)
  if mgmt_json:
    prompt = ("Vcenter details for ip %s exists, Reuse it? ([Y]/N): " %
              mgmt_json["ip"])
    while True:
      confirm = raw_input(prompt)
      if not confirm or confirm.lower() in ["y", "yes"]:
        log.DEBUG("Reuse existing vcenter details")
        return mgmt_json["ip"], mgmt_json["user"], mgmt_json["password"]
      elif confirm.lower() in ["n", "no"]:
        log.INFO("Ask for for management server details")
        ip, user, password = prompt_mgmt_server()
        break
  else:
    ip, user, password = prompt_mgmt_server()
  return ip, user, password

def set_mgmt_server_details(host_type=None):
  """
  In case of host upgrade, management server details needs to
  be provided. Prompt for details of management server and save details in
  zookeeper.
  """
  ip, user, password = prompt_mgmt_server_details(host_type=host_type)
  host_upgrade_helper.set_zk_host_management_server(ip, user, password,
                                                    host_type=host_type)
  return True

def set_post_upgrade_params():
  """
  For hyperv-host upgrade, domain credentials and sku are needed.
  This function sets flags for username, password and sku.
  """
  # Checking domain username format.
  username = FLAGS.domain_username.split("\\")
  if len(username) == 1:
    log.ERROR("Please check domain username format")
    return False

  if not host_upgrade_helper.set_zk_host_post_upgrade_params(
      FLAGS.domain_username, FLAGS.domain_password,
      FLAGS.hyperv_sku, False, FLAGS.md5sum):
    log.ERROR("Failed to set HyperV post upgrade parameters")
    return False

def do_set_two_node_leader():
  """
  Manually set the current node as the leader node in a two node cluster.
  """
  ret = genesis_utils.call_genesis_method(["localhost"],
    TwoNodeClusterManager.set_two_node_leader)
  if isinstance(ret, RpcError):
    log.FATAL("Could not reach local ClusterManager, Error: %s" % ret)
    return False
  if not ret:
    log.INFO("Failed to select this node as leader. Try again later")
    return False
  log.INFO("This node is now the leader")
  return True

# Only create, ipconfig require external svm ips.
# upgrade_node does not require a svm ip belonging to current cluster.
# All the rest of commands can work over backplane svm ips.
# When adding a new command to this map, make sure it works in
# backplane network on a segmented mode.
commands = {
  'create': do_config,
  'destroy': do_unconfig,
  'reconfig': do_reconfig,
  'reset': do_reset,
  'migrate_zeus': do_migrate_zookeeper,
  'start': do_start,
  'stop': do_stop,
  'status': do_status,
  'restart_genesis': do_restart_genesis,
  'upgrade': do_upgrade,
  'lite_upgrade': do_lite_upgrade,
  'pass_shutdown_token': do_pass_shutdown_token,
  'disable_auto_install': do_disable_auto_install,
  'enable_auto_install':  do_enable_auto_install,
  'ipconfig': do_ipconfig,
  'add_public_key': do_add_public_key,
  'remove_public_key': do_remove_public_key,
  'remove_all_public_keys': do_remove_all_public_keys,
  'upgrade_node': do_upgrade_node,
  'host_upgrade': do_host_upgrade,
  'convert_cluster': do_convert_cluster,
  'foundation_upgrade': do_foundation_upgrade,
  'set_two_node_cluster_leader': do_set_two_node_leader,
}

if not FLAGS.enable_lite_upgrade:
  commands.pop("lite_upgrade", None)

def main(args, commands):
  try:
    args = FLAGS(sys.argv)
  except gflags.FlagsError, e:
    sys.stderr.write("%s\n" % str(e))
    FLAGS([sys.argv[0], "--helpshort"])
    sys.exit(1)

  if len(args) < 2 or args[1] not in commands:
    FLAGS([sys.argv[0], "--helpshort"])
    sys.exit(1)

  # If we are doing any operations where we need to SSH, then we need to make
  # sure that the SSH private key exists.
  ssh_key = get_default_ssh_key()

  if (args[1] in ["destroy", "reconfig", "restart_genesis"] and
      not os.path.exists(ssh_key)):
    if ssh_key:
      log.FATAL("SSH private key %s does not exist, please check the path to "
                "the SSH private key and retry." % ssh_key)
    else:
      log.FATAL("Operation %s requires an SSH private key, please specify a "
                "key with the -k option" % args[1])

  if FLAGS.svm_ips and FLAGS.config:
    log.FATAL("Do not specify both -s/--svm_ips and -c/--config options")

  if FLAGS.svm_ips and FLAGS.ip_specification_json:
    log.FATAL("Do not specify both -s/--svm_ips and "
              "-j/--ip_specification_json option")

  if not FLAGS.svm_ips:
    svm_ips = ["localhost"]
  else:
    svm_ips = FLAGS.svm_ips.split(",")
    # Check if there are any invalid IPv4 addresses in the SVM IPs list.
    invalid_ips = filter(lambda ip: not IPv4Config.is_valid_address(ip),
                         svm_ips)
    if invalid_ips:
      log.FATAL("Invalid IPv4 addresses %s" % invalid_ips)

  if FLAGS.cluster_external_ip and FLAGS.ip_specification_json:
    log.FATAL("Do not specify both --cluster_external_ip and "
              "-j/--ip_specification_json option")

  if FLAGS.cluster_external_ip:
    if not IPv4Config.is_valid_address(FLAGS.cluster_external_ip):
      log.FATAL("Invalid Cluster external ip %s" %
                FLAGS.cluster_external_ip)

  if FLAGS.config:
    if not os.path.isfile(FLAGS.config):
      log.FATAL("cluster.cfg file %s does not exist" % FLAGS.config)

    # Read the cluster cfg file and get IPs.
    cc = ClusterConfig().load(FLAGS.config)
    if not cc:
      log.FATAL("Failed to load cluster.cfg: %s" % FLAGS.config)
    svm_ips = get_svm_ips(cc)
    FLAGS.cluster_name = cc["cluster"]["cluster_name"]

  if len(svm_ips) != len(set(svm_ips)):
    log.WARNING("List of SVM IPs contains duplicates: %s" % svm_ips)

  cmd = args[1].lower()

  # If we are not forcing, then perform the action on every node in the
  # cluster.
  # This is a list of commands which can only be called on an
  # unconfigured node.
  cmds_only_for_unconfigured_node = ["create", "ipconfig",
                                     "set_two_node_cluster_leader"]
  if cmd not in cmds_only_for_unconfigured_node:
    ret = genesis_utils.call_genesis_method(svm_ips, NodeManager.configured)
    if isinstance(ret, RpcError):
      log.FATAL("Could not reach any of the SVM IPs : %r" % svm_ips)
    if not ret:
      # 'cmd' is not supposed to be called on an unconfigured node.
      # FATAL out with appropriate message.
      ret = genesis_utils.call_genesis_method(
          svm_ips, NodeManager.in_reconfiguration)
      if ret:
        log.FATAL("Cluster is currently in the process of being reconfigured. "
                  "Please finish reconfiguring the cluster.")
      else:
        log.FATAL("Cluster is currently unconfigured. Please create the "
                  "cluster.")
    ret = get_backplane_svm_ips()
    if ret:
      svm_ips = ret
    else:
      log.WARNING("Could not read SVM backplane IPs from zk")
  elif "localhost" in svm_ips:
    log.WARNING("Executing operation %s on localhost" % cmd)

  if cmd == "set_two_node_cluster_leader":
    log.INFO("Executing action only on localhost")
  else:
    log.INFO("Executing action %s on SVMs %s" % (cmd, ",".join(svm_ips)))
  if cmd in ["destroy", "stop", "reconfig", "reset"]:
    # Print the cluster name.
    ret = genesis_utils.call_genesis_method(
                       svm_ips, ClusterManager.cluster_name)
    if isinstance(ret, RpcError):
      log.FATAL("Could not reach any of the SVM IPs : %r. Error: %s" %
                (svm_ips, ret))
    cluster_name = ret or "Not configured"
    log.INFO("\n\n***** CLUSTER NAME *****\n%s\n" % cluster_name)
    if cmd == "destroy":
      prompt = ("This operation will completely erase all data and all "
                "metadata, and each node will no longer belong to a "
                "cluster. Do you want to proceed? (Y/[N]): ")
    elif cmd == "stop":
      prompt = ("This operation will stop the Nutanix storage services and any "
                "VMs using Nutanix storage will become unavailable. Do you "
                "want to proceed? (Y/[N]): ")
    elif cmd == "reset":
      prompt = ("This operation will COMPLETELY ERASE ALL DATA and ALL "
                "METADATA, and each node will no longer belong to a "
                "cluster and REIMAGE each node. Do you want to proceed?"
                " (Y/[N]): ")
    else:
      # Command is reconfig.
      prompt = ("After executing this operation any VMs using Nutanix storage "
                "will become unavailable. Do you want to proceed? (Y/[N]): ")

    # Check if the command is excuted from a terminal. Piping for destructive
    # operations, eg: "$ echo y | cluster destroy" is not allowed. The stop cmd
    # allows piping for automation purpose as it is not destructive.
    if cmd != "stop" and not True:
      log.ERROR("Destructive operations like %s should get the confirmation "
                "(Y/[N]) from terminal. Seems like the confirmation is piped "
                "or redirected from another process into this command." % cmd)
      sys.exit(1)

    while True:
      confirmation = raw_input(prompt)
      if not confirmation or confirmation.upper() in ["N", "NO"]:
        # Default value is no.
        # Do not continue and exit.
        log.INFO("User requested cancel of cmd %s." % cmd)
        sys.exit(0)
      if confirmation.upper() in ["Y", "YES"]:
        if cmd != "reset":
          break
        else:
          # ask second question for reset to avoid accident wipe out
          prompt = "Please enter a CVM's IP, which WOULD BE RESET: "
          confirmation = raw_input(prompt)
          if not confirmation:
            log.INFO("User cancel of cmd %s." % cmd)
            sys.exit(0)
          svmips = genesis_utils.get_svm_ips()
          if confirmation in svmips:
            break
          else:
            log.INFO("%s does not match any CVM's IP." % confirmation)
            sys.exit(0)

      # If we reach here the input is invalid.
      print "Please enter a valid input."

  if cmd == "start":
    if len(args) > 2:
      log.FATAL("cluster start takes no arguments")
    ret = commands["start"](svm_ips)
  elif cmd == "stop":
    if len(args) > 2:
      log.FATAL("cluster stop takes no arguments")
    ret = commands["stop"](svm_ips)
  elif cmd == "ipconfig":
    ret = commands[cmd]()
  elif (cmd == "create" and FLAGS.ip_specification_json):
    svm_ips = get_svm_ips_json()
    if len(svm_ips) < 3:
      log.FATAL("Provide IPs of at least 3 nodes")
    ret = do_ipconfig()
    if ret:
      ret = commands[cmd](svm_ips=svm_ips,
                          cluster_external_ip=get_cluster_external_ip_json())
  elif cmd == "pass_shutdown_token":
    if not FLAGS.shutdown_token_ip:
      log.FATAL("Please provide IP address of svm")
    else:
      if len(FLAGS.shutdown_token_ip.split(",")) != 1:
        log.FATAL("Please provide only one svm ip for passing shutdown token")
    ret = commands[cmd](svm_ips=svm_ips, node_ip=FLAGS.shutdown_token_ip)
  elif cmd == "host_upgrade":
    if not FLAGS.bundle or not FLAGS.md5sum:
      log.FATAL("Provide provide bundle location, md5sum for host upgrade")
    if not FLAGS.version:
      if (host_upgrade_common.get_host_type() !=
          ConfigurationProto.ManagementServer.kVMware):
        log.FATAL("Provide version information for host upgrade")
      else:
        FLAGS.version = ""
    ret = commands[cmd]()
  elif cmd == "convert_cluster":
    if not FLAGS.target_hypervisor:
      log.FATAL("Provide target hypervisor type")
    ret = commands[cmd]()
  elif cmd == "set_two_node_cluster_leader":
    ret = commands[cmd]()
  else:
    if cmd == "create":
      ret = commands[cmd](svm_ips=svm_ips,
                          cluster_external_ip=FLAGS.cluster_external_ip)
    else:
      ret = commands[cmd](svm_ips=svm_ips)

  if ret:
    log.INFO("Success!")
    sys.exit(0)
  log.ERROR("Operation failed")
  sys.exit(1)

if __name__ == "__main__":
  try:
    if "--help" in sys.argv:
      sys.argv.insert(1, "--helpshort")
    elif "--helpfull" in sys.argv:
      sys.argv.insert(1, "--help")

    global __doc__
    __doc__ = ("Usage: %s [flags] [command]\n\n"
               "commands:\n\n"
               "\t%s\n" %
               (sys.argv[0], "\n\t".join(sorted(commands.keys()))))
    args = FLAGS(sys.argv)

    FLAGS.logtostderr = True
    log.initialize()

    main(args, commands)
  except gflags.FlagsError, e:
    sys.stderr.write("%s\n" % str(e))
    FLAGS([sys.argv[0], "--helpshort"])
    sys.exit(1)
  except KeyboardInterrupt:
    log.WARNING("Exiting on Ctrl-C")
    sys.exit(1)
  except Exception as e:
    log.ERROR("Failed to execute action %s. Error(%s), "
              "Traceback:\n%s\nExiting..." %
              (args[1], str(e), traceback.format_exc()))
    sys.exit(1)
