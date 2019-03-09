"""
VM IO integrity test library functions.

This file contains all library functions which are used in VM IO integrity
tests.

Copyright (c) 2019 Nutanix Inc. All rights reserved.
Author: arun.kumar@nutanix.com
"""

# pylint: disable=too-many-locals
# pylint: disable = unused-argument

import signal
import sys
import time

from framework.lib.nulog import INFO, STEP, ERROR
from framework.exceptions.nutest_error import NuTestError
from workflows.async_dr import async_dr_library
from workflows.cbt import cbt_utils_lib as cbt_utils
from workflows.async_dr.dr_util_lib import is_accessible
from workflows.async_dr.async_dr_workflow import DRWorkflows
from workflows.error_injection.error_injection_manager import \
  ErrorInjectionManager

def get_prev_snap_id(pd, snap_id):
  """
    This methods returns the id of snapshot taken before snap_id.

    Args:
      pd(ProtectionDomain obj): Protection domain using which the snapshots
        were created.
      snap_id(string): snapshot id of snapshot whose previous snapshot needs
        to be found.

    Returns: Snapshot id of the previous snapshot. Returns None if no
      previous snapshot is found.
  """
  current_snap_id_list = [snap_json["snapshotId"]
                          for snap_json in pd.ls_snaps()]
  num_snapshots = len(current_snap_id_list)
  if num_snapshots <= 1:
    return None
  for index in range(num_snapshots-1):
    if current_snap_id_list[index] == snap_id:
      return current_snap_id_list[index+1]
  return None

def attach_gold_vdisk_to_vms(vms, uvm_disk_file_map, vm_name_prefix,
                             delete_existing_disks=True):
  """
    This method is used to attach gold NFS vidisks to restored UVMs.

    Args:
      vms(VM obj list): List of restored vm objects to which the disks need to
        be attached.
      uvm_disk_file_map(dict): dictionary object which maps UVM name to list of
        corresponding gold NFS vdisk files.
      vm_name_prefix(string): prefix of restored VM names.
      delete_existing_disks(bool): flag for deleting the existing vdisks of UVM.
        Default is True.

    Returns: None
  """
  for vm in vms:
    INFO("Attaching gold disks to UVM: {}".format(vm.get()))
    orig_vm_name = vm.name[len(vm_name_prefix):]
    num_vdisks = len(uvm_disk_file_map[orig_vm_name])
    if delete_existing_disks:
      for index in range(1, num_vdisks+1):
        vm.delete_disk("scsi", index)
    for index in range(num_vdisks):
      vm.add_disk(clone_from_adsf_file=uvm_disk_file_map[orig_vm_name][index])

def create_gold_vdisk_for_uvm(cluster, container, uvms):
  """
    This methods creates gold NFS vdisk for each vdisk of the UVM and then
      creates mapping between the uvm name and the gold vdisks.

    Args:
      cluster(NOCCluster obj): cluster object on which UVMs created.
      container(Container obj): container on which the gold vdisks will be
        created.
      uvms(list of VM objects): lists of UVMs for which the mapping will be
        created.

    Returns: dictionary object which maps UVM name to list of
        corresponding gold NFS vdisk files. for eg.
        {
          uvm_1_name : [<gold vdisk1 of uvm_1>, <gold vdisk2 of uvm_1>, ...],
          uvm_2_name : [<gold vdisk1 of uvm_2>, <gold vdisk2 of uvm_2>, ...],,
          ...
        }
  """
  uvm_gold_file_map = {}
  for uvm in uvms:
    uvm_info = uvm.get()
    uvm_name = uvm.name
    uvm_gold_file_map[uvm_name] = []
    disks = uvm_info["config"]["disk_list"][1:]
    for disk in disks:
      vdisk_uuid = disk["vmdisk_uuid"]
      disk_file_path = "/{}/.acropolis/vmdisk/{}".format(container.name,
                                                         vdisk_uuid)
      gold_disk_path = "/{}/vm-{}-vdisk-{}".format(container.name,
                                                   uvm.name, vdisk_uuid)
      cbt_utils.copy_vdisk(cluster, disk_file_path, gold_disk_path)
      uvm_gold_file_map[uvm_name].append(gold_disk_path)
  INFO("UVM to gold vdisk map:\n{}".format(uvm_gold_file_map))
  return uvm_gold_file_map

def delete_older_snapshot(pd, max_snapshot_depth):
  """
    Deletes older snapshots of the PD. If the pd has more than given number of
      snapshots X, then all the snapshots other than latest X snapshots are
      deleted.

    Args:
      pd(ProtectionDomain obj): ProtectionDomain whose snapshots are to be
        deleted.
      max_snapshot_depth(int): maximum number of snapshots that should be
        available for the pd.

    Returns: None
  """
  if max_snapshot_depth == -1:
    INFO("Skipping deleting of snapshots as max_snapshot_depth is -1")
    return
  curr_snap_ids = [snap_json["snapshotId"] for snap_json in pd.ls_snaps()]
  num_snaps = len(curr_snap_ids)
  if num_snaps > max_snapshot_depth:
    INFO("Number of current live snapshots {} is more than {}".format(
      num_snaps, max_snapshot_depth))
    num_snaps_to_delete = num_snaps - max_snapshot_depth
    INFO("Deleting {} snapshots".format(num_snaps_to_delete))
    for index in range(num_snaps_to_delete):
      snap_id_to_delete = curr_snap_ids[-1-index]
      INFO("Deleting snapshot with snap id {}".format(snap_id_to_delete))
      async_dr_library.delete_snapshot(pd, snap_id_to_delete)
      INFO("Deleted snap id: {}".format(snap_id_to_delete))

def query_and_apply_crt_uvms(cluster, container, uvms, gold_file_map,
                             snap_id, ref_snap_id):
  """
    This method queries the changed blocks using the current and previous
      snapshot id as the reference snapshot and applies the changed blocks on
      gold vdisk files.

    Args:
      cluster(NOSCluster obj): cluster on which the uvms are present.
      container(Container obj): Container on which the snapshot are stored.
      uvms(List of VM obj): List of UVMs for which gold files will be updated.
      gold_file_map(dict): mapping between UVM name and list of gold NFS vdisk
        files.
      snap_id(string): snapshot id of the current snapshot.
      ref_snap_id(string): snapshot id of the reference snapshot.

    Returns: None
  """
  for uvm in uvms:
    INFO("Mount the container on UVM {}({})".format(uvm.name, uvm.ip))
    uvm_mount_point = DRWorkflows.mount_ctr_on_uvm(cluster, uvm, container)
    vdisk_uuids = [vdisk["vmdisk_uuid"] for vdisk in
                   uvm.get()["config"]["disk_list"][1:]]
    for index, vdisk_uuid in enumerate(vdisk_uuids):
      gold_vdisk = gold_file_map[uvm.name][index].split("/")[-1]
      crt_client_args_map = cbt_utils.get_crt_args_map(cluster, snap_id,
                                                       vdisk_uuid, gold_vdisk,
                                                       container.name,
                                                       ref_snap_id=ref_snap_id,
                                                       is_nfs_file=False,
                                                       ctr_mnt_point=
                                                       uvm_mount_point)
      cbt_utils.query_and_apply_crt(uvm, crt_client_args_map)
    INFO("Unmount the container on UVM {}".format(uvm.name))
    uvm.unmount(uvm_mount_point)

def verify_io_integrity_of_uvms(cluster, uvms, kwargs, delete_uvms=True):
  """
    This method verifies the IO integrity of UVMs. After verification deletes
      the UVMs

    Args:
      cluster(NOSCluster obj): cluster on which the uvms are present.
      uvms(List of VM obj): List of UVMs whose IO integrity is verified.
      kwargs(dict): a dictionary which contains following key value pairs:
        {
          integrity_runner_inputs : <integrity_runner_inputs>,
          interface_type : <interface_type>,
          num_vdisks : <num of vdisks per uvm>
          vdisk_size : <size of vidisks>
        }
      delete_uvms(bool): flag to delete the verified uvms. Defaults to True.

    Returns: None
  """
  integrity_runner_inputs = kwargs["integrity_runner_inputs"]
  interface_type = kwargs["interface_type"]
  num_vdisks = kwargs["num_vdisks"]
  vdisk_size = kwargs["vdisk_size"]

  INFO("Power on the restored uvms")
  for uvm in uvms:
    uvm.power_on()
  INFO("Check if restored uvms are accessible")
  is_accessible(uvms, num_retries=10, poll_interval=30,
                reboot_vms=True)
  INFO("Run integrity tester in verify mode")
  try:
    async_dr_library.run_integrity_tester_in_verify_mode(cluster,
                                                         interface_type,
                                                         integrity_runner_inputs
                                                         , uvms, num_vdisks,
                                                         start_drive_letter="b",
                                                         vdisk_size=vdisk_size)
  except AssertionError:
    ERROR("UVM Integrity verification failed")
    raise
  if delete_uvms:
    INFO("Delete the restored uvms")
    for uvm in uvms:
      INFO("Deleting the restored uvm: {}".format(uvm.name))
      uvm.power_off()
      uvm.remove()

def run_query_and_apply_crt(cluster, container, pd, snapshot_id,
                            ref_snapshot_id, gold_file_map, interface_type,
                            test_args):
  """
    This methods runs CRT query on the snapshot and applies the result on gold
    disks. Also this method runs IO integrity in verify mode on restored VMs
    Steps in this method would be:
      1) Take a one time out of band snapshot of the UVM.
      2) Restore the UVM from the snapshot on the cluster.
      3) Detach all the vdisks associated with the restored UVM.
      4) Query changed blocks using the current snapshot id and the last
         snapshot id as the reference snapshot.
      5) Apply the changed blocks on the gold NFS vdisk file associated with the
         IO Integrity raw device.
      6) Run Integrity Tester on the Restored UVM in verify mode with leveldb
         residing inside the UVM against the NFS vdisk file.
      7) Delete the Restored UVM.

    Args:
      cluster(NOSCluster obj): The local cluster object.
      container(Container obj): Container object in the local cluster.
      pd(ProtectionDomain obj): ProtectionDomain object which protects the VMs.
      snapshot_id(string): id of the current snapshot.
      ref_snapshot_id(string): id of the snapshot against which the changed
        blocks will be queried.
      gold_file_map(dict): dictionary object which maps UVM name to list of
        corresponding gold NFS vdisk files.
      interface_type(string): Interface Type (ACLI or API)
      test_args(dict): dictionary which has following keys value mappings.

    Returns:
      None

    Raises:
      NuTestError: when method fails to take snapshot
      NuTestError: when method fails to recover UVMs
  """
  def sigterm_handler(signum, frame):
    """Sigterm handler for the function run_query_and_apply_crt.

      Args:
        signum (int) : Signal number passed to the handler.
        frame (object): Current execution frame.
    """
    INFO("Sigterm handler called with signal: %s in method:"
         "'run_query_and_apply_crt' " % (signum))
  signal.signal(signal.SIGTERM, sigterm_handler)

  start_time = time.clock()
  cbt_loop_wait_interval = test_args.get("snapshot_cbt_loop_interval", 900)
  INFO("Wait {} secs before starting the loop".format(cbt_loop_wait_interval))
  time.sleep(cbt_loop_wait_interval)

  STEP("Starting incremental snapshot cbt loop")
  if not snapshot_id:
    INFO("Taking a one time snapshot of the IO Integrity UVMs")
    snapshot_id = async_dr_library.take_one_time_snapshot_return_snapid(pd)
    if not snapshot_id:
      raise NuTestError("Failed to take snapshot")

  if not ref_snapshot_id:
    INFO("Finding id of snapshot preceding to snapshot: {}".format(snapshot_id))
    ref_snapshot_id = get_prev_snap_id(pd, snapshot_id)

  INFO("Snapshot id to be used for CRT: {}".format(snapshot_id))
  INFO("Reference snapshot id to be used for CRT: {}".format(ref_snapshot_id))

  STEP("Restoring UVMs from the current snapshot: {}".format(snapshot_id))
  res_vm_name_prefix = "restored_vm_snap_id_{}_".format(snapshot_id)
  pd.restore(vm_name_prefix=res_vm_name_prefix, snap_id=snapshot_id)

  test_uvms = [uvm for uvm in cluster.uvms
               if res_vm_name_prefix not in uvm.name]
  restored_uvms = [uvm for uvm in cluster.uvms
                   if res_vm_name_prefix in uvm.name]
  if not restored_uvms:
    raise NuTestError("No UVM is restored")
  INFO("Test UVMS are: {}".format(test_uvms))
  INFO("Restored UVMS are: {}".format(restored_uvms))

  delete_older_snapshot(pd, test_args.get("max_snapshot_depth", 3))
  STEP("Querying test UVMS and applying CRT om gold disks")
  query_and_apply_crt_uvms(cluster, container, test_uvms, gold_file_map,
                           snapshot_id, ref_snapshot_id)
  STEP("Attaching gold disks to restored UVMs")
  attach_gold_vdisk_to_vms(restored_uvms, gold_file_map, res_vm_name_prefix)
  kwargs = {}
  kwargs["integrity_runner_inputs"] = test_args["integrity_runner_inputs"]
  kwargs["interface_type"] = interface_type
  kwargs["num_vdisks"] = test_args["uvm_spec"]["num_vdisks"]
  kwargs["vdisk_size"] = test_args["uvm_spec"]["vdisk_size"]
  STEP("Verify IO integrity of restored UVMs")
  verify_io_integrity_of_uvms(cluster, restored_uvms, kwargs)

  INFO("CBT Query and IO Verification took {} secs".format(time.clock() -
                                                           start_time))


def run_error_injection(ref):
  """
    This method start and control Error Injection as a process

    Args:
      ref(NOSTest obj): Test class instance.

    Returns:
      None

    Raises:
      None
  """
  def sigterm_handler(signum, frame):
    """Sigterm handler for the function run_error_injection.

      Args:
        signum (int) : Signal number passed to the handler.
        frame (object): Current execution frame.
    """
    INFO("Sigterm handler called with signal: %s in method:"
         "'run_error_injection' " % (signum))
    try:
      ref.error_injector.terminate_all()
    except:
        # Terminate for now is failing however putting this hack as
        # still not able to do full RCA. Some issue with multiprocessing
        # library. However this will unblock the test execution for now.
        INFO("Terminate failed")
    sys.exit(signum)

  signal.signal(signal.SIGTERM, sigterm_handler)
  # Init the error injector util.
  ref.error_injector = ErrorInjectionManager(ref.local_cluster)
  ref.error_injector.create_kill_components_on_random_vm_processes(
    components=ref.component_kill_list,
    frequency_secs=ref.component_kill_freq)

  # Start error injection.
  STEP("Starting error injection process in background")
  ref.error_injector.start_all()
  INFO("Started error injection process in background")
