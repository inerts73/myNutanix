"""
Copyright (c) 2019 Nutanix Inc. All rights reserved.

Author: arun.kumar@nutanix.com

"This module contains test which test CBT features with VM based testing.
"""

# pylint: disable=no-member
import signal
import copy
import json
import time
import traceback
from functools import partial

from framework.entities.vm.vm import Vm
from framework.lib.test.nos_test import NOSTest
from framework.components.cerebro import Cerebro
from framework.lib.nulog import INFO, STEP, ERROR
from framework.exceptions.nutest_error import NuTestError
from workflows.cbt.io_integrity_lib import create_gold_vdisk_for_uvm, run_query_and_apply_crt, error_injection_wrapper, verify_io_integrity_of_uvms
from workflows.metro import metro_lib
from workflows.async_dr import async_dr_library
from workflows.near_sync import near_sync_library
from workflows.cbt import cbt_utils_lib as cbt_utils
from workflows.cdp.download_binary import DownloadBinary
from workflows.async_dr.async_dr_workflow import DRWorkflows
from workflows.async_dr.dr_util_lib import \
  clear_gflags_with_cluster_restart, set_gflags_with_cluster_restart
from workflows.manageability.api.aplos.aplos_client import reset_password
from workflows.monitor_util.monitor_lib import MonitorUtil

class CbtIOIntegrityTest(NOSTest):
  """
  This class contains VM based test cases to verify CBT feature
  """
  def class_setup(self):
    """
    Test class setup.
    """
    INFO("Starting class setup")
    self.local_cluster = self.clusters[0]

  def setup(self):
    return
    """
    Test specific setup.
    """
    STEP("Starting test setup")

    if self.test_args.get("recreate_cluster", False):
      STEP("Destroying and recreating the cluster as required")
      clean_debug_data = self.test_args.get("clean_debug_data", True)
      async_dr_library.recreate_clusters(self.clusters,
                                         clean_debug_data=clean_debug_data)
    reset_password(self.local_cluster)

    STEP("Generating unique uvm, container, pd name prefix for this test run.")
    self.test_args["pd_name"] += "_" + self.local_cluster.name[:8]
    near_sync_library.add_unique_suffix_to_test_args(self.test_args)
    self.pd_name = self.test_args.get("pd_name", "default_ns_pd")
    self.uvms_spec_args = self.test_args["uvm_spec"]

    # Configure nas_archival, Scavenger, genesis, binary_logging
    gflag_items = cbt_utils.gflag_update_args(self.local_cluster,
                                              self.interface_type,
                                              **self.test_args)
    self.test_args.update(gflag_items)
    set_gflags_with_cluster_restart(self.clusters, **self.test_args)

    STEP("Creating storage pool and containers")
    entities_created = async_dr_library.setup_helper(self.clusters,
                                                     min_clusters=1,
                                                     **self.test_args)
    self.ctr = entities_created[self.local_cluster.name]["ctr"]
    self.sp = entities_created[self.local_cluster.name]["sp"]
    self.pd = entities_created["protection_domain"]

    STEP("Creating uvms")
    uvms_spec_args_copy = copy.deepcopy(self.uvms_spec_args)
    # Passing the container and storage pool on which uvms should be deployed.
    uvms_spec_args_copy["storage_pool"] = self.sp
    uvms_spec_args_copy["container"] = self.ctr
    num_nodes = len(self.local_cluster.svms)
    vm_count = self.test_args.get("vm_count", None)
    if vm_count:
      if vm_count == "null":
        vm_count = num_nodes
      node_affinity = async_dr_library.get_node_affinity(num_nodes, vm_count)
      uvms_spec_args_copy["node_affinity"] = node_affinity
    self.manager, self.uvms = async_dr_library.create_io_integrity_uvms(
      self.local_cluster, self.interface_type, uvms_spec_args_copy,
      self.sp, self.ctr)
    self.created_entities = {"uvms": self.uvms}
    INFO("Following {} uvms are created:".format(len(self.uvms)))
    INFO(", ".join(["{}({})".format(uvm.name, uvm.ip) for uvm in self.uvms]))

    STEP("Configure virtual ip of the source cluster")
    source_v1_ip = self.local_cluster.fetch_v1_ip_from_metadata()
    self.local_cluster.set_cluster_virtual_ip(ip=source_v1_ip)
    INFO("Cluster Virtual IP: %s" % source_v1_ip)

    STEP("Protect created UVMs")
    DRWorkflows.protect_entities(self.pd, uvms=self.uvms)

    STEP("Create gold disks for each UVM")
    self.uvm_to_gold_file_map = create_gold_vdisk_for_uvm(self.local_cluster,
                                                          self.ctr, self.uvms)
    # Transfer the CRT client tool to the UVMs.
    STEP("Download and deploy crt_client binary on the UVMs")
    db_obj = DownloadBinary(self.local_cluster, svms=self.uvms)
    kwargs = {'parallel': True, 'target_svms': self.uvms}
    db_obj.prepare_and_push_binaries(tool_name="crt_client", **kwargs)

    STEP("Configure cerebro gflags.")
    Cerebro(self.cluster).set_flags(flags={"v": 1}, update=False,
                                    persistent=True, parallel=True)

    self.data_corruption = False

  def teardown(self):
    return
    """Test specific tear down.

       Returns:
         None
    """
    STEP("Starting test teardown")
    # Copy the crt_client logs and the metadata logs from the container.
    cbt_utils.transfer_crt_client_logs(self.local_cluster, self.ctr, self.uvms,
                                       self.log_dir)
    STEP("Unmounting mounted containers on all cluster")
    _ = [cluster.clear_all_svm_mounts() for cluster in self.clusters]

    # Reset the oplog draining gflags to enabled
    cbt_utils.toggle_oplog_draining_via_http(self.local_cluster,
                                             intent="enabled")
    STEP("Clearing gflags that were set")
    clear_gflags_with_cluster_restart(self.clusters, **self.test_args)

    if hasattr(self, "manager"):
      INFO("Stopping the testers on the test uvms and doing post run on them")
      stop_req = self.manager.stop_requests()
      stop_req.wait_for_completion()
      self.io_req.wait_for_completion()
      INFO("Killing the manager")
      self.manager.terminate()

    if hasattr(self, "data_corruption"):
      INFO("Data Corruption: %s " % self.data_corruption)
      if self.data_corruption:
        INFO("Data corruption was encountered in the test. Hence skipping "
             "further test teardown.")
        return

    INFO("Removing pd, uvms and local sites")
    teardown_items = {}
    teardown_items["pd_list"] = [self.pd]
    teardown_items["vm_list"] = Vm.list(self.local_cluster)
    async_dr_library.teardown_helper(**teardown_items)

    STEP("Deleting local container")
    metro_lib.remove_ctr(self.local_cluster, self.ctr)

    if self.succeeded:
      for svm in self.local_cluster.svms:
        svm.execute("rm -fr /home/nutanix/data/binary_logs")

  def test_incremental_snapshots(self, parallel_test_methods=None):
    """Verify the IO integrity of restored UVMs
      Method does the following steps:
        1. Continously runs IO on protected UVMs.
        2. parallel to step 1 -
          a. Take snapshot of UVMs
          b. Recover UVMs from snapshot
          c. Verify IO integrity of restored UVMs
    Raises:
      None
    Metadata:
      Summary: TBD
      Priority: $P0
      Components: [$CEREBRO]
      Services: [$AOS_TAR]
      Requirements: [FEAT-2028]
      Steps:
        - TBD
      Tags: [$REG_HANDEDOVER]
    """
    INFO("Starting test")

    STEP("Start io on test uvms using integrity tester")
    self.io_req = self.manager.run_integrity_tester(
      global_options=self.test_args.get("integrity_runner_inputs"))
    num_testers = len(self.uvms) * self.uvms_spec_args.get("num_vdisks")

    STEP("Check IO Integrity testers have started on all uvms")
    if not async_dr_library.wait_for_testers_to_start(self.io_req, num_testers):
      assert False, "Failed to start integrity testers on all uvms"

    main_method = partial(async_dr_library.wait_till_integrity_testers_finish,
                          io_integrity_manager=self.manager,
                          run_integrity_tester_req=self.io_req)
    cbt_loop_method = partial(run_query_and_apply_crt, self.local_cluster,
                              self.ctr, self.pd, None, None,
                              self.uvm_to_gold_file_map, self.interface_type,
                              self.test_args)
    if not parallel_test_methods:
      parallel_test_methods = {}
    parallel_test_methods["Apply_CRT_and_Verify_IO"] = [cbt_loop_method,
                                                        "FAIL_TEST_ON_FAILURE",
                                                        "RESTART_ON_SUCCESS"]
    monitor = MonitorUtil("IO_Integrity_Monitor", main_method,
                          parallel_test_methods)
    io_timeout = self.test_args["integrity_runner_inputs"]["timeout_secs"]
    STEP("Starting main method to run IO for {} secs.".format(io_timeout))
    monitor.start_main_method()
    time.sleep(120)
    STEP("Starting query and apply CRT and verify io in parallel")
    monitor.start_other_methods()
    if self.test_args.get("error_injection", False):
      self.succeeded = error_injection_wrapper(monitor.start_monitoring,
                                              self.local_cluster,
                                              self.component_kill_list,
                                              self.component_kill_freq)
    else:
      self.succeeded = monitor.start_monitoring()

    if not self.succeeded:
      INFO("Verifying if test failed because of data corruption")
      res_vm_name_prefix = "restored_vm_snap_id_"
      restored_uvms = [uvm for uvm in self.local_cluster.uvms
                       if res_vm_name_prefix in uvm.name]
      INFO("Restored UVMS are: {}".format(restored_uvms))

      kwargs = {}
      kwargs["integrity_runner_inputs"] = \
        self.test_args["integrity_runner_inputs"]
      kwargs["interface_type"] = self.interface_type
      kwargs["num_vdisks"] = self.test_args["uvm_spec"]["num_vdisks"]
      kwargs["vdisk_size"] = self.test_args["uvm_spec"]["vdisk_size"]
      STEP("Verify IO integrity of restored UVMs")
      try:
        verify_io_integrity_of_uvms(self.local_cluster, restored_uvms, kwargs)
      except AssertionError:
        ERROR("{}".format(traceback.format_exc()))
        self.data_corruption = True
        raise NuTestError("Data corruption is detected on restored UVMS")

      INFO("No data corruption is detected on restored UVMS but some methods "
           "failed")
      raise NuTestError(
        'Failing method(s) => {0}'.format(
          [(method, exit_code) for (method, exit_code) in
           monitor.get_processes_exit_codes().items() if exit_code]))

  def test_cbt_on_compression_ctr(self):
    """Run test_incremental_snapshots on a compression enabled container
    Raises:
      None
    Metadata:
      Summary: TBD
      Priority: $P1
      Components: [$CEREBRO]
      Services: [$AOS_TAR]
      Requirements: [FEAT-2028]
      Steps:
        - TBD
      Tags: [$REG_HANDEDOVER]
    """
    self.test_incremental_snapshots()

  def test_cbt_error_injection(self):
    """Run test_incremental_snapshots with error injection on
    Raises:
      None
    Metadata:
      Summary: TBD
      Priority: $P0
      Components: [$CEREBRO]
      Services: [$AOS_TAR]
      Requirements: [FEAT-2028]
      Steps:
        - TBD
      Tags: [$REG_HANDEDOVER]
    """
    self.component_kill_list = self.test_args["error_injection"][
      "component_kill_list"]
    self.component_kill_freq = self.test_args["error_injection"][
      "component_kill_freq"]
    INFO("Retrieved info for error injection.")
    INFO("Component kill list: {0}, kill frequency in sec: {1}.".format(
      self.component_kill_list, self.component_kill_freq))

    max_cores = (
      len(self.component_kill_list) *
      self.test_args['integrity_runner_inputs']['timeout_secs'] /
      self.component_kill_freq
    )
    INFO("Calculated max_cores. Result = {}.".format(max_cores))

    STEP("Initializing expected_cores with max_cores")
    self.params["expected_cores"] = {
      "alert_manager": max_cores,
      "arithmos": max_cores,
      "cassandra_monitor": max_cores,
      "cassandra_monit": max_cores,
      "cerebro": max_cores,
      "chronos_node_ma": max_cores,
      "chronos_node_main": max_cores,
      "curator": max_cores,
      "gdb": max_cores,
      "java": max_cores,
      "pithos": max_cores,
      "prism_monitor": max_cores,
      "python": max_cores,
      "stargate": max_cores,
      "stats_aggregator": max_cores
    }
    INFO("Initialized expected_cores. Result = {}.".format(
      json.dumps(self.params["expected_cores"], indent=2, sort_keys=True)))
    import sys

    def main_method():
      INFO("##### main begin")
      time.sleep(30)
      INFO("##### main end")

    def side_method():
      def sigterm_handler(signum, frame):
        INFO("Sigterm handler called with signal: %s. "
             "Will exit 'SIDE_METHOD' " % (signum))
        sys.exit(0)

      signal.signal(signal.SIGTERM, sigterm_handler)
      INFO("##### side begin")
      for i in range(20):
        print '********************SIDE ', str(i)
        time.sleep(1)
        if i % 10 == 0:
          _ = error_injection_wrapper(DUMMY,
                                      self.local_cluster,
                                      self.component_kill_list,
                                      self.component_kill_freq)
      INFO("##### side end")

    def DUMMY():
      print '$$$$$$$$$$$$$$$$ DUMMY START'
      time.sleep(5)
      print '$$$$$$$$$$$$$$$$ DUMMY END'
      return True

    parallel_test_methods = {}
    parallel_test_methods["SIDE"] = [side_method,
                                     "FAIL_TEST_ON_FAILURE",
                                     "RESTART_ON_SUCCESS"]
    monitor = MonitorUtil("ADAM_IO", main_method,
                          parallel_test_methods, 2, 0)
    monitor.start_main_method()
    time.sleep(0)
    monitor.start_other_methods()
    print '################'
    from multiprocessing import active_children
    print active_children()
    print '################'
    monitor.start_monitoring()

    return

    self.test_incremental_snapshots()

  def test_lr_incremental_snapshots(self):
    """Run test_incremental_snapshots in long running mode
    Raises:
      None
    Metadata:
      Summary: TBD
      Priority: $P1
      Components: [$CEREBRO]
      Services: [$AOS_TAR]
      Requirements: [FEAT-2028]
      Steps:
        - TBD
    """
    self.test_incremental_snapshots()

  def test_lr_cbt_on_compression_ctr(self):
    """Run test_cbt_on_compression_ctr in long running mode
    Raises:
      None
    Metadata:
      Summary: TBD
      Priority: $P0
      Components: [$CEREBRO]
      Services: [$AOS_TAR]
      Requirements: [FEAT-2028]
      Steps:
        - TBD
      Tags: [$PARTIAL_METADATA]
    """
    self.test_cbt_on_compression_ctr()

  def test_lr_cbt_error_injection(self):
    """Run test_cbt_error_injection in long running mode
    Raises:
      None
    Metadata:
      Summary: TBD
      Priority: $P1
      Components: [$CEREBRO]
      Services: [$AOS_TAR]
      Requirements: [FEAT-2028]
      Steps:
        - TBD
      Tags: [$PARTIAL_METADATA]
    """
    self.test_cbt_error_injection()
