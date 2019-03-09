import json

expected = {
           "nic_list": [],
           "is_agent_vm": False
         }

actual_raw = {u'status': {u'state': u'COMPLETE', u'cluster_reference': {u'kind': u'cluster', u'name': u'auto_AdamHsu_Cluster_Gamma', u'uuid': u'000582da-59be-1300-0000-000000011600'}, u'name': u'RestoreResourcesTest_VM1', u'resources': {u'num_threads_per_core': 1, u'vnuma_config': {u'num_vnuma_nodes': 0}, u'serial_port_list': [], u'nic_list': [], u'hypervisor_type': u'AHV', u'num_vcpus_per_socket': 1, u'num_sockets': 1, u'enable_cpu_passthrough': False, u'gpu_list': [], u'is_agent_vm': False, u'memory_size_mib': 1024, u'power_state': u'OFF', u'hardware_clock_timezone': u'UTC', u'disable_branding': False, u'machine_type': u'PC', u'power_state_mechanism': {u'guest_transition_config': {u'should_fail_on_script_failure': False, u'enable_script_exec': False}, u'mechanism': u'HARD'}, u'vga_console_enabled': True, u'disk_list': []}, u'execution_context': {u'task_uuid': [u'7bfe6196-b4b6-42b0-91af-994efbca84e5']}}, u'spec': {u'name': u'RestoreResourcesTest_VM1', u'resources': {u'num_threads_per_core': 1, u'vnuma_config': {u'num_vnuma_nodes': 0}, u'serial_port_list': [], u'nic_list': [], u'num_vcpus_per_socket': 1, u'num_sockets': 1, u'enable_cpu_passthrough': False, u'gpu_list': [], u'is_agent_vm': False, u'memory_size_mib': 1024, u'power_state': u'OFF', u'hardware_clock_timezone': u'UTC', u'disable_branding': False, u'power_state_mechanism': {u'guest_transition_config': {u'should_fail_on_script_failure': False, u'enable_script_exec': False}, u'mechanism': u'HARD'}, u'vga_console_enabled': True, u'disk_list': []}, u'cluster_reference': {u'kind': u'cluster', u'name': u'auto_AdamHsu_Cluster_Gamma', u'uuid': u'000582da-59be-1300-0000-000000011600'}}, u'api_version': u'3.1', u'metadata': {u'last_update_time': u'2019-03-04T18:05:46Z', u'kind': u'vm', u'uuid': u'64091bb9-bde1-5ff1-be08-afc0411f073c', u'project_reference': {u'kind': u'project', u'name': u'default', u'uuid': u'8ef148e3-4a7c-4dc0-9f8e-af038d19cdd1'}, u'creation_time': u'2019-03-04T18:05:35Z', u'spec_version': 1, u'owner_reference': {u'kind': u'user', u'uuid': u'00000000-0000-0000-0000-000000000000', u'name': u'admin'}, u'categories': {}}}
mismatch = dict()
for vm_attribute in expected:
    if expected[vm_attribute] != actual_raw["spec"]["resources"][vm_attribute]:
        compared_results = {
            "override(expected)": expected[vm_attribute],
            "restored(actual)": actual_raw["spec"]["resources"][vm_attribute]}
        mismatch[vm_attribute] = compared_results


print json.dumps(mismatch, indent=2, sort_keys=True)
if len(mismatch):
    raise Exception("mismatach found")
else:
    print "No mismatch found => Test succeeded."

from collections import OrderedDict
a = OrderedDict()
a["actual"] = "2"
a["expected"] = "1"
print json.dumps(a, indent=2)



