STEP("Create RPs for {0} VMs".format(len(self.vms)))
vm_to_rp_list_map = self.polaris_wf.create_recovery_point_for_vms(
    self.vms)
for vm, rpt in vm_to_rp_list_map.items():
    recovery_point = RecoveryPoint.from_identifier(
        cluster=self.pc_cluster,
        interface_type=Interface.REST,
        interface_version=PrismRestVersion.V3_0,
        identifier=rpt[0])
    STEP("Attempting Restore for VM : %s with RPT : %s" % (vm, rpt[0]))
    restore_override_spec = self.test_args.get("restore_override_spec")
    STEP("Create Category for override spec: %s" % restore_override_spec.get(
        "categories_mapping"))
    category_list = [
        {'category': restore_override_spec.get("categories_mapping")}]
    self.polaris_wf.create_categories(categories_list=category_list)
    vm_rpt_uuid_list = \
        fetch_vm_rpt_from_top_level_rpt(rpt[0], self.polaris_wf.src_pc_polaris)
    INFO("vm_rp_uuid_list : %s" % vm_rpt_uuid_list[0])
    rp_override_spec = \
        RecoveryPointOverrideSpec(vm_rpt_uuid=vm_rpt_uuid_list[0],
                                  name= \
                                      restore_override_spec. \
                                  get("restored_vm_name"),
                                  categories_mapping= \
                                      {"TestSQL": ["Nutest"]})
    restored_vm = recovery_point.restore(async=False, spec=rp_override_spec)