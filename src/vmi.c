#include "vmi.h"

extern os_t os;
extern int interrupted;
extern page_mode_t pm;

bool setup_vmi(vmi_instance_t *vmi, char *socket, char *json) {
    vmi_init_data_entry_t entry;
    entry.type = VMI_INIT_DATA_KVMI_SOCKET;
    entry.data = socket;

    vmi_init_data_t init_data;
    init_data.count = 1;
    init_data.entry[0] = entry;

    if (VMI_FAILURE ==
        vmi_init(vmi, VMI_KVM, NULL, VMI_INIT_EVENTS | VMI_INIT_DOMAINNAME, &init_data, NULL))
        return false;

    if (VMI_OS_UNKNOWN == (os = vmi_init_os(*vmi, VMI_CONFIG_JSON_PATH, json, NULL))) {
        vmi_destroy(*vmi);
        return false;
    }

    pm = vmi_get_page_mode(*vmi, 0);

    return true;
}

void loop(vmi_instance_t vmi) {
    if (!vmi)
        return;

    vmi_resume_vm(vmi);

    while (!interrupted) {
        if (vmi_events_listen(vmi, 500) == VMI_FAILURE) {
            fprintf(stderr, "Error in vmi_events_listen!\n");
            break;
        }
    }
}
