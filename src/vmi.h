#ifndef VMI_H
#define VMI_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

bool setup_vmi(vmi_instance_t *vmi, char *domain, char *json);
void loop(vmi_instance_t vmi);

#endif
