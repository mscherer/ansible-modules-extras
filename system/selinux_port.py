#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Michael Scherer <misc@zarb.org>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# TODO relite
DOCUMENTATION = '''
---
module: selinux_port
short_description: Change port label in SELinux policy
description:
  - TODO
version_added: "1.9"
options:
  port:
    description:
        - "the port that will be labeled"
    required: true
  protocol:
    description:
        - "the protocol used for the port to label, tcp or udp"
    required: true
    default: "tcp"
  type:
    description:
        - "SELinux type to use for the port"
    required: true
  range:
    description:
      - "SELinux range"
      - "only used for MLS/MCS, not needed to change most of the time"
    required: false
    default: "s0"
  state:
    description:
      - "State of the port, use absent to remove it"
    required: false
    default: present
  store:
    description:
      - "name of the SELinux policy store to use"
    required: false
    default: null
  no_reload:
    description:
        - "automatically reload the policy after a change"
        - "default is 'true' as that's what most people would want after changing one domain"
        - "Note that this doesn't work on older version of the library (example EL 6), the module will silently ignore it in this case"
    required: false
    default: False
notes:
    - Requires a version of SELinux recent enough ( ie EL 6 or newer )
requirements: [ policycoreutils-python ]
author: Michael Scherer <misc@zarb.org>
'''


EXAMPLES = '''
- selinux_port: port=5353 type=dns_port_t protocol=udp
'''

HAVE_SEOBJECT = False
try:
    import seobject
    HAVE_SEOBJECT = True
except ImportError:
    pass


def main():
    module = AnsibleModule(
        argument_spec=dict(
            port=dict(required=True),
            protocol=dict(required=False, default='tcp', choices=['tcp', 'udp']),
            type=dict(required=True),
            range=dict(required=False, default='s0'),
            state=dict(default='present', choices=['absent', 'present'],
                       required=False),
            store=dict(required=False, default=''),
            no_reload=dict(type='bool', required=False, default=False),
        ),
        supports_check_mode=True
    )

    # global vars
    changed = False
    store = module.params['store']
    no_reload = module.params['no_reload']
    state = module.params['state']
    se_type = module.params['type']
    se_range = module.params['range']
    port = module.params['port']
    protocol = module.params['protocol']

    # TODO check for selinux
    if not HAVE_SEOBJECT:
        module.fail_json(changed=False, msg="policycoreutils-python required for this module")

    try:
        ports = seobject.portRecords(store)
    except ValueError, e:
        module.fail_json(port=port, protocol=protocol, type=se_type, msg=str(e))

    if not se_type in ports.valid_types:
        module.fail_json(port=port, protocol=protocol, type=se_type, msg="Incorrect type %s for port" % se_type)

    # not supported on EL 6
    if 'set_reload' in dir(fcontexts):
        fcontexts.set_reload(not no_reload)

    if '-' in port:
        port_start, port_end = port.split('-')
    else:
        port_start = port_end = port

    if not port_start.isdigit() or not port_end.isdigit():
        module.fail_json(msg="Incorrect port specification: %s" % port)

    if int(port_end) < int(port_start):
        module.fail_json(msg="Wrong port specification, range %s is not correctly ordered" % port)

    # port_start is always > 0, or isdigit fail
    if int(port_end) > 65536:
        module.fail_json(msg="Wrong port specification, port is too high: %s" % port)

    key = (port_start, port_end, protocol)
    value = (se_type, se_range)
    record_present = key in ports.get_all()

    changed = False
    if state == 'present':
        if record_present:
            if not value == ports.get_all()[key]:
                if not module.check_mode:
                    ports.modify(port, protocol, se_range, se_type)
                changed = True
        else:
            if not module.check_mode:
                ports.add(port, protocol, se_range, se_type)
            changed = True
    else:
        if record_present:
            if not module.check_mode:
                ports.delete(port, protocol)
            changed = True
    # TODO fix
    module.exit_json(changed=changed, store=store,
                     state=state, type=se_type, file_spec=file_spec,
                     file_type=file_type, )


#################################################
# import module snippets
from ansible.module_utils.basic import *

main()
