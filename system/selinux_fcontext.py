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

DOCUMENTATION = '''
---
module: selinux_fcontext
short_description: Change file contexts in SELinux policy
description:
  - Modify the SELinux file context base
version_added: "1.9"
options:
  file_spec:
    description:
      - "specification of files to match"
    required: true
  type:
    description:
      - "SELinux type that would be applied on file matching the specification"
    required: true
  no_reload:
    description:
      - "automatically reload the policy after a change"
      - "default is 'true' as that's what most people would want after changing one domain"
      - "Note that this doesn't work on older version of the library (example EL 6), the module will silently ignore it in this case"
    required: false
    default: False
  store:
    description:
      - "name of the SELinux policy store to use"
      - "Default should be good for most operations"
    required: false
    default: null
  user:
    description:
      - "SELinux user for the object"
      - "Usually not needed to change"
    required: false
    default: "system_u"
  range:
    description:
      - "SELinux range"
      - "only used for MLS/MCS, not needed to change most of the time"
    required: false
    default: "s0"
  state:
    description:
      - "State of the fcontext, use absent to remove it"
    required: false
    default: present
  file_type:
    description:
      - "filter applied to the type of file, like directory, socket, etc."
      - "see manpage of semanage-fcontext, option -f for possible arguments"
    required: false
    default: "a"
notes:
    - Requires a version of SELinux recent enough ( ie EL 6 or newer )
requirements: [ policycoreutils-python ]
author: Michael Scherer <misc@zarb.org>
'''


EXAMPLES = '''
- selinux_fcontext: file_spec=/srv/www/(/.*)? type=httpd_user_rw_content_t
'''

HAVE_SEOBJECT = False
try:
    import seobject
    HAVE_SEOBJECT = True
except ImportError:
    pass

ftypes = {
    'a': 'all files',
    'b': 'block device',
    'c': 'character device',
    'd': 'directory',
    'f': 'regular file',
    'l': 'symbolic link',
    'p': 'named pipe',
    's': 'socket'
}


def convert_type_from_letters(letter):
    return ftypes[letter]


def main():
    module = AnsibleModule(
        argument_spec=dict(
            file_spec=dict(aliases=['path'], required=True),
            type=dict(required=True),
            user=dict(required=False, default='system_u'),
            range=dict(required=False, default='s0'),
            file_type=dict(required=False, default='a'),
            store=dict(required=False, default=''),
            no_reload=dict(type='bool', required=False, default=False),
            state=dict(default='present', choices=['absent', 'present'],
                       required=False),
        ),
        supports_check_mode=True
    )

    file_spec = module.params['file_spec']
    se_type = module.params['type']
    se_user = module.params['user']
    se_range = module.params['range']
    file_type = module.params['file_type']
    store = module.params['store']
    no_reload = module.params['no_reload']
    state = module.params['state']

    se_role = 'object_r'

    if not HAVE_SEOBJECT:
        module.fail_json(changed=False, msg="policycoreutils-python required for this module")

    try:
        fcontexts = seobject.fcontextRecords(store)
    except ValueError, e:
        module.fail_json(changed=False, msg=str(e))

    if not se_type in fcontexts.valid_types:
        module.fail_json(changed=False, type=se_type, msg="Invalid SELinux type: %s" % se_type)

    # not supported on EL 6
    if 'set_reload' in dir(fcontexts):
        fcontexts.set_reload(not no_reload)

    key = (file_spec, convert_type_from_letters(file_type))
    value = (se_user, se_role, se_type, se_range)
    record_present = key in fcontexts.get_all()

    changed = False
    if state == 'present':
        if record_present:
            if not value == fcontexts.get_all()[key]:
                if not module.check_mode:
                    fcontexts.modify(file_spec, se_type, file_type, se_range, se_user)
                changed = True
        else:
            if not module.check_mode:
                fcontexts.add(file_spec, se_type, file_type, se_range, se_user)
            changed = True
    else:
        if record_present:
            if not module.check_mode:
                fcontexts.delete(key)
            changed = True

    module.exit_json(changed=changed, file_spec=file_spec, type=se_type,
                     user=se_user, range=se_range,
                     file_type=file_type, store=store, state=state)


#################################################
# import module snippets
from ansible.module_utils.basic import *

main()
