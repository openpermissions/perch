
from __future__ import unicode_literals
import perch

VERSION = '22e76f4ff8bd41e19aa52839fc8f13a1'
PREVIOUS_VERSION = ''


@perch.migrate.migration(perch.User, VERSION, PREVIOUS_VERSION)
def migrate_user(instance):
    """
    Move User.organisations['global']['role'] to top-level property and remove
    verified flag
    """
    instance._resource.pop('verified', None)

    if 'role' in instance._resource:
        return instance

    global_org = instance.organisations.pop('global', {})
    instance.role = global_org.get('role', perch.User.roles.default.value)

    return instance
