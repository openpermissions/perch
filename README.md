# Perch

A library used in Open Permissions Platform services for accessing registry
data stored in CouchDB.

__NOTE: To use this library CouchDB must be configured to support Python views. See <https://pythonhosted.org/CouchDB/views.html>__


## Migrations

There is support for simple migrations when schemas change.

To create an empty migration using the command line interface, run:

```bash
# create an initial migration file for the perch.Organisation document

perch migrations create perch.Organisation
```

This will create a file in `perch/migrations` containing a function that will
be applied to each `perch.Organisation` document in the database.

For example, this migration will add a key "test" with value 1 to each
organisation:

```python
import perch

VERSION = '36d0e91bf63d479597bb1fccec30a3b0'
PREVIOUS_VERSION = ''


@perch.migrate.migration(perch.Organisation, VERSION, PREVIOUS_VERSION)
def migrate_organisation(instance):
    instance.test = 1

    return instance
```

__NOTE__: Versions are simply UUIDs, the graph of migrations is calculated by
chaining together the version and previous version.

After a migration has been applied the `doc_version` will be updated to match
the last migration

To run migrations:

```bash
perch migrations run
```

### Migrating subresources

Subresource can be migrated the same way as documents (e.g.
`perch migrations create perch.Service`), however the migration version refers
to the document not the subresource.

If a subresource and document migration have the same previous version the
subresources are migrated before the rest of the document. For example, if the
following migrations are created:

```bash

perch create perch.Organisation --previous=36d0e91bf63d479597bb1fccec30a3b0
perch create perch.Service --previous=36d0e91bf63d479597bb1fccec30a3b0
```

then the `perch.Service` migration will run first and the final `doc_version`
will match the `perch.Organisation` version.
