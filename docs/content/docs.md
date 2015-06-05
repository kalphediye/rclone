---
title: "Documentation"
description: "Rclone Documentation"
date: "2014-07-17"
---

Install
-------

Rclone is a Go program and comes as a single binary file.

[Download](/downloads/) the relevant binary.

Or alternatively if you have Go installed use

    go get github.com/ncw/rclone

and this will build the binary in `$GOPATH/bin`.

Configure
---------

First you'll need to configure rclone.  As the object storage systems
have quite complicated authentication these are kept in a config file
`.rclone.conf` in your home directory by default.  (You can use the
`--config` option to choose a different config file.)

The easiest way to make the config is to run rclone with the config
option:

    rclone config

See below for detailed instructions for

  * [Google drive](/drive/)
  * [Amazon S3](/s3/)
  * [Swift / Rackspace Cloudfiles / Memset Memstore](/swift/)
  * [Local filesystem](/local/)

Usage
-----

Rclone syncs a directory tree from one storage system to another.

Its syntax is like this

    Syntax: [options] subcommand <parameters> <parameters...>

Source and destination paths are specified by the name you gave the
storage system in the config file then the sub path, eg
"drive:myfolder" to look at "myfolder" in Google drive.

You can define as many storage paths as you like in the config file.

Subcommands
-----------

    rclone copy source:path dest:path

Copy the source to the destination.  Doesn't transfer
unchanged files, testing by size and modification time or
MD5SUM.  Doesn't delete files from the destination.

    rclone sync source:path dest:path

Sync the source to the destination, changing the destination
only.  Doesn't transfer unchanged files, testing by size and
modification time or MD5SUM.  Destination is updated to match
source, including deleting files if necessary.  Since this can
cause data loss, test first with the `--dry-run` flag.

    rclone ls [remote:path]

List all the objects in the the path with size and path.

    rclone lsd [remote:path]

List all directories/containers/buckets in the the path.

    rclone lsl [remote:path]

List all the objects in the the path with modification time,
size and path.

    rclone md5sum [remote:path]

Produces an md5sum file for all the objects in the path.  This
is in the same format as the standard md5sum tool produces.

    rclone mkdir remote:path

Make the path if it doesn't already exist

    rclone rmdir remote:path

Remove the path.  Note that you can't remove a path with
objects in it, use purge for that.

    rclone purge remote:path

Remove the path and all of its contents.

    rclone check source:path dest:path

Checks the files in the source and destination match.  It
compares sizes and MD5SUMs and prints a report of files which
don't match.  It doesn't alter the source or destination.

    rclone config

Enter an interactive configuration session.

    rclone help

This help.

```
      --bwlimit=0: Bandwidth limit in kBytes/s, or use suffix k|M|G
      --checkers=8: Number of checkers to run in parallel.
      -c, --checksum=false: Skip based on checksum, not mod-time & size
      --config="~/.rclone.conf": Config file.
      --contimeout=1m0s: Connect timeout
  -n, --dry-run=false: Do a trial run with no permanent changes
      --log-file="": Log everything to this file
      --modify-window=1ns: Max time diff to be considered the same
  -q, --quiet=false: Print as little stuff as possible
      --stats=1m0s: Interval to print stats (0 to disable)
      --timeout=5m0s: IO idle timeout
      --transfers=4: Number of file transfers to run in parallel.
  -v, --verbose=false: Print lots more stuff
  -V, --version=false: Print the version number
```

Developer options:

```
      --cpuprofile="": Write cpu profile to file
```

License
-------

This is free software under the terms of MIT the license (check the
COPYING file included in this package).

Bugs
----

  * Empty directories left behind with Local and Drive
    * eg purging a local directory with subdirectories doesn't work

Contact and support
-------------------

The project website is at:

  * https://github.com/ncw/rclone

There you can file bug reports, ask for help or contribute patches.

Authors
-------

  * Nick Craig-Wood <nick@craig-wood.com>

Contributors
------------

  * Your name goes here!
