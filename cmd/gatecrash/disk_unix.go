//go:build unix

package main

import "golang.org/x/sys/unix"

// diskFree reports the free and total bytes on the filesystem holding dir.
//
// A full SD card is the single most common way a box fails mid-event, and it fails
// by refusing to write admissions — so this is worth a syscall rather than a
// guess. Unix-only because the box runs on Linux and this is a diagnostic; the
// stub build reports unknown rather than failing to compile on a developer's
// machine.
func diskFree(dir string) (free, total uint64, err error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		return 0, 0, err
	}
	return fs.Bavail * uint64(fs.Bsize), fs.Blocks * uint64(fs.Bsize), nil
}
