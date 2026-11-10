//go:build amd64 || arm64

package cli

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// renameNoReplace renames oldpath to newpath in one step, unless newpath exists: renameat2 with RENAME_NOREPLACE. It
// returns an error matching fs.ErrExist if newpath exists, and errors.ErrUnsupported if the kernel or the file system
// can't rename that way.
func renameNoReplace(oldpath, newpath string) error {
	from, err := syscall.BytePtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := syscall.BytePtrFromString(newpath)
	if err != nil {
		return err
	}
	const renameNoReplaceFlag = 1
	cwd := -100 // AT_FDCWD: the paths are relative to the working directory
	//nolint:gosec // pointers converted in the system call's own argument list, as package unsafe allows
	_, _, errno := syscall.Syscall6(sysRenameat2, uintptr(cwd), uintptr(unsafe.Pointer(from)), uintptr(cwd),
		uintptr(unsafe.Pointer(to)), renameNoReplaceFlag, 0)
	switch errno {
	case 0:
		return nil
	case syscall.EINVAL, syscall.ENOSYS:
		return errors.ErrUnsupported
	}
	return &os.LinkError{Op: "renameat2", Old: oldpath, New: newpath, Err: errno}
}
