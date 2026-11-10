//go:build windows

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// soleLink refuses the file at path if it has other hard links.
func soleLink(path string, _ fs.FileInfo) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return outputError(path, err)
	}
	h, err := syscall.CreateFile(name, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return outputError(path, err)
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return outputError(path, err)
	}
	if info.NumberOfLinks > 1 {
		return otherLinks(path)
	}
	return nil
}

// openDir returns nil: Windows can't flush a directory to disk, and its file systems keep their names in a journal.
func openDir(string) *os.File { return nil }

// renameNoReplace renames oldpath to newpath in one step, unless newpath exists: MoveFile, unlike os.Rename, never
// replaces a file. It returns an error matching fs.ErrExist if newpath exists.
func renameNoReplace(oldpath, newpath string) error {
	from, err := syscall.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	if err := syscall.MoveFile(from, to); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}
