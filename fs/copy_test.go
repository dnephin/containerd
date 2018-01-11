package fs

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/containerd/containerd/fs/fstest"
	"github.com/gotestyourself/gotestyourself/fs"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// TODO: Create copy directory which requires privilege
//  chown
//  mknod
//  setxattr fstest.SetXAttr("/home", "trusted.overlay.opaque", "y"),

func TestCopyDirectory(t *testing.T) {
	apply := fstest.Apply(
		fstest.CreateDir("/etc/", 0755),
		fstest.CreateFile("/etc/hosts", []byte("localhost 127.0.0.1"), 0644),
		fstest.Link("/etc/hosts", "/etc/hosts.allow"),
		fstest.CreateDir("/usr/local/lib", 0755),
		fstest.CreateFile("/usr/local/lib/libnothing.so", []byte{0x00, 0x00}, 0755),
		fstest.Symlink("libnothing.so", "/usr/local/lib/libnothing.so.2"),
		fstest.CreateDir("/home", 0755),
	)

	if err := testCopy(apply); err != nil {
		t.Fatalf("Copy test failed: %+v", err)
	}
}

// This test used to fail because link-no-nothing.txt would be copied first,
// then file operations in dst during the CopyDir would follow the symlink and
// fail.
func TestCopyDirectoryWithLocalSymlink(t *testing.T) {
	apply := fstest.Apply(
		fstest.CreateFile("nothing.txt", []byte{0x00, 0x00}, 0755),
		fstest.Symlink("nothing.txt", "link-no-nothing.txt"),
	)

	if err := testCopy(apply); err != nil {
		t.Fatalf("Copy test failed: %+v", err)
	}
}

func testCopy(apply fstest.Applier) error {
	t1, err := ioutil.TempDir("", "test-copy-src-")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary directory")
	}
	defer os.RemoveAll(t1)

	t2, err := ioutil.TempDir("", "test-copy-dst-")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary directory")
	}
	defer os.RemoveAll(t2)

	if err := apply.Apply(t1); err != nil {
		return errors.Wrap(err, "failed to apply changes")
	}

	if err := CopyDir(t2, t1); err != nil {
		return errors.Wrap(err, "failed to copy")
	}

	return fstest.CheckDirectoryEqual(t1, t2)
}

func TestCopyDirErrors(t *testing.T) {
	defaultPath := func() fs.Path {
		return fs.NewDir(t, "test-copy-dir-default")
	}

	var testcases = []struct {
		name     string
		src      fs.Path
		dst      fs.Path
		expected string
	}{
		{
			name:     "missing source dir",
			src:      nonExistantPath{path: "/does/not/exist"},
			dst:      defaultPath(),
			expected: "failed to stat source: stat /does/not/exist: no such file or directory",
		},
		{
			name:     "source is a file",
			src:      fs.NewFile(t, "test-copy-dir-src-file"),
			dst:      defaultPath(),
			expected: "source is not a directory",
		},
		{
			name:     "dest can't be created",
			src:      defaultPath(),
			dst:      nonExistantPath{path: "/bad/dest"},
			expected: "failed to make destination: mkdir /bad/dest",
		},
		{
			name:     "dest is a file",
			src:      defaultPath(),
			dst:      fs.NewFile(t, "test-copy-dir-dest-file"),
			expected: "cannot copy to non-directory",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			defer testcase.src.Remove()
			defer testcase.dst.Remove()

			err := CopyDir(testcase.dst.Path(), testcase.src.Path())
			require.Error(t, err)
			require.Contains(t, err.Error(), testcase.expected)
		})
	}
}

type nonExistantPath struct {
	path string
}

func (n nonExistantPath) Path() string {
	return n.path
}

func (n nonExistantPath) Remove() {}

var _ fs.Path = nonExistantPath{}
