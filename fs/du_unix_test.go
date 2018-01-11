// +build !windows

package fs

import (
	"testing"

	"github.com/gotestyourself/gotestyourself/fs"
	"github.com/stretchr/testify/require"
)

func TestDiskUsage(t *testing.T) {
	root := fs.NewDir(t, "test-disk-usage",
		fs.WithFile("onefile", "abcdef"),
		fs.WithDir("subdir",
			fs.WithFile("somefile", "abcdef")))
	defer root.Remove()

	usage, err := DiskUsage(root.Path())
	require.NoError(t, err)
	require.Equal(t, Usage{Size: 152, Inodes: 4}, usage)
}
