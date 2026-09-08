package main

import "testing"

func TestPackageFilenameUsesManifestVersion(t *testing.T) {
	name, err := packageFilename([]byte("appname = flclash\r\nversion = 0.1.1\r\n"))
	if err != nil || name != "FlClash-0.1.1-fnOS-x86_64.fpk" {
		t.Fatal("输出文件名未使用包描述版本", name, err)
	}
	for _, source := range []string{"version = ../bad", "version = 0.1.1\nversion = 0.1.2", "appname = flclash"} {
		if _, err := packageFilename([]byte(source)); err == nil {
			t.Fatal("接受了错误包版本", source)
		}
	}
}
