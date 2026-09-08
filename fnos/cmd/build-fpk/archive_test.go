package main

import (
	"archive/tar"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchivePermissionsAndChecksum(t *testing.T) {
	inner, err := writeArchive([]archiveEntry{{tar.Header{Name: "bin/FlClashCore", Typeflag: tar.TypeReg}, []byte("核心")}}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	h := md5.Sum(inner)
	manifest := []byte("appname = flclash\nchecksum = " + hex.EncodeToString(h[:]) + "\n")
	outer, err := writeArchive([]archiveEntry{{tar.Header{Name: "app.tgz", Typeflag: tar.TypeReg}, inner}, {tar.Header{Name: "manifest", Typeflag: tar.TypeReg}, manifest}, {tar.Header{Name: "cmd/main", Typeflag: tar.TypeReg}, []byte("#!/bin/bash\nexit 0\n")}}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "input.fpk")
	dest := filepath.Join(dir, "output.fpk")
	if err = os.WriteFile(source, outer, 0600); err != nil {
		t.Fatal(err)
	}
	if err = normalizePackage(source, dest); err != nil {
		t.Fatal(err)
	}
	result, _ := os.ReadFile(dest)
	entries, _, err := readArchive(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.header.Mode&0022 != 0 {
			t.Fatal("安装包存在组或其他用户可写文件")
		}
		if entry.header.Name == "cmd/main" && entry.header.Mode != 0755 {
			t.Fatal("生命周期脚本不可执行")
		}
		if entry.header.Name == "app.tgz" {
			app, _, err := readArchive(entry.data)
			if err != nil {
				t.Fatal(err)
			}
			if app[0].header.Mode != 0755 {
				t.Fatal("核心二进制不可执行")
			}
		}
	}
}

func TestArchiveRejectsTraversalAndForeignChecksum(t *testing.T) {
	b, err := writeArchive([]archiveEntry{{tar.Header{Name: "../escape", Typeflag: tar.TypeReg}, []byte("拒绝")}}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = readArchive(b); err == nil {
		t.Fatal("接受了路径越界")
	}
	bad, err := writeArchive([]archiveEntry{{tar.Header{Name: "app.tgz", Typeflag: tar.TypeReg}, []byte("包")}, {tar.Header{Name: "manifest", Typeflag: tar.TypeReg}, []byte("checksum = 00000000000000000000000000000000\n")}}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "bad.fpk")
	_ = os.WriteFile(src, bad, 0600)
	if normalizePackage(src, filepath.Join(dir, "out.fpk")) == nil {
		t.Fatal("校验约定不匹配时仍修改安装包")
	}
}

func TestBuiltPackage(t *testing.T) {
	p := os.Getenv("FLCLASH_TEST_FPK")
	if p == "" {
		t.Skip("未指定实际 FPK")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := readArchive(b)
	if err != nil {
		t.Fatal(err)
	}
	var manifest string
	var app []byte
	for _, entry := range entries {
		if entry.header.Mode&0022 != 0 || entry.header.Uid != 0 {
			t.Fatal("包权限不安全")
		}
		if strings.HasPrefix(entry.header.Name, "cmd/") && entry.header.Mode != 0755 {
			t.Fatal("脚本没有可执行权限")
		}
		if entry.header.Name == "manifest" {
			manifest = string(entry.data)
		}
		if entry.header.Name == "app.tgz" {
			app = entry.data
		}
	}
	h := md5.Sum(app)
	if !strings.Contains(manifest, hex.EncodeToString(h[:])) || !strings.Contains(manifest, "1.2.0505") {
		t.Fatal("包内校验或最低系统版本错误")
	}
	inner, _, err := readArchive(app)
	if err != nil {
		t.Fatal(err)
	}
	binaries := 0
	documents := map[string]bool{"安装与恢复说明.md": false, "TESTING-0.2.0.md": false, "TESTING-0.2.1.md": false, "docs/screenshots/0.2.0/narrow-dialog.png": false}
	for _, entry := range inner {
		if _, exists := documents[entry.header.Name]; exists {
			documents[entry.header.Name] = len(entry.data) > 0
		}
		if entry.header.Mode&0022 != 0 {
			t.Fatal("应用文件权限不安全")
		}
		if entry.header.Name == "bin/FlClashFnos" || entry.header.Name == "bin/FlClashCore" {
			binaries++
			if entry.header.Mode != 0755 || len(entry.data) < 20 || string(entry.data[:4]) != "\x7fELF" || entry.data[4] != 2 || binary.LittleEndian.Uint16(entry.data[18:20]) != 62 {
				t.Fatal("二进制不是可执行 Linux AMD64 ELF")
			}
		}
	}
	if binaries != 2 {
		t.Fatalf("二进制数量错误: %d", binaries)
	}
	for name, present := range documents {
		if !present {
			t.Fatalf("安装包缺少交付说明或截图: %s", name)
		}
	}
}
