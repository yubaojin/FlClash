package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

type archiveEntry struct {
	header tar.Header
	data   []byte
}

func readArchive(data []byte) ([]archiveEntry, bool, error) {
	var reader io.Reader = bytes.NewReader(data)
	zipped := len(data) > 1 && data[0] == 0x1f && data[1] == 0x8b
	if zipped {
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, false, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	tr := tar.NewReader(reader)
	var entries []archiveEntry
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return entries, zipped, nil
		}
		if err != nil {
			return nil, zipped, err
		}
		name := path.Clean(header.Name)
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || header.Size > 512<<20 {
			return nil, zipped, errors.New("安装包包含不安全路径或过大文件")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return nil, zipped, errors.New("安装包包含非预期链接或特殊文件")
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, zipped, err
		}
		entries = append(entries, archiveEntry{*header, b})
	}
}

func writeArchive(entries []archiveEntry, zipped bool, inner bool) ([]byte, error) {
	var out bytes.Buffer
	var writer io.Writer = &out
	var gz *gzip.Writer
	if zipped {
		gz = gzip.NewWriter(&out)
		writer = gz
	}
	tw := tar.NewWriter(writer)
	for _, entry := range entries {
		header := entry.header
		header.Uid = 0
		header.Gid = 0
		header.Uname = "root"
		header.Gname = "root"
		header.Mode = 0644
		name := strings.TrimPrefix(path.Clean(header.Name), "./")
		if header.Typeflag == tar.TypeDir || (!inner && strings.HasPrefix(name, "cmd/")) || (inner && strings.HasPrefix(name, "bin/")) {
			header.Mode = 0755
		}
		header.Size = int64(len(entry.data))
		if err := tw.WriteHeader(&header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(entry.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func normalizePackage(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	entries, zipped, err := readArchive(b)
	if err != nil {
		return err
	}
	appIndex, manifestIndex := -1, -1
	for i, entry := range entries {
		switch path.Clean(entry.header.Name) {
		case "app.tgz":
			appIndex = i
		case "manifest":
			manifestIndex = i
		}
	}
	if appIndex < 0 || manifestIndex < 0 {
		return errors.New("官方 FPK 缺少 app.tgz 或 manifest")
	}
	pattern := regexp.MustCompile(`(?m)^(checksum\s*=\s*)([0-9a-f]{32})(\r?)$`)
	manifest := string(entries[manifestIndex].data)
	match := pattern.FindStringSubmatch(manifest)
	originalHash := md5.Sum(entries[appIndex].data)
	if len(match) != 4 || match[2] != hex.EncodeToString(originalHash[:]) {
		return errors.New("官方 FPK 校验约定不匹配，拒绝修改安装包权限")
	}
	innerEntries, innerZipped, err := readArchive(entries[appIndex].data)
	if err != nil {
		return err
	}
	inner, err := writeArchive(innerEntries, innerZipped, true)
	if err != nil {
		return err
	}
	newHash := md5.Sum(inner)
	entries[appIndex].data = inner
	entries[manifestIndex].data = []byte(pattern.ReplaceAllStringFunc(manifest, func(line string) string { return strings.Replace(line, match[2], hex.EncodeToString(newHash[:]), 1) }))
	result, err := writeArchive(entries, zipped, false)
	if err != nil {
		return err
	}
	return write(dst, result, 0644)
}
