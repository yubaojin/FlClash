package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	root := flag.String("root", "..", "FlClash 仓库根目录")
	fnpack := flag.String("fnpack", "fnpack", "官方 fnpack 1.2.3 路径")
	goBin := flag.String("go", "go", "Go 1.26.4 路径")
	flag.Parse()
	if err := build(*root, *fnpack, *goBin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(dir, program string, env []string, args ...string) (string, error) {
	cmd := exec.Command(program, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s 失败: %w\n%s", program, err, b)
	}
	return strings.TrimSpace(string(b)), nil
}

func write(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, b, mode)
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return write(dst, b, mode)
}

func packageFilename(manifest []byte) (string, error) {
	matches := regexp.MustCompile(`(?m)^version[ \t]*=[ \t]*([0-9]+(?:\.[0-9]+){2,3})[ \t]*\r?$`).FindAllSubmatch(manifest, -1)
	if len(matches) != 1 {
		return "", errors.New("包描述必须包含唯一的数字版本号")
	}
	return "FlClash-" + string(matches[0][1]) + "-fnOS-x86_64.fpk", nil
}

func build(root, fnpack, goBin string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(filepath.Join(root, "fnos/package/manifest"))
	if err != nil {
		return err
	}
	filename, err := packageFilename(manifest)
	if err != nil {
		return err
	}
	for _, binary := range []*string{&fnpack, &goBin} {
		if strings.ContainsAny(*binary, `/\`) {
			*binary, err = filepath.Abs(*binary)
			if err != nil {
				return err
			}
		}
	}
	version, err := run(root, goBin, nil, "version")
	if err != nil {
		return err
	}
	if !strings.Contains(version, "go1.26.4 ") {
		return errors.New("可复现构建要求 Go 1.26.4")
	}
	fpVersion, err := run(root, fnpack, nil, "--help")
	if err != nil {
		return err
	}
	if !strings.Contains(fpVersion, "1.2.3") {
		return errors.New("请使用官方 fnpack 1.2.3")
	}
	fpVersion = "fnpack 1.2.3"
	opts, err := os.ReadFile(filepath.Join(root, "plugins/setup/buildkit/build_tool/lib/src/options.dart"))
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, field := range []string{"tags", "goLdflags", "coreDir", "coreName"} {
		match := regexp.MustCompile(field + `: '([^']*)'`).FindSubmatch(opts)
		if len(match) != 2 {
			return fmt.Errorf("无法读取现有核心构建默认项 %s", field)
		}
		values[field] = string(match[1])
	}
	if b, e := os.ReadFile(filepath.Join(root, "build_config.yaml")); e == nil {
		var overrides map[string]string
		if e = yaml.Unmarshal(b, &overrides); e != nil {
			return e
		}
		for external, internal := range map[string]string{"tags": "tags", "go_ldflags": "goLdflags", "core_dir": "coreDir", "core_name": "coreName"} {
			if v, ok := overrides[external]; ok {
				values[internal] = v
			}
		}
	}
	coreDir := filepath.Join(root, values["coreDir"])
	pin, err := run(root, "git", nil, "ls-tree", "HEAD", "core/Clash.Meta")
	if err != nil {
		return err
	}
	actual, err := run(filepath.Join(coreDir, "Clash.Meta"), "git", nil, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if !strings.Contains(pin, actual) {
		return errors.New("mihomo 子模块不在仓库固定提交")
	}
	dirty, err := run(filepath.Join(coreDir, "Clash.Meta"), "git", nil, "status", "--porcelain")
	if err != nil {
		return err
	}
	if dirty != "" {
		return errors.New("mihomo 子模块有本地改动，拒绝不可复现构建")
	}
	output := filepath.Join(root, "build", "fnos")
	if err = os.MkdirAll(output, 0755); err != nil {
		return err
	}
	work, err := os.MkdirTemp(output, "package-")
	if err != nil {
		return err
	}
	stage := filepath.Join(work, "flclash")
	err = filepath.WalkDir(filepath.Join(root, "fnos", "package"), func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(filepath.Join(root, "fnos", "package"), path)
		if e != nil {
			return e
		}
		mode := os.FileMode(0644)
		if strings.HasPrefix(filepath.ToSlash(rel), "cmd/") {
			mode = 0755
		}
		return copyFile(path, filepath.Join(stage, rel), mode)
	})
	if err != nil {
		return err
	}
	for _, size := range []string{"64", "256"} {
		src := filepath.Join(root, "macos/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_"+size+".png")
		name := "ICON.PNG"
		if size == "256" {
			name = "ICON_256.PNG"
		}
		if err = copyFile(src, filepath.Join(stage, name), 0644); err != nil {
			return err
		}
		if err = copyFile(src, filepath.Join(stage, "app/ui/images/icon_"+size+".png"), 0644); err != nil {
			return err
		}
	}
	for _, name := range []string{"GEOIP.dat", "GEOIP.metadb", "GEOSITE.dat", "ASN.mmdb"} {
		if err = copyFile(filepath.Join(root, "assets/data", name), filepath.Join(stage, "app/data", name), 0644); err != nil {
			return err
		}
	}
	replacements := map[string]string{}
	overlay := func(src, from, to, filename string) error {
		b, e := os.ReadFile(src)
		if e != nil {
			return e
		}
		if strings.Count(string(b), from) != 1 {
			return fmt.Errorf("隔离补丁不再唯一匹配 %s，请人工审核固定核心版本", src)
		}
		dest := filepath.Join(work, filename)
		if e = write(dest, []byte(strings.Replace(string(b), from, to, 1)), 0644); e != nil {
			return e
		}
		replacements[src] = dest
		return nil
	}
	if err = overlay(filepath.Join(coreDir, "Clash.Meta/listener/sing_tun/server.go"), `TableName:              "mihomo",`, `TableName:              "flclash_tun",`, "tun-server.go"); err != nil {
		return err
	}
	singDir, err := run(coreDir, goBin, nil, "list", "-m", "-f", "{{.Dir}}", "github.com/metacubex/sing-tun")
	if err != nil {
		return err
	}
	localSing := filepath.Join(work, "sing-tun")
	err = filepath.WalkDir(singDir, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(singDir, path)
		if e != nil {
			return e
		}
		return copyFile(path, filepath.Join(localSing, rel), 0644)
	})
	if err != nil {
		return err
	}
	singDir = localSing
	modFile := filepath.Join(work, "core.mod")
	if err = copyFile(filepath.Join(coreDir, "go.mod"), modFile, 0644); err != nil {
		return err
	}
	if err = copyFile(filepath.Join(coreDir, "go.sum"), filepath.Join(work, "core.sum"), 0644); err != nil {
		return err
	}
	if _, err = run(coreDir, goBin, nil, "mod", "edit", "-modfile="+modFile, "-replace=github.com/metacubex/sing-tun="+localSing, "-replace=github.com/metacubex/mihomo="+filepath.Join(coreDir, "Clash.Meta")); err != nil {
		return err
	}
	if err = overlay(filepath.Join(singDir, "redirect_linux.go"), "r.useNFTables = false", `return nil, E.Cause(err, "飞牛集成需要 nftables 支持")`, "redirect-linux.go"); err != nil {
		return err
	}
	if err = overlay(filepath.Join(singDir, "redirect_nftables_exprs.go"), `		endAddr := rr.To().Next()
		if !endAddr.IsValid() {
			endAddr = rr.From()
		}
		setElements = append(setElements, nftables.SetElement{
			Key: rr.From().AsSlice(),
		})
		setElements = append(setElements, nftables.SetElement{
			Key:         endAddr.AsSlice(),
			IntervalEnd: true,
		})`, `		setElements = append(setElements, nftables.SetElement{
			Key: rr.From().AsSlice(),
		})
		endAddr := rr.To().Next()
		if endAddr.IsValid() {
			setElements = append(setElements, nftables.SetElement{
				Key:         endAddr.AsSlice(),
				IntervalEnd: true,
			})
		}`, "redirect-nftables-exprs.go"); err != nil {
		return err
	}
	overlayJSON, _ := json.Marshal(map[string]any{"Replace": replacements})
	overlayPath := filepath.Join(work, "overlay.json")
	if err = write(overlayPath, overlayJSON, 0644); err != nil {
		return err
	}
	env := []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOTOOLCHAIN=local"}
	coreOutput := filepath.Join(stage, "app/bin/FlClashCore")
	fmt.Println("构建固定版本核心（飞牛专用隔离覆盖，不修改子模块）…")
	if _, err = run(coreDir, goBin, env, "build", "-trimpath", "-buildvcs=false", "-modfile="+modFile, "-overlay="+overlayPath, "-tags="+values["tags"], "-ldflags="+values["goLdflags"], "-o", coreOutput, "."); err != nil {
		return err
	}
	fmt.Println("构建监督服务和内嵌中文管理页面…")
	if _, err = run(filepath.Join(root, "fnos"), goBin, env, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", filepath.Join(stage, "app/bin/FlClashFnos"), "./cmd/flclash-fnos"); err != nil {
		return err
	}
	if err = copyFile(filepath.Join(root, "fnos/README.md"), filepath.Join(stage, "app/安装与恢复说明.md"), 0644); err != nil {
		return err
	}
	for _, document := range []string{"TESTING.md", "TESTING-0.2.0.md", "TESTING-0.2.1.md", "TESTING-0.3.0.md"} {
		if err = copyFile(filepath.Join(root, "fnos", document), filepath.Join(stage, "app", document), 0644); err != nil {
			return err
		}
	}
	for _, pattern := range []string{"docs/screenshots/*/*.png", "docs/acceptance/*/*.jsonl"} {
		artifacts, err := filepath.Glob(filepath.Join(root, "fnos", pattern))
		if err != nil {
			return err
		}
		for _, artifact := range artifacts {
			rel, err := filepath.Rel(filepath.Join(root, "fnos"), artifact)
			if err != nil {
				return err
			}
			if err = copyFile(artifact, filepath.Join(stage, "app", rel), 0644); err != nil {
				return err
			}
		}
	}
	for _, license := range []struct{ source, target string }{{"LICENSE", "FlClash-LICENSE"}, {"core/Clash.Meta/LICENSE", "mihomo-LICENSE"}} {
		if err = copyFile(filepath.Join(root, license.source), filepath.Join(stage, "app/licenses", license.target), 0644); err != nil {
			return err
		}
	}
	netModule, err := run(filepath.Join(root, "fnos"), goBin, nil, "list", "-m", "-f", "{{.Dir}}", "golang.org/x/net")
	if err != nil {
		return err
	}
	if err = copyFile(filepath.Join(strings.TrimSpace(netModule), "LICENSE"), filepath.Join(stage, "app/licenses", "golang-x-net-LICENSE"), 0644); err != nil {
		return err
	}
	metadata, _ := json.MarshalIndent(map[string]any{"go": version, "fnpack": fpVersion, "mihomoCommit": actual, "buildConfig": values, "target": "linux/amd64/v1", "fnOSMin": "1.2.0505", "isolationOverlay": []string{"独立 nftables 表 flclash_tun", "nftables 初始化失败时拒绝 iptables 回退", "修复最大地址区间触发 nftables EEXIST"}, "hardwareAcceptance": false}, "", "  ")
	if err = write(filepath.Join(stage, "app/build-info.json"), metadata, 0644); err != nil {
		return err
	}
	fmt.Println("使用官方 fnpack 生成 FPK…")
	message, err := run(work, fnpack, nil, "build", "--directory", stage)
	if err != nil {
		return err
	}
	fmt.Println(message)
	var packagePath string
	err = filepath.WalkDir(work, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && strings.HasSuffix(path, ".fpk") {
			packagePath = path
		}
		return nil
	})
	if err != nil {
		return err
	}
	if packagePath == "" {
		return errors.New("fnpack 未生成 FPK")
	}
	final := filepath.Join(output, filename)
	if err = normalizePackage(packagePath, final); err != nil {
		return err
	}
	f, err := os.Open(final)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	f.Close()
	if err != nil {
		return err
	}
	if err = write(final+".sha256", []byte(hex.EncodeToString(hash.Sum(nil))+"  "+filepath.Base(final)+"\n"), 0644); err != nil {
		return err
	}
	if err = write(filepath.Join(output, "build-info.json"), metadata, 0644); err != nil {
		return err
	}
	fmt.Println("安装包已生成：" + final + "；尚未完成 fnOS 实机验收。")
	return nil
}
