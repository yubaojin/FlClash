package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradeAndUninstallRequireGatewayConfirmation(t *testing.T) {
	for _, name := range []string{"upgrade", "uninstall"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "package", "wizard", name))
			if err != nil {
				t.Fatal(err)
			}
			var steps []struct {
				Items []struct {
					Field     string `json:"field"`
					InitValue string `json:"initValue"`
					Options   []struct {
						Value string `json:"value"`
					} `json:"options"`
				} `json:"items"`
			}
			if err = json.Unmarshal(data, &steps); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, step := range steps {
				for _, item := range step.Items {
					if item.Field != "wizard_gateway_restored" {
						continue
					}
					if item.InitValue != "false" {
						t.Fatal("不能默认确认网关已恢复")
					}
					for _, option := range item.Options {
						found = found || option.Value == "true"
					}
				}
			}
			if !found {
				t.Fatal("向导没有提供卸载阶段需要的网关确认字段")
			}
		})
	}
}
