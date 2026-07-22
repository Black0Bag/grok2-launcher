package embed

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed webui/index.html
var WebUI embed.FS

//go:embed grok2api.exe
var Grok2ApiExe []byte

//go:embed python
var pythonFS embed.FS

//go:embed provision
var provisionFS embed.FS

func ExtractPython(dstDir string) error {
	return extractFS(pythonFS, "python", filepath.Join(dstDir, "python"))
}

func ExtractProvision(dstDir string) error {
	return extractFS(provisionFS, "provision", filepath.Join(dstDir, "provision"))
}

func ExtractGrok2Api(dstDir string) error {
	return os.WriteFile(filepath.Join(dstDir, "grok2api.exe"), Grok2ApiExe, 0755)
}

func WebUIFile() ([]byte, error) {
	return WebUI.ReadFile("webui/index.html")
}

func extractFS(src embed.FS, srcDir, dstDir string) error {
	return fs.WalkDir(src, srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := src.ReadFile(path)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		return os.WriteFile(target, data, 0644)
	})
}
