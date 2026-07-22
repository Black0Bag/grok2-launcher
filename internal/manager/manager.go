package manager

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Black0Bag/grok2-launcher/internal/embed"
	"github.com/Black0Bag/grok2-launcher/internal/logger"
)

type Status int

const (
	Stopped  Status = iota
	Starting
	Running
	Failed
)

type ServiceState struct {
	Grok2api Status `json:"grok2api"`
	WebUI    Status `json:"webui"`
}

type Manager struct {
	WorkDir       string
	PythonPath    string
	ProxyPort     int
	ProxyEnabled  bool
	YescaptchaKey string
	TempmailKey   string

	ctx    context.Context
	cancel context.CancelFunc
	state  ServiceState
}

func New(workDir, pythonPath string, proxyPort int, proxyEnabled bool, ycKey, tmKey string) *Manager {
	return &Manager{
		WorkDir:       workDir,
		PythonPath:    pythonPath,
		ProxyPort:     proxyPort,
		ProxyEnabled:  proxyEnabled,
		YescaptchaKey: ycKey,
		TempmailKey:   tmKey,
	}
}

func (m *Manager) State() ServiceState { return m.state }

func (m *Manager) log(lvl logger.Level, msg string, args ...interface{}) {
	logger.Global.Write(lvl, msg, args...)
}

func (m *Manager) logPipe(prefix string, r io.Reader) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				m.log(logger.Info, "[%s] %s", prefix, line)
			}
		}
		if err != nil {
			break
		}
	}
}

func (m *Manager) runCmd(name string, args ...string) *exec.Cmd {
	return exec.CommandContext(m.ctx, name, args...)
}

func (m *Manager) Start(ctx context.Context) {
	m.ctx, m.cancel = context.WithCancel(ctx)

	m.log(logger.Info, "正在释放内嵌文件到工作目录...")
	os.MkdirAll(filepath.Join(m.WorkDir, "python"), 0755)
	os.MkdirAll(filepath.Join(m.WorkDir, "provision"), 0755)
	if err := embed.ExtractPython(m.WorkDir); err != nil {
		m.log(logger.Error, "释放 Python 文件失败: %v", err)
	}
	if err := embed.ExtractProvision(m.WorkDir); err != nil {
		m.log(logger.Error, "释放 provision 脚本失败: %v", err)
	}
	if err := embed.ExtractGrok2Api(m.WorkDir); err != nil {
		m.log(logger.Error, "释放 grok2api.exe 失败: %v", err)
	}
	m.log(logger.Ok, "文件释放完成")

	m.startGrok2api()
	if m.state.Grok2api != Running {
		m.log(logger.Warn, "grok2api 未就绪，跳过后续步骤")
		return
	}
	m.setupPython()
	m.startWebUI()
	m.runProvision()
	m.log(logger.Ok, "全部就绪！")
}

func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.state = ServiceState{}
	m.log(logger.Info, "所有服务已停止")
}

func (m *Manager) HealthzGrok2api() bool {
	resp, err := http.Get("http://127.0.0.1:8000/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (m *Manager) generateConfig() error {
	cfgPath := filepath.Join(m.WorkDir, "config.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		m.log(logger.Info, "config.yaml 已存在，跳过生成")
		return nil
	}

	adminPass := randomBase64(12)
	yaml := fmt.Sprintf(`server:
  listen: "0.0.0.0:8000"
  maxBodyBytes: "32MiB"
  readTimeout: "15m"
  requestTimeout: "2h"
  swaggerEnabled: false

auth:
  accessTokenTTL: "15m"
  refreshTokenTTL: "720h"
  secureCookies: false

secrets:
  jwtSecret: "%s"
  credentialEncryptionKey: "%s"

bootstrapAdmin:
  username: "admin"
  password: "%s"

frontend:
  staticPath: "./frontend/dist"

database:
  driver: "sqlite"
  sqlite:
    path: "./data/grok2api.db"

runtimeStore:
  driver: "memory"

media:
  driver: "local"
  local:
    path: "./data/media"
`,
		randomHex(32),
		randomBase64(32),
		adminPass,
	)

	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		return err
	}

	credPath := filepath.Join(m.WorkDir, "grok2api-admin-credentials.txt")
	cred := fmt.Sprintf("url: http://127.0.0.1:8000\nusername: admin\npassword: %s\n", adminPass)
	os.WriteFile(credPath, []byte(cred), 0644)

	m.log(logger.Ok, "config.yaml + 管理员凭证已生成 (密码保存在 grok2api-admin-credentials.txt)")
	return nil
}

func (m *Manager) startGrok2api() {
	m.state.Grok2api = Starting
	m.log(logger.Info, "正在启动 grok2api...")

	if err := m.generateConfig(); err != nil {
		m.log(logger.Error, "生成 config.yaml 失败: %v", err)
		m.state.Grok2api = Failed
		return
	}

	grokBin := filepath.Join(m.WorkDir, "grok2api.exe")
	if info, err := os.Stat(grokBin); err != nil || info.Size() == 0 {
		m.log(logger.Error, "grok2api.exe 不存在或为空文件。请在 CI 中重新编译，或手动放入: %s", grokBin)
		m.state.Grok2api = Failed
		return
	}

	cmd := m.runCmd(grokBin,
		"--config", filepath.Join(m.WorkDir, "config.yaml"),
		"--listen", "0.0.0.0:8000",
	)
	cmd.Dir = m.WorkDir
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		m.log(logger.Error, "grok2api 启动失败: %v", err)
		m.state.Grok2api = Failed
		return
	}
	go m.logPipe("grok2api", stdout)
	go m.logPipe("grok2api", stderr)

	m.log(logger.Info, "等待 grok2api 就绪 (健康检查)...")
	for i := 0; i < 30; i++ {
		select {
		case <-m.ctx.Done():
			return
		default:
		}
		if m.HealthzGrok2api() {
			m.state.Grok2api = Running
			m.log(logger.Ok, "grok2api 已就绪 → http://127.0.0.1:8000")
			return
		}
		time.Sleep(2 * time.Second)
	}
	m.log(logger.Warn, "grok2api 健康检查超时，请查看上方日志排查")
	m.state.Grok2api = Failed
}

func (m *Manager) setupPython() {
	m.log(logger.Info, "正在配置 Python 环境...")

	if _, err := os.Stat(m.PythonPath); os.IsNotExist(err) {
		m.log(logger.Error, "Python 路径不存在: %s", m.PythonPath)
		return
	}

	pyDir := filepath.Dir(m.PythonPath)
	pthFile := filepath.Join(pyDir, "python._pth")
	if data, err := os.ReadFile(pthFile); err == nil {
		content := string(data)
		if strings.Contains(content, "#import site") {
			content = strings.ReplaceAll(content, "#import site", "import site")
			os.WriteFile(pthFile, []byte(content), 0644)
			m.log(logger.Ok, "已启用 site-packages (修改 python._pth)")
		}
	}

	getPip := filepath.Join(m.WorkDir, "get-pip.py")
	if _, err := os.Stat(getPip); os.IsNotExist(err) {
		m.log(logger.Info, "正在下载 get-pip.py...")
		resp, err := http.Get("https://bootstrap.pypa.io/get-pip.py")
		if err != nil {
			m.log(logger.Error, "下载 get-pip.py 失败: %v", err)
			return
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		os.WriteFile(getPip, data, 0644)
		m.log(logger.Ok, "get-pip.py 已下载")
	}

	m.log(logger.Info, "正在安装 pip...")
	cmd := m.runCmd(m.PythonPath, getPip, "--no-warn-script-location")
	cmd.Dir = m.WorkDir
	out, _ := cmd.CombinedOutput()
	m.log(logger.Info, "pip 安装: %s", strings.TrimSpace(string(out)))

	m.log(logger.Info, "正在安装 Python 依赖 (curl_cffi, requests)...")
	reqFile := filepath.Join(m.WorkDir, "python", "requirements.txt")
	cmd = m.runCmd(m.PythonPath, "-m", "pip", "install", "-r", reqFile)
	cmd.Dir = m.WorkDir
	if out, err := cmd.CombinedOutput(); err != nil {
		m.log(logger.Warn, "pip install 输出: %s", strings.TrimSpace(string(out)))
	} else {
		m.log(logger.Ok, "Python 依赖安装完成")
	}

	m.log(logger.Info, "验证 curl_cffi...")
	cmd = m.runCmd(m.PythonPath, "-c", "import curl_cffi; print('OK')")
	if out, err := cmd.CombinedOutput(); err != nil {
		m.log(logger.Warn, "curl_cffi 导入失败，可能需要 VC++ 运行库: %s", strings.TrimSpace(string(out)))
	} else {
		m.log(logger.Ok, "curl_cffi 可用")
	}
}

func (m *Manager) startWebUI() {
	m.state.WebUI = Starting
	m.log(logger.Info, "正在启动注册控制台...")

	webuiPath := filepath.Join(m.WorkDir, "python", "webui.py")
	if _, err := os.Stat(webuiPath); os.IsNotExist(err) {
		m.log(logger.Error, "webui.py 不存在: %s", webuiPath)
		m.state.WebUI = Failed
		return
	}

	env := os.Environ()
	env = append(env, fmt.Sprintf("YESCAPTCHA_API_KEY=%s", m.YescaptchaKey))
	env = append(env, fmt.Sprintf("TEMPMAIL_API_KEY=%s", m.TempmailKey))
	env = append(env, "WEBUI_HOST=127.0.0.1")
	env = append(env, "WEBUI_PORT=8765")
	if m.ProxyEnabled && m.ProxyPort > 0 {
		proxyUrl := fmt.Sprintf("http://127.0.0.1:%d", m.ProxyPort)
		env = append(env, fmt.Sprintf("HTTPS_PROXY=%s", proxyUrl))
		env = append(env, fmt.Sprintf("HTTP_PROXY=%s", proxyUrl))
	}

	cmd := m.runCmd(m.PythonPath, "-u", webuiPath)
	cmd.Dir = filepath.Join(m.WorkDir, "python")
	cmd.Env = env
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		m.log(logger.Error, "WebUI 启动失败: %v", err)
		m.state.WebUI = Failed
		return
	}
	go m.logPipe("webui", stdout)
	go m.logPipe("webui", stderr)

	m.state.WebUI = Running
	m.log(logger.Ok, "注册控制台已启动 → http://127.0.0.1:8765")
}

func (m *Manager) runProvision() {
	provPath := filepath.Join(m.WorkDir, "provision", "grok2api_provision.py")
	if _, err := os.Stat(provPath); os.IsNotExist(err) {
		m.log(logger.Warn, "provision 脚本不存在，跳过")
		return
	}

	m.log(logger.Info, "正在初始化 grok2api (创建 API Key + 导入账号)...")
	cmd := m.runCmd(m.PythonPath, "-u", provPath,
		"--base-url", "http://127.0.0.1:8000",
		"--user", "admin",
		"--password", "admin",
		"--key-name", "default",
	)
	cmd.Dir = m.WorkDir
	if out, err := cmd.CombinedOutput(); err != nil {
		m.log(logger.Warn, "provision 输出: %s", strings.TrimSpace(string(out)))
	} else {
		m.log(logger.Ok, "grok2api 初始化完成")
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func randomBase64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	s := base64.URLEncoding.EncodeToString(b)
	s = strings.NewReplacer("+", "A", "/", "B", "=", "").Replace(s)
	return s
}
