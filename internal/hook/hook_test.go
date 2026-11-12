package hook

import (
	"strings"
	"testing"
)

func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
func cc(tool, key, val string) string {
	return `{"tool_name":"` + tool + `","tool_input":{"` + key + `":` + quote(val) + `}}`
}
func omp(tool, key, val string) string {
	return `{"toolName":"` + tool + `","input":{"` + key + `":` + quote(val) + `}}`
}

func TestCheck(t *testing.T) {
	home := `C:\Users\me\.keygate`
	cases := []struct {
		name  string
		in    string
		block bool
	}{
		{"read .env", cc("Read", "file_path", "/app/.env"), true},
		{"read .env.local", cc("Read", "file_path", "/app/.env.local"), true},
		{"read .env.production win", cc("Read", "file_path", `C:\app\.env.production`), true},
		{"read .env.example ok", cc("Read", "file_path", "/app/.env.example"), false},
		{"read .env.sample ok", cc("Read", "file_path", "/app/.env.sample"), false},
		{"read .env.template ok", cc("Read", "file_path", "/app/.env.template"), false},
		{"omp read .env selector", omp("read", "path", "/app/.env:1-5"), true},
		{"read sso", cc("Read", "file_path", "/w/cwallet.sso"), true},
		{"read p12", cc("Read", "file_path", "/w/cert.p12"), true},
		{"read cwallet lck", cc("Read", "file_path", "/w/cwallet.sso.lck"), true},
		{"read kgHome file", cc("Read", "file_path", `C:\Users\me\.keygate\vault.json`), true},
		{"read kgHome fwd slash", cc("Read", "file_path", "C:/Users/me/.keygate/devices/x"), true},
		{"grep in kgHome", cc("Grep", "path", `C:\Users\me\.keygate`), true},
		{"glob env", cc("Glob", "pattern", "**/.env*"), true},
		{"glob p12", cc("Glob", "pattern", "**/*.p12"), true},
		{"omp glob ok", omp("glob", "path", "src/**/*.go"), false},
		{"read README ok", cc("Read", "file_path", "/app/README.md"), false},
		{"write go ok", cc("Write", "file_path", "/app/main.go"), false},
		{"edit environment.ts ok", cc("Edit", "file_path", "/app/environment.ts"), false},
		{"cat .env", cc("Bash", "command", "cat .env"), true},
		{"cat .env.local quoted", cc("Bash", "command", `cat "./cfg/.env.local"`), true},
		{"source .env", omp("bash", "command", "set -a; source .env; set +a"), true},
		{"cat README ok", cc("Bash", "command", "cat README.md"), false},
		{"cat .env.example ok", cc("Bash", "command", "cat .env.example"), false},
		{"cat kgHome", cc("Bash", "command", `type C:\Users\me\.keygate\vault.json`), true},
		{"ls kgHome unix style", cc("Bash", "command", "ls ~/.keygate/"), true},
		{"env alone", cc("Bash", "command", "env"), true},
		{"env pipe grep", cc("Bash", "command", "env | grep KEY"), true},
		{"env run cmd ok", cc("Bash", "command", "env FOO=1 go test ./..."), false},
		{"printenv", cc("Bash", "command", "printenv"), true},
		{"printenv var", cc("Bash", "command", "printenv OPENAI_API_KEY"), true},
		{"set alone", cc("Bash", "command", "set"), true},
		{"set -e ok", cc("Bash", "command", "set -e"), false},
		{"export -p", cc("Bash", "command", "export -p"), true},
		{"bash -c env", cc("Bash", "command", `bash -c "env"`), true},
		{"gci env:", cc("Bash", "command", "gci env:"), true},
		{"Get-ChildItem Env:", cc("Bash", "command", "powershell -Command \"Get-ChildItem Env:\""), true},
		{"ls env:", cc("Bash", "command", "ls env:"), true},
		{"$env: listing", cc("Bash", "command", "Get-Member -InputObject $env:"), true},
		{"GetEnvironmentVariables", cc("Bash", "command", `[Environment]::GetEnvironmentVariables()`), true},
		{"proc environ", cc("Bash", "command", "cat /proc/self/environ"), true},
		{"echo $PATH ok", cc("Bash", "command", "echo $PATH"), false},
		{"echo $env:PATH ok", cc("Bash", "command", "echo $env:PATH"), false},
		{"git commit env var ok", cc("Bash", "command", `git commit -m "fix env var"`), false},
		{"kg reveal", cc("Bash", "command", "kg reveal llm/openai"), true},
		{"kg.exe reveal", cc("Bash", "command", `C:\bin\kg.exe reveal x`), true},
		{"kg run ok", cc("Bash", "command", "kg run --secret db/test -- sql /@HTTEST @x.sql"), false},
		{"sql user/pass@tns", cc("Bash", "command", "sql scott/tiger@HTTEST @x.sql"), true},
		{"sqlplus conn string", cc("Bash", "command", "sqlplus apps/Secret1@//host:1521/EBS"), true},
		{"sql wallet ok", cc("Bash", "command", "sql /@HTTEST @x.sql"), false},
		{"sql nolog ok", cc("Bash", "command", "sql /nolog"), false},
		{"scoped npm ok", cc("Bash", "command", "npm i @scope/pkg@1.2.3"), false},
		{"git ssh url ok", cc("Bash", "command", "git clone git@github.com:org/repo.git"), false},
		{"mysql -p", cc("Bash", "command", "mysql -u root -pS3cret db"), true},
		{"mysql -p prompt ok", cc("Bash", "command", "mysql -u root -p db"), false},
		{"--password=", cc("Bash", "command", "tool --password=abc123 run"), true},
		{"--password x", cc("Bash", "command", "tool --password abc123"), true},
		{"--password-stdin ok", cc("Bash", "command", "docker login --password-stdin"), false},
		{"mkdir -p ok", cc("Bash", "command", "mkdir -p out/dir"), false},
		{"cp -pr ok", cc("Bash", "command", "cp -pr a b"), false},
		{"docker -p port ok", cc("Bash", "command", "docker run -p8080:80 nginx"), false},
		{"bearer long", cc("Bash", "command", `curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456" x`), true},
		{"bearer var ok", cc("Bash", "command", `curl -H "Authorization: Bearer $TOKEN" x`), false},
		{"bearer short ok", cc("Bash", "command", `curl -H "Authorization: Bearer abc" x`), false},
		{"PASSWORD=", cc("Bash", "command", "DB_PASSWORD=hunter2 ./run.sh"), true},
		{"PASSWORD= empty ok", cc("Bash", "command", "echo PASSWORD="), false},
		{"IDENTIFIED BY", cc("Bash", "command", `sql -S x "alter user a identified by Foo123"`), true},
		{"plain ls ok", cc("Bash", "command", "ls -la"), false},
		{"go test ok", omp("bash", "command", "go test ./... -count=1"), false},
		{"unknown tool ok", `{"tool_name":"Task","tool_input":{"prompt":"hi"}}`, false},
		{"no input ok", `{"tool_name":"Bash"}`, false},
		// --- M10: globs and *.env
		{"cat .e*", cc("Bash", "command", "cat .e*"), true},
		{"cat .en?", cc("Bash", "command", "cat .en?"), true},
		{"cat prod.env", cc("Bash", "command", "cat config/prod.env"), true},
		{"read prod.env", cc("Read", "file_path", "/a/prod.env"), true},
		{"glob .e*", cc("Glob", "pattern", ".e*"), true},
		{"find exec cat dotenv", cc("Bash", "command", `find . -name '.env*' -exec cat {} +`), true},
		{"find iname glob", cc("Bash", "command", `find . -iname ".e*" -exec cat {} +`), true},
		{"cp dotenv", cc("Bash", "command", "cp .env /tmp/x.txt"), true},
		{"cp dotenv glob", cc("Bash", "command", "cp .e* /tmp/x"), true},
		{"omp multi-path", omp("read", "path", "README.md;.env"), true},
		{"omp multi-path ok", omp("read", "path", "README.md;main.go"), false},
		{"omp paths array", `{"toolName":"read","input":{"paths":["a.go",".env.local"]}}`, true},
		{"ls star ok", cc("Bash", "command", "ls *"), false},
		{"ls star.go ok", cc("Bash", "command", "ls *.go"), false},
		{"dir *.* ok", cc("Bash", "command", "dir *.*"), false},
		{"grep process.env ok", cc("Bash", "command", "grep process.env src/a.ts"), false},
		{"grep regex tool ok", cc("Grep", "pattern", `\.env`), false},
		{"webfetch file url", `{"tool_name":"WebFetch","tool_input":{"url":"file:///C:/app/.env"}}`, true},
		{"webfetch https ok", `{"tool_name":"WebFetch","tool_input":{"url":"https://example.com/.env"}}`, false},
		{"notebook .env", `{"tool_name":"NotebookEdit","tool_input":{"notebook_path":"/a/.env"}}`, true},
		// --- M10: recursive grep / rg
		{"grep -r PASSWORD", cc("Bash", "command", "grep -r PASSWORD ."), true},
		{"grep -rni secret", cc("Bash", "command", "grep -rni secret /app"), true},
		{"grep --recursive token", cc("Bash", "command", "grep --recursive token ."), true},
		{"rg PASSWORD", cc("Bash", "command", "rg PASSWORD"), true},
		{"rg --hidden", cc("Bash", "command", "rg --hidden foo"), true},
		{"rg -uu", cc("Bash", "command", "rg -uu foo"), true},
		{"findstr /s", cc("Bash", "command", "findstr /s /i password *.*"), true},
		{"sls recurse", cc("Bash", "command", "Get-ChildItem -Recurse | Select-String password"), true},
		{"grep -r TODO ok", cc("Bash", "command", "grep -r TODO ."), false},
		{"rg foo ok", cc("Bash", "command", "rg foo"), false},
		{"grep password one file ok", cc("Bash", "command", "grep password main.go"), false},
		// --- M10: interpreters and env dumps
		{"python os.environ", cc("Bash", "command", `python -c "import os;print(os.environ)"`), true},
		{"python3 getenv", cc("Bash", "command", `python3 -c 'import os; print(os.getenv("X"))'`), true},
		{"node process.env", cc("Bash", "command", `node -p process.env`), true},
		{"node -e env", cc("Bash", "command", `node -e "console.log(process.env.KEY)"`), true},
		{"perl %ENV", cc("Bash", "command", `perl -e 'print %ENV'`), true},
		{"ruby ENV", cc("Bash", "command", `ruby -e 'puts ENV.to_h'`), true},
		{"python script ok", cc("Bash", "command", "python script.py"), false},
		{"node script ok", cc("Bash", "command", "node build.js --prod"), false},
		{"declare -p", cc("Bash", "command", "declare -p"), true},
		{"declare -x", cc("Bash", "command", "declare -x"), true},
		{"compgen -v", cc("Bash", "command", "compgen -v"), true},
		{"cmd /c set", cc("Bash", "command", "cmd /c set > f.txt"), true},
		{"cmd /c set quoted", cc("Bash", "command", `cmd.exe /c "set"`), true},
		{"bash -c env redirect", cc("Bash", "command", `bash -c "env > f" && echo done`), true},
		{"bash -lc printenv mid", cc("Bash", "command", `echo a; bash -lc 'printenv | sort'; echo b`), true},
		{"bash -c harmless ok", cc("Bash", "command", `bash -c "set -e; make"`), false},
		{"bash -c env cmd ok", cc("Bash", "command", `bash -c "env FOO=1 make"`), false},
		{"subshell env", cc("Bash", "command", `echo "$(env)"`), true},
		{"backtick env", cc("Bash", "command", "echo `env`"), true},
		{"env redirect", cc("Bash", "command", "env > out.txt"), true},
		{"ps eww", cc("Bash", "command", "ps eww"), true},
		{"ps e", cc("Bash", "command", "ps e"), true},
		{"ps axe", cc("Bash", "command", "ps axe"), true},
		{"ps aux ok", cc("Bash", "command", "ps aux"), false},
		{"ps -ef ok", cc("Bash", "command", "ps -ef"), false},
		{"proc environ pid", cc("Bash", "command", "cat /proc/1234/environ"), true},
		// --- M10: KG_HOME and temp material
		{"glob .keyg*", cc("Bash", "command", "cd ~; cat .keyg*/policy.yaml"), true},
		{"Join-Path HOME", cc("Bash", "command", `Get-Content (Join-Path $HOME '.keygate\policy.yaml')`), true},
		{"Join-Path only", cc("Bash", "command", `Join-Path $HOME '.keygate'`), true},
		{"$HOME/.keygate", cc("Bash", "command", "ls $HOME/.keygate"), true},
		{"%USERPROFILE%", cc("Bash", "command", `dir %USERPROFILE%\.keygate`), true},
		{"KG_HOME var", cc("Bash", "command", `ls "$KG_HOME/run"`), true},
		{"KG_HOME win var", cc("Bash", "command", `dir %KG_HOME%\run`), true},
		{"KG_HOME run dir", cc("Read", "file_path", `C:\Users\me\.keygate\run\kg-file-1\secret.txt`), true},
		{"temp kg-file", cc("Bash", "command", `type %TEMP%\kg-file-*\secret.txt`), true},
		{"temp kg-wallet", cc("Bash", "command", `ls /tmp/kg-wallet-123/`), true},
		{"read kg-wallet", cc("Read", "file_path", `C:\Users\me\AppData\Local\Temp\kg-wallet-99\cwallet.sso`), true},
		{"mac security", cc("Bash", "command", "security find-generic-password -s keygate -w"), true},
		{"nc -U", cc("Bash", "command", "nc -U /x/broker.sock"), true},
		{"socat", cc("Bash", "command", "socat - UNIX-CONNECT:s.sock"), true},
		{"python socket", cc("Bash", "command", `python -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('broker.sock')"`), true},
		{"curl unix-socket", cc("Bash", "command", "curl --unix-socket s.sock http://x/"), true},
		{"git .keygate-notes ok", cc("Bash", "command", "git add notes.md"), false},
		// --- M10: kg reveal variants
		{"bash -c kg reveal", cc("Bash", "command", `bash -c "kg reveal db/x"`), true},
		{"backtick kg reveal", cc("Bash", "command", "echo `kg reveal db/x`"), true},
		{"subshell kg reveal", cc("Bash", "command", "echo $(kg reveal db/x)"), true},
		{"quoted kg reveal", cc("Bash", "command", `kg "reveal" db/x`), true},
		{"quoted kg binary reveal", cc("Bash", "command", `"kg" 'reveal' db/x`), true},
		{"kg status ok", cc("Bash", "command", "kg status"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, reason, err := Check([]byte(c.in), home)
			if err != nil {
				t.Fatal(err)
			}
			if b != c.block {
				t.Fatalf("blocked=%v want %v (reason=%q)", b, c.block, reason)
			}
			if b && !strings.Contains(reason, "kg run --secret") {
				t.Fatalf("reason lacks guidance: %q", reason)
			}
		})
	}
}

func TestCheckBadJSON(t *testing.T) {
	if _, _, err := Check([]byte("{nope"), ""); err == nil {
		t.Fatal("want error")
	}
}

func TestEmptyHomeNoPanic(t *testing.T) {
	b, _, err := Check([]byte(cc("Read", "file_path", "/x/y.txt")), "")
	if err != nil || b {
		t.Fatal(b, err)
	}
}
