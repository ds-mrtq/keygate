package execwrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"keygate/internal/redact"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const pkiClass = "oracle.security.pki.OracleSecretStoreTextUI"

var javaVersionRe = regexp.MustCompile(`version "(\d+)(?:\.(\d+))?`)

// JavaMajor runs `java -version` and returns the major version (8 for "1.8.x").
func JavaMajor(javaExe string) (int, error) {
	out, err := exec.Command(javaExe, "-version").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("%s -version: %w", javaExe, err)
	}
	m := javaVersionRe.FindSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("không đọc được phiên bản java từ %s", javaExe)
	}
	maj, _ := strconv.Atoi(string(m[1]))
	if maj == 1 && len(m[2]) > 0 {
		maj, _ = strconv.Atoi(string(m[2]))
	}
	return maj, nil
}

func javaExeName() string {
	if os.PathSeparator == '\\' {
		return "java.exe"
	}
	return "java"
}

// FindJava resolves the java executable: config, JAVA_HOME (>= 11), Eclipse Adoptium, PATH (>= 11).
func FindJava(cfg Config) (string, error) {
	if cfg.Java != "" {
		if _, err := os.Stat(cfg.Java); err != nil {
			return "", fmt.Errorf("oracle.java không tồn tại: %w", err)
		}
		return cfg.Java, nil
	}
	ok := func(exe string) bool {
		if _, err := os.Stat(exe); err != nil {
			return false
		}
		v, err := JavaMajor(exe)
		return err == nil && v >= 11
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		if exe := filepath.Join(jh, "bin", javaExeName()); ok(exe) {
			return exe, nil
		}
	}
	cands, _ := filepath.Glob(filepath.Join("C:\\", "Program Files", "Eclipse Adoptium", "*", "bin", "java.exe"))
	sort.Sort(sort.Reverse(sort.StringSlice(cands)))
	for _, exe := range cands {
		if ok(exe) {
			return exe, nil
		}
	}
	if exe, err := exec.LookPath("java"); err == nil && ok(exe) {
		return exe, nil
	}
	return "", errors.New("không tìm thấy JDK >= 11 (đặt oracle.java trong vault.json)")
}

// FindPkiJar resolves oraclepki.jar: config, else <SQLcl>/lib/oraclepki.jar via `sql` on PATH.
func FindPkiJar(cfg Config) (string, error) {
	if cfg.PkiJar != "" {
		if _, err := os.Stat(cfg.PkiJar); err != nil {
			return "", fmt.Errorf("oracle.pki_jar không tồn tại: %w", err)
		}
		return cfg.PkiJar, nil
	}
	for _, name := range []string{"sql", "sql.exe"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		jar := filepath.Join(filepath.Dir(filepath.Dir(p)), "lib", "oraclepki.jar")
		if _, err := os.Stat(jar); err == nil {
			return jar, nil
		}
	}
	return "", errors.New("không tìm thấy oraclepki.jar (đặt oracle.pki_jar trong vault.json, hoặc để SQLcl `sql` trên PATH)")
}

// FindTNSAdmin resolves the directory holding tnsnames.ora: config, $TNS_ADMIN,
// C:/DevSuiteHome_1/network/admin, $ORACLE_HOME/network/admin.
func FindTNSAdmin(cfg Config) (string, error) {
	var cands []string
	if cfg.TNSAdmin != "" {
		cands = append(cands, cfg.TNSAdmin)
	}
	if v := os.Getenv("TNS_ADMIN"); v != "" {
		cands = append(cands, v)
	}
	cands = append(cands, "C:/DevSuiteHome_1/network/admin")
	if oh := os.Getenv("ORACLE_HOME"); oh != "" {
		cands = append(cands, filepath.Join(oh, "network", "admin"))
	}
	for _, d := range cands {
		if _, err := os.Stat(filepath.Join(d, "tnsnames.ora")); err == nil {
			return d, nil
		}
	}
	return "", errors.New("không tìm thấy tnsnames.ora (đặt oracle.tns_admin trong vault.json hoặc TNS_ADMIN)")
}

// pki runs OracleSecretStoreTextUI with every password on stdin (never on argv).
func pki(ctx context.Context, java, jar string, stdin string, scrub func(string) string, args ...string) error {
	full := append([]string{"-cp", jar, pkiClass}, args...)
	cmd := exec.CommandContext(ctx, java, full...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if scrub != nil {
			msg = scrub(msg)
		}
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return fmt.Errorf("OracleSecretStoreTextUI %s: %w: %s", args[2], err, msg)
	}
	return nil
}

// testWalletPasswordHook is set only by tests to read back the generated wallet password.
var testWalletPasswordHook func(string)

// makeWallet creates the temp wallet dir with wallet + tnsnames.ora + sqlnet.ora.
func (e *Env) makeWallet(ctx context.Context, cfg Config, wallets []Secret) (string, error) {
	java, err := FindJava(cfg)
	if err != nil {
		return "", err
	}
	jar, err := FindPkiJar(cfg)
	if err != nil {
		return "", err
	}
	tns, err := FindTNSAdmin(cfg)
	if err != nil {
		return "", err
	}
	dir, err := cfg.mkTemp("kg-wallet-")
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	e.dirs = append(e.dirs, dir)
	e.mu.Unlock()
	wpw, err := RandomPassword(24)
	if err != nil {
		return "", err
	}
	if testWalletPasswordHook != nil {
		testWalletPasswordHook(wpw)
	}
	rs := []redact.Secret{{Name: "wallet", Value: wpw}}
	for _, w := range wallets {
		rs = append(rs, redact.Secret{Name: w.Name, Value: w.Value})
	}
	rd := redact.New(rs)
	scrub := rd.String
	if err := pki(ctx, java, jar, wpw+"\n"+wpw+"\n", scrub, "-wrl", dir, "-create"); err != nil {
		return "", err
	}
	for _, w := range wallets {
		if strings.ContainsAny(w.Value, "\r\n") {
			return "", fmt.Errorf("secret %q: mật khẩu chứa xuống dòng, không thể nạp vào wallet", w.Name)
		}
		in := w.Value + "\n" + w.Value + "\n" + wpw + "\n"
		if err := pki(ctx, java, jar, in, scrub, "-wrl", dir, "-createCredential", w.TNSAlias, w.User); err != nil {
			return "", err
		}
	}
	tb, err := os.ReadFile(filepath.Join(tns, "tnsnames.ora"))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "tnsnames.ora"), tb, 0o600); err != nil {
		return "", err
	}
	sqlnet := fmt.Sprintf("WALLET_LOCATION = (SOURCE = (METHOD = FILE) (METHOD_DATA = (DIRECTORY = %s)))\nSQLNET.WALLET_OVERRIDE = TRUE\n", filepath.ToSlash(dir))
	if err := os.WriteFile(filepath.Join(dir, "sqlnet.ora"), []byte(sqlnet), 0o600); err != nil {
		return "", err
	}
	// JDBC thin (SQLcl) ignores sqlnet.ora WALLET_LOCATION; it reads ojdbc.properties in TNS_ADMIN.
	ojdbc := fmt.Sprintf("oracle.net.wallet_location=(source=(method=file)(method_data=(directory=%s)))\n", filepath.ToSlash(dir))
	if err := os.WriteFile(filepath.Join(dir, "ojdbc.properties"), []byte(ojdbc), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

var tmplRe = regexp.MustCompile(`\$\{secret:([^}\s]+)\}`)

// TemplateNames lists the distinct ${secret:NAME} names in tmpl (first-seen order).
func TemplateNames(tmpl string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range tmplRe.FindAllStringSubmatch(tmpl, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// ResolveTemplate substitutes ${secret:NAME}; a missing name is an error (names only, no values).
func ResolveTemplate(tmpl string, values map[string]string) (string, error) {
	var missing []string
	out := tmplRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := tmplRe.FindStringSubmatch(m)[1]
		v, ok := values[name]
		if !ok {
			missing = append(missing, name)
			return m
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("template tham chiếu secret chưa cấp: %s", strings.Join(missing, ", "))
	}
	return out, nil
}
