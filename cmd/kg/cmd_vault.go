package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"keygate/internal/approve"
	"keygate/internal/audit"
	"keygate/internal/broker"
	"keygate/internal/broker/wire"
	"keygate/internal/brokerclient"
	"keygate/internal/channel"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/recovery"
	"keygate/internal/store"
	"keygate/internal/transport"
	"keygate/internal/transport/dir"
	"keygate/internal/transport/git"
	"keygate/internal/transport/relay"
)

const minMasterLen = 12

type chanFlags struct {
	via, dir, gitDir, relayURL *string
}

func addChanFlags(fs interface {
	String(string, string, string) *string
}) chanFlags {
	return chanFlags{
		via:      fs.String("via", "", "dir|git|relay"),
		dir:      fs.String("dir", "", "thư mục đồng bộ dùng chung"),
		gitDir:   fs.String("git-dir", "", "git work tree dùng làm kênh"),
		relayURL: fs.String("relay-url", "", "URL relay"),
	}
}

func (c chanFlags) any() bool { return *c.dir != "" || *c.gitDir != "" || *c.relayURL != "" }

func (c chanFlags) apply(cfg *store.VaultConfig) {
	if *c.dir != "" {
		cfg.SyncDir = absPath(*c.dir)
	}
	if *c.gitDir != "" {
		cfg.GitDir = absPath(*c.gitDir)
	}
	if *c.relayURL != "" {
		cfg.RelayURL = *c.relayURL
	}
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func (a *app) cmdInit(args []string) error {
	fs := newFS("init", a.errw)
	label := fs.String("label", "", "nhãn thiết bị, vd laptop (không chứa tên hệ thống/secret)")
	cf := addChanFlags(fs)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *label == "" || len(*label) > members.MaxLabel {
		return errors.New("cần --label <nhãn thiết bị>")
	}
	if _, err := os.Stat(filepath.Join(a.home, "vault.json")); err == nil {
		return fmt.Errorf("%s đã có vault", a.home)
	}
	pwd, err := a.readSecret("Mật khẩu chủ (>= 12 ký tự): ", true)
	if err != nil {
		return err
	}
	if len([]rune(pwd)) < minMasterLen {
		return fmt.Errorf("mật khẩu chủ cần ít nhất %d ký tự", minMasterLen)
	}
	pwd2, err := a.readSecret("Nhập lại mật khẩu chủ: ", true)
	if err != nil {
		return err
	}
	if pwd != pwd2 {
		return errors.New("hai lần nhập mật khẩu không khớp")
	}
	vault := kcrypto.NewVaultID()
	setup, err := recovery.NewSetup(vault, pwd, kcrypto.DefaultArgon2)
	if err != nil {
		return err
	}
	id := store.NewIdentity(*label)
	ks, err := a.openKeys()
	if err != nil {
		return err
	}
	if err := store.SaveIdentity(a.home, id, ks); err != nil {
		return err
	}
	st, err := store.Init(a.home, vault, id, setup.Keys, setup.Salt, setup.Params, time.Now())
	if err != nil {
		return err
	}
	defer st.Close()
	cfg := st.Config()
	cf.apply(&cfg)
	if err := st.SaveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã tạo vault %s, thiết bị %s (%s).\n\n", vault, id.Dev, *label)
	fmt.Fprintf(a.out, "KHÓA GIẤY (chỉ hiện một lần, cất ở nơi an toàn ngoài máy này):\n\n    %s\n\n", setup.PaperKey)
	fmt.Fprintln(a.out, "Thao tác owner (thêm/thu hồi thiết bị, khôi phục) cần cả mật khẩu chủ và khóa giấy.")
	if _, err := channel.Pick(cfg, *cf.via); err == nil {
		ctx := context.Background()
		if err := channel.PushMembersAsOwner(ctx, st, *cf.via, setup.Keys.OwnerPriv); err != nil {
			return err
		}
		r, err := channel.Sync(ctx, st, *cf.via, "")
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Đã đẩy lên kênh %s.\n", r.Channel)
	}
	return nil
}

func (a *app) ownerKeys(st *store.Store) (*recovery.Keys, error) {
	pwd, err := a.readSecret("Mật khẩu chủ: ", true)
	if err != nil {
		return nil, err
	}
	pk, err := a.readSecret("Khóa giấy: ", true)
	if err != nil {
		return nil, err
	}
	raw, err := recovery.ParsePaperKey(pk)
	if err != nil {
		return nil, err
	}
	ms := st.Members()
	return recovery.Derive(ms.Vault, pwd, ms.ArgonSalt, ms.ArgonParams, raw)
}

func (a *app) cmdDevice(args []string) error {
	if len(args) == 0 {
		return errors.New("dùng: kg device request|add|list|pair-url|revoke")
	}
	switch args[0] {
	case "request":
		return a.deviceRequest(args[1:])
	case "add":
		return a.deviceAdd(args[1:])
	case "pair-url":
		return a.devicePairURL(args[1:])
	case "list":
		return a.deviceList(args[1:])
	case "revoke":
		return a.deviceRevoke(args[1:])
	}
	return fmt.Errorf("lệnh con lạ %q", args[0])
}

// deviceList prints every device recorded in members.kgl (public file: no keys, no broker needed).
func (a *app) deviceList(args []string) error {
	fs := newFS("device list", a.errw)
	online := fs.Bool("seen", false, "lấy thêm hoạt động gần nhất (giờ, IP, nơi, mạng) từ relay")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	ms, err := store.ReadMembers(a.home)
	if err != nil {
		return err
	}
	paired, origins := pairedAt(a.home, ms)
	var seen map[string]relay.Seen
	if *online {
		if seen, err = a.seen(); err != nil {
			fmt.Fprintf(a.errw, "Cảnh báo: không lấy được hoạt động từ relay: %v\n", err)
		}
	}
	for _, d := range sortDevices(store.Devices(ms), "", paired) {
		line := fmt.Sprintf("%s | %s | %s | ghép %s", d.ID, d.Label, store.RoleText(d.Role), pairedText(paired, d.ID))
		if o := origins[d.ID].Summary(); o != "" {
			line += " từ " + o
		}
		if *online {
			line += " | gần nhất " + seenText(seen, d.ID)
		}
		if d.Revoked {
			line += " | đã thu hồi"
		}
		fmt.Fprintln(a.out, line)
	}
	return nil
}

// seen asks the relay for the last request of every device (needs the device identity).
func (a *app) seen() (map[string]relay.Seen, error) {
	cfg, err := store.ReadConfig(a.home)
	if err != nil {
		return nil, err
	}
	ks, err := a.openKeys()
	if err != nil {
		return nil, err
	}
	id, err := store.LoadIdentity(a.home, ks)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := channel.Seen(ctx, cfg, id)
	return seenMap(l), err
}

func seenMap(l []relay.Seen) map[string]relay.Seen {
	m := make(map[string]relay.Seen, len(l))
	for _, s := range l {
		m[s.Dev] = s
	}
	return m
}

// seenText is "time · origin" of a device's last relay request, or "không rõ".
func seenText(m map[string]relay.Seen, dev string) string {
	s, ok := m[dev]
	if !ok || s.Time <= 0 {
		return "không rõ"
	}
	t := time.UnixMilli(s.Time).Local().Format("2006-01-02 15:04")
	if o := s.Origin.Summary(); o != "" {
		return t + " · " + o
	}
	return t
}

// pairedAt is when each device joined the vault, for display: the audit `device-add` time (tray
// pairing) or, for the device that created the vault (first add after genesis), the genesis time.
// The signed member events carry no time, so devices paired earlier with `kg device add` are absent.
// origins is the network origin of the phone's pairing request, when the relay recorded one.
func pairedAt(home string, ms *members.State) (times map[string]time.Time, origins map[string]relay.Origin) {
	out := map[string]time.Time{}
	origins = map[string]relay.Origin{}
	for _, d := range ms.Devices {
		if d.AddedN == 1 {
			if t, err := time.Parse(time.RFC3339, ms.Created); err == nil {
				out[d.ID] = t
			}
		}
	}
	led := audit.Open(filepath.Join(home, "audit", "ledger.jsonl"), filepath.Join(home, "state", "audit.head"), nil)
	es, _ := led.Show(time.Time{})
	for _, e := range es {
		if e.Event != audit.EvDeviceAdd || len(e.Argv) == 0 {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
			out[e.Argv[0]] = t
		}
		var o relay.Origin
		if len(e.Argv) > 3 && json.Unmarshal([]byte(e.Argv[3]), &o) == nil {
			origins[e.Argv[0]] = o
		}
	}
	return out, origins
}

// sortDevices orders ds for display: this machine first, active before revoked, then the most
// recently paired first (unknown pairing time last), then by id.
func sortDevices(ds []*members.Device, self string, paired map[string]time.Time) []*members.Device {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if (a.ID == self) != (b.ID == self) {
			return a.ID == self
		}
		if a.Revoked != b.Revoked {
			return !a.Revoked
		}
		ta, oka := paired[a.ID]
		tb, okb := paired[b.ID]
		if oka != okb {
			return oka
		}
		if !ta.Equal(tb) {
			return ta.After(tb)
		}
		return a.ID < b.ID
	})
	return ds
}

func pairedText(m map[string]time.Time, dev string) string {
	if t, ok := m[dev]; ok {
		return t.Local().Format("2006-01-02 15:04")
	}
	return "không rõ"
}

// auditOwner records an owner operation done by the CLI (the broker is stopped: it holds the lock).
func (a *app) auditOwner(st *store.Store, e audit.Entry) {
	led := audit.Open(filepath.Join(a.home, "audit", "ledger.jsonl"), filepath.Join(a.home, "state", "audit.head"), st.LocalMacKey())
	if err := led.Append(e); err != nil {
		fmt.Fprintf(a.errw, "Cảnh báo: ghi audit lỗi: %v\n", err)
	}
}

func (a *app) deviceRequest(args []string) error {
	fs := newFS("device request", a.errw)
	label := fs.String("label", "", "nhãn thiết bị mới")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *label == "" || len(*label) > members.MaxLabel {
		return errors.New("cần --label <nhãn>")
	}
	if _, err := os.Stat(filepath.Join(a.home, "device.json")); err == nil {
		return fmt.Errorf("%s đã có khóa thiết bị", a.home)
	}
	id := store.NewIdentity(*label)
	ks, err := a.openKeys()
	if err != nil {
		return err
	}
	if err := store.SaveIdentity(a.home, id, ks); err != nil {
		return err
	}
	code := store.RequestCode(id.Public())
	fmt.Fprintf(a.out, "Thiết bị %s (%s).\nMã đăng ký:\n%s\n\n6 từ xác nhận: %s\n\n", id.Dev, *label, code, store.RequestWords(code))
	fmt.Fprintln(a.out, "Đưa mã cho máy cũ chạy `kg device add <mã>`, rồi trên máy này chạy `kg sync --via dir --dir <thư mục chung>`.")
	return nil
}

func (a *app) syncAfterOwnerOp(st *store.Store) {
	if _, err := channel.Pick(st.Config(), ""); err != nil {
		fmt.Fprintln(a.out, "Chưa cấu hình kênh đồng bộ: chạy `kg sync` sau khi cấu hình.")
		return
	}
	if r, err := channel.Sync(context.Background(), st, "", ""); err != nil {
		fmt.Fprintf(a.errw, "Cảnh báo: sync lỗi: %v\n", err)
	} else {
		fmt.Fprintf(a.out, "Đã đồng bộ qua %s.\n", r.Channel)
	}
	fmt.Fprintln(a.out, "Nếu broker đang chạy, chạy `kg lock` để nó nạp lại trạng thái thành viên mới.")
}

// fetchPairCode downloads the registration code a phone published under the 8-char pairing code.
// It only needs the device identity and vault.json (no vault lock, no owner keys).
func (a *app) fetchPairCode(pair string) (string, relay.Origin, error) {
	cfg, err := store.ReadConfig(a.home)
	if err != nil {
		return "", relay.Origin{}, err
	}
	ks, err := a.openKeys()
	if err != nil {
		return "", relay.Origin{}, err
	}
	id, err := store.LoadIdentity(a.home, ks)
	if err != nil {
		return "", relay.Origin{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return channel.FetchPair(ctx, cfg, id, pair)
}

// pairURL is the link that opens the phone web app pre-filled with vault and genesis pin.
func pairURL(home string) (string, error) {
	cfg, err := store.ReadConfig(home)
	if err != nil {
		return "", err
	}
	if cfg.RelayURL == "" {
		return "", errors.New("vault chưa gắn relay: kg channel add --relay-url …")
	}
	pin, err := genesisPin(home)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/app/#v=%s&p=%s", strings.TrimRight(cfg.RelayURL, "/"), cfg.Vault, pin), nil
}

// devicePairURL prints pairURL.
func (a *app) devicePairURL(args []string) error {
	fs := newFS("device pair-url", a.errw)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	u, err := pairURL(a.home)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, u)
	return nil
}

func (a *app) deviceAdd(args []string) error {
	fs := newFS("device add", a.errw)
	pair := fs.String("pair", "", "mã ghép 8 ký tự hiện trên điện thoại")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	var code string
	var origin relay.Origin
	switch {
	case *pair != "" && len(pos) > 0:
		return errors.New("dùng một trong hai: kg device add <mã đăng ký> hoặc kg device add --pair <mã ghép>")
	case *pair != "":
		if code, origin, err = a.fetchPairCode(*pair); err != nil {
			return err
		}
	case len(pos) == 0:
		return errors.New("dùng: kg device add <mã đăng ký> | kg device add --pair <mã ghép>")
	default:
		code = strings.Join(pos, "")
	}
	body, err := store.DecodeRequest(code)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Thiết bị %s (%s). 6 từ xác nhận: %s\n", body.Dev, body.Label, store.RequestWords(code))
	if body.Role == members.RoleApprover {
		fmt.Fprintln(a.out, "THIẾT BỊ DUYỆT: không nhận vault key, chỉ ký duyệt và gửi lệnh.")
	}
	ans, err := a.readLine("Khớp với 6 từ hiển thị trên máy mới? Gõ 'yes' để tiếp tục: ")
	if err != nil {
		return err
	}
	if strings.TrimSpace(ans) != "yes" {
		return errors.New("đã hủy")
	}
	st, err := a.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	keys, err := a.ownerKeys(st)
	if err != nil {
		return err
	}
	if err := st.AddDevice(keys.OwnerPriv, body); err != nil {
		return err
	}
	a.auditOwner(st, audit.Entry{Event: audit.EvDeviceAdd, Argv: broker.PairArgv(body, origin), Approval: "owner", Peer: "kg device add"})
	fmt.Fprintf(a.out, "Đã thêm %s vào vault.\n", body.Dev)
	fmt.Fprintf(a.out, "Mã ghim genesis (kiểm bằng kênh khác; máy mới chạy): kg sync --vault %s --pin %s\n", st.Vault(), st.GenesisPin())
	if err := channel.PushMembersAsOwner(context.Background(), st, "", keys.OwnerPriv); err != nil {
		fmt.Fprintf(a.errw, "Cảnh báo: %v\n", err)
	}
	a.syncAfterOwnerOp(st)
	return nil
}

func (a *app) deviceRevoke(args []string) error {
	fs := newFS("device revoke", a.errw)
	reason := fs.String("reason", "", "lý do thu hồi")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("dùng: kg device revoke <dev_id> [--reason ...]")
	}
	st, err := a.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	// Pull first so last_seq/last_hash cover every record the revoked device already published.
	pull := func() error {
		if _, err := channel.Sync(context.Background(), st, "", ""); err != nil {
			if _, perr := channel.Pick(st.Config(), ""); perr == nil {
				return fmt.Errorf("đồng bộ trước khi thu hồi thất bại: %w", err)
			}
		}
		return nil
	}
	if d, ok := st.Members().Devices[pos[0]]; ok && !d.Revoked && d.Role == members.RoleApprover {
		// An approver never held the vault key: this key holder signs the revoke itself (no owner keys).
		if err := a.userPresence(fmt.Sprintf("KeyGate: THU HỒI thiết bị duyệt %s (%s)", d.ID, d.Label)); err != nil {
			return err
		}
		if err := pull(); err != nil {
			return err
		}
		if err := st.RevokeApprover(pos[0], *reason); err != nil {
			return err
		}
		a.auditOwner(st, audit.Entry{Event: audit.EvDeviceRevoke, Argv: []string{pos[0]}, Approval: "user-presence", Peer: "kg device revoke"})
		fmt.Fprintf(a.out, "Đã thu hồi thiết bị duyệt %s (không đổi epoch, không cần mã hóa lại).\n", pos[0])
		a.syncAfterOwnerOp(st)
		return nil
	}
	keys, err := a.ownerKeys(st)
	if err != nil {
		return err
	}
	if err := pull(); err != nil {
		return err
	}
	n, err := st.RevokeDevice(keys.OwnerPriv, pos[0], *reason)
	if err != nil {
		return err
	}
	a.auditOwner(st, audit.Entry{Event: audit.EvDeviceRevoke, Argv: []string{pos[0]}, Approval: "owner", Peer: "kg device revoke"})
	fmt.Fprintf(a.out, "Đã thu hồi %s, mã hóa lại %d secret theo epoch %d.\n", pos[0], n, st.Epoch())
	var names []string
	for _, it := range st.List() {
		if !it.Deleted && it.Name != "" {
			names = append(names, it.Name)
		}
	}
	sort.Strings(names)
	if len(names) > 0 {
		fmt.Fprintf(a.out, "Thiết bị đó có thể đã giải mã các secret sau; hãy đổi giá trị ở hệ thống đích: %s\n", strings.Join(names, ", "))
	}
	a.syncAfterOwnerOp(st)
	return nil
}

func (a *app) cmdRecover(args []string) error {
	fs := newFS("recover", a.errw)
	from := fs.String("from", "", "thư mục đồng bộ hoặc URL relay")
	useGit := fs.Bool("git", false, "coi --from là git work tree")
	vaultFlag := fs.String("vault", "", "ID vault (chỉ cần khi relay)")
	label := fs.String("label", "", "nhãn thiết bị mới")
	genesis := fs.String("members-file", "", "members.kgl chứa genesis (bắt buộc khi khôi phục từ relay)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *from == "" || *label == "" {
		return errors.New("dùng: kg recover --from <dir|relay-url> --label <nhãn> [--vault vlt_… --members-file …]")
	}
	if _, err := os.Stat(filepath.Join(a.home, "vault.json")); err == nil {
		return fmt.Errorf("%s đã có vault", a.home)
	}
	ctx := context.Background()
	isRelay := strings.HasPrefix(*from, "http://") || strings.HasPrefix(*from, "https://")
	id := store.NewIdentity(*label)
	var pull func(signer transport.Signer) (transport.Snapshot, error)
	var firstMember []byte
	cfg := store.VaultConfig{}
	switch {
	case isRelay:
		if *vaultFlag == "" || *genesis == "" {
			return errors.New("khôi phục từ relay cần --vault và --members-file (genesis chứa salt; relay không cho đọc khi chưa là thành viên)")
		}
		lines, err := readLinesFile(*genesis)
		if err != nil || len(lines) == 0 {
			return fmt.Errorf("đọc --members-file: %v", err)
		}
		firstMember = lines[0]
		cfg.RelayURL = *from
		pull = func(s transport.Signer) (transport.Snapshot, error) {
			return relay.New(*from, *vaultFlag, s, nil).Pull(ctx, transport.Since{})
		}
	default:
		var t transport.Transport
		var err error
		if *useGit {
			t, err = git.New(*from, id.Dev)
			cfg.GitDir = absPath(*from)
		} else {
			t, err = dir.New(*from, id.Dev)
			cfg.SyncDir = absPath(*from)
		}
		if err != nil {
			return err
		}
		snap, err := t.Pull(ctx, transport.Since{})
		if err != nil {
			return err
		}
		if len(snap.Members) == 0 {
			return errors.New("kênh không có vault")
		}
		firstMember = snap.Members[0]
		pull = func(transport.Signer) (transport.Snapshot, error) { return snap, nil }
	}
	ev, err := members.Parse(firstMember)
	if err != nil {
		return err
	}
	var gb members.GenesisBody
	if err := ev.DecodeBody(&gb); err != nil {
		return err
	}
	salt, err := kcrypto.UnB64(gb.ArgonSalt)
	if err != nil {
		return err
	}
	pwd, err := a.readSecret("Mật khẩu chủ: ", true)
	if err != nil {
		return err
	}
	pk, err := a.readSecret("Khóa giấy: ", true)
	if err != nil {
		return err
	}
	raw, err := recovery.ParsePaperKey(pk)
	if err != nil {
		return err
	}
	keys, err := recovery.Derive(ev.Vault, pwd, salt, gb.ArgonParams, raw)
	if err != nil {
		return err
	}
	cfg.Vault = ev.Vault
	snap, err := pull(channel.OwnerSigner{Priv: keys.OwnerPriv})
	if err != nil {
		return err
	}
	st, err := store.Recover(a.home, id, keys, snap, "")
	if err != nil {
		return err
	}
	defer st.Close()
	ks, err := a.openKeys()
	if err != nil {
		return err
	}
	if err := store.SaveIdentity(a.home, id, ks); err != nil {
		return err
	}
	if err := st.SaveConfig(cfg); err != nil {
		return err
	}
	if err := channel.PushMembersAsOwner(ctx, st, "", keys.OwnerPriv); err != nil {
		return err
	}
	r, err := channel.Sync(ctx, st, "", "")
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã khôi phục vault %s trên thiết bị %s (%s), kênh %s.\n", ev.Vault, id.Dev, *label, r.Channel)
	return nil
}

func readLinesFile(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, []byte(l))
		}
	}
	return out, nil
}

func (a *app) cmdApprove(args []string) error {
	fs := newFS("approve", a.errw)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("dùng: kg approve <challenge>")
	}
	ch, err := approve.DecodeChallenge(pos[0])
	if err != nil {
		return err
	}
	if time.Now().Unix() > ch.Expires {
		return approve.ErrExpired
	}
	ks, err := a.openKeys()
	if err != nil {
		return err
	}
	id, err := store.LoadIdentity(a.home, ks)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.errw, "%s\n", ch.Prompt())
	ap := a.approver
	if ap == nil {
		ap = approve.Platform()
	}
	if err := ap.Approve(context.Background(), ch.Prompt()); err != nil {
		return err
	}
	fmt.Fprintln(a.out, approve.Sign(ch, id.Dev, id.EdPriv))
	return nil
}

func (a *app) cmdFingerprint(args []string) error {
	if fp, err := a.client().Fingerprint(context.Background()); err == nil {
		fmt.Fprintln(a.out, fp)
		return nil
	} else if !errors.Is(err, brokerclient.ErrNoBroker) {
		return err
	}
	st, err := a.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	fmt.Fprintln(a.out, st.Fingerprint())
	return nil
}

func (a *app) cmdConflicts(args []string) error {
	ctx := context.Background()
	l, err := a.client().Conflicts(ctx)
	if errors.Is(err, brokerclient.ErrNoBroker) {
		var st *store.Store
		if st, err = a.openStore(); err != nil {
			return err
		}
		l = nil
		for _, it := range st.Conflicts() {
			ci := wire.ConflictInfo{Name: it.Name, Item: it.Item}
			for _, h := range it.Heads {
				ci.Heads = append(ci.Heads, wire.ConflictHead{Hash: h.Hash, Dev: h.Dev, Seq: h.Seq, Op: h.Op})
			}
			l = append(l, ci)
		}
		st.Close()
	} else if err != nil {
		return err
	}
	if len(l) == 0 {
		fmt.Fprintln(a.out, "Không có xung đột.")
		return nil
	}
	for _, c := range l {
		fmt.Fprintf(a.out, "%s\n", c.Name)
		for _, h := range c.Heads {
			fmt.Fprintf(a.out, "  thiết bị %s seq %d %s %s\n", h.Dev, h.Seq, h.Op, h.Hash)
		}
	}
	return nil
}

func (a *app) cmdResolveConflict(args []string) error {
	fs := newFS("resolve-conflict", a.errw)
	keep := fs.String("keep", "", "mã băm bản ghi hoặc ID thiết bị cần giữ")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || *keep == "" {
		return errors.New("dùng: kg resolve-conflict <tên> --keep <dev|hash>")
	}
	ctx := context.Background()
	err = a.client().ResolveConflict(ctx, wire.ResolveConflictArgs{Name: pos[0], Keep: *keep})
	if errors.Is(err, brokerclient.ErrNoBroker) {
		st, oerr := a.openStore()
		if oerr != nil {
			return oerr
		}
		defer st.Close()
		err = errors.New("không có xung đột cho " + pos[0])
		for _, it := range st.Conflicts() {
			if it.Name == pos[0] {
				// No broker to ask: the human check happens here (Hello / Touch ID).
				if err = a.userPresence("CHỌN bản giữ cho xung đột " + pos[0] + ", giữ: " + *keep); err == nil {
					_, err = st.ResolveConflict(it.Item, *keep)
				}
			}
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã giải quyết xung đột %s (giữ %s). Chạy `kg sync` để đẩy lên.\n", pos[0], *keep)
	return nil
}

func (a *app) cmdSync(args []string) error {
	fs := newFS("sync", a.errw)
	cf := addChanFlags(fs)
	verify := fs.String("verify-via", "", "kênh thứ hai để so fingerprint (vd git)")
	vaultFlag := fs.String("vault", "", "ID vault (bắt buộc khi tham gia lần đầu)")
	pinFlag := fs.String("pin", "", "mã ghim genesis do `kg device add`/`kg status` in ra (bắt buộc khi tham gia lần đầu)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	ctx := context.Background()
	var res wire.SyncResult
	_, haveVault := os.Stat(filepath.Join(a.home, "vault.json"))
	if haveVault == nil && !cf.any() {
		r, err := a.client().Sync(ctx, wire.SyncArgs{Via: *cf.via, VerifyVia: *verify})
		if err == nil {
			a.printSync(r)
			return nil
		}
		if !errors.Is(err, brokerclient.ErrNoBroker) {
			return err
		}
	}
	ks, err := a.openKeys()
	if err != nil {
		return err
	}
	id, err := store.LoadIdentity(a.home, ks)
	if err != nil {
		return err
	}
	var st *store.Store
	if haveVault != nil {
		// First sync of a device the owner already added: join from a full pull.
		if *vaultFlag == "" || *pinFlag == "" {
			return errors.New("lần đồng bộ đầu cần --vault <id> và --pin <mã ghim> lấy từ máy đã tin cậy (kênh không được tin)")
		}
		cfg := store.VaultConfig{Vault: *vaultFlag}
		cf.apply(&cfg)
		t, err := channel.Open(cfg, *cf.via, id)
		if err != nil {
			return err
		}
		snap, err := t.Pull(ctx, transport.Since{})
		if err != nil {
			return err
		}
		if len(snap.Members) == 0 {
			return errors.New("kênh chưa có vault")
		}
		if g, perr := members.Parse(snap.Members[0]); perr != nil || g.Vault != *vaultFlag {
			return store.ErrPin
		}
		if st, err = store.Join(a.home, id, snap, *pinFlag); err != nil {
			return err
		}
		cfg.Vault = st.Vault()
		if err := st.SaveConfig(cfg); err != nil {
			return err
		}
	} else {
		if st, err = store.Open(a.home, id); err != nil {
			return lockedHint(err)
		}
		if cf.any() {
			cfg := st.Config()
			cf.apply(&cfg)
			if err := st.SaveConfig(cfg); err != nil {
				return err
			}
		}
	}
	defer st.Close()
	if res, err = channel.Sync(ctx, st, *cf.via, *verify); err != nil {
		return err
	}
	a.printSync(res)
	return nil
}

func (a *app) printSync(r wire.SyncResult) {
	fmt.Fprintf(a.out, "Đồng bộ qua %s: nhận %d, đẩy %d. Fingerprint: %s\n", r.Channel, r.Pulled, r.Pushed, r.Fingerprint)
	if r.Verified != "" {
		fmt.Fprintf(a.out, "Đã đối chiếu fingerprint với kênh %s: khớp.\n", r.Verified)
	}
}

func (a *app) cmdAudit(args []string) error {
	if len(args) == 0 {
		return errors.New("dùng: kg audit verify | kg audit show [--since 7d]")
	}
	// Only the device key is needed (for the MAC key): opening the whole vault would need the lock
	// the broker holds.
	ks, err := a.openKeys()
	if err != nil {
		return err
	}
	id, err := store.LoadIdentity(a.home, ks)
	if err != nil {
		return err
	}
	mac := kcrypto.HKDF(id.EdPriv.Seed(), []byte(kcrypto.LabelLocalMac), 32)
	led := audit.Open(filepath.Join(a.home, "audit", "ledger.jsonl"), filepath.Join(a.home, "state", "audit.head"), mac)
	switch args[0] {
	case "verify":
		n, err := led.Verify()
		if err != nil {
			return fmt.Errorf("audit KHÔNG hợp lệ: %w", err)
		}
		fmt.Fprintf(a.out, "Audit hợp lệ: %d dòng, chuỗi hash, MAC và neo đầu chuỗi đều khớp.\n", n)
		return nil
	case "show":
		fs := newFS("audit show", a.errw)
		since := fs.String("since", "", "vd 7d, 12h, hoặc RFC3339")
		if _, err := parseArgs(fs, args[1:]); err != nil {
			return err
		}
		t, err := audit.ParseSince(*since, time.Now())
		if err != nil {
			return err
		}
		es, err := led.ShowVerified(t)
		if err != nil {
			return fmt.Errorf("audit KHÔNG hợp lệ, không hiển thị: %w", err)
		}
		for _, e := range es {
			ex := ""
			if e.Exit != nil {
				ex = fmt.Sprintf(" exit=%d", *e.Exit)
			}
			fmt.Fprintf(a.out, "%s %-9s %s env=%s agent=%s peer=%s approval=%s%s | %s\n", e.Time, e.Event,
				approve.Sanitize(e.Secret, 200), e.Env, approve.Sanitize(e.Agent, 100), approve.Sanitize(e.Peer, 200), e.Approval, ex, approve.FormatArgv(e.Argv))
		}
		return nil
	}
	return fmt.Errorf("lệnh con lạ %q", args[0])
}

// userPresence asks the local human (Hello / Touch ID / test stub) when no broker is involved.
func (a *app) userPresence(prompt string) error {
	ap := a.approver
	if ap == nil {
		ap = approve.Platform()
	}
	return ap.Approve(context.Background(), prompt)
}

// cmdChannel implements `kg channel add`: an owner operation that attaches a sync channel to an
// existing vault (e.g. one created by `kg init` without a channel). For a relay the genesis and
// the first add events are pushed signed with the owner key, then a normal sync follows.
func (a *app) cmdChannel(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("dùng: kg channel add --relay-url U | --git-dir G | --dir D")
	}
	fs := newFS("channel add", a.errw)
	cf := addChanFlags(fs)
	if _, err := parseArgs(fs, args[1:]); err != nil {
		return err
	}
	var via string
	n := 0
	for _, c := range []struct{ set, name string }{{*cf.dir, "dir"}, {*cf.gitDir, "git"}, {*cf.relayURL, "relay"}} {
		if c.set != "" {
			via, n = c.name, n+1
		}
	}
	if n != 1 {
		return errors.New("chọn đúng một kênh: --relay-url U | --git-dir G | --dir D")
	}
	st, err := a.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	keys, err := a.ownerKeys(st)
	if err != nil {
		return err
	}
	if !bytes.Equal(keys.OwnerPub, st.Members().OwnerPub) {
		return store.ErrWrongKeys
	}
	cfg := st.Config()
	cf.apply(&cfg)
	if err := st.SaveConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	if err := channel.PushMembersAsOwner(ctx, st, via, keys.OwnerPriv); err != nil {
		return err
	}
	r, err := channel.Sync(ctx, st, via, "")
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Đã thêm kênh %s và đồng bộ lần đầu.\n", r.Channel)
	return nil
}
