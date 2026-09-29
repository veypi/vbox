//go:build windows

// Windows 沙箱运行时集成测试（需真实 Windows 环境；mbp 交叉编译不执行）。
// 验证受限令牌 + ACL 授权的实际行为：
//   - read-only：写任意路径被拒
//   - workspace-write：写工作区成功、写外部路径被拒、TMP/TEMP 指向私有目录
//   - deny：per-call 拒绝 ACE 拦写（读侧为 windows 沙箱的文档化边界，不拦），进程结束后撤销
//   - cleanup：私有临时目录在进程结束后被删除
package vbox

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runWithPlan 以 launchPlan 启动命令并等待，返回输出与退出码。
// 三段式 Start → assignJob（Job Object 资源限制生效）→ Wait，
// 与 exec_procs.Start 同生命周期（spawn 后关闭令牌、进程结束后 cleanup）。
func runWithPlan(t *testing.T, plan launchPlan, argv []string, workdir string) (string, int) {
	t.Helper()
	if plan.token == 0 {
		t.Fatal("expected a restricted token")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = workdir
	if plan.env != nil {
		cmd.Env = append(os.Environ(), plan.env...)
	}
	// 控制台策略与生产一致：SetSysProcAttr（HideWindow + CREATE_NO_WINDOW）= 受限
	// spawn 的实际生产配置；令牌经 SysProcAttr.Token 注入（applyToken）。
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(plan.token), HideWindow: true, CreationFlags: 0x08000000}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return "", -1
	}
	if plan.job != 0 {
		if err := assignJob(cmd.Process.Pid, plan.job); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return "", -1
		}
	}
	err := cmd.Wait()
	exit := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exit = ee.ExitCode()
	} else if err != nil {
		exit = -1
	}
	closeToken(plan.token)
	if plan.cleanup != nil {
		plan.cleanup()
	}
	return buf.String(), exit
}

// writeCmd 构造 cmd /c 写文件命令（> 重定向）。
func writeCmd(path string) []string {
	return []string{"cmd", "/c", "echo x > " + path}
}

func TestWindowsSandboxProbe(t *testing.T) {
	if backend := probeBackend(); backend != backendWindowsAcl {
		tok, err := createRestrictedToken(nil)
		if err != nil {
			t.Fatalf("probeBackend=%v; createRestrictedToken error: %v", backend, err)
		}
		tok.Close()
		t.Fatalf("probeBackend should report windows-acl backend, got %v", backend)
	}
}

// 诊断：定位哪个 Flags 组合在普通用户下被拒；检查当前令牌是否本身受限。
func TestWindowsCreateRestrictedTokenFlagMatrix(t *testing.T) {
	procToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer procToken.Close()

	// 当前令牌受限状态（OpenSSH 会话可能已是 restricted token）
	var buf [4096]byte
	var retLen uint32
	if err := windows.GetTokenInformation(procToken, windows.TokenRestrictedSids, &buf[0], uint32(len(buf)), &retLen); err == nil {
		groups := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
		t.Logf("TokenRestrictedSids count=%d", groups.GroupCount)
	} else {
		t.Logf("TokenRestrictedSids query failed: %v", err)
	}
	var elev int32
	if err := windows.GetTokenInformation(procToken, windows.TokenElevation, (*byte)(unsafe.Pointer(&elev)), 4, &retLen); err == nil {
		t.Logf("TokenElevation=%d", elev)
	}

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid: %v", err)
	}

	// 空限制列表
	var tok0 windows.Token
	r1, _, e1 := procCreateRestrictedToken.Call(
		uintptr(procToken), 0x1, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&tok0)))
	if r1 == 0 {
		t.Logf("empty restrictions: FAILED %v", e1)
	} else {
		t.Logf("empty restrictions: OK")
		tok0.Close()
	}

	// TOKEN_ALL_ACCESS 打开后重试
	var allTok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &allTok); err == nil {
		defer allTok.Close()
		restrictions := []windows.SIDAndAttributes{{Sid: everyone}}
		var tokA windows.Token
		r1, _, e1 := procCreateRestrictedToken.Call(
			uintptr(allTok), 0x1,
			0, 0, // DisableSidCount, SidsToDisable
			0, 0, // DeletePrivilegeCount, PrivilegesToDelete
			uintptr(len(restrictions)),
			uintptr(unsafe.Pointer(&restrictions[0])),
			uintptr(unsafe.Pointer(&tokA)),
		)
		if r1 == 0 {
			t.Logf("TOKEN_ALL_ACCESS handle: FAILED %v", e1)
		} else {
			t.Logf("TOKEN_ALL_ACCESS handle: OK")
			tokA.Close()
		}
	} else {
		t.Logf("OpenProcessToken ALL_ACCESS failed: %v", err)
	}

	for _, flags := range []uintptr{0x1, 0x1 | 0x8, 0x1 | 0x4, 0x1 | 0x4 | 0x8} {
		restrictions := []windows.SIDAndAttributes{{Sid: everyone}}
		var tok windows.Token
		r1, _, e1 := procCreateRestrictedToken.Call(
			uintptr(procToken), flags,
			0, 0, // DisableSidCount, SidsToDisable
			0, 0, // DeletePrivilegeCount, PrivilegesToDelete
			uintptr(len(restrictions)),
			uintptr(unsafe.Pointer(&restrictions[0])),
			uintptr(unsafe.Pointer(&tok)),
		)
		if r1 == 0 {
			t.Logf("flags=0x%x: FAILED %v", flags, e1)
		} else {
			t.Logf("flags=0x%x: OK", flags)
			tok.Close()
		}
	}
}

// 未授权写：ws 不在可写根（extra）内，写工作区被拒（profile 由 rules 派生）。
func TestWindowsSandboxReadOnlyDeniesWrite(t *testing.T) {
	ws := t.TempDir()
	target := filepath.Join(ws, "ro.txt")
	plan, err := planConfined(confineSpec{netOpen: true, workdir: ws, argv: writeCmd(target)})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	out, exit := runWithPlan(t, plan, plan.argv, ws)
	if exit == 0 {
		t.Fatalf("ungranted write should fail: %s", out)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("ungranted target file must not exist")
	}
}

// 不可表达的策略仍拒绝：写全放（fs_policy=open）与网络管控。
func TestWindowsSandboxRejectsUnsupportedPolicy(t *testing.T) {
	if _, err := planConfined(confineSpec{workdir: t.TempDir(), argv: []string{"cmd", "/c", "echo ok"}, netOpen: true, fsOpen: true}); err == nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Fatalf("fs_policy=open write must reject: %v", err)
	}
	if _, err := planConfined(confineSpec{workdir: t.TempDir(), argv: []string{"cmd", "/c", "echo ok"}}); err == nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Fatalf("closed network policy must reject: %v", err)
	}
}

// TMP/TEMP 注入：受限进程看到的是私有临时目录。
func TestWindowsSandboxTempEnv(t *testing.T) {
	ws := t.TempDir()
	plan, err := planConfined(confineSpec{netOpen: true, workdir: ws, extra: []string{ws}, argv: []string{"cmd", "/c", "echo TMP=[%TMP%]"}})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	out, exit := runWithPlan(t, plan, plan.argv, ws)
	if exit != 0 || !strings.Contains(out, "aic-sandbox") {
		t.Fatalf("TMP should point at private aic-sandbox dir: exit=%d out=%q", exit, out)
	}
}

// cleanup：进程结束后私有临时目录被删除。
func TestWindowsSandboxCleanupRemovesTemp(t *testing.T) {
	ws := t.TempDir()
	plan, err := planConfined(confineSpec{netOpen: true, workdir: ws, extra: []string{ws}, argv: []string{"cmd", "/c", "echo %TMP%"}})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	tmpDir := ""
	for _, kv := range plan.env {
		if strings.HasPrefix(kv, "TMP=") {
			tmpDir = strings.TrimPrefix(kv, "TMP=")
		}
	}
	if tmpDir == "" {
		t.Fatal("plan.env missing TMP")
	}
	if _, err := os.Stat(tmpDir); err != nil {
		t.Fatalf("private temp should exist before run: %v", err)
	}
	runWithPlan(t, plan, plan.argv, ws)
	if _, err := os.Stat(tmpDir); err == nil {
		t.Fatal("private temp should be removed after run")
	}
}

// aclAceCount 返回对象 DACL 的 ACE 数（deny ACE 增删断言用）。
func aclAceCount(t *testing.T, path string) int {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if dacl == nil {
		return 0
	}
	head := (*[8]byte)(unsafe.Pointer(dacl))
	return int(binary.LittleEndian.Uint16(head[4:6]))
}

// aclDenyAceCount 返回对象 DACL 中的拒绝类 ACE 数（deny 增删断言用）。
func aclDenyAceCount(t *testing.T, path string) int {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if dacl == nil {
		return 0
	}
	head := (*[8]byte)(unsafe.Pointer(dacl))
	aclSize := int(binary.LittleEndian.Uint16(head[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(head[4:6]))
	off := 8
	n := 0
	for i := 0; i < aceCount; i++ {
		if off+8 > aclSize {
			t.Fatalf("acl parse: ace header out of range")
		}
		ace := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + uintptr(off)))
		if int(ace.AceSize) < 8 || off+int(ace.AceSize) > aclSize {
			t.Fatalf("acl parse: ace size out of range")
		}
		if ace.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			n++
		}
		off += int(ace.AceSize)
	}
	return n
}

// deny（Windows 边界，持久 ACE 模型）：稳定 SID 的拒绝 ACE 使目标【写】被拒
// （pass-2 写检查命中 deny）；读不在 WRITE_RESTRICTED 的交叉检查范围——deny
// 不拦读（Windows 受限令牌的数据边界，与 dsh/codex 一致；读侧隔离需另一机制，
// fs 工具层 deny 不受影响）；ACE 持久保留（不随进程结束撤销，codex 同款：
// 后代可能比 launcher 活得久），幂等 ensure 不重复打。
func TestWindowsDenyWriteACEAndCleanup(t *testing.T) {
	// 状态文件隔离：不污染真实用户状态，并清进程内快照
	oldOverride := denyACLStatePathOverride
	denyACLStatePathOverride = filepath.Join(t.TempDir(), "deny_acl_state.json")
	defer func() {
		denyACLStatePathOverride = oldOverride
		denyACLMu.Lock()
		denyACLCache = nil
		denyACLMu.Unlock()
	}()
	denyACLMu.Lock()
	denyACLCache = nil
	denyACLMu.Unlock()

	ws := t.TempDir()
	secret := filepath.Join(ws, "secret.key")
	if err := os.WriteFile(secret, []byte("top-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := aclDenyAceCount(t, secret)

	// 写 deny：白名单内可写路径上的 deny 文件写也必须失败且内容不变
	plan, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, deny: []string{secret}, netOpen: true, argv: writeCmd(secret)})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	if got := aclDenyAceCount(t, secret); got != before+1 {
		t.Fatalf("deny ACE not added: before=%d after=%d", before, got)
	}
	out, exit := runWithPlan(t, plan, plan.argv, ws)
	if exit == 0 {
		t.Fatalf("deny write should fail: %s", out)
	}
	if b, _ := os.ReadFile(secret); string(b) != "top-secret" {
		t.Fatalf("denied file changed: %q", b)
	}
	// 持久 ACE：runWithPlan 已触发 cleanup，但拒绝 ACE 不撤销（计数不回落）
	if got := aclDenyAceCount(t, secret); got != before+1 {
		t.Fatalf("deny ACE must persist after run: before=%d after=%d", before, got)
	}
	// 幂等：再次 plan 同一目标不重复打 ACE（状态对账命中，零 ACL 写）
	if _, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, deny: []string{secret}, netOpen: true, argv: writeCmd(secret)}); err != nil {
		t.Fatalf("planConfined (again): %v", err)
	}
	if got := aclDenyAceCount(t, secret); got != before+1 {
		t.Fatalf("deny ACE must not duplicate: before=%d after=%d", before, got)
	}

	// 读边界：WRITE_RESTRICTED 只交叉检查写访问——deny 不拦读（文档化行为；
	// 若未来引入读侧隔离机制，此断言需随之更新）。
	// 用相对路径：os/exec 会把 argv 内嵌引号转义成 \"，cmd 解析后报"文件名…
	// 语法不正确"；cmd cwd 即 ws，相对路径避开引号。
	plan2, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, deny: []string{secret}, netOpen: true, argv: []string{"cmd", "/c", "type secret.key"}})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	out2, exit2 := runWithPlan(t, plan2, plan2.argv, ws)
	if exit2 != 0 || !strings.Contains(out2, "top-secret") {
		t.Fatalf("windows read boundary changed: deny must not block reads: exit=%d out=%q", exit2, out2)
	}

	// 非 deny 路径：白名单内写正常
	open := filepath.Join(ws, "open.txt")
	plan3, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, deny: []string{secret}, netOpen: true, argv: writeCmd(open)})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	out3, exit3 := runWithPlan(t, plan3, plan3.argv, ws)
	if exit3 != 0 {
		t.Fatalf("non-deny write should succeed: %s", out3)
	}
}

// 持久 deny ACE 对账：换 deny 目标后，不再需要的旧目标被撤销（状态文件对账），
// 新目标打上；对账只在实例化重算/目标集变化时发生（稳态零 ACL 写）。
func TestWindowsDenyStaleRevocation(t *testing.T) {
	oldOverride := denyACLStatePathOverride
	denyACLStatePathOverride = filepath.Join(t.TempDir(), "deny_acl_state.json")
	defer func() {
		denyACLStatePathOverride = oldOverride
		denyACLMu.Lock()
		denyACLCache = nil
		denyACLMu.Unlock()
	}()
	denyACLMu.Lock()
	denyACLCache = nil
	denyACLMu.Unlock()

	ws := t.TempDir()
	a := filepath.Join(ws, "a.key")
	b := filepath.Join(ws, "b.key")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	beforeA := aclDenyAceCount(t, a)

	if _, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, deny: []string{a}, netOpen: true, argv: writeCmd(a)}); err != nil {
		t.Fatalf("planConfined(a): %v", err)
	}
	if got := aclDenyAceCount(t, a); got != beforeA+1 {
		t.Fatalf("deny ACE for a not added: before=%d after=%d", beforeA, got)
	}

	// 目标集变化（a → b）：a 的 ACE 应被对账撤销，b 打上
	if _, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, deny: []string{b}, netOpen: true, argv: writeCmd(b)}); err != nil {
		t.Fatalf("planConfined(b): %v", err)
	}
	if got := aclDenyAceCount(t, a); got != beforeA {
		t.Fatalf("stale deny ACE for a must be revoked: before=%d after=%d", beforeA, got)
	}
	if got := aclDenyAceCount(t, b); got != 1 {
		t.Fatalf("deny ACE for b not added: %d", got)
	}
}

// workspace-write 边界：授权根（workspace）内写成功；根外写被拒
// （pass-2 写白名单——受限令牌只放行 restricting list 所授权的对象）。
func TestWindowsSandboxWriteConfinement(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	inFile := filepath.Join(ws, "in.txt")
	outFile := filepath.Join(outside, "out.txt")

	plan, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, netOpen: true, argv: writeCmd(inFile)})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	if out, exit := runWithPlan(t, plan, plan.argv, ws); exit != 0 {
		t.Fatalf("granted workspace write should succeed: exit=%d out=%q", exit, out)
	}
	if _, err := os.Stat(inFile); err != nil {
		t.Fatalf("granted workspace write did not materialize: %v", err)
	}

	plan2, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, netOpen: true, argv: writeCmd(outFile)})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	if out, exit := runWithPlan(t, plan2, plan2.argv, ws); exit == 0 {
		t.Fatalf("write outside granted roots should fail: %q", out)
	}
	if _, err := os.Stat(outFile); err == nil {
		t.Fatal("outside file must not exist")
	}
}

// Job Object 资源限制：创建成功、限制 flags 正确（进程内存 4GiB / job 内存
// 8GiB / 活动进程 256），受限令牌子进程 assign 后正常运行（集成路径）。
func TestWindowsJobLimits(t *testing.T) {
	job, err := newJobWithLimits()
	if err != nil {
		t.Fatalf("newJobWithLimits: %v", err)
	}
	defer windows.CloseHandle(job)

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var retLen uint32
	if err := windows.QueryInformationJobObject(job, int32(windows.JobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &retLen); err != nil {
		t.Fatalf("QueryInformationJobObject: %v", err)
	}
	flags := info.BasicLimitInformation.LimitFlags
	for _, f := range []uint32{
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY,
		windows.JOB_OBJECT_LIMIT_JOB_MEMORY,
		windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
	} {
		if flags&f == 0 {
			t.Fatalf("job flags 0x%x missing 0x%x", flags, f)
		}
	}
	if info.ProcessMemoryLimit != uintptr(resourceLimitAS) {
		t.Fatalf("ProcessMemoryLimit = %d, want %d", info.ProcessMemoryLimit, resourceLimitAS)
	}
	if info.JobMemoryLimit != uintptr(resourceLimitJobMemory) {
		t.Fatalf("JobMemoryLimit = %d, want %d", info.JobMemoryLimit, resourceLimitJobMemory)
	}
	if info.BasicLimitInformation.ActiveProcessLimit != resourceLimitJobProcesses {
		t.Fatalf("ActiveProcessLimit = %d, want %d", info.BasicLimitInformation.ActiveProcessLimit, resourceLimitJobProcesses)
	}

	// planConfined 集成：job 句柄随 plan 返回，子进程 assign 后正常执行
	ws := t.TempDir()
	plan, err := planConfined(confineSpec{netOpen: true, workdir: ws, extra: []string{ws}, argv: []string{"cmd", "/c", "echo ok"}})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	if plan.job == 0 {
		t.Fatal("planConfined should attach a job object")
	}
	out, exit := runWithPlan(t, plan, plan.argv, ws)
	if exit != 0 || !strings.Contains(out, "ok") {
		t.Fatalf("job-attached run failed: exit=%d out=%q", exit, out)
	}
}

// 诊断矩阵：受限令牌（WRITE_RESTRICTED|LUA）下各控制台模式的可启动性——
// dsh 实测记录 CREATE_NO_WINDOW / CREATE_NEW_CONSOLE 子进程 DLL init 必死
// （STATUS_DLL_INIT_FAILED 0xC0000142），共享控制台可存活。用
// cmd /c exit /b 7 观察退出码即可判定（7 = 正常启动）。
func TestWindowsConsoleModeMatrix(t *testing.T) {
	runConsoleModeMatrix(t, t.Logf)
}

// 模拟 GUI pod 后端（无控制台父进程）重跑同一矩阵：先 spawn 一个 DETACHED
// 无控制台子进程（本测试的二阶段），在它里面执行矩阵并回传日志——生产
// 形态（桌面后端无控制台）下的控制台策略验证。
func TestWindowsConsoleModeDetachedParent(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run", "^TestWindowsConsoleModeDetachedStage$", "-test.v")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008} // CREATE_DETACHED_PROCESS：无控制台
	cmd.Env = append(os.Environ(), "AIC_SBX_STAGE=1")
	out, err := cmd.CombinedOutput()
	t.Logf("detached-parent child (err=%v):\n%s", err, out)
}

func TestWindowsConsoleModeDetachedStage(t *testing.T) {
	if os.Getenv("AIC_SBX_STAGE") != "1" {
		t.Skip("stage child: only run from TestWindowsConsoleModeDetachedParent")
	}
	runConsoleModeMatrix(t, func(format string, args ...any) { fmt.Printf(format+"\n", args...) })
}

// 诊断：grantDirWrite 幂等授权 + 受限令牌 restricting SID 与 workspace ACE
// 的实际状态（定位“授权目录内写仍被拒”的成因）。
func TestWindowsGrantDiag(t *testing.T) {
	ws := t.TempDir()
	plan, err := planConfined(confineSpec{workdir: ws, extra: []string{ws}, netOpen: true, argv: []string{"cmd", "/c", "exit /b 0"}})
	if err != nil {
		t.Fatalf("planConfined: %v", err)
	}
	defer func() { plan.cleanup(); closeToken(plan.token) }()
	logAceDump(t, "ws", ws)
	logTokenRestrictedSids(t, "token", windows.Token(plan.token))
	sid, err := capabilitySID("ws", ws)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(ws, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := aclHasFullGrant(dacl, sid)
	t.Logf("capSid=%s aclHasFullGrant=%v err=%v", sid, ok, err)

	// 写探针：现有文件追加（创建时已继承 cap ACE） vs 新建文件（新对象安全描述符）
	existing := filepath.Join(ws, "existing.txt")
	if err := os.WriteFile(existing, []byte("e"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := exec.Command("cmd", "/c", "echo y >> "+existing)
	app.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(plan.token), CreationFlags: 0x00000008}
	out, werr := app.CombinedOutput()
	t.Logf("append existing: err=%v out=%q", werr, out)
	newf := filepath.Join(ws, "newfile.txt")
	crt := exec.Command("cmd", "/c", "echo x > "+newf)
	crt.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(plan.token), CreationFlags: 0x00000008}
	out2, werr2 := crt.CombinedOutput()
	t.Logf("create new: err=%v out=%q", werr2, out2)
}

// 诊断：deny ACE 增删链路（add → 计数 → revoke → 计数 + 错误）。
func TestWindowsDenyRevokeDiag(t *testing.T) {
	ws := t.TempDir()
	f := filepath.Join(ws, "x.key")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sid, err := randomDenySID()
	if err != nil {
		t.Fatal(err)
	}
	before := aclDenyAceCount(t, f)
	ok, err := addDenyACE(f, sid, restrictedSIDsForReachability())
	t.Logf("add ok=%v err=%v count=%d→%d", ok, err, before, aclDenyAceCount(t, f))
	logAceDump(t, "after-add", f)

	// 隔离点：仅做 SetEntriesInAcl 合并（应用前），观察 REVOKE 是否真的移除
	sd2, err := windows.GetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl2, _, err := sd2.DACL()
	if err != nil {
		t.Fatal(err)
	}
	merged, merr := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessMode:  windows.REVOKE_ACCESS,
		Inheritance: subContainersAndObjectsInherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, dacl2)
	t.Logf("merge-only err=%v", merr)
	if merr == nil {
		dumpACL(t, "merge-only", merged)
	}

	rerr := revokeDenyACE(f, sid)
	t.Logf("revoke err=%v count=%d", rerr, aclDenyAceCount(t, f))
	logAceDump(t, "after-revoke", f)
}

// logAceDump 输出对象 DACL 的全部 ACE（诊断：trustee SID/掩码/类型/标志）。
func logAceDump(t *testing.T, label, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Logf("%s %s: GetNamedSecurityInfo: %v", label, path, err)
		return
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Logf("%s %s: DACL: %v", label, path, err)
		return
	}
	dumpACL(t, label, dacl)
}

// dumpACL 输出一个 DACL 指针的全部 ACE（诊断用）。
func dumpACL(t *testing.T, label string, dacl *windows.ACL) {
	t.Helper()
	if dacl == nil {
		t.Logf("%s: <nil dacl>", label)
		return
	}
	head := (*[8]byte)(unsafe.Pointer(dacl))
	aclSize := int(binary.LittleEndian.Uint16(head[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(head[4:6]))
	off := 8
	for i := 0; i < aceCount; i++ {
		if off+8 > aclSize {
			t.Logf("%s: truncated", label)
			return
		}
		ace := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + uintptr(off)))
		if int(ace.AceSize) < 8 || off+int(ace.AceSize) > aclSize {
			t.Logf("%s: bad ace size", label)
			return
		}
		switch ace.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			aa := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(ace))
			sid := (*windows.SID)(unsafe.Pointer(&aa.SidStart))
			t.Logf("%s[%d]: allow %s mask=%#x flags=%#x", label, i, sid.String(), aa.Mask, ace.AceFlags)
		case windows.ACCESS_DENIED_ACE_TYPE:
			// ACCESS_DENIED_ACE 与 ACCESS_ALLOWED_ACE 同布局（x/sys 未导出前者）
			da := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(ace))
			sid := (*windows.SID)(unsafe.Pointer(&da.SidStart))
			t.Logf("%s[%d]: deny  %s mask=%#x flags=%#x", label, i, sid.String(), da.Mask, ace.AceFlags)
		default:
			t.Logf("%s[%d]: type=%d flags=%#x", label, i, ace.AceType, ace.AceFlags)
		}
		off += int(ace.AceSize)
	}
}

// logTokenRestrictedSids 输出受限令牌的 restricting SID 列表（诊断用）。
func logTokenRestrictedSids(t *testing.T, label string, tok windows.Token) {
	t.Helper()
	var need uint32
	err := windows.GetTokenInformation(tok, windows.TokenRestrictedSids, nil, 0, &need)
	if err != nil && need == 0 {
		t.Logf("%s: restricted sids size query failed: %v", label, err)
		return
	}
	buf := make([]byte, need)
	if err := windows.GetTokenInformation(tok, windows.TokenRestrictedSids, &buf[0], need, &need); err != nil {
		t.Logf("%s: restricted sids read failed: %v", label, err)
		return
	}
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	for _, g := range groups.AllGroups() {
		t.Logf("%s: restricted sid %s (attr=%#x)", label, g.Sid.String(), g.Attributes)
	}
}

// runConsoleModeMatrix 对每种控制台模式创建受限令牌并启动 cmd /c exit /b 7，
// 记录退出码（7 = 正常启动；-1073741502 = 0xC0000142 DLL init 失败）。
func runConsoleModeMatrix(t *testing.T, logf func(string, ...any)) {
	t.Helper()
	modes := []struct {
		name  string
		flags uint32
	}{
		{"inherit", 0},
		{"no-window", 0x08000000}, // CREATE_NO_WINDOW（历史生产形态）
		{"detached", 0x00000008},  // CREATE_DETACHED_PROCESS
		{"new-console", 0x00000010},
	}
	for _, m := range modes {
		tok, err := createRestrictedToken(nil)
		if err != nil {
			logf("%-12s createRestrictedToken: %v", m.name, err)
			continue
		}
		cmd := exec.Command("cmd", "/c", "exit /b 7")
		cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok), CreationFlags: m.flags}
		out, werr := cmd.CombinedOutput()
		code := -1
		if ee, ok := werr.(*exec.ExitError); ok {
			code = ee.ExitCode()
			werr = nil
		}
		logf("%-12s exit=%d err=%v out=%q", m.name, code, werr, strings.TrimSpace(string(out)))
		closeToken(uintptr(tok))
	}
	// PowerShell（pod 常用解释器）在 DETACHED 策略下的启动确认
	tok, err := createRestrictedToken(nil)
	if err != nil {
		logf("powershell   createRestrictedToken: %v", err)
		return
	}
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "exit 7")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok), CreationFlags: 0x00000008}
	out, werr := cmd.CombinedOutput()
	code := -1
	if ee, ok := werr.(*exec.ExitError); ok {
		code = ee.ExitCode()
		werr = nil
	}
	logf("powershell   exit=%d err=%v out=%q", code, werr, strings.TrimSpace(string(out)))
	closeToken(uintptr(tok))
}
