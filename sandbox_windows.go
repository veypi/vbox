//go:build windows

// Windows 沙箱后端（路径 A）：受限令牌（CreateRestrictedToken）+ ACL 授权，
// host 进程内创建令牌后经 SysProcAttr.Token 注入子进程，无独立 runner。
//
// 机制（与 dsh sandbox-windows-acl / codex windows-sandbox-rs 同模型，
// Go 原生实现）：
//   - 受限令牌：flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED，
//     restricting list = logon SID + Everyone + 能力 SID（工作区/私有临时）+
//     per-call deny SID。写类访问做两次检查（正常 SID + restricting SID），
//     两次都通过才放行 —— restricting 列表即进程的写白名单；读不做第二次
//     检查（WRITE_RESTRICTED 只交叉检查写访问，dsh/codex 同边界）。
//   - 能力 SID 是确定性派生（路径哈希）或随机（私有临时目录）的自定义 SID，
//     对应目录的 DACL 上授予完全访问 ACE：
//   - 工作区：standing ACE，幂等授权——每次调用先检查 DACL 是否已有该
//     能力 SID 的完全访问 ACE，有则跳过（不产生重复 ACE）；目录被删重建
//     后 ACE 消失，下次调用自动重新授权（无进程级缓存，无陈旧状态）
//   - 私有临时目录：per-call 随机创建 + 随机 SID，进程结束后删除目录
//     （ACE 随目录消失，无需显式撤销）
//   - read-only：restricting list 无能力 SID → 除 Everyone 可写对象外全部
//     写被拒。
//   - fs deny：per-call 随机 SID 的完全拒绝 ACE（DENY 置于 ACL 首部、继承
//     到子对象；其他进程无该 SID 不受影响）——写被拒（pass-2 命中 deny）；
//     读不在 WRITE_RESTRICTED 检查范围（Windows 边界：读侧隔离需另一机制，
//     与 dsh/codex 一致）；进程结束后撤销。
//   - spawn 控制台策略：保持既有 CREATE_NO_WINDOW（proc_windows.go
//     SetSysProcAttr）——restricting 列表正确时各控制台模式均可启动
//
// （TestWindowsConsoleModeMatrix 真机矩阵）。
//   - TMP/TEMP 环境变量指向私有临时目录（子进程继承）。
package vbox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---- x/sys 缺失的 advapi32/kernel32 API（LazyDLL 自封装）----

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	// Win10+ 将安全 API 迁移到 API set（api-ms-win-security-*），advapi32 仅
	// 部分转发（实测 Win11 26200：CreateRestrictedToken 在 advapi32）。
	// ACL 读写（SetEntriesInAcl / Get/SetSecurityInfo 句柄版）走 x/sys 封装
	// （zsyscall 静态绑定 advapi32），不在此手写；对象一律经 \\?\ 前缀句柄
	// 打开（长路径安全，见 aclOpenObject）。
	securityBaseDll = windows.NewLazySystemDLL("api-ms-win-security-base-l1-2-0.dll")

	procCreateRestrictedToken = findProcAny("CreateRestrictedToken", advapi32, kernel32, securityBaseDll)
)

// findProcAny 在多个 DLL 中查找过程（Find 不 panic，Call 才 panic）。
// 全部缺失返回 nil，调用方需判空返回错误。
func findProcAny(name string, dlls ...*windows.LazyDLL) *windows.LazyProc {
	for _, d := range dlls {
		p := d.NewProc(name)
		if err := p.Find(); err == nil {
			return p
		}
	}
	return nil
}

const (
	subContainersAndObjectsInherit = 3 // 子目录 + 文件继承 ACE
	fileAllAccess                  = 0x001F01FF

	// CreateRestrictedToken Flags（dsh sandbox-windows-acl / codex
	// windows-sandbox-rs 同款组合，Win11 26200 实测）：
	//   - DISABLE_MAX_PRIVILEGE：除 SeChangeNotifyPrivilege 外特权全禁；
	//   - LUA_TOKEN：LUA 令牌；
	//   - WRITE_RESTRICTED：restricting SID 仅参与写访问的第二次检查
	//     （pass-2）——写隔离的唯一开关：缺它时 restricting 列表整体惰性
	//     （实测读写均不拦截）。
	// 历史排查结论（2026-09-23 真机矩阵复核）：bfe547d 的 "加 flags 后
	// cmd/powershell/git 全灭 0xC0000142" 根因是 CreateRestrictedToken 参数
	// 错位——restricting SID 数组被传进 PrivilegesToDelete 槽位，列表实际
	// 为空。flag 恢复 + 参数修正后各控制台模式（含 CREATE_NO_WINDOW）在
	// 有无控制台父进程下均正常启动，无需换 spawn 侧控制台策略。
	disableMaxPrivilege = 0x1
	luaToken            = 0x4
	writeRestricted     = 0x8
)

// createRestrictedToken 创建受限令牌（dsh sandbox-windows-acl / codex
// windows-sandbox-rs 同款组合）：restricting list = logon SID + Everyone +
// 能力 SIDs（工作区/私有临时）+ per-call deny SID；flags =
// DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED。
// 随后设置宽松默认 DACL：沙箱进程新建对象（pipe/IPC 等）的自身 DACL
// 必须能命中 restricting SID，否则新建即被 pass-2 写检查拒
// （codex/dsh 同策略）；结尾显式启用 SeChangeNotifyPrivilege。
// 现有令牌必须以 TOKEN_ALL_ACCESS 打开——实测 TOKEN_QUERY|TOKEN_DUPLICATE
// 句柄调用 CreateRestrictedToken 返回 Access denied（win11 26200）。
func createRestrictedToken(extraSids []*windows.SID) (windows.Token, error) {
	var procToken windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &procToken); err != nil {
		return 0, err
	}
	defer procToken.Close()

	logonSid, err := logonSidOf(procToken)
	if err != nil {
		return 0, err
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return 0, err
	}
	// 列表刻意不含用户 SID 与 INTERACTIVE/Authenticated Users/BUILTIN
	// Users：这些身份在宿主上有大量环境写授权（用户自有文件、C:\ 根树、
	// Public 树、WMI 命名空间等），进入 restricting 列表等于把这些写路径
	// 全部放行——写白名单的唯一粒度 = 能力 SID（dsh 同款裁剪）。
	// [logon SID, Everyone] 保底：缺它们在 Win11 下早期 DLL 初始化即
	// STATUS_DLL_INIT_FAILED、CNG 写失败（pwsh 崩溃）——dsh 实测记录。
	restrictions := []windows.SIDAndAttributes{
		{Sid: logonSid},
		{Sid: everyone},
	}
	// 去重：planConfined 的 dirs（工作区/缓存/公共/extra）可能重复出现同一
	// 路径（如 workdir 同时作为 extra），能力 SID 随之重复——restricting
	// 列表保持每个 SID 一条。
	seen := map[string]bool{logonSid.String(): true, everyone.String(): true}
	for _, s := range extraSids {
		if s == nil || seen[s.String()] {
			continue
		}
		seen[s.String()] = true
		restrictions = append(restrictions, windows.SIDAndAttributes{Sid: s})
	}

	var newToken windows.Token
	if procCreateRestrictedToken == nil {
		return 0, procMissing("CreateRestrictedToken")
	}
	// CreateRestrictedToken(Existing, Flags, DisableCount, SidsToDisable,
	//   DeletePrivilegeCount, PrivilegesToDelete, RestrictCount, SidsToRestrict,
	//   NewToken)——注意 PrivilegesToDelete 对在 SidsToRestrict 之前；
	// 参数错位会把 restricting SID 数组当成特权列表传入（空 restricting
	// 列表，写全拒而任何 ACE 都无关——2026-09-23 实测定位）。
	r1, _, e1 := procCreateRestrictedToken.Call(
		uintptr(procToken),
		uintptr(disableMaxPrivilege|luaToken|writeRestricted),
		0, 0, // DisableSidCount, SidsToDisable
		0, 0, // DeletePrivilegeCount, PrivilegesToDelete
		uintptr(len(restrictions)),
		uintptr(unsafe.Pointer(&restrictions[0])),
		uintptr(unsafe.Pointer(&newToken)),
	)
	if r1 == 0 {
		return 0, e1
	}
	if err := setDefaultDacl(newToken, restrictions); err != nil {
		newToken.Close()
		return 0, err
	}
	if err := enableChangeNotify(newToken); err != nil {
		newToken.Close()
		return 0, err
	}
	return newToken, nil
}

// enableChangeNotify 显式启用 SeChangeNotifyPrivilege（目录遍历旁路）。
// 该特权本应被 DISABLE_MAX_PRIVILEGE 保留，显式启用为对齐已实测的参考
// 实现（codex windows-sandbox-rs 同做法），防 LUA 令牌下被禁。
func enableChangeNotify(token windows.Token) error {
	name, err := windows.UTF16PtrFromString("SeChangeNotifyPrivilege")
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// procMissing 是 win32 过程缺失错误。
func procMissing(name string) error {
	return fmt.Errorf("sandbox: %s not found in advapi32/kernel32", name)
}

// setDefaultDacl 给令牌设置宽松默认 DACL（所有 restricting SID 获得
// 完全访问）：沙箱进程新建对象（pipe/IPC）时无需逐对象授权。
func setDefaultDacl(token windows.Token, sids []windows.SIDAndAttributes) error {
	if len(sids) == 0 {
		return nil
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sa := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(sa.Sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	type defaultDaclInfo struct {
		defaultDacl *windows.ACL
	}
	info := defaultDaclInfo{defaultDacl: acl}
	return windows.SetTokenInformation(token, uint32(windows.TokenDefaultDacl),
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
}

// logonSidOf 取当前令牌的 logon SID（TokenLogonSid 信息类）。
// 动态 buffer：先问大小再读——固定缓冲在组数多的交互令牌上会
// 因 ERROR_INSUFFICIENT_BUFFER 失败。
func logonSidOf(token windows.Token) (*windows.SID, error) {
	var retLen uint32
	windows.GetTokenInformation(token, windows.TokenLogonSid, nil, 0, &retLen)
	buf := make([]byte, retLen)
	err := windows.GetTokenInformation(token, windows.TokenLogonSid, &buf[0], uint32(len(buf)), &retLen)
	if err != nil {
		return nil, err
	}
	groups := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	if groups.GroupCount == 0 {
		return nil, fmt.Errorf("sandbox: token has no logon sid")
	}
	return groups.Groups[0].Sid, nil
}

// userSidOf 取令牌的用户 SID（TokenUser 信息类）。
// HKCU/用户配置文件的 DACL 普遍只授用户 SID——restricting 集合缺它时，
// WRITE_RESTRICTED 下进程初始化写这些对象被拒（STATUS_DLL_INIT_FAILED）。
func userSidOf(token windows.Token) (*windows.SID, error) {
	var retLen uint32
	windows.GetTokenInformation(token, windows.TokenUser, nil, 0, &retLen)
	buf := make([]byte, retLen)
	err := windows.GetTokenInformation(token, windows.TokenUser, &buf[0], uint32(len(buf)), &retLen)
	if err != nil {
		return nil, err
	}
	user := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))
	return user.User.Sid, nil
}

// aclObjectPath 把原生态路径规整为长路径安全形态（\\?\ 前缀）：绕过
// MAX_PATH 限制——注册表 LongPathsEnabled=0 的机器上，无前缀的 >260 字符
// 路径在 Win32 层直接失败（本机注册表已开，见 permission_rules/测试）。
func aclObjectPath(path string) string {
	p := strings.ReplaceAll(path, "/", `\`)
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) { // UNC：\\server\share → \\?\UNC\server\share
		return `\\?\UNC\` + strings.TrimPrefix(p, `\\`)
	}
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' {
		return `\\?\` + filepath.Clean(p)
	}
	if abs, err := filepath.Abs(p); err == nil {
		return aclObjectPath(abs)
	}
	return p
}

// aclOpenObject 打开对象句柄（共享全开；目录需 FILE_FLAG_BACKUP_SEMANTICS，
// 文件无害）。不显式穿透/驻留重解析点，与命名 API 的路径解析口径一致。
func aclOpenObject(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(aclObjectPath(path))
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

// aclReadDACL 经对象句柄读 DACL（长路径安全；READ_CONTROL）。
func aclReadDACL(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	h, err := aclOpenObject(path, windows.READ_CONTROL)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	return windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
}

// aclWriteDACL 经对象句柄写 DACL（长路径安全；WRITE_DAC）。
func aclWriteDACL(path string, dacl *windows.ACL) error {
	h, err := aclOpenObject(path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// grantDirWrite 保证目录的 DACL 上存在能力 SID 完全访问 ACE（继承到子对象）。
// 幂等：已有该 SID 的完全访问允许 ACE 时跳过——既避免重复调用产生重复 ACE
// （SetEntriesInAcl 不去重），也让目录被删重建后自动重新授权（无进程级缓存）。
func grantDirWrite(dir string, sid *windows.SID) error {
	sd, err := aclReadDACL(dir)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	// 幂等检查：已有该能力 SID 的完全访问允许 ACE 则跳过
	if dacl != nil {
		granted, err := aclHasFullGrant(dacl, sid)
		if err != nil {
			return err
		}
		if granted {
			return nil
		}
	}

	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileAllAccess,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       subContainersAndObjectsInherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	newAcl, err := windows.ACLFromEntries(entries, dacl)
	if err != nil {
		return err
	}
	return aclWriteDACL(dir, newAcl)
}

// aclHasFullGrant 检查 ACL 是否已有指定 SID 的完全访问允许 ACE
// （直接解析 ACL 内存布局：ACL 头 + ACE 链表，不依赖额外 API）。
func aclHasFullGrant(acl *windows.ACL, sid *windows.SID) (bool, error) {
	if acl == nil {
		return false, nil
	}
	head := (*[8]byte)(unsafe.Pointer(acl))
	aclSize := int(binary.LittleEndian.Uint16(head[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(head[4:6]))
	off := 8
	for i := 0; i < aceCount; i++ {
		if off+8 > aclSize {
			return false, fmt.Errorf("sandbox: acl parse: ace header out of range")
		}
		ace := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(acl)) + uintptr(off)))
		if int(ace.AceSize) < 8 || off+int(ace.AceSize) > aclSize {
			return false, fmt.Errorf("sandbox: acl parse: ace size out of range")
		}
		if ace.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			aa := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(ace))
			if aa.Mask&fileAllAccess == fileAllAccess {
				aceSid := (*windows.SID)(unsafe.Pointer(&aa.SidStart))
				if aceSid.String() == sid.String() {
					return true, nil
				}
			}
		}
		off += int(ace.AceSize)
	}
	return false, nil
}

// capabilitySID 派生确定性能力 SID（S-1-4-<a>-<b>，自路径哈希）：
// 同路径（同命名空间）恒得同一 SID，跨进程稳定。
func capabilitySID(ns, path string) (*windows.SID, error) {
	h := sha256.Sum256([]byte(ns + ":" + filepath.Clean(path)))
	a := binary.BigEndian.Uint32(h[0:4]) & 0x7fffffff
	b := binary.BigEndian.Uint32(h[4:8]) & 0x7fffffff
	return windows.StringToSid(fmt.Sprintf("S-1-4-%d-%d", a, b))
}

// probeBackend（windows）：创建空受限令牌探测——成功即可用
// （不实际启动子进程，验证 CreateRestrictedToken 可用即可）。
func probeBackend() sandboxBackend {
	tok, err := createRestrictedToken(nil)
	if err != nil {
		return backendUnavailable
	}
	tok.Close()
	return backendWindowsAcl
}

// planConfined（windows）：受限令牌 + ACL 授权（写白名单）+ 持久 deny ACE
// + Job Object 资源限制。
//   - read-only：restricting list 无能力 SID → 除 Everyone 可写对象外全拒
//   - workspace-write：工作区/缓存目录（fsauth.CacheRoots）/追加根（extra）
//     standing ACE + per-call 私有临时目录（TMP/TEMP 指向它），进程结束后清理
//   - deny：稳定 deny SID 加入 restricting list，对 deny 目标确保存在完全拒绝
//     ACE（写被拒——WRITE_RESTRICTED 的 pass-2 只覆盖写访问，读不在受限令牌
//     可表达范围（Windows 边界，与 dsh/codex 一致：读侧隔离需另一机制，fs 工具
//     层不受影响）；ACE 继承到子对象并持久保留，到期对账见持久模型注释）；
//     模式形态不可实例化或可达对象加不上 ACE → 拒绝执行（fail-closed）
//   - 资源限制：Job Object（进程内存 4GiB / job 内存 8GiB / 活动进程 256），
//     spawn 后由 Manager assign 子进程（assignJob）；job 句柄随 cleanup 关闭
//   - 返回原样 argv + 令牌句柄 + job 句柄（spawn 后由 Manager 使用/关闭）
//
// fsOpen（写全放）与网络规则无法用令牌模型表达，已由 validateProcessPolicy
// 拒绝；fs_allow 通配写授权（writeAllow）同样无法表达——忽略即少授（安全方向）。
func planConfined(spec confineSpec) (launchPlan, error) {
	// 阶段计时（打点）：每步耗时随 plan 完成一次性写出（spec.logf 未注入则静默）
	t0 := time.Now()
	last := t0
	mark := func() time.Duration {
		now := time.Now()
		d := now.Sub(last)
		last = now
		return d.Round(time.Millisecond)
	}
	// 路径形态边界（2026-09-24 /c/ 规范形全局统一）：策略层路径（deny/extra/
	// workdir 可能带 /c/ 规范形）一律转原生态——本文件后续全按 OS 路径消费。
	spec.deny = pathsToOS(spec.deny)
	spec.extra = pathsToOS(spec.extra)
	if spec.workdir != "" {
		spec.workdir = pathToOS(spec.workdir)
	}
	logf := spec.logf
	if err := validateProcessPolicy(spec, "windows"); err != nil {
		return launchPlan{}, err
	}
	validateD := mark()
	if selectBackend() == backendUnavailable {
		return launchPlan{}, sandboxUnavailable()
	}
	var extraSids []*windows.SID
	var tmpDir string
	var grantD, tmpD time.Duration
	// fs deny：稳定 SID + 持久拒绝 ACE（幂等 ensure；不按进程撤销）
	denySid, err := ensureDenyACEs(spec.deny, spec.fsRules, spec.extra, logf)
	if err != nil {
		return launchPlan{}, err
	}
	denyD := mark()
	if denySid != nil {
		extraSids = append(extraSids, denySid)
	}
	cleanup := func() {}

	// 可写区授权（workspace-write profile 由 rules 派生，数字等级已删除）。
	{
		dirs := make([]string, 0, 4)
		if spec.workdir != "" {
			dirs = append(dirs, spec.workdir)
		}
		dirs = append(dirs, cacheRoots()...)
		dirs = append(dirs, publicRoots()...)
		dirs = append(dirs, spec.extra...)
		for _, d := range dirs {
			sid, err := capabilitySID("ws", d)
			if err != nil {
				return launchPlan{}, fmt.Errorf("sandbox: workspace sid: %w", err)
			}
			// 幂等授权：已有 ACE 跳过，目录重建后自动补授
			if err := grantDirWrite(d, sid); err != nil {
				return launchPlan{}, fmt.Errorf("sandbox: grant workspace %s: %w", d, err)
			}
			extraSids = append(extraSids, sid)
		}
		grantD = mark()

		// per-call 私有临时目录：随机路径 + 随机 SID，进程结束后删除
		var err error
		tmpDir, err = os.MkdirTemp("", "aic-sandbox-*")
		if err != nil {
			return launchPlan{}, fmt.Errorf("sandbox: private temp: %w", err)
		}
		tmpSid, err := capabilitySID("tmp", tmpDir)
		if err != nil {
			os.RemoveAll(tmpDir)
			return launchPlan{}, fmt.Errorf("sandbox: temp sid: %w", err)
		}
		if err := grantDirWrite(tmpDir, tmpSid); err != nil {
			os.RemoveAll(tmpDir)
			return launchPlan{}, fmt.Errorf("sandbox: grant temp: %w", err)
		}
		extraSids = append(extraSids, tmpSid)
		tmpD = mark()
		cleanup = func() { os.RemoveAll(tmpDir) } // 私有临时目录随进程结束删除
	}

	tok, err := createRestrictedToken(extraSids)
	if err != nil {
		cleanup()
		return launchPlan{}, fmt.Errorf("sandbox: restricted token: %w", err)
	}
	tokenD := mark()

	// Job Object 资源限制（与令牌/ACL 正交，read-only 与 workspace-write 同限）
	job, err := newJobWithLimits()
	if err != nil {
		tok.Close()
		cleanup()
		return launchPlan{}, fmt.Errorf("sandbox: job object: %w", err)
	}
	jobD := mark()
	cleanup = func() {
		start := time.Now()
		os.RemoveAll(tmpDir)
		closeJob(uintptr(job))
		if logf != nil && tmpDir != "" {
			logf("sandbox: cleanup tmp-remove+close-job=%s", time.Since(start).Round(time.Millisecond))
		}
	}

	if logf != nil {
		logf("sandbox(windows): plan validate=%s deny=%s ws-grant=%s tmp=%s token=%s job=%s total=%s",
			validateD, denyD, grantD, tmpD, tokenD, jobD, time.Since(t0).Round(time.Millisecond))
	}

	env := []string{}
	if tmpDir != "" {
		env = append(env, "TMP="+tmpDir, "TEMP="+tmpDir)
	}
	return launchPlan{argv: spec.argv, token: uintptr(tok), job: uintptr(job), env: env, cleanup: cleanup}, nil
}

// newJobWithLimits 创建 Job Object 并施加资源限制：
//   - JOB_OBJECT_LIMIT_PROCESS_MEMORY：job 内单进程内存上限（4GiB）
//   - JOB_OBJECT_LIMIT_JOB_MEMORY：job 内全部进程合计内存上限（8GiB）
//   - JOB_OBJECT_LIMIT_ACTIVE_PROCESS：job 内活动进程数上限（防 fork 炸弹）
//
// 限制对 job 内所有子孙进程强制（超限即创建失败/分配失败，不会打爆系统）。
func newJobWithLimits() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
				windows.JOB_OBJECT_LIMIT_JOB_MEMORY |
				windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
			ActiveProcessLimit: resourceLimitJobProcesses,
		},
		ProcessMemoryLimit: uintptr(resourceLimitAS),
		JobMemoryLimit:     uintptr(resourceLimitJobMemory),
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// assignJob 把已启动的进程关联进 Job Object（spawn 后立即调用，限制即生效）。
// 失败必须 fail-closed：调用方负责终止进程并返回错误（不裸跑）。
func assignJob(pid int, job uintptr) error {
	if job == 0 {
		return nil
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)
	return windows.AssignProcessToJobObject(windows.Handle(job), proc)
}

// closeJob 关闭 Job Object 句柄（进程结束后调用；job 内进程已全部退出）。
func closeJob(job uintptr) {
	if job != 0 {
		_ = windows.CloseHandle(windows.Handle(job))
	}
}

// applyToken 把受限令牌注入子进程启动属性（windows）。
// 控制台策略保持 SetSysProcAttr 的 CREATE_NO_WINDOW：2026-09-23 真机矩阵
// （TestWindowsConsoleModeMatrix）证实 restricting list 正确携带
// [logon, Everyone]+能力 SID 时，各控制台模式（含 NO_WINDOW/NEW_CONSOLE）
// 在有无控制台父进程下均正常启动——历史 "WRITE_RESTRICTED 下子进程全灭"
// 与 CREATE_NO_WINDOW 无关（实为 CreateRestrictedToken 参数错位致
// restricting 列表为空，见 createRestrictedToken 注）。
func applyToken(cmd *exec.Cmd, token uintptr) error {
	cmd.SysProcAttr.Token = syscall.Token(token)
	return nil
}

// closeToken 关闭令牌句柄（spawn 成功后子进程持有副本，句柄可释放）。
func closeToken(token uintptr) {
	if token != 0 {
		_ = windows.CloseHandle(windows.Handle(token))
	}
}

// ---- fs deny 的 windows 落地：持久拒绝 ACE ----
//
// 稳定 SID（S-1-4-<a>-<b>，能力 SID 确定性派生）加入受限令牌的 restricting
// list，并对每个 deny 目标对象确保存在该 SID 的完全拒绝 ACE：
//   - SetEntriesInAcl 把 deny ACE 放在 ACL 首部（先于 allow 求值），写访问的
//     pass-2 检查命中拒绝 → 写被拒（WRITE_DAC/WRITE_OWNER 等写类位一并拒，
//     防沙箱进程自行摘除 ACE）；读不做 pass-2 检查（Windows 边界，见文件头注）；
//   - ACE 继承到子对象（目录整棵子树）；
//   - 该 SID 只出现在沙箱进程令牌中，宿主机其他进程不受 DACL 变更影响；
//   - ACE 持久保留（不随进程结束撤销），到期对账见下文持久模型注释。
//
// 可达性判定：加不上 ACE（无 WRITE_DAC）时，若 DACL 未向任何通用 restricted
// SID 授读/写/执行权（沙箱本就不可达）则跳过（语义等价的无操作）；否则
// fail-closed 拒绝执行。

// denyAceMask 是 deny ACE 的拒绝掩码：完全拒绝（读/写/执行/删除/改
// DACL/owner；也是可达性判定时排除元数据位的参考值）。
const denyAceMask = fileAllAccess

// reachMask 是可达性判定的访问位：读/写/执行/删子项（不含 SYNCHRONIZE/
// READ_CONTROL 这类元数据位，避免过度保守）。
const reachMask = 0x120089 | 0x120116 | 0x1200A0 | 0x40

// randomDenySID 生成本次调用的随机 deny SID（两段随机 31 位）。
func randomDenySID() (*windows.SID, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	a := binary.BigEndian.Uint32(b[0:4]) & 0x7fffffff
	c := binary.BigEndian.Uint32(b[4:8]) & 0x7fffffff
	return windows.StringToSid(fmt.Sprintf("S-1-4-%d-%d", a, c))
}

// denyACLWorkers 是 deny ACE 校验/施加/撤销的并发度：目标可达上百个，逐个
// Get/SetSecurityInfo 数毫秒到十几毫秒（win 实测 79 目标一轮 ≈ 1.3s），
// 这些对象彼此独立，并发跑互不相干。
const denyACLWorkers = 8

// ---- 持久 deny ACE（codex windows-sandbox-rs 同模型，2026-09-23 改）----
//
// 稳定 deny SID + 持久 ACE + 幂等 ensure（有则跳过），不再「每调用随机 SID、
// 全量打、全量撤」：
//  1) 旧模型每条命令对上百个目标做两轮 Get/Set（79 目标 ≈ 施加 1.3s + 撤销
//     1.3s）；codex 的稳定 SID + 幂等 ensure 在稳态下零 ACL 操作；
//  2) 沙箱进程的后代可能比 launcher 活得久（codex 同款理由）——进程结束即
//     撤销会把仍在运行的后代暴露在无 deny 状态，持久 ACE 反而更安全；
//  3) 残留 ACE 只对稳定 deny SID 生效：该 SID 仅出现在沙箱进程令牌的
//     restricting list 中，宿主机其他进程（含用户自己）不受影响。
//
// 代价与对账：文件上会留下拒绕 ACE（icacls 可见，无写权即无害）。不再需要的
// 目标靠状态文件对账撤销（新目标补打、旧目标撤销、重算时并行校验——对象删除
// 重建会丢 ACE）；目标对象消失时其 ACE 随对象消亡。

// denyACLStateFile 是持久状态文件名（记录稳定 SID 已打 ACE 的路径）。
const denyACLStateFile = "deny_acl_state.json"

// denyACLStatePathOverride 供测试改写状态文件路径（空 = 用户配置目录默认位置）。
var denyACLStatePathOverride string

// denyACLStatePath 返回状态文件路径（{UserConfigDir}/aic/sandbox/deny_acl_state.json）。
func denyACLStatePath() string {
	if denyACLStatePathOverride != "" {
		return denyACLStatePathOverride
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "aic", "sandbox", denyACLStateFile)
}

// denyACLState 是持久状态（codex deny_read_acl_state.json 同构）。
type denyACLState struct {
	SID     string   `json:"sid"`
	Applied []string `json:"applied"`
}

var (
	denyACLMu    sync.Mutex
	denyACLCache *denyACLState
)

// stableDenySID 返回跨调用/重启稳定的 deny SID（能力 SID 确定性派生：同一
// 安装恒得同一 SID，已打 ACE 长期有效）。
func stableDenySID() (*windows.SID, error) {
	return capabilitySID("deny", "aic-windows-sandbox")
}

// denyPathKey 归一化路径键（状态比较用；与状态文件内的字面路径解耦）。
func denyPathKey(p string) string {
	return strings.ToLower(filepath.ToSlash(p))
}

// loadDenyACLState 读状态文件（缺失/损坏 = 空状态：损坏时下次对账以读校验
// 补齐，不会重复打 ACE）。
func loadDenyACLState() *denyACLState {
	path := denyACLStatePath()
	if path == "" {
		return &denyACLState{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return &denyACLState{}
	}
	var st denyACLState
	if err := json.Unmarshal(b, &st); err != nil {
		return &denyACLState{}
	}
	return &st
}

// storeDenyACLState 落盘状态（best-effort：失败仅记日志——最坏情形是下次
// 重算把已有 ACE 再校验一遍）。
func storeDenyACLState(st *denyACLState, logf func(string, ...any)) {
	path := denyACLStatePath()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		if logf != nil {
			logf("sandbox: deny state dir: %v", err)
		}
		return
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		if logf != nil {
			logf("sandbox: deny state write: %v", err)
		}
		return
	}
	if err := os.Rename(tmp, path); err != nil && logf != nil {
		logf("sandbox: deny state rename: %v", err)
	}
}

// denyParallelPaths 以 denyACLWorkers 并发处理路径列表，返回首个错误。
func denyParallelPaths(paths []string, fn func(i int, path string) error) error {
	if len(paths) == 0 {
		return nil
	}
	var (
		wg       sync.WaitGroup
		sem      = make(chan struct{}, denyACLWorkers)
		errMu    sync.Mutex
		firstErr error
	)
	for i, p := range paths {
		i, p := i, p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(i, p); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

// ensureDenyACEs 使 deny 目标集带上稳定 deny SID 的拒绝 ACE（幂等）。目标集
// 来自 denyCoverAllCached（TTL 缓存）：
//   - 缓存命中的稳态调用：只做内存差集（仅新目标要读校验），零 ACL 读；
//   - 缓存重算（TTL 过期/模式变化）：既有目标全部并行校验（对象删除重建会
//     丢 ACE，需补打），不再需要的旧目标撤销（对账）。
//
// 返回 deny SID（无目标 = nil，此时无需放进 restricting list）与错误：
// 可达对象加不上 ACE → fail-closed（命令不执行；已打上的 ACE 保留并落状态）。
func ensureDenyACEs(patterns []string, rules *FSRuleSet, writable []string, logf func(string, ...any)) (*windows.SID, error) {
	if len(patterns) == 0 && rules == nil {
		return nil, nil
	}
	sid, err := stableDenySID()
	if err != nil {
		return nil, fmt.Errorf("sandbox: deny sid: %w", err)
	}
	targets, cached, err := denyCoverAllCached(patterns, logf)
	if err != nil {
		return nil, err
	}
	if rules != nil {
		// W3：授权快照经 first-wins 统一求值——终局 rw 的目标跳过 ACE
		// （内核放行，与快照终局一致）；ro 与 deny 仍落 ACE（windows
		// per-call ACE = 写拒/读放，与 ro 语义一致；读侧 deny 是文档化边界）。
		// 独立 ro 行（落在可写白名单根之下）同口径补 ACE；嵌套洞内核不可落
		// ——仅工具层生效。不可精确表达的 ro 通配行在此拒绝执行。
		plan, err := evaluateFSPolicy(targets, rules, writable, false)
		if err != nil {
			return nil, err
		}
		targets = append(append([]string{}, plan.cover...), plan.ro...)
		if len(plan.rw) > 0 && logf != nil {
			logf("sandbox: deny ACE skip rw-hole targets=%d", len(plan.rw))
		}
	}
	// 策略层 → ACL 边界的路径形态统一：ro 行经 evaluateFSPolicy 产出 /c/ 规范形
	// （canonical），Win32 安全 API 只认原生态路径——不转换会被静默跳过（对象
	// 不可读口径），ro 行 ACE 永不落地。deny 实例化目标在此已是原生态，转换幂等。
	targets = pathsToOS(targets)
	if len(targets) == 0 {
		return nil, nil
	}
	restricted := restrictedSIDsForReachability()

	denyACLMu.Lock()
	if denyACLCache == nil {
		denyACLCache = loadDenyACLState()
	}
	previous := append([]string(nil), denyACLCache.Applied...)
	denyACLMu.Unlock()

	prevSet := make(map[string]bool, len(previous))
	for _, p := range previous {
		prevSet[denyPathKey(p)] = true
	}
	desiredSet := make(map[string]bool, len(targets))
	var toCheck []string
	for _, p := range targets {
		desiredSet[denyPathKey(p)] = true
		if !cached || !prevSet[denyPathKey(p)] {
			// 重算：全部校验；命中：仅校验不在状态里的新目标（稳态 0 读）
			toCheck = append(toCheck, p)
		}
	}
	var toRevoke []string
	for _, p := range previous {
		if !desiredSet[denyPathKey(p)] {
			toRevoke = append(toRevoke, p)
		}
	}

	start := time.Now()
	present := make([]bool, len(toCheck))
	addedFlags := make([]bool, len(toCheck))
	err = denyParallelPaths(toCheck, func(i int, p string) error {
		a, ok, err := ensureDenyACE(p, sid, restricted)
		if err != nil {
			return err
		}
		present[i], addedFlags[i] = ok, a
		return nil
	})

	// 组装新的已应用集合（保留旧顺序 + 校验通过的新目标）
	next := make([]string, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, p := range previous {
		k := denyPathKey(p)
		if desiredSet[k] && !seen[k] {
			next = append(next, p)
			seen[k] = true
		}
	}
	addedCount := 0
	for i, p := range toCheck {
		if !present[i] {
			continue
		}
		k := denyPathKey(p)
		if !seen[k] {
			next = append(next, p)
			seen[k] = true
		}
		if addedFlags[i] {
			addedCount++
		}
	}
	// 不再需要的旧目标：撤销（best-effort）
	if len(toRevoke) > 0 {
		_ = denyParallelPaths(toRevoke, func(_ int, p string) error {
			_ = revokeDenyACE(p, sid)
			return nil
		})
	}
	state := &denyACLState{SID: sid.String(), Applied: next}
	denyACLMu.Lock()
	changed := len(next) != len(previous)
	denyACLCache = state
	denyACLMu.Unlock()
	if changed || len(toCheck) > 0 || len(toRevoke) > 0 {
		storeDenyACLState(state, logf)
	}
	if logf != nil {
		logf("sandbox: deny ensure: desired=%d checked=%d added=%d stale=%d cached=%v took=%s",
			len(targets), len(toCheck), addedCount, len(toRevoke), cached, time.Since(start).Round(time.Millisecond))
	}
	if err != nil {
		return nil, err
	}
	return sid, nil
}

// ensureDenyACE 确保对象带稳定 SID 的拒绝 ACE（先读校验、缺才写——codex
// add_deny_write_ace 同款幂等语义）。added = 本次写入；present = 对象当前已
// 有该 ACE（含本次写入）。对象不可读 → (false, false, nil) 跳过（与
// addDenyACE 的不可达口径一致）。
func ensureDenyACE(path string, sid *windows.SID, restricted []*windows.SID) (added, present bool, err error) {
	sd, err := aclReadDACL(path)
	if err != nil {
		return false, false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, false, nil
	}
	if aclHasDenyForSID(dacl, sid) {
		return false, true, nil
	}
	ok, err := addDenyACE(path, sid, restricted)
	if err != nil {
		return false, false, err
	}
	return ok, ok, nil
}

// aclHasDenyForSID 检查 DACL 中是否已有该 SID 的有效拒绝 ACE（仅继承位
// （INHERIT_ONLY）的 ACE 对对象自身不生效，不算）。
func aclHasDenyForSID(acl *windows.ACL, sid *windows.SID) bool {
	if acl == nil || sid == nil {
		return false
	}
	head := (*[8]byte)(unsafe.Pointer(acl))
	aclSize := int(binary.LittleEndian.Uint16(head[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(head[4:6]))
	off := 8
	for i := 0; i < aceCount; i++ {
		if off+8 > aclSize {
			return false
		}
		ace := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(acl)) + uintptr(off)))
		if int(ace.AceSize) < 8 || off+int(ace.AceSize) > aclSize {
			return false
		}
		if ace.AceType == windows.ACCESS_DENIED_ACE_TYPE && ace.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			// ACCESS_DENIED_ACE 与 ACCESS_ALLOWED_ACE 布局一致（头 + 掩码 + SidStart）
			da := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(ace))
			aceSid := (*windows.SID)(unsafe.Pointer(&da.SidStart))
			if aceSid.String() == sid.String() {
				return true
			}
		}
		off += int(ace.AceSize)
	}
	return false
}

// addDenyACE 在目标对象上追加 deny SID 的完全拒绝 ACE（继承到子对象）。
// ok=false 表示对象对受限令牌本就不可达（DACL 未向通用 restricted SID 授
// 访问权）——跳过是语义等价的无操作；其余失败返回错误（fail-closed）。
func addDenyACE(path string, denySid *windows.SID, restricted []*windows.SID) (bool, error) {
	sd, err := aclReadDACL(path)
	if err != nil {
		// 宿主无 READ_CONTROL：读/改该对象 DACL 均不可行；受限令牌同样拿不到
		// 读授权（READ_CONTROL 普遍对所有用户开放），跳过等价无操作。
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, nil
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: denyAceMask,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       subContainersAndObjectsInherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(denySid),
		},
	}}
	if dacl == nil {
		// NULL DACL = 所有人完全访问：追加 Everyone 完全允许条目保持既有
		// 语义（否则只含 deny 的 DACL 会锁死其他进程）。
		everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			return false, fmt.Errorf("sandbox: deny %s: %w", path, err)
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		})
	}
	newAcl, err := windows.ACLFromEntries(entries, dacl)
	if err != nil {
		return false, fmt.Errorf("sandbox: deny acl %s: %w", path, err)
	}
	if err := aclWriteDACL(path, newAcl); err != nil {
		if aclReachable(dacl, restricted) {
			return false, fmt.Errorf("sandbox: deny %s: %w", path, err)
		}
		return false, nil
	}
	return true, nil
}

// removeAcesForSID 返回 DACL 的字节级重建副本：删除 trustee 为该 SID 的
// 全部 ACE（allow/deny 同删），其余 ACE 原样保留。ACL 结构自包含（ACE 内联
// SID），重建 = 拷贝 + 修正头（AclSize/AceCount）。第二个返回值为 false 表示
// DACL 中没有该 SID 的 ACE（无需变更）。
func removeAcesForSID(dacl *windows.ACL, sid *windows.SID) (*windows.ACL, bool, error) {
	if dacl == nil || sid == nil {
		return nil, false, nil
	}
	head := (*[8]byte)(unsafe.Pointer(dacl))
	aclSize := int(binary.LittleEndian.Uint16(head[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(head[4:6]))
	if aclSize < 8 {
		return nil, false, fmt.Errorf("sandbox: acl parse: implausible size %d", aclSize)
	}
	buf := make([]byte, 8, aclSize)
	copy(buf, head[:])
	want := sid.String()
	kept := 0
	removed := false
	off := 8
	for i := 0; i < aceCount; i++ {
		if off+8 > aclSize {
			return nil, false, fmt.Errorf("sandbox: acl parse: ace header out of range")
		}
		ace := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + uintptr(off)))
		size := int(ace.AceSize)
		if size < 8 || off+size > aclSize {
			return nil, false, fmt.Errorf("sandbox: acl parse: ace size out of range")
		}
		match := false
		switch ace.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_DENIED_ACE_TYPE:
			aa := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(ace))
			aceSid := (*windows.SID)(unsafe.Pointer(&aa.SidStart))
			match = aceSid.String() == want
		}
		if match {
			removed = true
		} else {
			buf = append(buf, (*[(1 << 16) - 1]byte)(unsafe.Pointer(ace))[:size:size]...)
			kept++
		}
		off += size
	}
	if !removed {
		return nil, false, nil
	}
	buf[2] = byte(len(buf))
	buf[3] = byte(len(buf) >> 8)
	buf[4] = byte(kept)
	buf[5] = byte(kept >> 8)
	return (*windows.ACL)(unsafe.Pointer(&buf[0])), true, nil
}

// revokeDenyACE 撤销本调用追加的 deny ACE：取对象当前 DACL，字节级重建副本
// （删除该 SID 的全部 ACE）后应用。不走 SetEntriesInAcl 的 REVOKE_ACCESS
// 合并——win11 26200 实测该路径返回 ERROR_SUCCESS 但 deny 类 ACE 残留
// （带/不带继承位均如此；同样形态在 codex/dsh 环境可用，本机行为未再归因），
// 字节级重建与 ACL 编辑器删除 ACE 同语义。返回错误供诊断/调用方处理
// （撤销调用方仍为 best-effort 语义）。
func revokeDenyACE(path string, denySid *windows.SID) error {
	sd, err := aclReadDACL(path)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	newAcl, changed, err := removeAcesForSID(dacl, denySid)
	if err != nil || !changed {
		return err
	}
	return aclWriteDACL(path, newAcl)
}

// restrictedSIDsForReachability 汇总 restricting list 中的通用 SID
// （Everyone/INTERACTIVE/Authenticated Users/BUILTIN Users/用户/logon）——
// 「加不上 deny ACE 时对象对沙箱是否可达」的判定集合。
func restrictedSIDsForReachability() []*windows.SID {
	out := make([]*windows.SID, 0, 6)
	for _, wks := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,
		windows.WinInteractiveSid,
		windows.WinAuthenticatedUserSid,
		windows.WinBuiltinUsersSid,
	} {
		if s, err := windows.CreateWellKnownSid(wks); err == nil {
			out = append(out, s)
		}
	}
	tok := windows.GetCurrentProcessToken()
	if s, err := userSidOf(tok); err == nil {
		out = append(out, s)
	}
	if s, err := logonSidOf(tok); err == nil {
		out = append(out, s)
	}
	return out
}

// aclReachable 判定 DACL 是否向给定 SID 集授予读/写/执行/删子项权。
// nil DACL = 所有人完全访问 → 恒可达；解析异常按可达处理（保守）。
func aclReachable(dacl *windows.ACL, sids []*windows.SID) bool {
	if dacl == nil {
		return true
	}
	head := (*[8]byte)(unsafe.Pointer(dacl))
	aclSize := int(binary.LittleEndian.Uint16(head[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(head[4:6]))
	off := 8
	for i := 0; i < aceCount; i++ {
		if off+8 > aclSize {
			return true
		}
		ace := (*windows.ACE_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + uintptr(off)))
		if int(ace.AceSize) < 8 || off+int(ace.AceSize) > aclSize {
			return true
		}
		if ace.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			aa := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(ace))
			if aa.Mask&reachMask != 0 {
				aceSid := (*windows.SID)(unsafe.Pointer(&aa.SidStart))
				for _, s := range sids {
					if s != nil && aceSid.String() == s.String() {
						return true
					}
				}
			}
		}
		off += int(ace.AceSize)
	}
	return false
}

// pathToOS 把 /c/ 规范形（及旧输入形）转 windows 原生态（=
// proto.HostPathToOS）。策略层 → ACL/令牌边界的单一转换点。
func pathToOS(p string) string { return HostPathToOS(p) }

func pathsToOS(in []string) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = pathToOS(p)
	}
	return out
}
